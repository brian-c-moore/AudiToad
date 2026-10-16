//! Bounded physical reads and immutable source content.
use crate::{
    ScanError, json,
    schema::{Limits, SourceIdentity, TargetIdentity},
};
use automation_structures::{Budget, Sequential};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs,
    io::Read,
    path::{Component, Path, PathBuf},
};

pub(crate) const SERIALIZER: &str = "serde-json/1.0.151/declared-fields-sorted-maps/1";

pub fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

pub(crate) fn digest_fields(fields: &[&str]) -> String {
    let mut hash = Sha256::new();
    for field in fields {
        hash.update((field.len() as u64).to_be_bytes());
        hash.update(field.as_bytes());
    }
    format!("{hash:x}", hash = hash.finalize())
}

/// Reject symbolic links, Windows junctions and other reparse points at every existing component.
pub(crate) fn unlinked_path(path: &Path) -> Result<PathBuf, String> {
    let absolute = std::path::absolute(path).map_err(|e| e.to_string())?;
    let mut current = PathBuf::new();
    for component in absolute.components() {
        if matches!(component, Component::ParentDir) {
            return Err("parent traversal is not supported".into());
        }
        current.push(component);
        let Ok(meta) = fs::symlink_metadata(&current) else {
            continue;
        };
        if meta.file_type().is_symlink() {
            return Err(format!("linked path refused: {}", current.display()));
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if meta.file_attributes() & 0x400 != 0 {
                return Err(format!("reparse path refused: {}", current.display()));
            }
        }
    }
    Ok(absolute)
}

pub(crate) fn read_bounded(path: &Path, limit: u64) -> Result<Vec<u8>, String> {
    read_budgeted(path, &mut Budget::new(limit))
}

/// Physical binding of one read to a possibly cumulative byte owner.
pub(crate) fn read_budgeted(path: &Path, budget: &mut Budget) -> Result<Vec<u8>, String> {
    let limit = budget.available();
    let path = unlinked_path(path)?;
    let file = fs::File::open(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    if !file.metadata().map_err(|e| e.to_string())?.is_file() {
        return Err("input must be a regular file".into());
    }
    let mut bytes = Vec::new();
    file.take(limit.checked_add(1).ok_or("invalid byte ceiling")?)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if !budget.try_allocate(bytes.len() as u64) {
        return Err(format!("input exceeds {limit} byte limit"));
    }
    Ok(bytes)
}

pub(crate) fn fixture_path(root: &Path, path: &str) -> Result<PathBuf, String> {
    if Path::new(path).is_absolute()
        || Path::new(path)
            .components()
            .any(|c| !matches!(c, Component::Normal(_) | Component::CurDir))
    {
        return Err(format!(
            "fixture must be relative without parent traversal: {path}"
        ));
    }
    unlinked_path(&root.join(path))
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InventoryItem {
    pub id: String,
    pub kind: String,
    pub facts: Map<String, Value>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Inventory {
    schema: String,
    snapshot_id: String,
    items: Vec<InventoryItem>,
}

#[derive(Debug, Clone)]
pub(crate) struct Target {
    pub identity: TargetIdentity,
    pub bytes: Vec<u8>,
    pub applicability_key: String,
    pub path: Option<PathBuf>,
    pub dependencies: std::sync::Arc<[(PathBuf, String)]>,
}

/// Immutable supplied snapshot. Private fields prevent callers from relabeling its bytes.
#[derive(Debug)]
pub struct Snapshot {
    pub(crate) identity: SourceIdentity,
    pub(crate) targets: Vec<Target>,
    pub(crate) input_path: Option<PathBuf>,
    pub(crate) protected_paths: Vec<PathBuf>,
    pub(crate) excluded: Vec<String>,
}

impl Snapshot {
    pub fn raw_bytes(bytes: Vec<u8>, name: &str, limits: &Limits) -> Result<Self, ScanError> {
        if !Budget::new(limits.input_bytes).try_allocate(bytes.len() as u64)
            || !Budget::new(limits.targets as u64).try_allocate(1)
        {
            return Err(ScanError::unresolved(
                "raw-byte source exceeds input/target limit",
            ));
        }
        if name.is_empty() {
            return Err(ScanError::invalid("input name is empty"));
        }
        let digest = sha256(&bytes);
        Ok(Self {
            identity: SourceIdentity {
                binding: "raw-bytes/1".into(),
                snapshot_id: digest.clone(),
                input_sha256: digest.clone(),
                serializer: SERIALIZER.into(),
                metadata: json!({"name": name}),
            },
            targets: vec![Target {
                identity: TargetIdentity {
                    id: "input/0".into(),
                    kind: "application/octet-stream".into(),
                    sha256: digest,
                    metadata: json!({"name": name}),
                },
                bytes,
                applicability_key: name.into(),
                path: None,
                dependencies: Default::default(),
            }],
            input_path: None,
            protected_paths: Vec::new(),
            excluded: Vec::new(),
        })
    }

    pub fn inventory(bytes: &[u8], limits: &Limits) -> Result<Self, ScanError> {
        if !Budget::new(limits.input_bytes).try_allocate(bytes.len() as u64) {
            return Err(ScanError::unresolved("inventory exceeds input byte limit"));
        }
        let inventory: Inventory = json::parse(bytes).map_err(ScanError::invalid)?;
        if !matches!(
            inventory.schema.as_str(),
            "auditoad-inventory/1" | "checkwarden-inventory/1"
        ) || inventory.snapshot_id.is_empty()
        {
            return Err(ScanError::invalid(
                "invalid inventory schema or empty snapshot_id",
            ));
        }
        let mut ids = BTreeSet::new();
        let mut targets = Vec::new();
        let mut target_owner = Budget::new(limits.targets as u64);
        let mut frame_owner = Budget::new(limits.evidence_bytes);
        let mut items = inventory.items.into_iter();
        let mut steps = if items.len() == 0 {
            None
        } else {
            Some(
                Sequential::new(items.len(), 1, 0)
                    .map_err(|e| ScanError::unresolved(e.to_string()))?,
            )
        };
        while let Some(owner) = steps.as_mut().filter(|owner| !owner.is_done()) {
            if !owner.begin_step() || !target_owner.try_allocate(1) {
                return Err(ScanError::unresolved(
                    "inventory target preparation refused admission",
                ));
            }
            let item = items.next().ok_or_else(|| {
                ScanError::unresolved("inventory item missing at admitted ordinal")
            })?;
            if item.id.is_empty() || item.kind.is_empty() || !ids.insert(item.id.clone()) {
                return Err(ScanError::invalid(
                    "inventory has empty identity/kind or duplicate target ID",
                ));
            }
            let item_bytes =
                serde_json::to_vec(&item).map_err(|e| ScanError::invalid(e.to_string()))?;
            if !frame_owner.try_allocate(item_bytes.len() as u64) {
                return Err(ScanError::unresolved(
                    "complete inventory frames exceed evidence byte limit; no truncated snapshot",
                ));
            }
            targets.push(Target {
                identity: TargetIdentity {
                    id: item.id,
                    kind: item.kind.clone(),
                    sha256: sha256(&item_bytes),
                    metadata: json!({}),
                },
                bytes: item_bytes,
                applicability_key: item.kind,
                path: None,
                dependencies: Default::default(),
            });
            if !owner.complete_step(0)
                || owner.completed() != targets.len()
                || target_owner.allocated() != targets.len() as u64
            {
                return Err(ScanError::unresolved(
                    "inventory preparation correspondence failed",
                ));
            }
        }
        Ok(Self {
            identity: SourceIdentity {
                binding: "inventory-json/1".into(),
                snapshot_id: inventory.snapshot_id,
                input_sha256: sha256(bytes),
                serializer: SERIALIZER.into(),
                metadata: json!({}),
            },
            targets,
            input_path: None,
            protected_paths: Vec::new(),
            excluded: Vec::new(),
        })
    }

    pub fn from_file(adapter: &str, path: &Path, limits: &Limits) -> Result<Self, ScanError> {
        let bytes = read_bounded(path, limits.input_bytes).map_err(ScanError::unresolved)?;
        match adapter {
            "raw-bytes/1" => {
                let name = path
                    .file_name()
                    .and_then(|v| v.to_str())
                    .ok_or_else(|| ScanError::invalid("input filename must be UTF-8"))?;
                let mut snapshot = Self::raw_bytes(bytes, name, limits)?;
                let path = unlinked_path(path).map_err(ScanError::invalid)?;
                snapshot.identity.metadata = json!({"path": path});
                let target = snapshot
                    .targets
                    .first_mut()
                    .ok_or_else(|| ScanError::unresolved("raw-byte snapshot has no target"))?;
                target.identity.metadata = json!({"path": path});
                snapshot.input_path = Some(path.clone());
                target.path = Some(path);
                Ok(snapshot)
            }
            "inventory-json/1" => {
                let mut snapshot = Self::inventory(&bytes, limits)?;
                snapshot.input_path = Some(unlinked_path(path).map_err(ScanError::invalid)?);
                Ok(snapshot)
            }
            _ => Err(ScanError::invalid(format!(
                "source adapter is not installed: {adapter}"
            ))),
        }
    }
}

pub(crate) fn same_path(left: &Path, right: &Path) -> bool {
    let left = std::fs::canonicalize(left).or_else(|_| std::path::absolute(left));
    let right = std::fs::canonicalize(right).or_else(|_| std::path::absolute(right));
    match (left, right) {
        #[cfg(windows)]
        (Ok(left), Ok(right)) => left
            .to_string_lossy()
            .eq_ignore_ascii_case(&right.to_string_lossy()),
        #[cfg(not(windows))]
        (Ok(left), Ok(right)) => left == right,
        _ => false,
    }
}

/// Frozen source files whose current content differs from the snapshot, or can no longer be
/// read. Each distinct file is read once, however many targets depend on it.
pub(crate) fn changed_sources(
    targets: &[Target],
    limits: &Limits,
) -> Result<BTreeSet<PathBuf>, ScanError> {
    let mut expected = std::collections::BTreeMap::<&PathBuf, BTreeSet<&String>>::new();
    let mut shared = BTreeSet::new();
    for target in targets {
        let dependencies = &target.dependencies;
        // An identical immutable slice contains the same expected digests. Distinct
        // slices still get checked, including conflicting expectations for one file.
        if !shared.insert((dependencies.as_ptr(), dependencies.len())) {
            continue;
        }
        for (path, digest) in dependencies.iter() {
            expected.entry(path).or_default().insert(digest);
        }
    }
    if expected.is_empty() {
        return Ok(BTreeSet::new());
    }
    let expected: Vec<_> = expected.into_iter().collect();
    let mut steps =
        Sequential::new(expected.len(), 1, 0).map_err(|e| ScanError::unresolved(e.to_string()))?;
    let mut verified = Vec::new();
    while !steps.is_done() {
        if !steps.begin_step() {
            return Err(ScanError::unresolved(
                "source verification read admission refused",
            ));
        }
        let (path, digests) = expected
            .get(steps.completed())
            .ok_or_else(|| ScanError::unresolved("source verification step has no input"))?;
        let actual = read_bounded(path, limits.input_bytes)
            .ok()
            .map(|bytes| sha256(&bytes));
        let changed = digests
            .iter()
            .any(|digest| actual.as_ref() != Some(*digest));
        verified.push(((*path).clone(), changed));
        if !steps.complete_step(0) || steps.completed() != verified.len() {
            return Err(ScanError::unresolved(
                "source verification correspondence failed",
            ));
        }
    }
    Ok(verified
        .into_iter()
        .filter_map(|(path, changed)| changed.then_some(path))
        .collect())
}

/// Reads a target's evidence. Its source files were checked by `changed_sources` before the
/// scan began, and are checked again before the report is returned.
pub(crate) fn read_target(
    target: &Target,
    limits: &Limits,
    changed: &BTreeSet<PathBuf>,
) -> Result<Vec<u8>, String> {
    if let Some((path, _)) = target
        .dependencies
        .iter()
        .find(|(p, _)| changed.contains(p))
    {
        return Err(format!(
            "required project source/context changed after freeze: {}",
            path.display()
        ));
    }
    let bytes = match &target.path {
        Some(path) => read_bounded(path, limits.input_bytes)?,
        None => target.bytes.clone(),
    };
    if sha256(&bytes) != target.identity.sha256 {
        return Err("source changed after snapshot freeze".into());
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "test assertions check cumulative admission and unchanged refusal state"
    )]
    fn cumulative_reads_use_one_owner_and_refuse_without_changing_it()
    -> Result<(), Box<dyn std::error::Error>> {
        let dir = crate::test_support::directory();
        let first = dir.path().join("first.txt");
        let last = dir.path().join("last.txt");
        fs::write(&first, b"ab")?;
        fs::write(&last, b"cde")?;
        let mut owner = Budget::new(4);
        assert_eq!(read_budgeted(&first, &mut owner)?, b"ab");
        assert!(read_budgeted(&last, &mut owner).is_err());
        assert_eq!(owner.allocated(), 2);
        assert_eq!(owner.available(), 2);
        let mut exact = Budget::new(5);
        read_budgeted(&first, &mut exact)?;
        assert_eq!(read_budgeted(&last, &mut exact)?, b"cde");
        assert_eq!(exact.available(), 0);
        fs::write(&last, b"")?;
        assert!(read_budgeted(&last, &mut exact)?.is_empty());
        assert!(read_budgeted(&first, &mut exact).is_err());
        assert_eq!(exact.allocated(), 5);
        Ok(())
    }

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "test assertions check exact frames and whole-input refusal"
    )]
    fn inventory_preparation_requires_all_targets_and_complete_frames()
    -> Result<(), Box<dyn std::error::Error>> {
        let items = vec![
            InventoryItem {
                id: "first".into(),
                kind: "host".into(),
                facts: Map::new(),
            },
            InventoryItem {
                id: "last".into(),
                kind: "host".into(),
                facts: Map::new(),
            },
        ];
        let [first, last] = items.as_slice() else {
            return Err("expected two inventory fixture items".into());
        };
        let first_bytes = serde_json::to_vec(first)?;
        let last_bytes = serde_json::to_vec(last)?;
        let bytes = serde_json::to_vec(&json!({"schema":"auditoad-inventory/1",
            "snapshot_id":"boundary","items":items}))?;
        let limits = Limits {
            targets: 2,
            evidence_bytes: u64::try_from(
                first_bytes
                    .len()
                    .checked_add(last_bytes.len())
                    .ok_or("fixture byte count overflows")?,
            )?,
            ..Limits::default()
        };
        let snapshot = Snapshot::inventory(&bytes, &limits)?;
        assert_eq!(snapshot.targets.len(), 2);
        let [first, last] = snapshot.targets.as_slice() else {
            return Err("expected two prepared inventory targets".into());
        };
        assert_eq!(first.bytes, first_bytes);
        assert_eq!(last.bytes, last_bytes);
        assert!(
            Snapshot::inventory(
                &bytes,
                &Limits {
                    targets: 1,
                    ..limits
                }
            )
            .is_err()
        );
        assert!(
            Snapshot::inventory(
                &bytes,
                &Limits {
                    evidence_bytes: limits
                        .evidence_bytes
                        .checked_sub(1)
                        .ok_or("fixture has no evidence bytes")?,
                    ..limits
                }
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "test assertions check conflict, mutation and missing dependency evidence"
    )]
    fn shared_dependencies_preserve_conflicts_mutation_and_missing_files()
    -> Result<(), Box<dyn std::error::Error>> {
        let dir = crate::test_support::directory();
        let path = dir.path().join("subject.txt");
        let other_path = dir.path().join("unchanged.txt");
        fs::write(&path, b"original")?;
        fs::write(&other_path, b"unchanged")?;
        let limits = Limits::default();
        let mut snapshot = Snapshot::raw_bytes(b"original".to_vec(), "subject", &limits)?;
        let [subject] = snapshot.targets.as_mut_slice() else {
            return Err("expected one raw-byte target".into());
        };
        subject.dependencies = vec![
            (path.clone(), sha256(b"original")),
            (other_path.clone(), sha256(b"unchanged")),
        ]
        .into();
        let mut targets = vec![subject.clone(); 3];
        let dependencies = std::sync::Arc::clone(&subject.dependencies);
        assert!(changed_sources(&targets, &limits)?.is_empty());
        targets
            .last_mut()
            .ok_or("missing conflict target")?
            .dependencies = vec![(path.clone(), sha256(b"different"))].into();
        assert_eq!(
            changed_sources(&targets, &limits)?,
            BTreeSet::from([path.clone()])
        );
        targets
            .last_mut()
            .ok_or("missing conflict target")?
            .dependencies = dependencies;
        fs::write(&path, b"changed")?;
        assert_eq!(
            changed_sources(&targets, &limits)?,
            BTreeSet::from([path.clone()])
        );
        fs::remove_file(&path)?;
        assert_eq!(
            changed_sources(&targets, &limits)?,
            BTreeSet::from([path.clone()])
        );
        fs::remove_file(&other_path)?;
        assert_eq!(
            changed_sources(&targets, &limits)?,
            BTreeSet::from([path, other_path])
        );
        Ok(())
    }
}
