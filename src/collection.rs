//! Confined input collections and declared correspondence between complete units.
use crate::{
    ScanError, Snapshot, ValidatedBaseline,
    baseline::{pointer_valid, selected_indices},
    bundle::{FrozenFiles, freeze_files, is_sha256},
    json,
    schema::{Limits, Scope, ScopeContext, SourceIdentity, TargetIdentity},
    scoped::ScopePlan,
    source::{SERIALIZER, Target, digest_fields, read_budgeted, sha256, unlinked_path},
};
use automation_structures::{Budget, RelationshipGraph, Sequential};
use serde::{Deserialize, Deserializer};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Collection {
    schema: String,
    inputs: BTreeMap<String, Input>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    adapter: String,
    path: Option<String>,
    unavailable: Option<String>,
    #[serde(default, deserialize_with = "optional_string")]
    sha256: Option<String>,
    #[serde(default, deserialize_with = "optional_string")]
    json_pointer: Option<String>,
}

fn optional_string<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<String>, D::Error> {
    String::deserialize(deserializer).map(Some)
}

fn missing_target(scope: &Scope, kind: &str, reason: &str) -> Result<Target, ScanError> {
    let bytes = serde_json::to_vec(&json!({"schema":"scoped-input/1", "scope":scope,
        "subject":null, "scope_error":reason}))
    .map_err(|e| ScanError::unresolved(e.to_string()))?;
    Ok(Target {
        identity: TargetIdentity {
            id: String::new(),
            kind: kind.into(),
            sha256: sha256(&bytes),
            metadata: json!({"scope":scope,"input":scope.input,"ordinal":0,"location":{"unavailable":reason}}),
        },
        bytes,
        applicability_key: String::new(),
        path: None,
        dependencies: Default::default(),
    })
}

fn scalar<'a>(value: &'a Value, pointer: &str) -> Option<&'a Value> {
    value
        .pointer(pointer)
        .filter(|value| matches!(value, Value::String(_) | Value::Number(_) | Value::Bool(_)))
}

impl Snapshot {
    /// Freeze named whole inputs and link their units using baseline-declared keys.
    /// An unavailable input is retained as a coverage gap, never an empty successful check.
    pub fn collection_file(
        manifest_path: &Path,
        root: Option<&Path>,
        baseline: &ValidatedBaseline,
        profile: &str,
        source_alias: &str,
        limits: &Limits,
    ) -> Result<Self, ScanError> {
        let manifest_path = unlinked_path(manifest_path).map_err(ScanError::invalid)?;
        let root = match root {
            Some(root) => root,
            None => manifest_path
                .parent()
                .ok_or_else(|| ScanError::invalid("collection manifest has no parent"))?,
        };
        let root = unlinked_path(root).map_err(ScanError::invalid)?;
        if !root.is_dir() {
            return Err(ScanError::invalid("collection root is not a directory"));
        }
        let mut input_budget = Budget::new(limits.input_bytes);
        let bytes =
            read_budgeted(&manifest_path, &mut input_budget).map_err(ScanError::unresolved)?;
        let collection: Collection = json::parse(&bytes).map_err(ScanError::invalid)?;
        if collection.schema != "auditoad-collection/1"
            || collection.inputs.is_empty()
            || !Budget::new(limits.manifest_work as u64)
                .try_allocate(collection.inputs.len() as u64)
        {
            return Err(ScanError::invalid(
                "collection requires auditoad-collection/1 and a bounded, nonempty input map",
            ));
        }
        for (name, input) in &collection.inputs {
            if name.trim().is_empty()
                || !matches!(input.adapter.as_str(), "text/1" | "json/1" | "json-lines/1")
                || !matches!(
                    (&input.path, &input.unavailable),
                    (Some(_), None) | (None, Some(_))
                )
                || input
                    .unavailable
                    .as_ref()
                    .is_some_and(|s| s.trim().is_empty())
            {
                return Err(ScanError::invalid(format!(
                    "input {name} requires an installed leaf adapter and exactly one of path or unavailable reason"
                )));
            }
            if input
                .sha256
                .as_ref()
                .is_some_and(|pin| input.path.is_none() || !is_sha256(pin))
            {
                return Err(ScanError::invalid(format!(
                    "input {name} SHA-256 pin requires a path and 64 lowercase hexadecimal digits"
                )));
            }
            if input.json_pointer.as_ref().is_some_and(|pointer| {
                input.path.is_none()
                    || input.adapter != "json/1"
                    || (!pointer.is_empty() && !pointer_valid(pointer))
            }) {
                return Err(ScanError::invalid(format!(
                    "input {name} JSON Pointer requires an available json/1 path and valid pointer syntax"
                )));
            }
        }
        let content = &baseline.content;
        let profile = content
            .profiles
            .iter()
            .find(|p| p.id == profile)
            .ok_or_else(|| ScanError::invalid("unknown profile"))?;
        let source = content
            .sources
            .get(source_alias)
            .filter(|s| s.adapter == "collection/1")
            .ok_or_else(|| ScanError::invalid("source must use collection/1"))?;
        let mut scopes = BTreeSet::new();
        for index in selected_indices(content, profile, &baseline.dependencies)? {
            let rule = content
                .rules
                .get(index)
                .ok_or_else(|| ScanError::invalid("selected collection rule is not bound"))?;
            if rule.source != source_alias {
                return Err(ScanError::invalid(
                    "selected rules must share the requested source",
                ));
            }
            scopes.insert(
                rule.scope
                    .clone()
                    .ok_or_else(|| ScanError::invalid("missing collection scope"))?,
            );
        }
        let mut declarations = Vec::new();
        let mut views = BTreeMap::<&str, BTreeSet<Option<&str>>>::new();
        for input in collection.inputs.values() {
            if let Some(path) = &input.path {
                let declared = views.entry(path.as_str()).or_default();
                let pointer = input.json_pointer.as_deref();
                if !declared.is_empty()
                    && (pointer.is_none()
                        || declared.contains(&None)
                        || declared.contains(&pointer))
                {
                    return Err(ScanError::invalid(format!(
                        "duplicate collection path requires distinct explicit JSON Pointer views: {path}"
                    )));
                }
                if declared.is_empty() {
                    declarations.push(path);
                }
                declared.insert(pointer);
            }
        }
        let frozen = if declarations.is_empty() {
            FrozenFiles {
                content: BTreeMap::new(),
                dependencies: Vec::new(),
                protected_paths: Vec::new(),
            }
        } else {
            freeze_files(&root, &declarations, None, None, limits, &mut input_budget)?
        };
        for (name, input) in &collection.inputs {
            if let (Some(path), Some(expected)) = (&input.path, &input.sha256) {
                let actual = frozen
                    .content
                    .get(path)
                    .and_then(|file| file.get("sha256"))
                    .and_then(Value::as_str)
                    .ok_or_else(|| ScanError::unresolved("frozen collection hash is absent"))?;
                if actual != expected {
                    return Err(ScanError::invalid(format!(
                        "pinned SHA-256 mismatch for collection input {name}: {path}"
                    )));
                }
            }
        }
        let mut selected_documents = BTreeMap::new();
        for (name, input) in &collection.inputs {
            if let (Some(path), Some(pointer)) = (&input.path, &input.json_pointer) {
                let document = match selected_documents.entry(path.as_str()) {
                    std::collections::btree_map::Entry::Occupied(entry) => entry.into_mut(),
                    std::collections::btree_map::Entry::Vacant(entry) => {
                        let text = frozen
                            .content
                            .get(path)
                            .and_then(|file| file.get("text"))
                            .and_then(Value::as_str)
                            .ok_or_else(|| {
                                ScanError::unresolved("frozen selected JSON input is absent")
                            })?;
                        entry.insert(json::parse::<Value>(text.as_bytes()).map_err(|error| {
                            ScanError::invalid(format!("input {name}: {error}"))
                        })?)
                    }
                };
                if document.pointer(pointer).is_none() {
                    return Err(ScanError::invalid(format!(
                        "input {name} JSON Pointer does not resolve: {pointer}"
                    )));
                }
            }
        }
        let mut all_scopes = scopes.clone();
        for scope in &scopes {
            for link in &scope.related {
                all_scopes.insert(Scope {
                    unit: link.unit,
                    context: ScopeContext::None,
                    input: Some(link.input.clone()),
                    related: Vec::new(),
                });
            }
        }
        let mut preparation = Budget::new(limits.manifest_work as u64);
        let mut frames = Budget::new(limits.evidence_bytes);
        let mut prepared = BTreeMap::new();
        let mut input_steps = Sequential::new(all_scopes.len(), 1, 0)
            .map_err(|e| ScanError::unresolved(e.to_string()))?;
        for scope in &all_scopes {
            if !input_steps.begin_step() {
                return Err(ScanError::unresolved(
                    "collection preparation refused begin_step",
                ));
            }
            let name = scope
                .input
                .as_deref()
                .ok_or_else(|| ScanError::invalid("collection scope must name its input"))?;
            let targets = match collection.inputs.get(name) {
                Some(Input {
                    path: Some(path),
                    adapter,
                    json_pointer,
                    ..
                }) => {
                    let text = frozen
                        .content
                        .get(path)
                        .and_then(|v| v.get("text"))
                        .and_then(Value::as_str)
                        .ok_or_else(|| {
                            ScanError::unresolved(format!(
                                "frozen collection input has no UTF-8 text: {path}"
                            ))
                        })?;
                    let selected_json = json_pointer
                        .as_deref()
                        .map(|pointer| {
                            selected_documents
                                .get(path.as_str())
                                .and_then(|document| document.pointer(pointer))
                                .map(|selected| (pointer, selected))
                                .ok_or_else(|| {
                                    ScanError::unresolved("validated JSON selection is absent")
                                })
                        })
                        .transpose()?;
                    let input_sha256 = frozen
                        .content
                        .get(path)
                        .and_then(|file| file.get("sha256"))
                        .and_then(Value::as_str)
                        .ok_or_else(|| ScanError::unresolved("frozen collection hash is absent"))?;
                    Self::scoped_prepared(
                        text.as_bytes(),
                        name,
                        baseline,
                        &profile.id,
                        source_alias,
                        limits,
                        Some(ScopePlan {
                            adapter,
                            scopes: &BTreeSet::from([scope.clone()]),
                            selected_json,
                            input_sha256: Some(input_sha256),
                        }),
                    )?
                    .targets
                }
                input => vec![missing_target(
                    scope,
                    source
                        .media
                        .first()
                        .ok_or_else(|| ScanError::invalid("collection source declares no media"))?,
                    &format!(
                        "input {name} unavailable: {}",
                        input
                            .and_then(|i| i.unavailable.as_deref())
                            .unwrap_or("not supplied in collection")
                    ),
                )?],
            };
            if !preparation.try_allocate(targets.len() as u64) {
                return Err(ScanError::unresolved(
                    "complete collection preparation exceeds work limit",
                ));
            }
            for target in &targets {
                if !frames.try_allocate(target.bytes.len() as u64) {
                    return Err(ScanError::unresolved(
                        "complete collection preparation exceeds evidence byte limit",
                    ));
                }
            }
            prepared.insert(scope.clone(), targets);
            if !input_steps.complete_step(0) || input_steps.completed() != prepared.len() {
                return Err(ScanError::unresolved(
                    "collection input preparation correspondence failed",
                ));
            }
        }
        let mut target_budget = Budget::new(limits.targets as u64);
        let mut manifest = Vec::new();
        for (scope_index, scope) in scopes.iter().enumerate() {
            let prepared_scope = prepared
                .get(scope)
                .ok_or_else(|| ScanError::unresolved("collection scope was not prepared"))?;
            if !target_budget.try_allocate(prepared_scope.len() as u64) {
                return Err(ScanError::unresolved(
                    "complete collection exceeds target limit",
                ));
            }
            for (ordinal, target) in prepared_scope.iter().enumerate() {
                manifest.push((scope_index, ordinal, scope, target));
            }
        }
        let mut comparisons = Budget::new(limits.manifest_work as u64);
        let mut steps = Sequential::new(manifest.len(), 1, 0)
            .map_err(|e| ScanError::unresolved(e.to_string()))?;
        let input_sha = sha256(&bytes);
        let mut dependencies = frozen.dependencies.clone();
        dependencies.push((manifest_path.clone(), input_sha.clone()));
        let dependencies: std::sync::Arc<[_]> = dependencies.into();
        let mut targets = Vec::new();
        while !steps.is_done() {
            let &(scope_index, ordinal, scope, original) =
                manifest.get(steps.completed()).ok_or_else(|| {
                    ScanError::unresolved("collection relation step has no manifest binding")
                })?;
            if !steps.begin_step() {
                return Err(ScanError::unresolved(
                    "collection relation preparation refused begin_step",
                ));
            }
            let mut target = original.clone();
            let mut frame: Value = json::parse(&target.bytes).map_err(ScanError::invalid)?;
            // This collection binding constructs the related-role projection.
            // Scoped input supplies the subject; it does not already own this output map.
            if !scope.related.is_empty() {
                json::object_mut(&mut frame)
                    .map_err(ScanError::unresolved)?
                    .insert("related".into(), Value::Object(serde_json::Map::new()));
            }
            let mut locations = BTreeMap::<String, Vec<Value>>::new();
            let mut errors = Vec::new();
            if let Some(error) = frame.get("scope_error").and_then(Value::as_str) {
                errors.push(error.to_owned());
            }
            for link in &scope.related {
                let peer_scope = Scope {
                    unit: link.unit,
                    context: ScopeContext::None,
                    input: Some(link.input.clone()),
                    related: Vec::new(),
                };
                let peers = prepared.get(&peer_scope).ok_or_else(|| {
                    ScanError::unresolved("related collection scope was not prepared")
                })?;
                let nodes = peers.len().checked_add(1).ok_or_else(|| {
                    ScanError::unresolved("collection relation node count overflows")
                })?;
                let mut relation = RelationshipGraph::new(nodes, 1);
                let mut subjects = Vec::new();
                let subject = frame.get("subject").ok_or_else(|| {
                    ScanError::unresolved("collection frame has no subject field")
                })?;
                let missing_subject_key = link
                    .on
                    .iter()
                    .any(|key| scalar(subject, &key.subject).is_none());
                if missing_subject_key {
                    errors.push(format!(
                        "role {}: subject lacks a scalar correspondence key",
                        link.role
                    ));
                }
                for (index, peer) in peers.iter().enumerate() {
                    if !comparisons.try_allocate(1) {
                        return Err(ScanError::unresolved(
                            "complete related evidence exceeds comparison work limit",
                        ));
                    }
                    let peer_frame: Value = json::parse(&peer.bytes).map_err(ScanError::invalid)?;
                    let peer_subject = peer_frame.get("subject").ok_or_else(|| {
                        ScanError::unresolved("related frame has no subject field")
                    })?;
                    subjects.push(peer_subject.clone());
                    if let Some(error) = peer_frame.get("scope_error").and_then(Value::as_str) {
                        // An available empty record list is different from absent telemetry.
                        if !(link.allow_empty
                            && peer.identity.metadata.pointer("/location/empty_selection")
                                == Some(&Value::Bool(true)))
                        {
                            errors.push(format!("role {}: {error}", link.role));
                        }
                        continue;
                    }
                    if link
                        .on
                        .iter()
                        .any(|key| scalar(peer_subject, &key.related).is_none())
                    {
                        errors.push(format!(
                            "role {}: input {} unit {index} lacks a scalar correspondence key",
                            link.role, link.input
                        ));
                        continue;
                    }
                    if !missing_subject_key
                        && link.on.iter().all(|key| {
                            scalar(subject, &key.subject) == scalar(peer_subject, &key.related)
                        })
                    {
                        let node = index.checked_add(1).ok_or_else(|| {
                            ScanError::unresolved("collection peer node overflows")
                        })?;
                        relation
                            .add_edge(0, node, 1)
                            .map_err(|e| ScanError::unresolved(e.to_string()))?;
                        if !relation.contains(0, node) {
                            return Err(ScanError::unresolved(
                                "relation owner did not retain admitted correspondence",
                            ));
                        }
                    }
                }
                let mut values = Vec::new();
                let mut provenance = Vec::new();
                for (_, peer, _) in relation.edges() {
                    let index = peer.checked_sub(1).ok_or_else(|| {
                        ScanError::unresolved("relation edge targets the subject node")
                    })?;
                    values.push(
                        subjects
                            .get(index)
                            .ok_or_else(|| {
                                ScanError::unresolved("relation edge has no subject binding")
                            })?
                            .clone(),
                    );
                    let metadata = &peers
                        .get(index)
                        .ok_or_else(|| ScanError::unresolved("relation edge has no peer binding"))?
                        .identity
                        .metadata;
                    let location = metadata
                        .get("location")
                        .ok_or_else(|| ScanError::unresolved("collection peer has no location"))?;
                    let input_sha = metadata.get("input_sha256").ok_or_else(|| {
                        ScanError::unresolved("collection peer has no input identity")
                    })?;
                    provenance.push(
                        json!({"input":link.input,"location":location,"input_sha256":input_sha}),
                    );
                }
                if relation.edge_count() != values.len() {
                    return Err(ScanError::unresolved(
                        "related evidence projection disagrees with graph owner",
                    ));
                }
                if relation.edge_count() == 0 && !link.allow_empty {
                    errors.push(format!(
                        "role {}: required related evidence is empty",
                        link.role
                    ));
                }
                let related = frame
                    .get_mut("related")
                    .ok_or_else(|| ScanError::unresolved("collection frame has no related map"))?;
                json::object_mut(related)
                    .map_err(ScanError::unresolved)?
                    .insert(link.role.clone(), json!(values));
                locations.insert(link.role.clone(), provenance);
            }
            if !errors.is_empty() {
                json::object_mut(&mut frame)
                    .map_err(ScanError::unresolved)?
                    .insert("scope_error".into(), json!(errors.join("; ")));
            }
            if source.include_provenance {
                json::object_mut(&mut frame)
                    .map_err(ScanError::unresolved)?
                    .insert(
                        "provenance".into(),
                        json!({"subject":original.identity.metadata,"related":locations}),
                    );
            }
            target.bytes =
                serde_json::to_vec(&frame).map_err(|e| ScanError::invalid(e.to_string()))?;
            if !frames.try_allocate(target.bytes.len() as u64) {
                return Err(ScanError::unresolved(
                    "complete related frames exceed evidence byte limit; no context was truncated",
                ));
            }
            target.identity.id = format!("collection/scope/{scope_index}/unit/{ordinal}");
            target.identity.sha256 = sha256(&target.bytes);
            json::object_mut(&mut target.identity.metadata)
                .map_err(ScanError::unresolved)?
                .insert("related".into(), json!(locations));
            target.dependencies = std::sync::Arc::clone(&dependencies);
            targets.push(target);
            if !steps.complete_step(0) || steps.completed() != targets.len() {
                return Err(ScanError::unresolved(
                    "collection target correspondence failed",
                ));
            }
        }
        let manifest_digest = sha256(
            &serde_json::to_vec(&frozen.content).map_err(|e| ScanError::invalid(e.to_string()))?,
        );
        let scope_digest =
            sha256(&serde_json::to_vec(&scopes).map_err(|e| ScanError::invalid(e.to_string()))?);
        let mut protected_paths = frozen.protected_paths;
        protected_paths.push(manifest_path.clone());
        Ok(Self {
            identity: SourceIdentity {
                binding: source.adapter.clone(),
                snapshot_id: digest_fields(&[&input_sha, &manifest_digest, &scope_digest]),
                input_sha256: input_sha,
                serializer: SERIALIZER.into(),
                metadata: json!({"baseline_sha256":baseline.identity.sha256,"profile":profile.id,"scopes":scopes,
                    "coverage":"every declared subject unit, with all peers selected by the declared correspondences"}),
            },
            targets,
            input_path: Some(manifest_path),
            protected_paths,
            excluded: Vec::new(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "test assertions check shared complete dependencies and unchanged-source verification"
    )]
    fn collection_targets_share_the_complete_frozen_dependencies()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/related-events");
        let baseline = ValidatedBaseline::from_file(&root.join("baseline.json"))?;
        let profile = &baseline
            .baseline()
            .profiles
            .first()
            .ok_or("fixture has no profile")?
            .id;
        let alias = baseline
            .baseline()
            .sources
            .keys()
            .next()
            .ok_or("fixture has no source")?;
        let snapshot = Snapshot::collection_file(
            &root.join("inputs.json"),
            None,
            &baseline,
            profile,
            alias,
            &Limits::default(),
        )?;
        assert!(snapshot.targets.len() > 1);
        let (first, others) = snapshot
            .targets
            .split_first()
            .ok_or("fixture has no prepared target")?;
        let first = &first.dependencies;
        assert!(first.len() > 1);
        for target in others {
            assert!(std::sync::Arc::ptr_eq(first, &target.dependencies));
        }
        assert!(first.iter().any(|(path, _)| path.ends_with("inputs.json")));
        assert!(crate::source::changed_sources(&snapshot.targets, &Limits::default())?.is_empty());
        Ok(())
    }
}
