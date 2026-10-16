//! Confined reads of explicitly listed, SHA-256-pinned files and the evidence bundles built from them.
use crate::{ScanError, Snapshot, ValidatedBaseline, json, schema::*, source::*};
use automation_structures::{Budget, Sequential};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

pub(crate) struct FrozenFiles {
    pub(crate) content: BTreeMap<String, Value>,
    pub(crate) dependencies: Vec<(std::path::PathBuf, String)>,
    pub(crate) protected_paths: Vec<std::path::PathBuf>,
}

pub(crate) fn freeze_files(
    root: &Path,
    declarations: &[&String],
    pins: Option<&BTreeMap<String, String>>,
    media: Option<&BTreeMap<String, String>>,
    limits: &Limits,
    byte_budget: &mut Budget,
) -> Result<FrozenFiles, ScanError> {
    if declarations.is_empty()
        || !Budget::new(limits.manifest_work as u64).try_allocate(declarations.len() as u64)
    {
        return Err(ScanError::unresolved(
            "file manifest exceeds work limit or is empty",
        ));
    }
    let mut paths = BTreeSet::new();
    for path in declarations {
        if path.is_empty()
            || path.contains(['\\', ':'])
            || path
                .split('/')
                .any(|part| part.is_empty() || part.ends_with(['.', ' ']))
            || !paths.insert(path.to_lowercase())
        {
            return Err(ScanError::invalid(
                "paths must be unique portable relative paths",
            ));
        }
        fixture_path(root, path).map_err(ScanError::invalid)?;
    }
    let mut steps =
        Sequential::new(declarations.len(), 1, 0).map_err(|e| ScanError::invalid(e.to_string()))?;
    let mut frozen = FrozenFiles {
        content: BTreeMap::new(),
        dependencies: Vec::new(),
        protected_paths: Vec::new(),
    };
    while !steps.is_done() {
        if !steps.begin_step() {
            return Err(ScanError::unresolved("file read admission refused"));
        }
        let relative = declarations
            .get(steps.completed())
            .ok_or_else(|| ScanError::unresolved("read position outside manifest"))?;
        let path = fixture_path(root, relative).map_err(ScanError::invalid)?;
        let bytes = read_budgeted(&path, byte_budget).map_err(ScanError::unresolved)?;
        let digest = sha256(&bytes);
        if pins.is_some_and(|p| p.get(*relative) != Some(&digest)) {
            return Err(ScanError::invalid(format!(
                "pinned SHA-256 mismatch: {relative}"
            )));
        }
        let content = match media
            .and_then(|declared| declared.get(*relative))
            .map(String::as_str)
        {
            None => {
                let text = String::from_utf8(bytes)
                    .map_err(|_| ScanError::invalid("declared file is not UTF-8"))?;
                json!({"path":relative,"sha256":digest,"text":text})
            }
            Some("image/png") => {
                let (width, height) = png_header_dimensions(&bytes)?;
                json!({"path":relative,"sha256":digest,"media":"image/png",
                    "width":width,"height":height,"bytes":encoded_bytes(&bytes)})
            }
            Some("image/jpeg") => {
                let (width, height) = jpeg_header_dimensions(&bytes)?;
                json!({"path":relative,"sha256":digest,"media":"image/jpeg",
                    "width":width,"height":height,"bytes":encoded_bytes(&bytes)})
            }
            Some(_) => return Err(ScanError::invalid("bundle image media is not installed")),
        };
        frozen.content.insert((*relative).clone(), content);
        frozen.dependencies.push((path.clone(), digest));
        frozen.protected_paths.push(path);
        if !steps.complete_step(0) || steps.completed() != frozen.content.len() {
            return Err(ScanError::unresolved("file read completion refused"));
        }
    }
    Ok(frozen)
}

pub(crate) fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BundleManifest {
    schema: String,
    files: BTreeMap<String, FileDeclaration>,
    packets: Vec<Packet>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum FileDeclaration {
    Text(String),
    Image(ImageDeclaration),
}

impl FileDeclaration {
    fn pin(&self) -> &str {
        match self {
            Self::Text(pin) => pin,
            Self::Image(image) => &image.sha256,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ImageDeclaration {
    sha256: String,
    media: String,
}

/// PNG header metadata only. Pixel decoding and complete format validation are helper work.
pub(crate) fn png_header_dimensions(bytes: &[u8]) -> Result<(u32, u32), ScanError> {
    if bytes.len() < 33
        || bytes.get(..8) != Some(b"\x89PNG\r\n\x1a\n".as_slice())
        || bytes.get(8..12) != Some(13_u32.to_be_bytes().as_slice())
        || bytes.get(12..16) != Some(b"IHDR".as_slice())
    {
        return Err(ScanError::invalid("image lacks a complete PNG IHDR header"));
    }
    let width = u32::from_be_bytes(
        bytes
            .get(16..20)
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| ScanError::invalid("PNG width is not four bytes"))?,
    );
    let height = u32::from_be_bytes(
        bytes
            .get(20..24)
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| ScanError::invalid("PNG height is not four bytes"))?,
    );
    if width == 0 || height == 0 || width > i32::MAX as u32 || height > i32::MAX as u32 {
        return Err(ScanError::invalid("invalid PNG header dimensions"));
    }
    Ok((width, height))
}

/// Read a JPEG frame header only; this does not validate or decode the pixels.
pub(crate) fn jpeg_header_dimensions(bytes: &[u8]) -> Result<(u32, u32), ScanError> {
    if bytes.get(..2) != Some(b"\xff\xd8".as_slice()) {
        return Err(ScanError::invalid("image lacks a JPEG start marker"));
    }
    let mut remaining = bytes.get(2..).unwrap_or_default();
    while let Some((&prefix, rest)) = remaining.split_first() {
        if prefix != 0xff {
            return Err(ScanError::invalid("malformed JPEG marker boundary"));
        }
        remaining = rest;
        while let Some((&0xff, rest)) = remaining.split_first() {
            remaining = rest;
        }
        let (&marker, rest) = remaining
            .split_first()
            .ok_or_else(|| ScanError::invalid("incomplete JPEG marker"))?;
        if matches!(marker, 0x00 | 0xd8 | 0xd9 | 0xda) {
            return Err(ScanError::invalid("JPEG has no supported frame header"));
        }
        if matches!(marker, 0x01 | 0xd0..=0xd7) {
            remaining = rest;
            continue;
        }
        let length = rest
            .get(..2)
            .and_then(|value| value.try_into().ok())
            .map(u16::from_be_bytes)
            .map(usize::from)
            .filter(|length| *length >= 2)
            .ok_or_else(|| ScanError::invalid("invalid JPEG segment length"))?;
        let segment = rest
            .get(..length)
            .ok_or_else(|| ScanError::invalid("incomplete JPEG segment"))?;
        if matches!(marker, 0xc0..=0xc3 | 0xc5..=0xc7 | 0xc9..=0xcb | 0xcd..=0xcf) {
            let dimensions = segment
                .get(3..7)
                .ok_or_else(|| ScanError::invalid("incomplete JPEG frame dimensions"))?;
            let height = dimensions
                .get(..2)
                .and_then(|value| value.try_into().ok())
                .map(u16::from_be_bytes)
                .map(u32::from)
                .unwrap_or(0);
            let width = dimensions
                .get(2..4)
                .and_then(|value| value.try_into().ok())
                .map(u16::from_be_bytes)
                .map(u32::from)
                .unwrap_or(0);
            if width == 0 || height == 0 {
                return Err(ScanError::invalid("invalid JPEG frame dimensions"));
            }
            return Ok((width, height));
        }
        remaining = rest.get(length..).unwrap_or_default();
    }
    Err(ScanError::invalid("JPEG has no frame dimensions"))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Packet {
    id: String,
    kind: String,
    scope_kind: String,
    parts: Vec<Part>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Part {
    role: String,
    path: String,
    region: Option<Region>,
}

#[derive(Clone, serde::Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Region {
    x: u32,
    y: u32,
    width: u32,
    height: u32,
}

fn part_content(part: &Part, files: &BTreeMap<String, Value>) -> Result<Value, ScanError> {
    if part.role.trim().is_empty() {
        return Err(ScanError::invalid("empty evidence role"));
    }
    let source = files
        .get(&part.path)
        .ok_or_else(|| ScanError::invalid("unlisted evidence path"))?;
    if source["media"] == "image/png" || source["media"] == "image/jpeg" {
        let width = source
            .get("width")
            .and_then(Value::as_u64)
            .and_then(|n| u32::try_from(n).ok())
            .ok_or_else(|| ScanError::invalid("frozen image width is not a u32"))?;
        let height = source
            .get("height")
            .and_then(Value::as_u64)
            .and_then(|n| u32::try_from(n).ok())
            .ok_or_else(|| ScanError::invalid("frozen image height is not a u32"))?;
        let region = part.region.clone().unwrap_or(Region {
            x: 0,
            y: 0,
            width,
            height,
        });
        if region.width == 0
            || region.height == 0
            || region
                .x
                .checked_add(region.width)
                .is_none_or(|end| end > width)
            || region
                .y
                .checked_add(region.height)
                .is_none_or(|end| end > height)
        {
            return Err(ScanError::invalid(
                "image region is empty or outside image header dimensions",
            ));
        }
        return Ok(
            json!({"role":part.role,"path":part.path,"source_sha256":source["sha256"],
            "media":source["media"],"width":width,"height":height,"region":region,
            "whole_file":region.x == 0 && region.y == 0 && region.width == width && region.height == height,
            "bytes":source["bytes"],"image_validation":if source["media"] == "image/png" {"png-header-only/1"} else {"jpeg-header-only/1"},
            "selection":"declared region; original image bytes retained without cropping"}),
        );
    }
    if part.region.is_some() {
        return Err(ScanError::invalid("text parts cannot select image regions"));
    }
    let text = source["text"]
        .as_str()
        .ok_or_else(|| ScanError::invalid("missing source text"))?;
    Ok(
        json!({"role":part.role,"path":part.path,"source_sha256":source["sha256"],
        "byte_start":0,"byte_end":text.len(),"whole_file":true,"text":text}),
    )
}

impl Snapshot {
    /// Freeze complete UTF-8 files or image regions from explicitly listed, SHA-256-pinned files.
    pub fn bundle(manifest_path: &Path, root: &Path, limits: &Limits) -> Result<Self, ScanError> {
        let root = unlinked_path(root).map_err(ScanError::invalid)?;
        if !root.is_dir() {
            return Err(ScanError::invalid("bundle root is not a directory"));
        }
        let input =
            read_bounded(manifest_path, limits.input_bytes).map_err(ScanError::unresolved)?;
        let manifest: BundleManifest = json::parse(&input).map_err(ScanError::invalid)?;
        if !matches!(
            manifest.schema.as_str(),
            "auditoad-evidence-bundle/1" | "checkwarden-evidence-bundle/1"
        ) || manifest.packets.is_empty()
            || !Budget::new(limits.manifest_work as u64).try_allocate(manifest.packets.len() as u64)
            || manifest.files.values().any(|file| !is_sha256(file.pin()))
        {
            return Err(ScanError::invalid(
                "invalid bundle schema, packet count or file pin",
            ));
        }
        let declarations: Vec<_> = manifest.files.keys().collect();
        let pins = manifest
            .files
            .iter()
            .map(|(path, file)| (path.clone(), file.pin().to_string()))
            .collect();
        let media = manifest
            .files
            .iter()
            .filter_map(|(path, file)| match file {
                FileDeclaration::Text(_) => None,
                FileDeclaration::Image(image) => Some((path.clone(), image.media.clone())),
            })
            .collect();
        let FrozenFiles {
            content,
            dependencies,
            protected_paths,
        } = freeze_files(
            &root,
            &declarations,
            Some(&pins),
            Some(&media),
            limits,
            &mut Budget::new(limits.input_bytes),
        )?;
        let mut targets = Vec::new();
        let mut ids = BTreeSet::new();
        let mut target_budget = Budget::new(limits.targets as u64);
        let mut part_budget = Budget::new(limits.manifest_work as u64);
        let mut frame_budget = Budget::new(limits.evidence_bytes);
        let mut packets = manifest.packets.into_iter();
        let mut steps = Sequential::new(packets.len(), 1, 0)
            .map_err(|e| ScanError::unresolved(e.to_string()))?;
        while !steps.is_done() {
            if !steps.begin_step() {
                return Err(ScanError::unresolved("bundle packet admission refused"));
            }
            let packet = packets.next().ok_or_else(|| {
                ScanError::unresolved("bundle packet missing at admitted ordinal")
            })?;
            if packet.id.trim().is_empty()
                || !ids.insert(packet.id.clone())
                || packet.kind.trim().is_empty()
                || !matches!(packet.scope_kind.as_str(), "site" | "relation" | "whole")
                || packet.parts.is_empty()
            {
                return Err(ScanError::invalid(
                    "invalid packet identity, scope or parts",
                ));
            }
            if !target_budget.try_allocate(1)
                || !part_budget.try_allocate(packet.parts.len() as u64)
            {
                return Err(ScanError::unresolved("bundle target/part budget exhausted"));
            }
            let parts = packet
                .parts
                .iter()
                .map(|p| part_content(p, &content))
                .collect::<Result<Vec<_>, _>>()?;
            let subjects: Vec<_> = parts.iter().filter(|p| p["role"] == "subject").collect();
            if subjects.is_empty()
                || packet.scope_kind != "whole" && subjects.len() != 1
                || packet.scope_kind == "whole" && subjects.iter().any(|p| p["whole_file"] != true)
            {
                return Err(ScanError::invalid(
                    "site/relation needs one subject; whole needs complete subject files",
                ));
            }
            let subject = subjects
                .first()
                .ok_or_else(|| ScanError::invalid("bundle has no subject"))?;
            if packet.scope_kind == "relation"
                && !parts.iter().any(|p| {
                    p["role"] == "peer"
                        && (p.get("path") != subject.get("path")
                            || p.get("byte_start") != subject.get("byte_start")
                            || p.get("byte_end") != subject.get("byte_end")
                            || p.get("region") != subject.get("region"))
                })
            {
                return Err(ScanError::invalid(
                    "relation requires a distinct peer endpoint",
                ));
            }
            let metadata = json!({"kind":packet.kind,
                "scope_kind":packet.scope_kind,"locations":parts.iter().map(|p| {
                    let mut location = p.clone();
                    if let Some(object) = location.as_object_mut() {
                        object.remove("text");
                        object.remove("bytes");
                    }
                    location
                }).collect::<Vec<_>>()});
            let frame = serde_json::to_vec(
                &json!({"schema":"bundle-source/1", "binding":metadata,"parts":parts}),
            )
            .map_err(|e| ScanError::invalid(e.to_string()))?;
            if !frame_budget.try_allocate(frame.len() as u64) {
                return Err(ScanError::unresolved("bundle frames exceed byte budget"));
            }
            // A packet's evidence depends only on the files its parts select; rechecking every
            // bundle file for every packet made preparation quadratic in bundle size.
            let used: BTreeSet<&str> = packet.parts.iter().map(|p| p.path.as_str()).collect();
            let packet_dependencies = declarations
                .iter()
                .zip(&dependencies)
                .filter(|(declared, _)| used.contains(declared.as_str()))
                .map(|(_, dependency)| dependency.clone())
                .collect();
            targets.push(Target {
                identity: TargetIdentity {
                    id: packet.id,
                    kind: if manifest.schema == "checkwarden-evidence-bundle/1" {
                        "application/vnd.checkwarden.bundle+json"
                    } else {
                        "application/vnd.auditoad.bundle+json"
                    }
                    .into(),
                    sha256: sha256(&frame),
                    metadata,
                },
                bytes: frame,
                applicability_key: packet.kind,
                path: None,
                dependencies: packet_dependencies,
            });
            if !steps.complete_step(0)
                || steps.completed() != targets.len()
                || target_budget.allocated() != targets.len() as u64
            {
                return Err(ScanError::unresolved(
                    "bundle preparation correspondence failed",
                ));
            }
        }
        Ok(Self {
            identity:SourceIdentity { binding:"evidence-bundle/1".into(), snapshot_id:sha256(&input),
                input_sha256:sha256(&input), serializer:SERIALIZER.into(),
                metadata:json!({"root":root,"manifest_bytes":crate::schema::encoded_bytes(&input),"coverage":"explicit pinned complete text files and image regions"}) },
            targets, input_path:Some(unlinked_path(manifest_path).map_err(ScanError::invalid)?),
            protected_paths, excluded:vec!["Unlisted files and unresolved dependencies are uncovered; evidence closure is reviewer-supplied".into()],
        })
    }

    /// Add every declared text unit of each applicable complete bundle subject.
    pub fn scoped_bundle(
        manifest_path: &Path,
        root: &Path,
        baseline: &ValidatedBaseline,
        profile: &str,
        source_alias: &str,
        limits: &Limits,
    ) -> Result<Self, ScanError> {
        let mut snapshot = Self::bundle(manifest_path, root, limits)?;
        let content = &baseline.content;
        let selected_profile = content
            .profiles
            .iter()
            .find(|p| p.id == profile)
            .ok_or_else(|| ScanError::invalid("unknown profile"))?;
        let selected =
            crate::baseline::selected_indices(content, selected_profile, &baseline.dependencies)?;
        let selected = selected
            .iter()
            .map(|index| {
                content
                    .rules
                    .get(*index)
                    .ok_or_else(|| ScanError::invalid("selected bundle rule is not bound"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        if selected.iter().any(|rule| rule.source != source_alias)
            || content
                .sources
                .get(source_alias)
                .is_none_or(|source| source.adapter != "evidence-bundle/1")
        {
            return Err(ScanError::invalid(
                "scoped bundle rules must share the requested bundle source",
            ));
        }
        if selected.iter().all(|rule| rule.scope.is_none()) {
            return Ok(snapshot);
        }
        let mut targets = Budget::new(limits.targets as u64);
        let mut frames = Budget::new(limits.evidence_bytes);
        let mut steps = Sequential::new(snapshot.targets.len(), 1, 0)
            .map_err(|e| ScanError::unresolved(e.to_string()))?;
        let mut expanded = Vec::new();
        for packet in &snapshot.targets {
            if !targets.try_allocate(1) || !frames.try_allocate(packet.bytes.len() as u64) {
                return Err(ScanError::unresolved(
                    "complete bundle scope exceeds target/frame allowance",
                ));
            }
            if !steps.begin_step() {
                return Err(ScanError::unresolved(
                    "bundle scope preparation refused begin_step",
                ));
            }
            let scopes: BTreeSet<_> = selected
                .iter()
                .filter(|rule| crate::scan::applies(rule, &packet.applicability_key))
                .filter_map(|rule| rule.scope.clone())
                .collect();
            if !scopes.is_empty() {
                let frame: Value = json::parse(&packet.bytes).map_err(ScanError::invalid)?;
                let parts = frame
                    .get("parts")
                    .and_then(Value::as_array)
                    .ok_or_else(|| ScanError::invalid("bundle frame has no parts array"))?;
                let subjects: Vec<_> = parts
                    .iter()
                    .filter(|part| part["role"] == "subject")
                    .collect();
                let [subject] = subjects.as_slice() else {
                    return Err(ScanError::invalid(
                        "automatic bundle scope requires one complete subject file per packet",
                    ));
                };
                if subject.get("whole_file") != Some(&Value::Bool(true)) {
                    return Err(ScanError::invalid(
                        "automatic bundle scope requires one complete subject file per packet",
                    ));
                }
                let text = subject.get("text").and_then(Value::as_str).ok_or_else(|| {
                    ScanError::invalid(
                        "automatic text scope requires a UTF-8 subject; image regions are explicit",
                    )
                })?;
                let prepared = Self::scoped_prepared(
                    text.as_bytes(),
                    &packet.identity.id,
                    baseline,
                    profile,
                    source_alias,
                    limits,
                    Some(crate::scoped::ScopePlan {
                        adapter: "text/1",
                        scopes: &scopes,
                        selected_json: None,
                        input_sha256: None,
                    }),
                )?;
                for mut unit in prepared.targets {
                    if !targets.try_allocate(1) {
                        return Err(ScanError::unresolved(
                            "complete bundle scope exceeds target allowance; no units were dropped",
                        ));
                    }
                    let mut evidence: Value =
                        json::parse(&unit.bytes).map_err(ScanError::invalid)?;
                    json::object_mut(&mut evidence)
                        .map_err(ScanError::unresolved)?
                        .insert(
                            "supporting".into(),
                            json!(
                                parts
                                    .iter()
                                    .filter(|part| part["role"] != "subject")
                                    .collect::<Vec<_>>()
                            ),
                        );
                    let bytes = serde_json::to_vec(&evidence)
                        .map_err(|e| ScanError::invalid(e.to_string()))?;
                    if !frames.try_allocate(bytes.len() as u64) {
                        return Err(ScanError::unresolved(
                            "complete bundle scope exceeds frame allowance; no context was truncated",
                        ));
                    }
                    unit.identity.id = format!("{}/{}", packet.identity.id, unit.identity.id);
                    unit.identity.sha256 = sha256(&bytes);
                    let locations = packet
                        .identity
                        .metadata
                        .get("locations")
                        .ok_or_else(|| {
                            ScanError::unresolved("bundle packet has no location bindings")
                        })?
                        .clone();
                    let metadata = json::object_mut(&mut unit.identity.metadata)
                        .map_err(ScanError::unresolved)?;
                    metadata.insert("packet".into(), json!(packet.identity.id));
                    metadata.insert("locations".into(), locations);
                    unit.bytes = bytes;
                    unit.applicability_key = packet.applicability_key.clone();
                    unit.dependencies = std::sync::Arc::clone(&packet.dependencies);
                    expanded.push(unit);
                }
            }
            if !steps.complete_step(0) {
                return Err(ScanError::unresolved(
                    "bundle scope preparation refused completion",
                ));
            }
        }
        if !steps.is_done() || steps.completed() != snapshot.targets.len() {
            return Err(ScanError::unresolved(
                "bundle scope packet correspondence failed",
            ));
        }
        snapshot.targets.extend(expanded);
        snapshot.identity.snapshot_id = digest_fields(&[
            &snapshot.identity.snapshot_id,
            &baseline.identity.sha256,
            profile,
        ]);
        let metadata =
            json::object_mut(&mut snapshot.identity.metadata).map_err(ScanError::unresolved)?;
        metadata.insert("baseline_sha256".into(), json!(baseline.identity.sha256));
        metadata.insert("profile".into(), json!(profile));
        metadata.insert(
            "unit_parser".into(),
            json!("unicode-segmentation/1.13.3/UAX29"),
        );
        Ok(snapshot)
    }
}

pub(crate) fn bundle_evidence(
    bytes: &[u8],
    declaration: &EvidenceDeclaration,
    rule: &Rule,
) -> Result<Vec<u8>, String> {
    let source: Value = json::parse(bytes)?;
    if source.get("schema").and_then(Value::as_str) != Some("bundle-source/1")
        || source
            .pointer("/binding/scope_kind")
            .and_then(Value::as_str)
            != Some(rule.scope_kind.as_str())
    {
        return Err("bundle representation/scope mismatch".into());
    }
    let roles = declaration
        .required_roles
        .as_ref()
        .ok_or("missing question evidence roles")?;
    let parts = source
        .get("parts")
        .and_then(Value::as_array)
        .ok_or("missing evidence parts")?;
    if roles
        .iter()
        .any(|role| !parts.iter().any(|part| part["role"] == *role))
    {
        return Err("required question evidence role absent; no request issued".into());
    }
    let selected: Vec<_> = parts
        .iter()
        .filter(|p| {
            p["role"]
                .as_str()
                .is_some_and(|r| roles.iter().any(|v| v == r))
        })
        .collect();
    serde_json::to_vec(&json!({"schema":"declared-parts/1",
        "scope_kind":rule.scope_kind,"parts":selected,
        "coverage":"only declared files and image regions; dependency closure and semantic sufficiency require review"}))
        .map_err(|e| e.to_string())
}
