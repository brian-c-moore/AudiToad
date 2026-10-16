//! Format bindings for complete, answer-independent unit enumeration.
use crate::{
    ScanError, Snapshot, ValidatedBaseline,
    baseline::selected_indices,
    json,
    schema::{Limits, Rule, Scope, ScopeContext, ScopeUnit, SourceIdentity, TargetIdentity},
    source::{SERIALIZER, Target, digest_fields, read_bounded, sha256, unlinked_path},
};
use automation_structures::{Budget, Sequential};
use serde_json::{Value, json};
use std::{collections::BTreeSet, ops::Range, path::Path};
use unicode_segmentation::UnicodeSegmentation;

pub(crate) struct ScopePlan<'a> {
    pub adapter: &'a str,
    pub scopes: &'a BTreeSet<Scope>,
    pub selected_json: Option<(&'a str, &'a Value)>,
    pub input_sha256: Option<&'a str>,
}

pub(crate) fn media(adapter: &str) -> Option<&'static str> {
    match adapter {
        "text/1" => Some("text/plain"),
        "json/1" => Some("application/json"),
        "json-lines/1" => Some("application/x-ndjson"),
        "collection/1" => Some("application/vnd.auditoad.collection+json"),
        _ => None,
    }
}

fn paragraphs(text: &str) -> Result<Vec<Range<usize>>, ScanError> {
    let mut ranges = Vec::new();
    let mut start = None;
    let mut offset: usize = 0;
    let mut end = 0;
    for line in text.split_inclusive('\n') {
        if line.trim().is_empty() {
            if let Some(begin) = start.take() {
                ranges.push(begin..end);
            }
        } else {
            start.get_or_insert(offset);
            end = offset
                .checked_add(line.trim_end_matches(['\r', '\n']).len())
                .ok_or_else(|| ScanError::invalid("paragraph end offset overflows"))?;
        }
        offset = offset
            .checked_add(line.len())
            .ok_or_else(|| ScanError::invalid("paragraph offset overflows"))?;
    }
    if let Some(begin) = start {
        ranges.push(begin..end);
    }
    Ok(ranges)
}

pub(crate) fn matches_scope(rule: &Rule, target: &Target) -> bool {
    rule.scope
        .as_ref()
        .map_or(target.identity.metadata.get("scope").is_none(), |scope| {
            // Input inequality already disproves full scope equality. Avoid serializing a
            // scope for every unrelated input in a large collection's finite manifest.
            if let Some(input) = &scope.input
                && target
                    .identity
                    .metadata
                    .pointer("/scope/input")
                    .and_then(Value::as_str)
                    != Some(input)
            {
                return false;
            }
            serde_json::to_value(scope)
                .is_ok_and(|value| target.identity.metadata.get("scope") == Some(&value))
        })
}

pub(crate) fn evidence(bytes: &[u8]) -> Result<Vec<u8>, String> {
    let frame: Value = json::parse(bytes)?;
    if let Some(error) = frame.get("scope_error").and_then(Value::as_str) {
        return Err(error.into());
    }
    Ok(bytes.to_vec())
}

impl Snapshot {
    /// Enumerate every declared unit of one UTF-8 or JSON input, before any answers exist.
    pub fn scoped_input(
        bytes: &[u8],
        name: &str,
        baseline: &ValidatedBaseline,
        profile: &str,
        source_alias: &str,
        limits: &Limits,
    ) -> Result<Self, ScanError> {
        Self::scoped_prepared(bytes, name, baseline, profile, source_alias, limits, None)
    }

    pub(crate) fn scoped_prepared(
        bytes: &[u8],
        name: &str,
        baseline: &ValidatedBaseline,
        profile: &str,
        source_alias: &str,
        limits: &Limits,
        plan: Option<ScopePlan<'_>>,
    ) -> Result<Self, ScanError> {
        if !Budget::new(limits.input_bytes).try_allocate(bytes.len() as u64) {
            return Err(ScanError::unresolved(
                "scoped input exceeds input byte limit",
            ));
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
            .ok_or_else(|| ScanError::invalid("unknown source alias"))?;
        let adapter = plan.as_ref().map_or(source.adapter.as_str(), |p| p.adapter);
        if media(adapter).is_none() || adapter == "collection/1" {
            return Err(ScanError::invalid(
                "automatic scope requires text/1, json/1 or json-lines/1",
            ));
        }
        let mut scopes = plan
            .as_ref()
            .map_or_else(BTreeSet::new, |p| p.scopes.clone());
        for index in if plan.is_none() {
            selected_indices(content, profile, &baseline.dependencies)?
        } else {
            Vec::new()
        } {
            let rule = content
                .rules
                .get(index)
                .ok_or_else(|| ScanError::invalid("selected scope rule is not bound"))?;
            if rule.source != source_alias {
                return Err(ScanError::invalid(
                    "selected rules must share the requested source",
                ));
            }
            scopes.insert(
                rule.scope
                    .clone()
                    .ok_or_else(|| ScanError::invalid("missing scope"))?,
            );
        }
        if scopes
            .iter()
            .any(|s| matches!(s.unit, ScopeUnit::Paragraph | ScopeUnit::Sentence))
            && adapter != "text/1"
        {
            return Err(ScanError::invalid(
                "paragraph and sentence scopes require a text input",
            ));
        }
        let text =
            std::str::from_utf8(bytes).map_err(|_| ScanError::invalid("input must be UTF-8"))?;
        let lines = if adapter == "json-lines/1" {
            text.lines()
                .enumerate()
                .filter(|(_, line)| !line.trim().is_empty())
                .map(|(ordinal, line)| {
                    let line_number = ordinal
                        .checked_add(1)
                        .ok_or_else(|| ScanError::invalid("JSON line number overflows"))?;
                    json::parse::<Value>(line.as_bytes())
                        .map(|value| (line_number, value))
                        .map_err(|error| {
                            ScanError::invalid(format!("JSON line {line_number}: {error}"))
                        })
                })
                .collect::<Result<Vec<_>, _>>()?
        } else {
            Vec::new()
        };
        let selection = plan.as_ref().and_then(|p| p.selected_json);
        let parsed;
        let document = if let Some((_, selected)) = selection {
            selected
        } else {
            parsed = if adapter == "json-lines/1" {
                Value::Array(lines.iter().map(|(_, value)| value.clone()).collect())
            } else if adapter == "json/1" {
                json::parse::<Value>(bytes).map_err(ScanError::invalid)?
            } else {
                Value::String(text.into())
            };
            &parsed
        };
        let ranges = if scopes.iter().any(|s| s.unit == ScopeUnit::Paragraph) {
            paragraphs(text)?
        } else {
            Vec::new()
        };
        let sentences: Vec<_> = if scopes.iter().any(|s| s.unit == ScopeUnit::Sentence) {
            text.split_sentence_bound_indices()
                .filter(|(_, sentence)| !sentence.trim().is_empty())
                .map(|(offset, sentence)| {
                    let leading = sentence
                        .len()
                        .checked_sub(sentence.trim_start().len())
                        .ok_or_else(|| ScanError::invalid("trimmed sentence exceeds its source"))?;
                    let start = offset
                        .checked_add(leading)
                        .ok_or_else(|| ScanError::invalid("sentence start overflows"))?;
                    let end = offset
                        .checked_add(sentence.trim_end().len())
                        .ok_or_else(|| ScanError::invalid("sentence end overflows"))?;
                    Ok(start..end)
                })
                .collect::<Result<Vec<_>, ScanError>>()?
        } else {
            Vec::new()
        };
        if scopes.iter().any(|s| s.unit == ScopeUnit::Record) && !document.is_array() {
            return Err(ScanError::invalid(
                "record scope requires a JSON root array; no alternative scope was substituted",
            ));
        }
        let input_sha = plan
            .as_ref()
            .and_then(|p| p.input_sha256)
            .map_or_else(|| sha256(bytes), str::to_owned);
        let mut manifest = Vec::new();
        let mut target_budget = Budget::new(limits.targets as u64);
        for scope in &scopes {
            let count = match scope.unit {
                ScopeUnit::Document => 1,
                ScopeUnit::Paragraph => ranges.len(),
                ScopeUnit::Sentence => sentences.len(),
                ScopeUnit::Record => document
                    .as_array()
                    .ok_or_else(|| ScanError::invalid("record scope has no root array"))?
                    .len(),
            };
            // An empty selection has an explicit unresolved record, not a vacuous pass.
            if !target_budget.try_allocate(count.max(1) as u64) {
                return Err(ScanError::unresolved(
                    "complete scope exceeds target limit; no units were dropped",
                ));
            }
            for ordinal in 0..count.max(1) {
                manifest.push((scope.clone(), ordinal, count == 0));
            }
        }
        let mut frames = Budget::new(limits.evidence_bytes);
        let mut steps = Sequential::new(manifest.len(), 1, 0)
            .map_err(|e| ScanError::unresolved(e.to_string()))?;
        let mut targets = Vec::new();
        while !steps.is_done() {
            let (scope, ordinal, empty) = manifest
                .get(steps.completed())
                .ok_or_else(|| ScanError::unresolved("scope step has no manifest binding"))?;
            let ordinal = *ordinal;
            if !steps.begin_step() {
                return Err(ScanError::unresolved(
                    "scope preparation refused begin_step",
                ));
            }
            let (subject, location) = if *empty {
                (
                    Value::Null,
                    selection.map_or_else(
                        || json!({"empty_selection":true}),
                        |(pointer, _)| json!({"empty_selection":true,"pointer":pointer}),
                    ),
                )
            } else {
                match scope.unit {
                    ScopeUnit::Document => (
                        document.clone(),
                        selection.map_or_else(
                            || json!({"whole_input":true}),
                            |(pointer, _)| json!({"pointer":pointer}),
                        ),
                    ),
                    ScopeUnit::Paragraph | ScopeUnit::Sentence => {
                        let range = if scope.unit == ScopeUnit::Sentence {
                            sentences.get(ordinal)
                        } else {
                            ranges.get(ordinal)
                        }
                        .ok_or_else(|| ScanError::unresolved("scope unit has no source range"))?;
                        (
                            json!(
                                text.get(range.clone())
                                    .ok_or_else(|| ScanError::unresolved(
                                        "scope range is outside UTF-8 source boundaries"
                                    ))?
                            ),
                            json!({"byte_start":range.start,"byte_end":range.end}),
                        )
                    }
                    ScopeUnit::Record => (
                        document
                            .get(ordinal)
                            .ok_or_else(|| {
                                ScanError::unresolved("record scope ordinal is not bound")
                            })?
                            .clone(),
                        if adapter == "json-lines/1" {
                            json!({"line":lines.get(ordinal).ok_or_else(|| ScanError::unresolved("record ordinal has no JSON line binding"))?.0})
                        } else {
                            json!({"pointer":format!("{}/{ordinal}", selection.map_or("", |(pointer, _)| pointer))})
                        },
                    ),
                }
            };
            let mut frame = json!({"schema":"scoped-input/1","scope":scope,"subject":subject});
            if scope.context == ScopeContext::Document {
                json::object_mut(&mut frame)
                    .map_err(ScanError::unresolved)?
                    .insert("context".into(), document.clone());
            }
            if *empty {
                json::object_mut(&mut frame)
                    .map_err(ScanError::unresolved)?
                    .insert(
                        "scope_error".into(),
                        json!("declared scope contains no units; no answer was inferred"),
                    );
            }
            let frame_bytes =
                serde_json::to_vec(&frame).map_err(|e| ScanError::invalid(e.to_string()))?;
            if !frames.try_allocate(frame_bytes.len() as u64) {
                return Err(ScanError::unresolved(
                    "complete scope frames exceed evidence byte limit; no context was truncated",
                ));
            }
            let unit = match scope.unit {
                ScopeUnit::Document => "document",
                ScopeUnit::Paragraph => "paragraph",
                ScopeUnit::Sentence => "sentence",
                ScopeUnit::Record => "record",
            };
            let context = match scope.context {
                ScopeContext::None => "alone",
                ScopeContext::Document => "with-document",
            };
            targets.push(Target {
                identity: TargetIdentity {
                    id: format!("input/{unit}/{ordinal}/{context}"),
                    kind: source.media.first().ok_or_else(|| ScanError::invalid("scoped source declares no media"))?.clone(),
                    sha256: sha256(&frame_bytes),
                    metadata: json!({"scope":scope,"input":scope.input,"input_sha256":input_sha,"location":location,"ordinal":ordinal}),
                },
                bytes: frame_bytes,
                applicability_key: name.into(),
                path: None,
                dependencies: Default::default(),
            });
            if !steps.complete_step(0) || steps.completed() != targets.len() {
                return Err(ScanError::unresolved(
                    "scope preparation coverage correspondence failed",
                ));
            }
        }
        let scope_bytes =
            serde_json::to_vec(&scopes).map_err(|e| ScanError::invalid(e.to_string()))?;
        Ok(Self {
            identity: SourceIdentity {
                binding: source.adapter.clone(),
                snapshot_id: digest_fields(&[&input_sha, &sha256(&scope_bytes)]),
                input_sha256: input_sha,
                serializer: SERIALIZER.into(),
                metadata: json!({"name":name,"scopes":scopes,"baseline_sha256":baseline.identity.sha256,
                    "profile":profile.id,"coverage":"every declared unit of this complete input"}),
            },
            targets,
            input_path: None,
            protected_paths: Vec::new(),
            excluded: Vec::new(),
        })
    }

    /// Read one confined input and bind every prepared unit to its complete source hash.
    pub fn scoped_file(
        path: &Path,
        baseline: &ValidatedBaseline,
        profile: &str,
        source_alias: &str,
        limits: &Limits,
    ) -> Result<Self, ScanError> {
        let path = unlinked_path(path).map_err(ScanError::invalid)?;
        let bytes = read_bounded(&path, limits.input_bytes).map_err(ScanError::unresolved)?;
        let name = path
            .file_name()
            .and_then(|s| s.to_str())
            .ok_or_else(|| ScanError::invalid("input filename must be UTF-8"))?;
        let mut snapshot =
            Self::scoped_input(&bytes, name, baseline, profile, source_alias, limits)?;
        snapshot.input_path = Some(path.clone());
        snapshot.protected_paths.push(path.clone());
        let dependencies: std::sync::Arc<[_]> = vec![(path, sha256(&bytes))].into();
        for target in &mut snapshot.targets {
            target.dependencies = std::sync::Arc::clone(&dependencies);
        }
        Ok(snapshot)
    }
}
