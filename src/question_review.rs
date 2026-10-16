//! Built-in declaration review. Domain normalization feeds the existing inventory scanner.
//! No artifact execution or runtime evidence-completeness claim is made here.
use crate::{
    Preparation, PublishedScan, ScanError, Snapshot, ValidatedBaseline,
    audit::{self, RunDefinition, RunOptions},
    json,
    schema::{Limits, Record},
    source::{read_bounded, sha256, unlinked_path},
};
use automation_structures::Budget;
use serde::Serialize;
use serde_json::{Value, json};
use std::{
    io::Write,
    path::{Path, PathBuf},
    sync::Arc,
};

/// The single shipped source of the six declaration-review questions.
pub const BASELINE: &[u8] = include_bytes!("../baselines/question-review/baseline.json");

/// Construct the installed baseline without runtime source-tree or fixture paths.
pub fn baseline(max_bytes: u64) -> Result<ValidatedBaseline, ScanError> {
    ValidatedBaseline::from_bytes_with_limit(BASELINE, Path::new("."), max_bytes)
}

/// Replace only the installed review profile's egress list with explicit operator origins.
/// Omitting the override preserves the shipped bytes and baseline identity.
pub fn baseline_with_allowed_egress(
    max_bytes: u64,
    allowed_egress: Option<&[String]>,
) -> Result<ValidatedBaseline, ScanError> {
    let Some(origins) = allowed_egress else {
        return baseline(max_bytes);
    };
    if !Budget::new(max_bytes).try_allocate(BASELINE.len() as u64) {
        return Err(ScanError::invalid(format!(
            "baseline exceeds {max_bytes} byte input limit"
        )));
    }
    let mut input_allowance = Budget::new(max_bytes);
    for origin in origins {
        if origin.contains('*') {
            return Err(ScanError::invalid(
                "review egress entries must be explicit origins; wildcards are not supported",
            ));
        }
        let bytes = origin
            .len()
            .checked_add(3)
            .ok_or_else(|| ScanError::invalid("review egress declaration byte size overflows"))?;
        if !input_allowance.try_allocate(bytes as u64) {
            return Err(ScanError::invalid(format!(
                "review egress declaration exceeds {max_bytes} byte input limit"
            )));
        }
    }
    let mut declaration = json::parse_value(BASELINE).map_err(ScanError::invalid)?;
    let policy = declaration
        .pointer_mut("/profiles/0/allowed_egress")
        .ok_or_else(|| ScanError::invalid("installed review egress policy is absent"))?;
    *policy = json!(origins);
    let mut output = BoundedJson {
        bytes: Vec::new(),
        allowance: Budget::new(max_bytes),
        refusal: "review baseline exceeds baseline byte limit",
    };
    serde_json::to_writer(&mut output, &declaration)
        .map_err(|error| ScanError::invalid(error.to_string()))?;
    ValidatedBaseline::from_bytes_with_limit(&output.bytes, Path::new("."), max_bytes)
}

// Serialization is a physical binding of a canonical byte allowance. Borrowed records
// prevent cloning a large declared context for every question before admission.
struct BoundedJson {
    bytes: Vec<u8>,
    allowance: Budget,
    refusal: &'static str,
}

impl Write for BoundedJson {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if !self.allowance.try_allocate(bytes.len() as u64) {
            return Err(std::io::Error::other(self.refusal));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[derive(Serialize)]
struct Origin<'a> {
    schema: &'a str,
    original_raw_sha256: &'a str,
    json_pointer: String,
}

#[derive(Serialize)]
struct Facts<'a> {
    question: &'a Value,
    rule: &'a Value,
    baseline: &'a Value,
    sources: &'a Value,
    builders: &'a Value,
    prerequisites: Prerequisites<'a>,
}

#[derive(Default, Serialize)]
struct Prerequisites<'a> {
    consult: Vec<Prerequisite<'a>>,
    check: Vec<Prerequisite<'a>>,
}

#[derive(Serialize)]
struct Prerequisite<'a> {
    id: &'a str,
    status: &'static str,
    declarations: Vec<&'a Value>,
}

// This selects direct JSON declarations only; baseline validation owns dependency legality.
fn prerequisites<'a>(
    question: &'a Value,
    rules: &'a [Value],
    work: &mut Budget,
) -> Result<Prerequisites<'a>, ScanError> {
    let mut result = Prerequisites::default();
    for (pointer, output) in [
        ("/consult/rules", &mut result.consult),
        ("/check/rules", &mut result.check),
    ] {
        let Some(references) = question.pointer(pointer) else {
            continue;
        };
        let references = references
            .as_array()
            .ok_or_else(|| ScanError::invalid("declared prerequisite rules must be arrays"))?;
        for reference in references {
            if !work.try_allocate(1) {
                return Err(ScanError::unresolved(
                    "question prerequisite selection exceeds work limit",
                ));
            }
            let id = reference
                .as_str()
                .filter(|id| !id.trim().is_empty())
                .ok_or_else(|| {
                    ScanError::invalid("declared prerequisite IDs must be nonblank strings")
                })?;
            let mut declarations = Vec::new();
            for rule in rules {
                if !work.try_allocate(1) {
                    return Err(ScanError::unresolved(
                        "question prerequisite lookup exceeds work limit",
                    ));
                }
                if rule.get("id").and_then(Value::as_str) == Some(id) {
                    declarations.push(rule);
                }
            }
            let status = match declarations.len() {
                0 => "missing",
                1 => "declared",
                _ => "ambiguous",
            };
            output.push(Prerequisite {
                id,
                status,
                declarations,
            });
        }
    }
    Ok(result)
}

#[derive(Serialize)]
struct Item<'a> {
    id: &'a str,
    kind: &'static str,
    facts: Facts<'a>,
}

#[derive(Serialize)]
struct Inventory<'a> {
    schema: &'static str,
    snapshot_id: &'a str,
    items: Vec<Item<'a>>,
}

fn fields(value: &Value, allowed: &[&str], description: &str) -> Result<(), ScanError> {
    let object = value
        .as_object()
        .ok_or_else(|| ScanError::invalid(format!("{description} must be an object")))?;
    if object.keys().any(|key| !allowed.contains(&key.as_str())) {
        return Err(ScanError::invalid(format!(
            "unknown field in {description}"
        )));
    }
    Ok(())
}

fn text<'a>(value: &'a Value, field: &str) -> Result<&'a str, ScanError> {
    value
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| ScanError::invalid(format!("question input requires nonblank {field}")))
}

fn generic_question(question: &Value) -> Result<(), ScanError> {
    fields(
        question,
        &[
            "id",
            "instructions",
            "criteria_true",
            "criteria_false",
            "options",
            "declared_context",
        ],
        "question",
    )?;
    text(question, "id")?;
    text(question, "instructions")?;
    let yes = question.get("criteria_true");
    let no = question.get("criteria_false");
    if yes.is_some() != no.is_some()
        || yes.is_some_and(|value| value.as_str().is_none_or(|value| value.trim().is_empty()))
        || no.is_some_and(|value| value.as_str().is_none_or(|value| value.trim().is_empty()))
    {
        return Err(ScanError::invalid(
            "criteria_true and criteria_false must be supplied together as nonblank strings",
        ));
    }
    if let Some(options) = question.get("options") {
        let options = options
            .as_object()
            .ok_or_else(|| ScanError::invalid("options must be an object"))?;
        if yes.is_some()
            || options.len() < 2
            || options.iter().any(|(key, value)| {
                key.trim().is_empty() || value.as_str().is_none_or(|value| value.trim().is_empty())
            })
        {
            return Err(ScanError::invalid(
                "options require at least two named nonblank strings and cannot combine with true/false criteria",
            ));
        }
    }
    Ok(())
}

/// Freeze a baseline or `auditoad-question-set/1` as source-bound inventory records.
/// Generic question sets accept `id`, `instructions`, paired criteria or named options,
/// and optional declared context. Original JSON pointers and raw SHA-256 are retained.
pub fn snapshot(bytes: &[u8], limits: &Limits) -> Result<Snapshot, ScanError> {
    if !Budget::new(limits.input_bytes).try_allocate(bytes.len() as u64) {
        return Err(ScanError::unresolved(
            "question input exceeds input byte limit",
        ));
    }
    let document = json::parse_value(bytes).map_err(ScanError::invalid)?;
    let schema = document
        .get("schema")
        .and_then(Value::as_str)
        .ok_or_else(|| ScanError::invalid("question input requires a versioned schema"))?;
    let generic = match schema {
        "auditoad-baseline/1" | "checkwarden-baseline/1" => false,
        "auditoad-question-set/1" => true,
        _ => return Err(ScanError::invalid("unsupported question input schema")),
    };
    if generic {
        fields(
            &document,
            &["schema", "id", "questions", "declared_context"],
            "question set",
        )?;
        text(&document, "id")?;
    }
    let field = if generic { "questions" } else { "rules" };
    let declarations = document
        .get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| ScanError::invalid(format!("question input requires a {field} array")))?;
    let null = Value::Null;
    let context = if generic {
        json!({"id":document.get("id"),"schema":schema,"declared_context":document.get("declared_context")})
    } else {
        let declaration = document
            .get("baseline")
            .ok_or_else(|| ScanError::invalid("baseline declaration is absent"))?;
        json!({"id":declaration.get("id"),"title":declaration.get("title")})
    };
    let input_sha256 = sha256(bytes);
    let mut targets = Budget::new(limits.targets as u64);
    let mut work = Budget::new(limits.manifest_work as u64);
    let mut items = Vec::new();
    let mut locations = Vec::new();
    for (index, question) in declarations.iter().enumerate() {
        if !work.try_allocate(1) {
            return Err(ScanError::unresolved(
                "question selection exceeds work limit",
            ));
        }
        if !generic && question.pointer("/evaluator/kind").and_then(Value::as_str) != Some("model")
        {
            continue;
        }
        if !targets.try_allocate(1) {
            return Err(ScanError::unresolved(
                "question selection exceeds target limit",
            ));
        }
        if generic {
            generic_question(question)?;
        } else {
            question
                .pointer("/check/instructions")
                .and_then(Value::as_str)
                .filter(|value| !value.trim().is_empty())
                .ok_or_else(|| {
                    ScanError::invalid("model rule requires nonblank check.instructions")
                })?;
        }
        items.push(Item {
            id: text(question, "id")?,
            kind: "question-declaration",
            facts: Facts {
                question: if generic {
                    question
                } else {
                    question
                        .get("check")
                        .ok_or_else(|| ScanError::invalid("model check declaration is absent"))?
                },
                rule: question,
                baseline: &context,
                sources: document.get("sources").unwrap_or(&null),
                builders: document.get("evidence").unwrap_or(&null),
                prerequisites: if generic {
                    Prerequisites::default()
                } else {
                    prerequisites(question, declarations, &mut work)?
                },
            },
        });
        locations.push(format!("/{field}/{index}"));
    }
    if items.is_empty() {
        return Err(ScanError::invalid(
            "question input has no model instructions",
        ));
    }
    let inventory = Inventory {
        schema: "auditoad-inventory/1",
        snapshot_id: &input_sha256,
        items,
    };
    let mut output = BoundedJson {
        bytes: Vec::new(),
        allowance: Budget::new(limits.input_bytes),
        refusal: "normalized questions exceed input byte limit",
    };
    serde_json::to_writer(&mut output, &inventory)
        .map_err(|error| ScanError::unresolved(error.to_string()))?;
    let mut snapshot = Snapshot::inventory(&output.bytes, limits)?;
    if snapshot.targets.len() != locations.len() {
        return Err(ScanError::unresolved(
            "normalized question locations do not cover the frozen targets",
        ));
    }
    for (target, json_pointer) in snapshot.targets.iter_mut().zip(locations) {
        target.identity.metadata = serde_json::to_value(Origin {
            schema,
            original_raw_sha256: &input_sha256,
            json_pointer,
        })
        .map_err(|error| ScanError::unresolved(error.to_string()))?;
    }
    snapshot.identity.metadata = json!({"normalization":"question-review/1","original_schema":schema,"original_raw_sha256":input_sha256,
        "coverage":"every declared generic question or AudiToad model instruction; runtime artifacts are not supplied"});
    Ok(snapshot)
}

/// Review declarations through the ordinary scanner, preparing locally unless live is enabled.
pub fn run_file(
    input: &Path,
    report: &Path,
    options: &RunOptions,
    allowed_egress: Option<&[String]>,
    on_prepared: impl FnMut(&Preparation),
    on_record: impl FnMut(&Record),
) -> Result<PublishedScan, ScanError> {
    let snapshot = snapshot_file(input, &options.limits)?;
    let definition = RunDefinition {
        name: "Question review".into(),
        baseline: PathBuf::new(),
        input: input.to_path_buf(),
        report: report.to_path_buf(),
        profile: Some("all".into()),
        source: Some("questions".into()),
        project_root: None,
        evaluators: None,
        labels: None,
        mock: None,
        replay: None,
        reuse: None,
    };
    audit::run_bound(
        &definition,
        options,
        baseline_with_allowed_egress(options.max_baseline_bytes, allowed_egress)?,
        snapshot,
        on_prepared,
        on_record,
    )
}

/// Freeze a question file and bind every normalized record to its unchanged raw source.
pub fn snapshot_file(input: &Path, limits: &Limits) -> Result<Snapshot, ScanError> {
    let input = unlinked_path(input).map_err(ScanError::invalid)?;
    let bytes = read_bounded(&input, limits.input_bytes).map_err(ScanError::unresolved)?;
    let mut snapshot = snapshot(&bytes, limits)?;
    let dependencies: Arc<[_]> = vec![(input.clone(), sha256(&bytes))].into();
    for target in &mut snapshot.targets {
        target.dependencies = Arc::clone(&dependencies);
    }
    snapshot.input_path = Some(input.clone());
    snapshot.protected_paths.push(input.clone());
    Ok(snapshot)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ScanRequest, scan, schema::ResultState};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn question_set() -> Value {
        json!({"schema":"auditoad-question-set/1","id":"review","questions":[{"id":"first","instructions":"Does the selected statement assert the supplied proposition?"}]})
    }

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "assertions check explicit review egress policy, unchanged default identity and existing origin validation"
    )]
    fn review_egress_override_changes_only_profile_policy_and_is_bounded() -> TestResult {
        let original = baseline_with_allowed_egress(2 * 1024 * 1024, None)?;
        assert_eq!(original.identity.sha256, sha256(BASELINE));
        assert_eq!(
            original
                .baseline()
                .profiles
                .first()
                .ok_or("review profile is absent")?
                .allowed_egress,
            vec!["https://api.typesafe.ai"]
        );
        let origins = vec!["loopback".into(), "https://review.example.test".into()];
        let overridden = baseline_with_allowed_egress(2 * 1024 * 1024, Some(&origins))?;
        let mut expected = serde_json::to_value(original.baseline())?;
        *expected
            .pointer_mut("/profiles/0/allowed_egress")
            .ok_or("review policy is absent")? = json!(origins);
        assert_eq!(serde_json::to_value(overridden.baseline())?, expected);
        assert_ne!(overridden.identity.sha256, original.identity.sha256);
        for origins in [
            vec!["https://review.example.test/path".into()],
            vec!["http://review.example.test".into()],
            vec!["https://*.example.test".into()],
            vec!["loopback".into(), "loopback".into()],
        ] {
            assert!(baseline_with_allowed_egress(2 * 1024 * 1024, Some(&origins)).is_err());
        }
        assert!(baseline_with_allowed_egress(1, Some(&origins)).is_err());
        let too_large = vec![format!("https://{}", "x".repeat(BASELINE.len()))];
        assert!(baseline_with_allowed_egress(BASELINE.len() as u64, Some(&too_large)).is_err());
        Ok(())
    }

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "assertions check frozen source identity, original JSON locations and current model selection"
    )]
    fn normalization_preserves_original_identity_and_filters_only_native_model_instructions()
    -> TestResult {
        let input = json!({"schema":"auditoad-baseline/1","baseline":{"id":"source","version":"7"},"sources":{},"evidence":{},"rules":[
            {"id":"local","evaluator":{"kind":"syntax"},"check":{"kind":"syntax/1"}},
            {"id":"judge","evaluator":{"kind":"model"},"check":{"kind":"yes-no/1","instructions":"One proposition?"}},
            {"id":"helper","evaluator":{"kind":"model"},"check":{"kind":"extract/1","instructions":"Copy the declared supporting fields."}}
        ]});
        let mut bytes = serde_json::to_vec(&input)?;
        let original = sha256(&bytes);
        let frozen = snapshot(&bytes, &Limits::default())?;
        bytes.fill(b' ');
        assert_eq!(frozen.targets.len(), 2);
        assert_eq!(
            frozen.identity.metadata.get("original_raw_sha256"),
            Some(&json!(original))
        );
        let [judge, helper] = frozen.targets.as_slice() else {
            return Err("expected a judge and helper".into());
        };
        assert_eq!(judge.identity.id, "judge");
        assert_eq!(helper.identity.id, "helper");
        let facts: Value = json::parse(&helper.bytes)?;
        assert_eq!(
            helper.identity.metadata.get("json_pointer"),
            Some(&json!("/rules/2"))
        );
        assert_eq!(
            helper.identity.metadata.get("original_raw_sha256"),
            Some(&json!(original))
        );
        assert!(facts.pointer("/facts/source_identity").is_none());
        assert_eq!(
            facts.pointer("/facts/rule/check/instructions"),
            Some(&json!("Copy the declared supporting fields."))
        );
        Ok(())
    }

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "assertions check exact candidate frames in both supported contracts without unrelated outer rule metadata"
    )]
    fn question_frames_preserve_both_input_contracts_without_outer_rule_metadata() -> TestResult {
        let instructions = "Does the selected paragraph identify its narrator?";
        let generic_question = json!({"id":"narrator","instructions":instructions,"criteria_true":"The paragraph identifies its narrator.","criteria_false":"The paragraph does not identify its narrator.","declared_context":{"subject":"one paragraph"}});
        let generic_input = json!({"schema":"auditoad-question-set/1","id":"source","questions":[generic_question]});
        let native_check = json!({"kind":"yes-no/1","instructions":instructions,"criteria_true":"The paragraph identifies its narrator.","criteria_false":"The paragraph does not identify its narrator.","state_projection":{"paragraph":"/subject/text"}});
        let native_input = json!({"schema":"auditoad-baseline/1","baseline":{"id":"source","version":"1"},"rules":[{"id":"narrator","title":"Outer metadata","falsifier":"Outer regression description","evaluator":{"kind":"model"},"check":native_check}]});
        let generic = snapshot(&serde_json::to_vec(&generic_input)?, &Limits::default())?;
        let native = snapshot(&serde_json::to_vec(&native_input)?, &Limits::default())?;
        let [generic_target] = generic.targets.as_slice() else {
            return Err("generic question is absent".into());
        };
        let [native_target] = native.targets.as_slice() else {
            return Err("native question is absent".into());
        };
        let generic_frame = json::parse_value(&generic_target.bytes)?;
        let native_frame = json::parse_value(&native_target.bytes)?;
        assert_eq!(
            generic_frame.pointer("/facts/question"),
            Some(&generic_question)
        );
        assert_eq!(native_frame.pointer("/facts/question"), Some(&native_check));
        assert_eq!(
            generic_frame.pointer("/facts/question/instructions"),
            native_frame.pointer("/facts/question/instructions")
        );
        assert_eq!(
            generic_frame.pointer("/facts/question/criteria_true"),
            native_frame.pointer("/facts/question/criteria_true")
        );
        assert_eq!(
            generic_frame.pointer("/facts/question/criteria_false"),
            native_frame.pointer("/facts/question/criteria_false")
        );
        assert!(native_frame.pointer("/facts/question/falsifier").is_none());
        assert_eq!(
            native_frame.pointer("/facts/rule/falsifier"),
            Some(&json!("Outer regression description"))
        );
        Ok(())
    }

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "assertions check semantic evidence stability while preserving different original custody metadata"
    )]
    fn unrelated_question_and_baseline_metadata_changes_preserve_untouched_evidence() -> TestResult
    {
        let mut input = json!({"schema":"auditoad-baseline/1","baseline":{"id":"source","version":"1","title":"Question source","publisher":"First","status":"draft"},"sources":{},"evidence":{},"rules":[
            {"id":"same","evaluator":{"kind":"model"},"check":{"kind":"yes-no/1","instructions":"Does the selected paragraph name its narrator?"}},
            {"id":"edited","evaluator":{"kind":"model"},"check":{"kind":"yes-no/1","instructions":"Does the selected paragraph identify its location?"}}
        ]});
        let first = snapshot(&serde_json::to_vec(&input)?, &Limits::default())?;
        *input
            .pointer_mut("/rules/1/check/instructions")
            .ok_or("edited instruction is absent")? =
            json!("Does the selected paragraph identify its date?");
        *input
            .pointer_mut("/baseline/version")
            .ok_or("version is absent")? = json!("2");
        *input
            .pointer_mut("/baseline/status")
            .ok_or("status is absent")? = json!("active");
        *input
            .pointer_mut("/baseline/publisher")
            .ok_or("publisher is absent")? = json!("Second");
        let second = snapshot(&serde_json::to_vec(&input)?, &Limits::default())?;
        let [first_same, first_edited] = first.targets.as_slice() else {
            return Err("first source has wrong targets".into());
        };
        let [second_same, second_edited] = second.targets.as_slice() else {
            return Err("second source has wrong targets".into());
        };
        assert_eq!(first_same.bytes, second_same.bytes);
        assert_eq!(first_same.identity.sha256, second_same.identity.sha256);
        assert_ne!(
            first_same.identity.metadata.get("original_raw_sha256"),
            second_same.identity.metadata.get("original_raw_sha256")
        );
        assert_ne!(first.identity.metadata, second.identity.metadata);
        assert_ne!(first_edited.bytes, second_edited.bytes);
        let evidence = json::parse_value(&first_same.bytes)?;
        assert_eq!(
            evidence.pointer("/facts/baseline"),
            Some(&json!({"id":"source","title":"Question source"}))
        );
        assert!(evidence.pointer("/facts/source_identity").is_none());
        Ok(())
    }

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "assertions check exact direct selector context, reference order and explicit missing or ambiguous declarations"
    )]
    fn direct_prerequisites_preserve_selectors_order_and_missing_or_ambiguous_references()
    -> TestResult {
        let query = "(call function: (identifier) @call arguments: (argument_list (_) @argument))";
        let input = json!({"schema":"auditoad-baseline/1","baseline":{"id":"source","title":"Selector context"},"rules":[
            {"id":"CAPTURE","evaluator":{"kind":"syntax"},"check":{"kind":"syntax/1","query":query}},
            {"id":"DUPLICATE","evaluator":{"kind":"syntax"}},
            {"id":"DUPLICATE","evaluator":{"kind":"local-json"}},
            {"id":"UNRELATED","evaluator":{"kind":"syntax"},"check":{"query":"not selected"}},
            {"id":"JUDGE","evaluator":{"kind":"model"},"consult":{"rules":["CAPTURE","ABSENT","DUPLICATE"]},"check":{"kind":"yes-no/1","rules":["CAPTURE"],"instructions":"Can supplied request text change the parsed XPath structure at call?","state_projection":{"call":{"pointer":"/prior/0/observation/fields/captures","capture":"call"},"argument":{"pointer":"/prior/0/observation/fields/captures","capture":"argument"}}}}
        ]});
        let bytes = serde_json::to_vec(&input)?;
        let frozen = snapshot(&bytes, &Limits::default())?;
        let [judge] = frozen.targets.as_slice() else {
            return Err("expected one judgment declaration".into());
        };
        let facts = json::parse_value(&judge.bytes)?;
        let declarations = facts
            .pointer("/facts/prerequisites/consult")
            .and_then(Value::as_array)
            .ok_or("consult declarations absent")?;
        let [capture, missing, ambiguous] = declarations.as_slice() else {
            return Err("prerequisite order or coverage changed".into());
        };
        assert_eq!(capture.get("id"), Some(&json!("CAPTURE")));
        assert_eq!(capture.get("status"), Some(&json!("declared")));
        assert_eq!(
            capture.pointer("/declarations/0/check/query"),
            Some(&json!(query))
        );
        assert_eq!(
            missing,
            &json!({"id":"ABSENT","status":"missing","declarations":[]})
        );
        assert_eq!(ambiguous.get("status"), Some(&json!("ambiguous")));
        assert_eq!(
            ambiguous
                .get("declarations")
                .and_then(Value::as_array)
                .map(Vec::len),
            Some(2)
        );
        assert_eq!(
            facts.pointer("/facts/prerequisites/check/0/id"),
            Some(&json!("CAPTURE"))
        );
        assert!(!String::from_utf8_lossy(&judge.bytes).contains("UNRELATED"));
        assert!(
            snapshot(
                &bytes,
                &Limits {
                    manifest_work: 5,
                    ..Limits::default()
                }
            )
            .is_err()
        );
        let generic = snapshot(&serde_json::to_vec(&question_set())?, &Limits::default())?;
        let [question] = generic.targets.as_slice() else {
            return Err("expected one generic question".into());
        };
        let facts = json::parse_value(&question.bytes)?;
        assert_eq!(
            facts.pointer("/facts/prerequisites"),
            Some(&json!({"consult":[],"check":[]}))
        );
        Ok(())
    }

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "assertions check closed generic contracts, duplicate identity and whole-input refusals"
    )]
    fn malformed_empty_duplicate_and_resource_stopped_question_sets_refuse() -> TestResult {
        for input in [
            json!({"schema":"auditoad-question-set/2","id":"bad","questions":[]}),
            json!({"schema":"auditoad-question-set/1","id":"bad","questions":[]}),
            json!({"schema":"auditoad-question-set/1","id":"bad","extra":true,"questions":[{"id":"one","instructions":"One?"}]}),
            json!({"schema":"auditoad-question-set/1","id":"bad","questions":[{"id":"same","instructions":"One?"},{"id":"same","instructions":"Two?"}]}),
            json!({"schema":"auditoad-question-set/1","id":"bad","questions":[{"id":"one","instructions":" "}]}),
            json!({"schema":"auditoad-question-set/1","id":"bad","questions":[{"id":"one","instructions":"One?","criteria_true":"Yes"}]}),
            json!({"schema":"auditoad-question-set/1","id":"bad","questions":[{"id":"one","instructions":"One?","criteria_true":null,"criteria_false":null}]}),
            json!({"schema":"auditoad-question-set/1","id":"bad","questions":[{"id":"one","instructions":"One?","criteria_true":" ","criteria_false":"No"}]}),
            json!({"schema":"auditoad-question-set/1","id":"bad","questions":[{"id":"one","instructions":"One?","criteria_true":"Yes","criteria_false":""}]}),
            json!({"schema":"auditoad-question-set/1","id":"bad","questions":[{"id":"one","instructions":"One?","options":{"only":"One"}}]}),
            json!({"schema":"auditoad-question-set/1","id":"bad","questions":[{"id":"one","instructions":"One?","options":{"a":"One","b":"Two"},"criteria_true":"Yes","criteria_false":"No"}]}),
        ] {
            assert!(
                snapshot(&serde_json::to_vec(&input)?, &Limits::default()).is_err(),
                "{input}"
            );
        }
        let bytes = serde_json::to_vec(&question_set())?;
        for limits in [
            Limits {
                input_bytes: 1,
                ..Limits::default()
            },
            Limits {
                targets: 0,
                ..Limits::default()
            },
            Limits {
                manifest_work: 0,
                ..Limits::default()
            },
            Limits {
                evidence_bytes: 1,
                ..Limits::default()
            },
        ] {
            assert!(snapshot(&bytes, &limits).is_err());
        }
        let mut large = question_set();
        large
            .as_object_mut()
            .ok_or("set is absent")?
            .insert("declared_context".into(), json!("context".repeat(2000)));
        large
            .get_mut("questions")
            .and_then(Value::as_array_mut)
            .ok_or("questions are absent")?
            .push(json!({"id":"second","instructions":"Second proposition?"}));
        let bytes = serde_json::to_vec(&large)?;
        let limit = u64::try_from(bytes.len())?
            .checked_add(1024)
            .ok_or("test byte bound overflows")?;
        assert!(
            snapshot(
                &bytes,
                &Limits {
                    input_bytes: limit,
                    ..Limits::default()
                }
            )
            .is_err()
        );
        assert!(snapshot(b"{\"schema\":\"auditoad-question-set/1\",\"id\":\"a\",\"id\":\"b\",\"questions\":[]}", &Limits::default()).is_err());
        Ok(())
    }

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "assertions check installed assets, ordinary scanner composition and changed-source refusal"
    )]
    fn shipped_criteria_use_the_existing_scanner_and_original_file_pins() -> TestResult {
        let baseline = baseline(2 * 1024 * 1024)?;
        assert_eq!(baseline.baseline().rules.len(), 6);
        let bytes = serde_json::to_vec(&question_set())?;
        let frozen = snapshot(&bytes, &Limits::default())?;
        let result = scan(ScanRequest {
            baseline: &baseline,
            snapshot: &frozen,
            profile: "all",
            source_alias: "questions",
            limits: Limits::default(),
            experimental: true,
            mock: None,
        })?;
        assert_eq!(result.report.records.len(), 6);
        assert_eq!(result.report.usage.provider_calls, 0);
        for record in &result.report.records {
            assert_eq!(record.result, ResultState::NotEvaluated);
            let evidence = json::parse_value(
                &record
                    .evidence
                    .as_ref()
                    .ok_or("prepared evidence is absent")?
                    .bytes,
            )?;
            assert_eq!(
                record.target.metadata.get("json_pointer"),
                Some(&json!("/questions/0"))
            );
            assert!(evidence.pointer("/facts/source_identity").is_none());
        }
        let dir = crate::test_support::directory();
        let input = dir.path().join("questions.json");
        std::fs::write(&input, &bytes)?;
        let frozen = snapshot_file(&input, &Limits::default())?;
        std::fs::write(&input, b"changed")?;
        let result = scan(ScanRequest {
            baseline: &baseline,
            snapshot: &frozen,
            profile: "all",
            source_alias: "questions",
            limits: Limits::default(),
            experimental: true,
            mock: None,
        })?;
        assert!(
            result
                .report
                .records
                .iter()
                .all(|record| record.result == ResultState::Error)
        );
        Ok(())
    }
}
