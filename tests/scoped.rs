mod support;
use auditoad::{
    MockModel, ScanRequest, Snapshot, ValidatedBaseline, scan,
    schema::{Limits, RequirementStatus, ResultState},
};
use serde_json::{Value, json};
use support::*;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn declaration(
    root: &std::path::Path,
    adapter: &str,
    unit: &str,
    context: &str,
) -> TestResult<Value> {
    let mut value = mock_baseline(root);
    *value
        .pointer_mut("/sources/bytes")
        .ok_or("fixture source is absent")? = json!({"adapter":adapter,"media":[if adapter == "text/1" { "text/plain" } else { "application/json" }]});
    *value
        .pointer_mut("/evidence/bytes")
        .ok_or("fixture evidence builder is absent")? =
        json!({"builder":"scoped-input/1","builder_revision":"r1"});
    value
        .get_mut("evidence")
        .and_then(Value::as_object_mut)
        .ok_or("fixture evidence declarations are absent")?
        .insert(
            "answers".into(),
            json!({"builder":"answers/1","builder_revision":"r1"}),
        );
    let rule = value
        .pointer_mut("/rules/0")
        .and_then(Value::as_object_mut)
        .ok_or("fixture rule is absent")?;
    rule.insert(
        "scope_kind".into(),
        json!(if unit == "document" { "whole" } else { "site" }),
    );
    rule.insert("scope".into(), json!({"unit":unit,"context":context}));
    rule.insert("id".into(), json!("A"));
    Ok(value)
}

fn append_combination(
    value: &mut Value,
    id: &str,
    dependencies: &[&str],
    unit: &str,
    operator: &str,
) -> TestResult {
    let mut rule = value
        .pointer("/rules/0")
        .and_then(Value::as_object)
        .ok_or("fixture rule is absent")?
        .clone();
    for (field, replacement) in [
        ("id", json!(id)),
        ("scope", json!({"unit":unit,"context":"none"})),
        (
            "scope_kind",
            json!(if unit == "document" { "whole" } else { "site" }),
        ),
        ("evidence", json!("answers")),
        (
            "evaluator",
            json!({"kind":"answers","contract":"answers/1"}),
        ),
        (
            "check",
            json!({"kind":"answers/1","rules":dependencies,"fail_when":operator,
        "coverage":"The parent asks exactly the declared Boolean combination of the complete child scope."}),
        ),
    ] {
        rule.insert(field.into(), replacement);
    }
    value
        .get_mut("rules")
        .and_then(Value::as_array_mut)
        .ok_or("fixture rules are absent")?
        .push(Value::Object(rule));
    Ok(())
}

fn run_scoped(
    baseline: &ValidatedBaseline,
    snapshot: &Snapshot,
    limits: Limits,
    mock: Option<&MockModel>,
) -> TestResult<auditoad::ScanResult> {
    Ok(scan(ScanRequest {
        baseline,
        snapshot,
        profile: "default",
        source_alias: "bytes",
        limits,
        experimental: true,
        mock,
    })?)
}

fn script(report: &auditoad::schema::Report, probabilities: &[f64]) -> TestResult<MockModel> {
    let mut probabilities = probabilities.iter();
    let mut replies = Vec::new();
    for record in report
        .records
        .iter()
        .filter(|r| matches!(r.evaluator.binding.as_str(), "mock-model" | "model"))
    {
        let probability = probabilities
            .next()
            .ok_or("mock fixture has fewer probabilities than model records")?;
        replies.push(json!({"rule":record.rule.id,"revision":record.rule.revision,
            "instructions_sha256":auditoad::sha256(b"Does this input violate the supplied policy?"),
            "evidence_sha256":record.evidence.as_ref().ok_or("model fixture record has no evidence")?.sha256,
            "response":{"kind":"probability","value":probability}}));
    }
    if probabilities.next().is_some() {
        return Err("mock fixture has more probabilities than model records".into());
    }
    Ok(MockModel::from_bytes(
        json!({"schema":"auditoad-mock-model/1","replies":replies})
            .to_string()
            .as_bytes(),
    )?)
}

fn choice_declaration(root: &std::path::Path) -> TestResult<Value> {
    let mut value = declaration(root, "json/1", "record", "none")?;
    *value
        .pointer_mut("/rules/0/evaluator")
        .ok_or("fixture evaluator is absent")? = json!({"kind":"model","contract":"choice/1"});
    *value
        .pointer_mut("/rules/0/check")
        .ok_or("fixture check is absent")? = json!({"kind":"choice/1",
        "instructions":"What activity does this record describe?",
        "options":{
            "alert":{"description":"The record describes a policy violation.","result":"fail"},
            "ordinary":{"description":"The record describes permitted activity.","result":"pass"},
            "unknown":{"description":"The activity cannot be determined.","result":"review"}},
        "min_choice_probability":0.9,"min_confidence":0.9});
    Ok(value)
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions check decoded-string selection, missing-value refusal and complete tail outcomes"
)]
fn selected_string_predicate_checks_only_decoded_text_and_refuses_missing_values() -> TestResult {
    let dir = directory();
    let mut value = declaration(dir.path(), "json/1", "record", "document")?;
    *value
        .pointer_mut("/rules/0/evaluator")
        .ok_or("fixture evaluator is absent")? =
        json!({"kind":"yara-x","contract":"yara-x/1.20.0"});
    *value
        .pointer_mut("/rules/0/check")
        .ok_or("fixture check is absent")? = json!({"kind":"yara-x/1.20.0",
        "source":"rule excess { strings: $dash = { E2 80 94 } condition: #dash > 1 }",
        "rule_name":"excess","fail_when":"match","json_string_pointer":"/subject/text"});
    let bad = br#"{"subject":{"text":"a \u2014 b \u2014 c"}}"#;
    let good = br#"{"subject":{"text":""},"context":"a \u2014 b \u2014 c"}"#;
    *value
        .pointer_mut("/rules/0/fixtures")
        .ok_or("fixture examples are absent")? = json!({
        "fail":[fixture(dir.path(),"two-dashes.json",bad,bad)],
        "pass":[fixture(dir.path(),"empty-text.json",good,good)]});
    let baseline = validate(&value, dir.path());
    let snapshot = Snapshot::scoped_input(
        br#"[{"text":"a \u2014 b \u2014 c"},{"text":"a \u2014 b"},{"text":"\\u2014 \\u2014"},{"text":""},{},{"text":null},{"text":4}]"#,
        "records.json", &baseline, "default", "bytes", &Limits::default(),
    )?;
    let result = run_scoped(&baseline, &snapshot, Limits::default(), None)?;
    assert_eq!(result.report.usage.provider_calls, 0);
    assert_eq!(result.report.fixture_usage.checks, 2);
    let expected = [
        ResultState::Fail,
        ResultState::Pass,
        ResultState::Pass,
        ResultState::Pass,
        ResultState::NotEvaluated,
        ResultState::NotEvaluated,
        ResultState::NotEvaluated,
    ];
    assert_eq!(
        result
            .report
            .records
            .iter()
            .map(|r| r.result)
            .collect::<Vec<_>>(),
        expected
    );
    let first = result
        .report
        .records
        .first()
        .ok_or("decoded-string record is absent")?;
    assert_eq!(
        first
            .observation
            .as_ref()
            .and_then(|v| v.get("selected_sha256")),
        Some(&json!(auditoad::sha256("a — b — c".as_bytes())))
    );
    assert_eq!(
        first
            .observation
            .as_ref()
            .and_then(|v| v.get("selected_bytes")),
        Some(&json!(13))
    );
    assert!(
        first
            .evidence
            .as_ref()
            .ok_or("decoded-string evidence is absent")?
            .bytes
            .len()
            > 13
    );
    for pointer in ["subject/text", "/subject/~2"] {
        let mut invalid = value.clone();
        *invalid
            .pointer_mut("/rules/0/check/json_string_pointer")
            .ok_or("selection pointer is absent")? = json!(pointer);
        assert!(ValidatedBaseline::from_bytes(invalid.to_string().as_bytes(), dir.path()).is_err());
    }
    let mut mismatched = value.clone();
    mismatched
        .pointer_mut("/rules/0/check")
        .and_then(Value::as_object_mut)
        .ok_or("fixture check is absent")?
        .remove("json_string_pointer");
    assert!(ValidatedBaseline::from_bytes(mismatched.to_string().as_bytes(), dir.path()).is_err());
    let limited = run_scoped(
        &baseline,
        &snapshot,
        Limits {
            checks: 1,
            ..Limits::default()
        },
        None,
    )?;
    assert_eq!(limited.report.records.len(), 7);
    assert!(
        limited
            .report
            .records
            .iter()
            .skip(1)
            .all(|r| r.result == ResultState::NotEvaluated)
    );
    std::fs::write(dir.path().join("empty-text.json"), bad)?;
    assert!(
        scan(ScanRequest {
            baseline: &baseline,
            snapshot: &snapshot,
            profile: "default",
            source_alias: "bytes",
            limits: Limits::default(),
            experimental: true,
            mock: None
        })
        .is_err()
    );
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions check complete shared dependencies without hiding missing facts"
)]
fn exact_json_and_semantic_answers_share_dependencies_without_hiding_missing_facts() -> TestResult {
    let dir = directory();
    let mut value = declaration(dir.path(), "json/1", "record", "none")?;
    let mut semantic = value
        .pointer("/rules/0")
        .ok_or("semantic fixture rule is absent")?
        .clone();
    *semantic
        .get_mut("id")
        .ok_or("semantic rule identity is absent")? = json!("B");
    *value
        .pointer_mut("/rules/0/evaluator")
        .ok_or("fixture evaluator is absent")? =
        json!({"kind":"json-pointer-equals","contract":"json-pointer-equals/1"});
    *value
        .pointer_mut("/rules/0/check")
        .ok_or("fixture check is absent")? = json!({"kind":"json-pointer-equals/1","pointer":"/subject/type","expected":"TXT","fail_when":"equal"});
    let bad = br#"{"subject":{"type":"TXT"}}"#;
    let good = br#"{"subject":{"type":"A"}}"#;
    *value
        .pointer_mut("/rules/0/fixtures")
        .ok_or("fixture examples are absent")? = json!({"fail":[fixture(dir.path(),"txt.json",bad,bad)],
        "pass":[fixture(dir.path(),"a.json",good,good)]});
    value
        .get_mut("rules")
        .and_then(Value::as_array_mut)
        .ok_or("fixture rules are absent")?
        .push(semantic);
    append_combination(&mut value, "BOTH", &["A", "B"], "record", "all_fail")?;
    *value
        .pointer_mut("/rules/2/fixtures")
        .ok_or("combination fixtures are absent")? = json!({"pass":[],"fail":[]});
    append_combination(&mut value, "ANY", &["BOTH"], "document", "any_fail")?;
    *value
        .pointer_mut("/rules/3/fixtures")
        .ok_or("summary fixtures are absent")? = json!({"pass":[],"fail":[]});
    *value
        .pointer_mut("/profiles/0/select")
        .ok_or("profile selection is absent")? = json!(["ANY"]);
    let baseline = validate(&value, dir.path());
    let snapshot = Snapshot::scoped_input(
        b"[{\"type\":\"TXT\"},{\"type\":\"A\"},{}]",
        "events.json",
        &baseline,
        "default",
        "bytes",
        &Limits::default(),
    )?;
    let prepared = run_scoped(&baseline, &snapshot, Limits::default(), None)?;
    let mock = script(&prepared.report, &[0.99, 0.99, 0.01])?;
    let result = run_scoped(&baseline, &snapshot, Limits::default(), Some(&mock))?;
    assert_eq!(result.report.usage.provider_calls, 3);
    assert_eq!(result.report.records.len(), 10);
    for (record, expected) in result.report.records.iter().take(3).zip([
        ResultState::Fail,
        ResultState::Pass,
        ResultState::NotEvaluated,
    ]) {
        assert_eq!(record.result, expected);
    }
    for (record, expected) in result
        .report
        .records
        .iter()
        .skip(6)
        .zip(["fail", "pass", "review", "review"])
    {
        assert_eq!(record.result, ResultState::NotEvaluated);
        assert_eq!(
            record
                .observation
                .as_ref()
                .and_then(|v| v.get("suggested_result")),
            Some(&json!(expected))
        );
    }
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions check choice uncertainty, complete dependencies and provider accounting"
)]
fn choice_preserves_uncertainty_dependencies_and_provider_accounting() -> TestResult {
    let dir = directory();
    let mut value = choice_declaration(dir.path())?;
    append_combination(&mut value, "SUMMARY", &["A"], "document", "any_fail")?;
    *value
        .pointer_mut("/profiles/0/select")
        .ok_or("profile selection is absent")? = json!(["SUMMARY"]);
    let baseline = validate(&value, dir.path());
    let snapshot = Snapshot::scoped_input(
        b"[0,1,2,3,4,5,6]",
        "events.json",
        &baseline,
        "default",
        "bytes",
        &Limits::default(),
    )?;
    let prepared = run_scoped(&baseline, &snapshot, Limits::default(), None)?;
    assert_eq!(prepared.report.usage.provider_calls, 0);
    let mut responses = vec![
        json!({"kind":"choice","choice":"alert","confidence":0.99,
            "probabilities":{"alert":0.99,"ordinary":0.01,"unknown":0.0}}),
        json!({"kind":"choice","choice":"ordinary","confidence":0.99,
            "probabilities":{"alert":0.01,"ordinary":0.99,"unknown":0.0}}),
        json!({"kind":"choice","choice":"unknown","confidence":1.0,
            "probabilities":{"alert":0.0,"ordinary":0.0,"unknown":1.0}}),
        json!({"kind":"choice","choice":"alert","confidence":0.95,
            "probabilities":{"alert":0.85,"ordinary":0.1,"unknown":0.05}}),
        json!({"kind":"choice","choice":"alert","confidence":0.85,
            "probabilities":{"alert":0.99,"ordinary":0.01,"unknown":0.0}}),
        json!({"kind":"choice","choice":"alert","confidence":0.99,
            "probabilities":{"alert":0.99,"foreign":0.01,"unknown":0.0}}),
        json!({"kind":"stale_check"}),
    ]
    .into_iter();
    let mut replies = Vec::new();
    for record in prepared.report.records.iter().filter(|r| r.rule.id == "A") {
        let observation = record
            .observation
            .as_ref()
            .ok_or("choice observation is absent")?;
        let request: Value = serde_json::from_str(&report_text(
            observation
                .get("request_bytes")
                .ok_or("choice request bytes are absent")?,
        ))?;
        let question_id = observation
            .get("question_id")
            .and_then(Value::as_str)
            .ok_or("choice question identity is absent")?;
        let question = request
            .get("questions")
            .and_then(|v| v.get(question_id))
            .ok_or("wire choice question is absent")?;
        assert_eq!(question.get("type"), Some(&json!("choice")));
        assert_eq!(
            question.get("criteria"),
            Some(&json!({
            "alert":"The record describes a policy violation.",
            "ordinary":"The record describes permitted activity.",
            "unknown":"The activity cannot be determined."}))
        );
        assert!(question.get("options").is_none());
        assert!(question.get("min_confidence").is_none());
        replies.push(
            json!({"rule":record.rule.id,"revision":record.rule.revision,
            "instructions_sha256":auditoad::sha256(b"What activity does this record describe?"),
            "evidence_sha256":record.evidence.as_ref().ok_or("choice evidence is absent")?.sha256,
            "response":responses.next().ok_or("choice response fixture is too short")?}),
        );
    }
    assert!(responses.next().is_none());
    let mock = MockModel::from_bytes(
        json!({"schema":"auditoad-mock-model/1","replies":replies})
            .to_string()
            .as_bytes(),
    )?;
    let result = run_scoped(&baseline, &snapshot, Limits::default(), Some(&mock))?;
    assert_eq!(result.report.usage.provider_calls, 7);
    assert_eq!(result.report.records.len(), 8);
    for (record, expected) in result
        .report
        .records
        .iter()
        .zip(["fail", "pass", "review", "review", "review"])
    {
        assert_eq!(record.result, ResultState::NotEvaluated);
        let observation = record
            .observation
            .as_ref()
            .ok_or("answered choice observation is absent")?;
        assert_eq!(observation.get("suggested_result"), Some(&json!(expected)));
        assert!(observation.get("choice").is_some());
        assert!(observation.get("probability").is_none());
    }
    assert_eq!(
        result
            .report
            .records
            .get(5)
            .ok_or("malformed-choice record is absent")?
            .result,
        ResultState::Error
    );
    assert_eq!(
        result
            .report
            .records
            .get(6)
            .ok_or("stale-choice record is absent")?
            .result,
        ResultState::Error
    );
    assert_eq!(
        result
            .report
            .records
            .get(7)
            .and_then(|r| r.observation.as_ref())
            .and_then(|v| v.get("suggested_result")),
        Some(&json!("review"))
    );
    let refused = run_scoped(
        &baseline,
        &snapshot,
        Limits {
            provider_calls: 0,
            ..Limits::default()
        },
        Some(&mock),
    )?;
    assert_eq!(refused.report.usage.provider_calls, 0);
    assert!(
        refused
            .report
            .records
            .iter()
            .all(|r| r.result == ResultState::NotEvaluated)
    );
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions distinguish typed frozen operands and preserve missing-operand uncertainty"
)]
fn json_comparison_uses_both_frozen_values_and_keeps_missing_operands_unresolved() -> TestResult {
    let dir = directory();
    let mut value = declaration(dir.path(), "json/1", "record", "none")?;
    *value
        .pointer_mut("/rules/0/evaluator")
        .ok_or("fixture evaluator is absent")? =
        json!({"kind":"json-pointer-compare","contract":"json-pointer-compare/1"});
    *value
        .pointer_mut("/rules/0/check")
        .ok_or("fixture check is absent")? = json!({"kind":"json-pointer-compare/1",
        "left":"/subject/current", "right":"/subject/recorded", "fail_when":"unequal"});
    let good = br#"{"subject":{"current":"source-a","recorded":"source-a"}}"#;
    let bad = br#"{"subject":{"current":"source-b","recorded":"source-a"}}"#;
    *value
        .pointer_mut("/rules/0/fixtures")
        .ok_or("fixture examples are absent")? = json!({
        "pass":[fixture(dir.path(),"equal.json",good,good)],
        "fail":[fixture(dir.path(),"different.json",bad,bad)]});
    append_combination(&mut value, "SUMMARY", &["A"], "document", "any_fail")?;
    *value
        .pointer_mut("/rules/1/fixtures")
        .ok_or("summary fixtures are absent")? = json!({"pass":[],"fail":[]});
    let baseline = validate(&value, dir.path());
    let input = br#"[
        {"current":"source-a","recorded":"source-a"},
        {"current":"source-b","recorded":"source-a"},
        {"current":"1","recorded":1},
        {"current":{"a":1,"b":2},"recorded":{"b":2,"a":1}},
        {"current":[1,2],"recorded":[2,1]},
        {"current":null,"recorded":null},
        {"current":null},
        {"recorded":null},
        {},
        {"current":1,"recorded":1.0}
    ]"#;
    let snapshot = Snapshot::scoped_input(
        input,
        "receipts.json",
        &baseline,
        "default",
        "bytes",
        &Limits::default(),
    )?;
    let result = run_scoped(&baseline, &snapshot, Limits::default(), None)?;
    use ResultState::{Fail, NotEvaluated, Pass};
    assert_eq!(result.report.usage.provider_calls, 0);
    assert_eq!(
        result
            .report
            .records
            .iter()
            .map(|r| r.result)
            .collect::<Vec<_>>(),
        [
            Pass,
            Fail,
            Fail,
            Pass,
            Fail,
            Pass,
            NotEvaluated,
            NotEvaluated,
            NotEvaluated,
            Fail,
            NotEvaluated
        ]
    );
    let changed = result
        .report
        .records
        .get(1)
        .and_then(|r| r.observation.as_ref())
        .ok_or("changed operands observation is absent")?;
    for (field, expected) in [
        ("left_pointer", "/subject/current"),
        ("right_pointer", "/subject/recorded"),
        ("left", "source-b"),
        ("right", "source-a"),
    ] {
        assert_eq!(changed.get(field), Some(&json!(expected)), "{field}");
    }
    assert_eq!(
        result
            .report
            .records
            .get(10)
            .and_then(|r| r.observation.as_ref())
            .and_then(|v| v.get("suggested_result")),
        Some(&json!("review"))
    );

    for pointer in ["", "subject/current", "/subject/~2invalid"] {
        for field in ["left", "right"] {
            let mut invalid = value.clone();
            *invalid
                .pointer_mut("/rules/0/check")
                .and_then(|v| v.get_mut(field))
                .ok_or_else(|| format!("operand pointer {field} is absent"))? = json!(pointer);
            assert!(
                ValidatedBaseline::from_bytes(invalid.to_string().as_bytes(), dir.path()).is_err()
            );
        }
    }
    let mut wrong_contract = value.clone();
    *wrong_contract
        .pointer_mut("/rules/0/evaluator/contract")
        .ok_or("comparison contract is absent")? = json!("json-pointer-equals/1");
    assert!(
        ValidatedBaseline::from_bytes(wrong_contract.to_string().as_bytes(), dir.path()).is_err()
    );

    *value
        .pointer_mut("/rules/0/check/fail_when")
        .ok_or("comparison decision policy is absent")? = json!("equal");
    *value
        .pointer_mut("/rules/0/fixtures")
        .ok_or("comparison fixtures are absent")? = json!({
        "fail":[fixture(dir.path(),"equal.json",good,good)],
        "pass":[fixture(dir.path(),"different.json",bad,bad)]});
    let inverse = validate(&value, dir.path());
    let inverse_snapshot = Snapshot::scoped_input(
        input,
        "receipts.json",
        &inverse,
        "default",
        "bytes",
        &Limits::default(),
    )?;
    let inverse_result = run_scoped(&inverse, &inverse_snapshot, Limits::default(), None)?;
    for (position, expected) in [(0, Fail), (1, Pass), (6, NotEvaluated)] {
        assert_eq!(
            inverse_result
                .report
                .records
                .get(position)
                .ok_or("inverse comparison record is absent")?
                .result,
            expected
        );
    }
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions check complete typed membership and prohibit missing-operand defaults"
)]
fn json_membership_checks_all_elements_without_coercion_or_missing_defaults() -> TestResult {
    let dir = directory();
    let mut value = declaration(dir.path(), "json/1", "record", "none")?;
    *value
        .pointer_mut("/rules/0/evaluator")
        .ok_or("fixture evaluator is absent")? =
        json!({"kind":"json-pointer-contains","contract":"json-pointer-contains/1"});
    *value
        .pointer_mut("/rules/0/check")
        .ok_or("fixture check is absent")? = json!({"kind":"json-pointer-contains/1",
        "array_pointer":"/subject/members", "value_pointer":"/subject/needle", "fail_when":false});
    let present = br#"{"subject":{"members":["A","B"],"needle":"B"}}"#;
    let absent = br#"{"subject":{"members":["A"],"needle":"B"}}"#;
    *value
        .pointer_mut("/rules/0/fixtures")
        .ok_or("fixture examples are absent")? = json!({
        "pass":[fixture(dir.path(),"present.json",present,present)],
        "fail":[fixture(dir.path(),"absent.json",absent,absent)]});
    append_combination(&mut value, "SUMMARY", &["A"], "document", "any_fail")?;
    *value
        .pointer_mut("/rules/1/fixtures")
        .ok_or("summary fixtures are absent")? = json!({"pass":[],"fail":[]});
    let baseline = validate(&value, dir.path());
    let input = br#"[
        {"members":["A","B"],"needle":"B"},
        {"members":["B","A","B"],"needle":"B"},
        {"members":[],"needle":"B"},
        {"members":["B2"],"needle":"B"},
        {"members":[1],"needle":"1"},
        {"members":[null],"needle":null},
        {"members":[{"a":1,"b":2}],"needle":{"b":2,"a":1}},
        {"members":[[1,2]],"needle":[2,1]},
        {"members":[1.0],"needle":1},
        {"members":["B"]},
        {"needle":"B"},
        {"members":"B","needle":"B"},
        {"members":null,"needle":null}
    ]"#;
    let snapshot = Snapshot::scoped_input(
        input,
        "membership.json",
        &baseline,
        "default",
        "bytes",
        &Limits::default(),
    )?;
    let result = run_scoped(&baseline, &snapshot, Limits::default(), None)?;
    use ResultState::{Fail, NotEvaluated, Pass};
    assert_eq!(result.report.usage.provider_calls, 0);
    assert_eq!(
        result
            .report
            .records
            .iter()
            .map(|record| record.result)
            .collect::<Vec<_>>(),
        [
            Pass,
            Pass,
            Fail,
            Fail,
            Fail,
            Pass,
            Pass,
            Fail,
            Fail,
            NotEvaluated,
            NotEvaluated,
            NotEvaluated,
            NotEvaluated,
            NotEvaluated
        ]
    );
    let observation = result
        .report
        .records
        .first()
        .and_then(|r| r.observation.as_ref())
        .ok_or("membership observation is absent")?;
    for (field, expected) in [
        ("type", json!("json-pointer-contains/1")),
        ("array_pointer", json!("/subject/members")),
        ("value_pointer", json!("/subject/needle")),
        ("operand", json!("B")),
        ("value", json!(true)),
    ] {
        assert_eq!(observation.get(field), Some(&expected), "{field}");
    }
    assert_eq!(
        result
            .report
            .records
            .get(13)
            .and_then(|r| r.observation.as_ref())
            .and_then(|v| v.get("suggested_result")),
        Some(&json!("review"))
    );
    for pointer in ["", "subject/members", "/subject/~2invalid"] {
        for field in ["array_pointer", "value_pointer"] {
            let mut invalid = value.clone();
            *invalid
                .pointer_mut("/rules/0/check")
                .and_then(|v| v.get_mut(field))
                .ok_or_else(|| format!("membership pointer {field} is absent"))? = json!(pointer);
            assert!(
                ValidatedBaseline::from_bytes(invalid.to_string().as_bytes(), dir.path()).is_err()
            );
        }
    }
    let mut wrong_contract = value.clone();
    *wrong_contract
        .pointer_mut("/rules/0/evaluator/contract")
        .ok_or("membership contract is absent")? = json!("json-pointer-compare/1");
    assert!(
        ValidatedBaseline::from_bytes(wrong_contract.to_string().as_bytes(), dir.path()).is_err()
    );
    *value
        .pointer_mut("/rules/0/check/fail_when")
        .ok_or("membership decision policy is absent")? = json!(true);
    *value
        .pointer_mut("/rules/0/fixtures")
        .ok_or("membership fixtures are absent")? = json!({
        "fail":[fixture(dir.path(),"present.json",present,present)],
        "pass":[fixture(dir.path(),"absent.json",absent,absent)]});
    let inverse = validate(&value, dir.path());
    let inverse_snapshot = Snapshot::scoped_input(
        input,
        "membership.json",
        &inverse,
        "default",
        "bytes",
        &Limits::default(),
    )?;
    let inverse_result = run_scoped(&inverse, &inverse_snapshot, Limits::default(), None)?;
    for (position, expected) in [(0, Fail), (2, Pass), (9, NotEvaluated)] {
        assert_eq!(
            inverse_result
                .report
                .records
                .get(position)
                .ok_or("inverse membership record is absent")?
                .result,
            expected
        );
    }
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions require an explicit unknown choice and a valid evaluator contract"
)]
fn choice_declarations_require_an_explicit_unknown_and_valid_contract() -> TestResult {
    let dir = directory();
    let original = choice_declaration(dir.path())?;
    for (pointer, replacement) in [
        ("/rules/0/check/options/unknown/result", json!("pass")),
        ("/rules/0/check/options/ordinary/result", json!("error")),
        ("/rules/0/check/min_choice_probability", json!(-0.01)),
        ("/rules/0/check/min_confidence", json!(1.01)),
        (
            "/rules/0/check/options",
            json!({"unknown":{"description":"Unclear.","result":"review"}}),
        ),
        ("/rules/0/check/options/alert/description", json!("")),
        ("/rules/0/evaluator/contract", json!("yes-no/1")),
        ("/rules/0/evaluator/kind", json!("jev")),
        ("/baseline/status", json!("admitted")),
    ] {
        let mut value = original.clone();
        *value
            .pointer_mut(pointer)
            .ok_or_else(|| format!("choice mutation field {pointer} is absent"))? = replacement;
        assert!(
            ValidatedBaseline::from_bytes(value.to_string().as_bytes(), dir.path()).is_err(),
            "{pointer}"
        );
    }
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions check exact wire projection and zero dispatch when required evidence is missing"
)]
fn state_projection_controls_wire_fields_and_refuses_missing_evidence() -> TestResult {
    let dir = directory();
    for field in [
        json!("/subject/message"),
        json!({"pointer":"/subject/message","optional":true}),
    ] {
        let parsed: auditoad::schema::StateField = serde_json::from_value(field.clone())?;
        assert_eq!(serde_json::to_value(parsed)?, field);
    }
    let mut value = declaration(dir.path(), "json/1", "document", "none")?;
    let frame = br#"{"message":"Review the record.","a/b":{"~key":null},"unused":"not selected"}"#;
    for mut check in [
        json!({"kind":"yes-no/1","instructions":"Does message request a review?",
               "criteria_true":"It requests a review.","criteria_false":"It does not request a review.",
               "pass_below":0.1,"fail_at_or_above":0.9}),
        json!({"kind":"choice/1","instructions":"Does message request a review?",
               "options":{"yes":{"description":"It requests a review.","result":"fail"},
                          "no":{"description":"It does not request a review.","result":"pass"},
                          "unknown":{"description":"The message cannot be understood.","result":"review"}},
               "min_choice_probability":0.9,"min_confidence":0.9}),
        json!({"kind":"extract/1","instructions":"Copy the message.",
               "fields":{"message":{"type":"quote","description":"The exact message."}}}),
    ] {
        *value
            .pointer_mut("/rules/0/evaluator")
            .ok_or("fixture evaluator is absent")? = json!({"kind":"model","contract":check.get("kind").ok_or("projection fixture contract is absent")?});
        check
            .as_object_mut()
            .ok_or("projection check is not an object")?
            .insert(
                "state_projection".into(),
                json!({"message":"/subject/message","optional":"/subject/a~1b/~0key"}),
            );
        *value
            .pointer_mut("/rules/0/check")
            .ok_or("fixture check is absent")? = check;
        let baseline = validate(&value, dir.path());
        assert!(
            serde_json::to_value(
                &baseline
                    .baseline()
                    .rules
                    .first()
                    .ok_or("projection rule is absent")?
                    .check
            )?
            .get("state_required_any")
            .is_none()
        );
        let mut empty_groups = value.clone();
        empty_groups
            .pointer_mut("/rules/0/check")
            .and_then(Value::as_object_mut)
            .ok_or("empty-group check is absent")?
            .insert("state_required_any".into(), json!([]));
        let empty_groups = validate(&empty_groups, dir.path());
        assert_eq!(
            serde_json::to_value(
                &empty_groups
                    .baseline()
                    .rules
                    .first()
                    .ok_or("empty-group rule is absent")?
                    .check
            )?,
            serde_json::to_value(
                &baseline
                    .baseline()
                    .rules
                    .first()
                    .ok_or("projection rule is absent")?
                    .check
            )?
        );
        let snapshot = Snapshot::scoped_input(
            frame,
            "input.json",
            &baseline,
            "default",
            "bytes",
            &Limits::default(),
        )?;
        let result = run_scoped(&baseline, &snapshot, Limits::default(), None)?;
        let [record] = result.report.records.as_slice() else {
            return Err("expected one state projection record".into());
        };
        let wire: Value = serde_json::from_str(&report_text(
            record
                .observation
                .as_ref()
                .and_then(|v| v.get("request_bytes"))
                .ok_or("projected request bytes are absent")?,
        ))?;
        assert_eq!(
            wire.get("state"),
            Some(&json!({"message":"Review the record.","optional":null}))
        );
        let retained: Value = serde_json::from_slice(
            &record
                .evidence
                .as_ref()
                .ok_or("projection evidence is absent")?
                .bytes,
        )?;
        assert_eq!(
            retained.pointer("/subject/unused"),
            Some(&json!("not selected"))
        );
        assert_eq!(result.report.usage.provider_calls, 0);

        let mock = MockModel::from_bytes(br#"{"schema":"auditoad-mock-model/1","replies":[]}"#)?;
        for projection in [
            json!({"missing":"/subject/absent"}),
            json!({"first":"/subject/message","second":"/subject/message","third":"/subject/message"}),
        ] {
            let mut refused = value.clone();
            let check = refused
                .pointer_mut("/rules/0/check")
                .and_then(Value::as_object_mut)
                .ok_or("refused projection check is absent")?;
            check.insert("state_projection".into(), projection);
            check.insert("max_request_bytes".into(), json!(64));
            let baseline = validate(&refused, dir.path());
            let snapshot = Snapshot::scoped_input(
                frame,
                "input.json",
                &baseline,
                "default",
                "bytes",
                &Limits::default(),
            )?;
            let result = run_scoped(&baseline, &snapshot, Limits::default(), Some(&mock))?;
            let [record] = result.report.records.as_slice() else {
                return Err("expected one refused projection record".into());
            };
            assert_eq!(record.result, ResultState::NotEvaluated);
            assert!(record.observation.is_none());
            assert!(record.evidence.is_some());
            assert!(
                record
                    .reason
                    .as_deref()
                    .is_some_and(|reason| reason.contains("required state field")
                        || reason.contains("state projection exceeds"))
            );
            assert_eq!(result.report.usage.provider_calls, 0);
        }
        for invalid in [
            json!({}),
            json!({" ":"/subject"}),
            json!({"value":"subject"}),
            json!({"value":"/bad~2escape"}),
        ] {
            let mut refused = value.clone();
            *refused
                .pointer_mut("/rules/0/check/state_projection")
                .ok_or("state projection is absent")? = invalid;
            assert!(
                ValidatedBaseline::from_bytes(refused.to_string().as_bytes(), dir.path()).is_err()
            );
        }

        let mut alternatives = value.clone();
        let alternative_check = alternatives
            .pointer_mut("/rules/0/check")
            .and_then(Value::as_object_mut)
            .ok_or("alternative projection check is absent")?;
        alternative_check.insert(
            "state_projection".into(),
            json!({
                "code_a":{"pointer":"/subject/code_a","optional":true},
                "code_b":{"pointer":"/subject/code_b","optional":true},
                "imports":{"pointer":"/subject/imports","optional":true}
            }),
        );
        alternative_check.insert("state_required_any".into(), json!([["code_a", "code_b"]]));
        let baseline = validate(&alternatives, dir.path());
        for frame in [
            json!({"code_a":"def first(): pass","imports":"import json"}),
            json!({"code_b":"def second(): pass"}),
            json!({"code_a":null,"code_b":"def second(): pass"}),
            json!({"code_a":false,"code_b":null}),
            json!({"code_a":"","code_b":null}),
            json!({"code_a":[],"code_b":null}),
        ] {
            let snapshot = Snapshot::scoped_input(
                frame.to_string().as_bytes(),
                "alternatives.json",
                &baseline,
                "default",
                "bytes",
                &Limits::default(),
            )?;
            let result = run_scoped(&baseline, &snapshot, Limits::default(), None)?;
            let record = result
                .report
                .records
                .first()
                .ok_or("alternative record is absent")?;
            let wire: Value = serde_json::from_str(&report_text(
                record
                    .observation
                    .as_ref()
                    .and_then(|v| v.get("request_bytes"))
                    .ok_or("alternative request was refused")?,
            ))?;
            for name in ["code_a", "code_b", "imports"] {
                assert_eq!(
                    wire.pointer(&format!("/state/{name}")),
                    Some(frame.get(name).unwrap_or(&Value::Null))
                );
            }
        }
        for frame in [
            json!({}),
            json!({"code_a":null,"code_b":null}),
            json!({"imports":"import json"}),
        ] {
            let snapshot = Snapshot::scoped_input(
                frame.to_string().as_bytes(),
                "absent-alternatives.json",
                &baseline,
                "default",
                "bytes",
                &Limits::default(),
            )?;
            let result = run_scoped(&baseline, &snapshot, Limits::default(), Some(&mock))?;
            let record = result
                .report
                .records
                .first()
                .ok_or("refused alternative record is absent")?;
            assert_eq!(record.result, ResultState::NotEvaluated);
            assert!(record.observation.is_none());
            assert!(record.evidence.is_some());
            assert!(
                record
                    .reason
                    .as_deref()
                    .is_some_and(|reason| reason.contains("required state alternative group"))
            );
            assert_eq!(result.report.usage.provider_calls, 0);
        }
        for (groups, projection) in [
            (json!([[]]), true),
            (json!([["unknown"]]), true),
            (json!([["code_a", "unknown"]]), true),
            (json!([["code_a"]]), false),
        ] {
            let mut invalid = alternatives.clone();
            let check = invalid
                .pointer_mut("/rules/0/check")
                .and_then(Value::as_object_mut)
                .ok_or("invalid alternative check is absent")?;
            check.insert("state_required_any".into(), groups);
            if !projection {
                check.remove("state_projection");
            }
            assert!(
                ValidatedBaseline::from_bytes(invalid.to_string().as_bytes(), dir.path()).is_err()
            );
        }
        *alternatives
            .pointer_mut("/rules/0/check/state_required_any")
            .ok_or("required alternative groups are absent")? =
            json!([["code_a", "code_b"], ["imports"]]);
        let baseline = validate(&alternatives, dir.path());
        let snapshot = Snapshot::scoped_input(
            br#"{"code_a":"def first(): pass"}"#,
            "missing-second-group.json",
            &baseline,
            "default",
            "bytes",
            &Limits::default(),
        )?;
        let result = run_scoped(&baseline, &snapshot, Limits::default(), Some(&mock))?;
        assert!(
            result
                .report
                .records
                .first()
                .and_then(|record| record.reason.as_deref())
                .is_some_and(|reason| reason.contains("required state alternative group"))
        );
        assert_eq!(result.report.usage.provider_calls, 0);

        let mut capture_selection = value.clone();
        let check = capture_selection
            .pointer_mut("/rules/0/check")
            .and_then(Value::as_object_mut)
            .ok_or("capture projection check is absent")?;
        check.insert(
            "state_projection".into(),
            json!({
                "code_a":{"pointer":"/subject/left","capture":"function","optional":true},
                "code_b":{"pointer":"/subject/right","capture":"function","optional":true}
            }),
        );
        check.insert("state_required_any".into(), json!([["code_a", "code_b"]]));
        let baseline = validate(&capture_selection, dir.path());
        for frame in [
            json!({"left":[{"capture":"imports","text":"import json"},{"capture":"function","text":"def first(): pass"}]}),
            json!({"left":[{"capture":"function","text":"def first(): pass"},{"capture":"imports","text":"import json"}]}),
            json!({"left":[],"right":[{"capture":"function","text":"def second(): pass"}]}),
        ] {
            let snapshot = Snapshot::scoped_input(
                frame.to_string().as_bytes(),
                "captures.json",
                &baseline,
                "default",
                "bytes",
                &Limits::default(),
            )?;
            let result = run_scoped(&baseline, &snapshot, Limits::default(), None)?;
            let record = result
                .report
                .records
                .first()
                .ok_or("capture projection record is absent")?;
            let wire: Value = serde_json::from_str(&report_text(
                record
                    .observation
                    .as_ref()
                    .and_then(|observation| observation.get("request_bytes"))
                    .ok_or("named capture request is absent")?,
            ))?;
            if frame.pointer("/left/0/capture") == Some(&json!("function"))
                || frame.pointer("/left/1/capture") == Some(&json!("function"))
            {
                assert_eq!(
                    wire.pointer("/state/code_a"),
                    Some(&json!("def first(): pass"))
                );
                assert_eq!(wire.pointer("/state/code_b"), Some(&Value::Null));
            } else {
                assert_eq!(wire.pointer("/state/code_a"), Some(&Value::Null));
                assert_eq!(
                    wire.pointer("/state/code_b"),
                    Some(&json!("def second(): pass"))
                );
            }
            assert!(
                !report_text(
                    record
                        .observation
                        .as_ref()
                        .and_then(|observation| observation.get("request_bytes"))
                        .ok_or("named capture request is absent")?
                )
                .contains("import json")
            );
        }
        for (frame, reason) in [
            (
                json!({"left":[{"capture":"imports","text":"import json"},{"capture":"imports","text":"import os"}]}),
                "required state alternative group",
            ),
            (
                json!({"left":[{"capture":"function","text":"def first(): pass"},{"capture":"function","text":"def duplicate(): pass"}]}),
                "multiple syntax captures",
            ),
            (
                json!({"left":[{"capture":"function","text":null}]}),
                "lacks nonempty string text",
            ),
            (
                json!({"left":[{"capture":"function","text":17}]}),
                "lacks nonempty string text",
            ),
            (
                json!({"left":[{"capture":"function","text":""}]}),
                "lacks nonempty string text",
            ),
            (
                json!({"left":[{"capture":"function"}]}),
                "lacks nonempty string text",
            ),
            (json!({"left":null}), "requires a syntax capture array"),
            (
                json!({"left":"not an array"}),
                "requires a syntax capture array",
            ),
            (
                json!({"left":[],"right":[]}),
                "required state alternative group",
            ),
        ] {
            let snapshot = Snapshot::scoped_input(
                frame.to_string().as_bytes(),
                "invalid-captures.json",
                &baseline,
                "default",
                "bytes",
                &Limits::default(),
            )?;
            let result = run_scoped(&baseline, &snapshot, Limits::default(), Some(&mock))?;
            let record = result
                .report
                .records
                .first()
                .ok_or("refused capture projection record is absent")?;
            assert_eq!(record.result, ResultState::NotEvaluated);
            assert!(record.observation.is_none());
            assert!(
                record
                    .reason
                    .as_deref()
                    .is_some_and(|actual| actual.contains(reason))
            );
            assert_eq!(result.report.usage.provider_calls, 0);
        }
        for field in [
            json!({"pointer":"/subject/left","capture":"","optional":true}),
            json!({"pointer":"/subject/left","capture":" ","optional":true}),
            json!({"pointer":"/subject/left","capture":null,"optional":true}),
            json!({"pointer":"/subject/left","capture":17,"optional":true}),
            json!({"pointer":"/subject/left","captuer":"function","optional":true}),
            json!({"pointer":"/subject/left","capture":"function","optional":true,"extra":true}),
        ] {
            let mut invalid = capture_selection.clone();
            *invalid
                .pointer_mut("/rules/0/check/state_projection/code_a")
                .ok_or("invalid capture selector is absent")? = field;
            assert!(
                ValidatedBaseline::from_bytes(invalid.to_string().as_bytes(), dir.path()).is_err()
            );
        }
        *capture_selection
            .pointer_mut("/rules/0/check/state_projection/code_a/optional")
            .ok_or("required capture optionality is absent")? = json!(false);
        let baseline = validate(&capture_selection, dir.path());
        let snapshot = Snapshot::scoped_input(
            br#"{"left":[]}"#,
            "required-capture.json",
            &baseline,
            "default",
            "bytes",
            &Limits::default(),
        )?;
        let result = run_scoped(&baseline, &snapshot, Limits::default(), Some(&mock))?;
        assert!(
            result
                .report
                .records
                .first()
                .and_then(|record| record.reason.as_deref())
                .is_some_and(|reason| reason.contains("required state field"))
        );
        assert_eq!(result.report.usage.provider_calls, 0);
    }
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions check every paragraph's exact byte span and complete input context"
)]
fn text_scope_discovers_every_paragraph_and_retains_complete_context() -> TestResult {
    let dir = directory();
    let value = declaration(dir.path(), "text/1", "paragraph", "document")?;
    let baseline = validate(&value, dir.path());
    for input in [
        "First.\r\nStill first.\r\n \t\r\nUnicode café.\r\n\r\nLast.",
        "Last.\n\nFirst.\nStill first.\n\nUnicode café.",
    ] {
        let snapshot = Snapshot::scoped_input(
            input.as_bytes(),
            "notes.txt",
            &baseline,
            "default",
            "bytes",
            &Limits::default(),
        )?;
        let result = run_scoped(&baseline, &snapshot, Limits::default(), None)?;
        assert_eq!(result.report.records.len(), 3);
        for record in &result.report.records {
            let evidence: Value = serde_json::from_slice(
                &record
                    .evidence
                    .as_ref()
                    .ok_or("paragraph evidence is absent")?
                    .bytes,
            )?;
            assert_eq!(evidence.get("context"), Some(&json!(input)));
            let location = record
                .target
                .metadata
                .get("location")
                .ok_or("paragraph location is absent")?;
            let start = usize::try_from(
                location
                    .get("byte_start")
                    .and_then(Value::as_u64)
                    .ok_or("paragraph start is absent")?,
            )?;
            let end = usize::try_from(
                location
                    .get("byte_end")
                    .and_then(Value::as_u64)
                    .ok_or("paragraph end is absent")?,
            )?;
            assert_eq!(
                evidence.get("subject"),
                Some(&json!(
                    input
                        .get(start..end)
                        .ok_or("paragraph location is not a valid UTF-8 span")?
                ))
            );
        }
        assert_eq!(result.report.usage.provider_calls, 0);
    }
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions check Unicode sentence byte spans, full context and complete scope refusal"
)]
fn sentence_scope_uses_unicode_byte_ranges_and_complete_context() -> TestResult {
    let dir = directory();
    let value = declaration(dir.path(), "text/1", "sentence", "document")?;
    let baseline = validate(&value, dir.path());
    let input = "  Ålpha waits. Then it runs.\r\nNext line!\n";
    let snapshot = Snapshot::scoped_input(
        input.as_bytes(),
        "prose.txt",
        &baseline,
        "default",
        "bytes",
        &Limits::default(),
    )?;
    let report = run_scoped(&baseline, &snapshot, Limits::default(), None)?.report;
    assert_eq!(report.records.len(), 3);
    for (record, expected) in
        report
            .records
            .iter()
            .zip(["Ålpha waits.", "Then it runs.", "Next line!"])
    {
        let frame: Value = serde_json::from_slice(
            &record
                .evidence
                .as_ref()
                .ok_or("sentence evidence is absent")?
                .bytes,
        )?;
        assert_eq!(frame.get("subject"), Some(&json!(expected)));
        assert_eq!(frame.get("context"), Some(&json!(input)));
        let location = record
            .target
            .metadata
            .get("location")
            .ok_or("sentence location is absent")?;
        let start = usize::try_from(
            location
                .get("byte_start")
                .and_then(Value::as_u64)
                .ok_or("sentence start is absent")?,
        )?;
        let end = usize::try_from(
            location
                .get("byte_end")
                .and_then(Value::as_u64)
                .ok_or("sentence end is absent")?,
        )?;
        assert_eq!(
            input
                .get(start..end)
                .ok_or("sentence location is not a valid UTF-8 span")?,
            expected
        );
    }
    assert!(
        Snapshot::scoped_input(
            input.as_bytes(),
            "prose.txt",
            &baseline,
            "default",
            "bytes",
            &Limits {
                targets: 2,
                ..Limits::default()
            }
        )
        .is_err()
    );
    let empty = Snapshot::scoped_input(
        b" \r\n",
        "prose.txt",
        &baseline,
        "default",
        "bytes",
        &Limits::default(),
    )?;
    let report = run_scoped(&baseline, &empty, Limits::default(), None)?.report;
    let [record] = report.records.as_slice() else {
        return Err("expected one empty-sentence error record".into());
    };
    assert_eq!(record.result, ResultState::Error);
    assert_eq!(report.usage.provider_calls, 0);
    let mut invalid = value;
    *invalid
        .pointer_mut("/sources/bytes")
        .ok_or("source declaration is absent")? =
        json!({"adapter":"json/1","media":["application/json"]});
    assert!(ValidatedBaseline::from_bytes(invalid.to_string().as_bytes(), dir.path()).is_err());
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions check separate packet answers and preserve unavailable child outcomes"
)]
fn bundle_answers_keep_packets_separate_and_preserve_unavailable_children() -> TestResult {
    let dir = directory();
    let mut value = declaration(dir.path(), "evidence-bundle/1", "document", "none")?;
    for (pointer, replacement) in [
        (
            "/sources/bytes/media",
            json!(["application/vnd.auditoad.bundle+json"]),
        ),
        (
            "/evidence/bytes",
            json!({"builder":"declared-parts/1","builder_revision":"r1","required_roles":["subject"]}),
        ),
        ("/rules/0/scope", Value::Null),
        ("/rules/0/scope_kind", json!("site")),
        (
            "/rules/0/evaluator",
            json!({"kind":"model","contract":"yes-no/1"}),
        ),
    ] {
        *value
            .pointer_mut(pointer)
            .ok_or_else(|| format!("bundle fixture field {pointer} is absent"))? = replacement;
    }
    *value
        .pointer_mut("/rules/0/check")
        .ok_or("fixture check is absent")? = json!({"kind":"yes-no/1",
        "instructions":"Does this input violate the supplied policy?",
        "criteria_true":"The input violates the policy.","criteria_false":"The input follows the policy.",
        "pass_below":0.1,"fail_at_or_above":0.9});
    let mut second = value
        .pointer("/rules/0")
        .ok_or("fixture rule is absent")?
        .clone();
    *second
        .get_mut("id")
        .ok_or("second rule identity is absent")? = json!("B");
    value
        .get_mut("rules")
        .and_then(Value::as_array_mut)
        .ok_or("fixture rules are absent")?
        .push(second);
    append_combination(&mut value, "SUMMARY", &["A", "B"], "document", "any_fail")?;
    *value
        .pointer_mut("/rules/2/scope")
        .ok_or("summary scope is absent")? = Value::Null;
    *value
        .pointer_mut("/rules/2/scope_kind")
        .ok_or("summary scope kind is absent")? = json!("site");
    let baseline = validate(&value, dir.path());
    let first = "First function.\n";
    let second = "Second function.\n";
    std::fs::write(dir.path().join("code-a.txt"), first)?;
    std::fs::write(dir.path().join("code-b.txt"), second)?;
    let manifest = json!({"schema":"auditoad-evidence-bundle/1",
        "files":{"code-a.txt":auditoad::sha256(first.as_bytes()),
            "code-b.txt":auditoad::sha256(second.as_bytes())},"packets":[
        {"id":"a","kind":"code","scope_kind":"site","parts":[{"role":"subject","path":"code-a.txt"}]},
        {"id":"b","kind":"code","scope_kind":"site","parts":[{"role":"subject","path":"code-b.txt"}]}
    ]});
    let path = dir.path().join("bundle.json");
    std::fs::write(&path, manifest.to_string())?;
    let snapshot = Snapshot::scoped_bundle(
        &path,
        dir.path(),
        &baseline,
        "default",
        "bytes",
        &Limits::default(),
    )?;
    let prepared = run_scoped(&baseline, &snapshot, Limits::default(), None)?;
    assert_eq!(prepared.report.records.len(), 6);
    let mock = script(&prepared.report, &[0.99, 0.01, 0.01, 0.01])?;
    let result = run_scoped(&baseline, &snapshot, Limits::default(), Some(&mock))?;
    assert_eq!(result.report.records.len(), 6);
    assert_eq!(result.report.usage.provider_calls, 4);
    for (record, expected) in result.report.records.iter().skip(4).zip(["fail", "pass"]) {
        assert_eq!(record.result, ResultState::NotEvaluated);
        assert_eq!(
            record
                .observation
                .as_ref()
                .and_then(|v| v.get("suggested_result")),
            Some(&json!(expected))
        );
        let evidence: Value = serde_json::from_slice(
            &record
                .evidence
                .as_ref()
                .ok_or("packet answer evidence is absent")?
                .bytes,
        )?;
        let answers = evidence
            .get("answers")
            .and_then(Value::as_array)
            .ok_or("packet child answers are absent")?;
        assert_eq!(answers.len(), 2);
        assert!(
            answers
                .iter()
                .all(|a| a.get("target") == Some(&json!(record.target.id)))
        );
    }
    let limits = Limits {
        provider_calls: 1,
        ..Limits::default()
    };
    let partial = run_scoped(&baseline, &snapshot, limits.clone(), Some(&mock))?;
    assert_eq!(partial.report.records.len(), 6);
    assert!(partial.report.records.iter().skip(4).all(|r| {
        r.observation
            .as_ref()
            .and_then(|v| v.get("suggested_result"))
            == Some(&json!("review"))
    }));
    value
        .pointer_mut("/rules/2/check")
        .and_then(Value::as_object_mut)
        .ok_or("summary check is absent")?
        .insert("resolution".into(), json!("decisive"));
    let decisive = validate(&value, dir.path());
    let partial = run_scoped(&decisive, &snapshot, limits, Some(&mock))?;
    for (position, field, expected) in [
        (4, "suggested_result", json!("fail")),
        (4, "unresolved", json!(1)),
        (5, "suggested_result", json!("review")),
    ] {
        assert_eq!(
            partial
                .report
                .records
                .get(position)
                .and_then(|r| r.observation.as_ref())
                .and_then(|v| v.get(field)),
            Some(&expected)
        );
    }
    for (key, replacement) in [
        ("scope_kind", json!("whole")),
        ("scope", json!({"unit":"document","context":"none"})),
    ] {
        let mut invalid = value.clone();
        *invalid
            .pointer_mut("/rules/2")
            .and_then(|v| v.get_mut(key))
            .ok_or_else(|| format!("summary field {key} is absent"))? = replacement;
        assert!(ValidatedBaseline::from_bytes(invalid.to_string().as_bytes(), dir.path()).is_err());
    }
    for path in ["code-a.txt", "code-b.txt"] {
        std::fs::write(dir.path().join(path), "Changed.\n")?;
    }
    let stale = run_scoped(&baseline, &snapshot, Limits::default(), Some(&mock))?;
    assert_eq!(stale.report.records.len(), 6);
    assert_eq!(stale.report.usage.provider_calls, 0);
    assert!(
        stale
            .report
            .records
            .iter()
            .all(|r| r.result == ResultState::Error)
    );
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions check legacy evidence, complete sentences and independent packet custody"
)]
fn bundle_sentence_scope_preserves_legacy_evidence_and_separates_documents() -> TestResult {
    let dir = directory();
    let mut value = declaration(dir.path(), "evidence-bundle/1", "sentence", "document")?;
    *value
        .pointer_mut("/sources/bytes/media")
        .ok_or("bundle media is absent")? = json!(["application/vnd.auditoad.bundle+json"]);
    *value
        .pointer_mut("/rules/0/evaluator")
        .ok_or("fixture evaluator is absent")? = json!({"kind":"model","contract":"yes-no/1"});
    *value
        .pointer_mut("/rules/0/check")
        .ok_or("fixture check is absent")? = json!({"kind":"yes-no/1",
        "instructions":"Does this input violate the supplied policy?",
        "criteria_true":"The input violates the policy.","criteria_false":"The input follows the policy.",
        "pass_below":0.1,"fail_at_or_above":0.9});
    let mut whole = value
        .pointer("/rules/0")
        .and_then(Value::as_object)
        .ok_or("whole rule template is absent")?
        .clone();
    for (field, replacement) in [
        ("id", json!("WHOLE")),
        ("scope", Value::Null),
        ("scope_kind", json!("site")),
        ("evidence", json!("whole")),
    ] {
        whole.insert(field.into(), replacement);
    }
    value.get_mut("evidence").and_then(Value::as_object_mut).ok_or("evidence declarations are absent")?.insert("whole".into(), json!({"builder":"declared-parts/1","builder_revision":"r1","required_roles":["subject"]}));
    value
        .get_mut("rules")
        .and_then(Value::as_array_mut)
        .ok_or("fixture rules are absent")?
        .push(Value::Object(whole));
    append_combination(&mut value, "SUMMARY", &["A"], "document", "any_fail")?;
    value
        .pointer_mut("/rules/2/check")
        .and_then(Value::as_object_mut)
        .ok_or("summary check is absent")?
        .insert("resolution".into(), json!("decisive"));
    let baseline = validate(&value, dir.path());
    let mut files = serde_json::Map::new();
    for (path, text) in [
        ("a.md", "Ålpha waits.\r\nThen it runs.\r\n"),
        ("b.md", "Beta sleeps.\n"),
        ("policy.md", "Read the entire article."),
    ] {
        std::fs::write(dir.path().join(path), text)?;
        files.insert(path.into(), json!(auditoad::sha256(text.as_bytes())));
    }
    let manifest = json!({"schema":"auditoad-evidence-bundle/1","files":files,"packets":[
        {"id":"a","kind":"writing","scope_kind":"site","parts":[{"role":"subject","path":"a.md"},{"role":"policy","path":"policy.md"}]},
        {"id":"b","kind":"writing","scope_kind":"site","parts":[{"role":"subject","path":"b.md"},{"role":"policy","path":"policy.md"}]}
    ]});
    let path = dir.path().join("bundle.json");
    std::fs::write(&path, manifest.to_string())?;
    let snapshot = Snapshot::scoped_bundle(
        &path,
        dir.path(),
        &baseline,
        "default",
        "bytes",
        &Limits::default(),
    )?;
    let prepared = run_scoped(&baseline, &snapshot, Limits::default(), None)?;
    assert_eq!(prepared.report.records.len(), 7);
    assert_eq!(
        prepared
            .report
            .records
            .iter()
            .filter(|r| r.rule.id == "WHOLE")
            .count(),
        2
    );
    let first: Value = serde_json::from_slice(
        &prepared
            .report
            .records
            .first()
            .and_then(|r| r.evidence.as_ref())
            .ok_or("first sentence evidence is absent")?
            .bytes,
    )?;
    assert_eq!(first.get("subject"), Some(&json!("Ålpha waits.")));
    assert_eq!(
        first.get("context"),
        Some(&json!("Ålpha waits.\r\nThen it runs.\r\n"))
    );
    assert_eq!(
        first.pointer("/supporting/0/text"),
        Some(&json!("Read the entire article."))
    );
    let legacy = Snapshot::bundle(&path, dir.path(), &Limits::default())?;
    let refused = scan(ScanRequest {
        baseline: &baseline,
        snapshot: &legacy,
        profile: "default",
        source_alias: "bytes",
        limits: Limits::default(),
        experimental: true,
        mock: None,
    });
    assert!(refused.is_err());
    let mut legacy_value = value.clone();
    *legacy_value
        .get_mut("rules")
        .ok_or("legacy fixture rules are absent")? =
        json!([value.pointer("/rules/1").ok_or("whole rule is absent")?]);
    let legacy_baseline = validate(&legacy_value, dir.path());
    let legacy_report = run_scoped(&legacy_baseline, &legacy, Limits::default(), None)?.report;
    assert_eq!(legacy_report.records.len(), 2);
    for (old, new) in legacy_report.records.iter().zip(
        prepared
            .report
            .records
            .iter()
            .filter(|r| r.rule.id == "WHOLE"),
    ) {
        assert_eq!(
            old.evidence
                .as_ref()
                .ok_or("legacy whole evidence is absent")?
                .bytes,
            new.evidence
                .as_ref()
                .ok_or("scoped whole evidence is absent")?
                .bytes
        );
    }
    let mock = script(&prepared.report, &[0.99, 0.5, 0.01, 0.01, 0.01])?;
    let result = run_scoped(&baseline, &snapshot, Limits::default(), Some(&mock))?;
    assert_eq!(
        result
            .report
            .records
            .iter()
            .filter(|r| r.rule.id == "SUMMARY")
            .count(),
        2
    );
    for (record, (packet, expected)) in result
        .report
        .records
        .iter()
        .filter(|r| r.rule.id == "SUMMARY")
        .zip([("a", "fail"), ("b", "pass")])
    {
        assert_eq!(record.target.metadata.get("packet"), Some(&json!(packet)));
        assert_eq!(
            record
                .observation
                .as_ref()
                .and_then(|v| v.get("suggested_result")),
            Some(&json!(expected))
        );
    }
    assert!(
        Snapshot::scoped_bundle(
            &path,
            dir.path(),
            &baseline,
            "default",
            "bytes",
            &Limits {
                targets: 5,
                ..Limits::default()
            }
        )
        .is_err()
    );
    for (altered, bundle_valid) in [
        (
            {
                let mut m = manifest.clone();
                let subject = m
                    .pointer_mut("/packets/0/parts/0")
                    .and_then(Value::as_object_mut)
                    .ok_or("subject declaration is absent")?;
                subject.insert("start_line".into(), json!(1));
                subject.insert("end_line".into(), json!(1));
                m
            },
            false,
        ),
        (
            {
                let mut m = manifest.clone();
                *m.pointer_mut("/packets/0/scope_kind")
                    .ok_or("packet scope kind is absent")? = json!("whole");
                m.pointer_mut("/packets/0/parts")
                    .and_then(Value::as_array_mut)
                    .ok_or("packet parts are absent")?
                    .push(json!({"role":"subject","path":"b.md"}));
                m
            },
            true,
        ),
    ] {
        std::fs::write(&path, altered.to_string())?;
        assert_eq!(
            Snapshot::bundle(&path, dir.path(), &Limits::default()).is_ok(),
            bundle_valid
        );
        assert!(
            Snapshot::scoped_bundle(
                &path,
                dir.path(),
                &baseline,
                "default",
                "bytes",
                &Limits::default()
            )
            .is_err()
        );
    }
    std::fs::write(&path, manifest.to_string())?;
    std::fs::write(dir.path().join("a.md"), "Changed after preparation.")?;
    let result = run_scoped(&baseline, &snapshot, Limits::default(), Some(&mock))?;
    // Only packet a reads a.md; packet b's evidence is unaffected and still evaluated.
    let packet = |r: &auditoad::schema::Record| {
        r.target
            .metadata
            .get("packet")
            .and_then(Value::as_str)
            .unwrap_or(&r.target.id)
            .to_string()
    };
    let (changed, unchanged): (Vec<_>, Vec<_>) =
        result.report.records.iter().partition(|r| packet(r) == "a");
    assert!(!changed.is_empty() && !unchanged.is_empty());
    assert!(changed.iter().all(|r| r.result == ResultState::Error));
    assert!(unchanged.iter().all(|r| r.result != ResultState::Error));
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions check complete nested children and exact record/check correspondence"
)]
fn nested_dependencies_select_all_children_and_never_mix_different_records() -> TestResult {
    let dir = directory();
    let mut value = declaration(dir.path(), "json/1", "record", "none")?;
    let mut second = value
        .pointer("/rules/0")
        .ok_or("fixture rule is absent")?
        .clone();
    *second
        .get_mut("id")
        .ok_or("second rule identity is absent")? = json!("B");
    value
        .get_mut("rules")
        .and_then(Value::as_array_mut)
        .ok_or("fixture rules are absent")?
        .push(second);
    append_combination(&mut value, "SAME-EVENT", &["A", "B"], "record", "all_fail")?;
    append_combination(
        &mut value,
        "ANY-EVENT",
        &["SAME-EVENT"],
        "document",
        "any_fail",
    )?;
    *value
        .pointer_mut("/profiles/0/select")
        .ok_or("profile selection is absent")? = json!(["ANY-EVENT"]);
    let baseline = validate(&value, dir.path());
    let snapshot = Snapshot::scoped_input(
        br#"[{"event":"one"},{"event":"two"}]"#,
        "events.json",
        &baseline,
        "default",
        "bytes",
        &Limits::default(),
    )?;
    let prepared = run_scoped(&baseline, &snapshot, Limits::default(), None)?;
    assert_eq!(prepared.report.work_count, 7);
    for (scores, expected) in [
        ([0.99, 0.01, 0.01, 0.99], "pass"),
        ([0.99, 0.01, 0.99, 0.01], "fail"),
        ([0.99, 0.01, 0.5, 0.01], "review"),
    ] {
        let mock = script(&prepared.report, &scores)?;
        let result = run_scoped(&baseline, &snapshot, Limits::default(), Some(&mock))?;
        assert_eq!(result.report.records.len(), 7);
        let last = result
            .report
            .records
            .last()
            .ok_or("nested summary record is absent")?;
        assert_eq!(
            last.observation
                .as_ref()
                .and_then(|v| v.get("suggested_result")),
            Some(&json!(expected))
        );
        assert!(
            result
                .report
                .records
                .iter()
                .all(|r| r.result == ResultState::NotEvaluated)
        );
        assert_eq!(result.report.usage.provider_calls, 4);
        let frame: Value = serde_json::from_slice(
            &result
                .report
                .records
                .get(4)
                .and_then(|r| r.evidence.as_ref())
                .ok_or("nested child evidence is absent")?
                .bytes,
        )?;
        let answers = frame
            .get("answers")
            .and_then(Value::as_array)
            .ok_or("nested child answers are absent")?;
        assert_eq!(answers.len(), 2);
        for answer in answers {
            assert_eq!(answer.get("target"), Some(&json!("input/record/0/alone")));
            let check_id = answer
                .get("check_id")
                .and_then(Value::as_str)
                .ok_or("child check identity is absent")?;
            assert!(result.report.records.iter().any(|r| r.check_id == check_id));
        }
    }
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions require missing/budget-refused/empty children to remain unresolved"
)]
fn missing_answers_budget_refusals_and_empty_selections_cannot_clear_a_combination() -> TestResult {
    let dir = directory();
    let mut value = declaration(dir.path(), "json/1", "record", "none")?;
    append_combination(&mut value, "SUMMARY", &["A"], "document", "any_fail")?;
    let baseline = validate(&value, dir.path());
    for input in [b"[]".as_slice(), b"[1,2]"] {
        let snapshot = Snapshot::scoped_input(
            input,
            "events.json",
            &baseline,
            "default",
            "bytes",
            &Limits::default(),
        )?;
        for limits in [
            Limits::default(),
            Limits {
                checks: 1,
                ..Limits::default()
            },
            Limits {
                evidence_bytes: 1,
                ..Limits::default()
            },
        ] {
            let report = run_scoped(&baseline, &snapshot, limits, None)?.report;
            assert!(!report.records.is_empty());
            assert!(
                report
                    .records
                    .iter()
                    .all(|r| !matches!(r.result, ResultState::Pass | ResultState::Fail))
            );
            assert!(
                report
                    .records
                    .last()
                    .ok_or("unresolved summary record is absent")?
                    .observation
                    .as_ref()
                    .is_none_or(|o| o.get("suggested_result") == Some(&json!("review")))
            );
            assert_eq!(report.usage.provider_calls, 0);
        }
    }
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions check decisive conclusions without discarding unresolved child evidence"
)]
fn decisive_resolution_keeps_all_children_and_cannot_clear_the_scan() -> TestResult {
    let dir = directory();
    let mut value = declaration(dir.path(), "json/1", "record", "none")?;
    let mut second = value
        .pointer("/rules/0")
        .ok_or("fixture rule is absent")?
        .clone();
    *second
        .get_mut("id")
        .ok_or("second rule identity is absent")? = json!("B");
    value
        .get_mut("rules")
        .and_then(Value::as_array_mut)
        .ok_or("fixture rules are absent")?
        .push(second);
    append_combination(&mut value, "BOTH", &["A", "B"], "record", "all_fail")?;
    append_combination(&mut value, "ANY", &["BOTH"], "document", "any_fail")?;
    append_combination(&mut value, "ALL", &["BOTH"], "document", "all_fail")?;
    for rule in value
        .get_mut("rules")
        .and_then(Value::as_array_mut)
        .ok_or("fixture rules are absent")?
        .iter_mut()
        .skip(2)
    {
        rule.get_mut("check")
            .and_then(Value::as_object_mut)
            .ok_or("combination check is absent")?
            .insert("resolution".into(), json!("decisive"));
    }
    *value
        .pointer_mut("/profiles/0/select")
        .ok_or("profile selection is absent")? = json!(["ANY", "ALL"]);
    let baseline = validate(&value, dir.path());
    for input in [b"[1,2,3]".as_slice(), b"[]"] {
        let snapshot = Snapshot::scoped_input(
            input,
            "events.json",
            &baseline,
            "default",
            "bytes",
            &Limits::default(),
        )?;
        let prepared = run_scoped(&baseline, &snapshot, Limits::default(), None)?;
        if input == b"[]" {
            assert!(!prepared.report.records.is_empty());
            assert_eq!(prepared.report.usage.provider_calls, 0);
            for record in &prepared.report.records {
                assert!(!matches!(
                    record.result,
                    ResultState::Pass | ResultState::Fail
                ));
                assert!(
                    record
                        .observation
                        .as_ref()
                        .is_none_or(|o| o.get("suggested_result") == Some(&json!("review")))
                );
            }
            continue;
        }
        let mock = script(&prepared.report, &[0.99, 0.01, 0.99, 0.99, 0.5, 0.5])?;
        let result = run_scoped(&baseline, &snapshot, Limits::default(), Some(&mock))?;
        assert_eq!(result.exit_code, 2);
        assert_eq!(result.report.work_count, 11);
        assert_eq!(result.report.records.len(), 11);
        assert_eq!(result.report.usage.provider_calls, 6);
        assert!(
            result
                .report
                .records
                .iter()
                .all(|r| r.result == ResultState::NotEvaluated)
        );
        for (record, (expected, unknown)) in result.report.records.iter().skip(6).zip([
            ("fail", 0),
            ("pass", 1),
            ("review", 1),
            ("fail", 1),
            ("pass", 1),
        ]) {
            let observation = record
                .observation
                .as_ref()
                .ok_or("decisive observation is absent")?;
            assert_eq!(observation.get("suggested_result"), Some(&json!(expected)));
            assert_eq!(observation.get("unresolved"), Some(&json!(unknown)));
            let evidence: Value = serde_json::from_slice(
                &record
                    .evidence
                    .as_ref()
                    .ok_or("decisive evidence is absent")?
                    .bytes,
            )?;
            let answers = evidence
                .get("answers")
                .and_then(Value::as_array)
                .ok_or("decisive child answers are absent")?;
            assert_eq!(answers.len(), if record.rule.id == "BOTH" { 2 } else { 3 });
            for answer in answers {
                let check_id = answer
                    .get("check_id")
                    .and_then(Value::as_str)
                    .ok_or("child check identity is absent")?;
                let child = result
                    .report
                    .records
                    .iter()
                    .find(|r| r.check_id == check_id)
                    .ok_or("decisive evidence names an absent child record")?;
                assert_eq!(
                    answer.get("evidence_sha256"),
                    Some(&json!(
                        child
                            .evidence
                            .as_ref()
                            .ok_or("decisive child evidence is absent")?
                            .sha256
                    ))
                );
            }
        }
    }
    *value
        .pointer_mut("/rules/2/check/resolution")
        .ok_or("combination resolution is absent")? = json!("guess");
    assert!(ValidatedBaseline::from_bytes(value.to_string().as_bytes(), dir.path()).is_err());
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions bind distinct target answers despite identical evidence bytes"
)]
fn targeted_mock_preserves_distinct_answers_for_identical_evidence() -> TestResult {
    let dir = directory();
    for jev in [false, true] {
        let mut value = declaration(dir.path(), "json/1", "record", "none")?;
        if jev {
            *value
                .pointer_mut("/rules/0/evaluator")
                .ok_or("fixture evaluator is absent")? =
                json!({"kind":"model","contract":"yes-no/1"});
            *value
                .pointer_mut("/rules/0/check")
                .ok_or("fixture check is absent")? = json!({"kind":"yes-no/1",
                "instructions":"Does this input violate the supplied policy?",
                "criteria_true":"It violates the policy.","criteria_false":"It follows the policy.",
                "pass_below":0.1,"fail_at_or_above":0.9});
        }
        let baseline = validate(&value, dir.path());
        let snapshot = Snapshot::scoped_input(
            b"[1,1]",
            "events.json",
            &baseline,
            "default",
            "bytes",
            &Limits::default(),
        )?;
        let prepared = run_scoped(&baseline, &snapshot, Limits::default(), None)?;
        let [first, second] = prepared.report.records.as_slice() else {
            return Err("expected both identical-evidence targets".into());
        };
        assert_eq!(
            first
                .evidence
                .as_ref()
                .ok_or("first target evidence is absent")?
                .sha256,
            second
                .evidence
                .as_ref()
                .ok_or("second target evidence is absent")?
                .sha256
        );
        let replies = prepared.report.records.iter().zip([0.99, 0.01]).map(|(record, score)| -> TestResult<Value> {
            Ok(json!({"rule":record.rule.id,"revision":record.rule.revision,"target":record.target.id,
                "instructions_sha256":auditoad::sha256(b"Does this input violate the supplied policy?"),
                "evidence_sha256":record.evidence.as_ref().ok_or("targeted reply evidence is absent")?.sha256,
                "response":{"kind":"probability","value":score}}))
        }).collect::<TestResult<Vec<_>>>()?;
        let data = json!({"schema":"auditoad-mock-model/1","replies":replies});
        let mock = MockModel::from_bytes(data.to_string().as_bytes())?;
        let result = run_scoped(&baseline, &snapshot, Limits::default(), Some(&mock))?;
        assert_eq!(result.report.records.len(), 2);
        for (record, expected) in result.report.records.iter().zip(["fail", "pass"]) {
            assert_eq!(
                record
                    .observation
                    .as_ref()
                    .and_then(|v| v.get("suggested_result")),
                Some(&json!(expected))
            );
        }
        for target in [
            Value::Null,
            json!(" "),
            data.pointer("/replies/0/target")
                .ok_or("first reply target is absent")?
                .clone(),
        ] {
            let mut invalid = data.clone();
            *invalid
                .pointer_mut("/replies/1/target")
                .ok_or("second reply target is absent")? = target;
            assert!(MockModel::from_bytes(invalid.to_string().as_bytes()).is_err());
        }
        let mut absent = data;
        *absent
            .pointer_mut("/replies/1/target")
            .ok_or("second reply target is absent")? = json!("absent-target");
        let mock = MockModel::from_bytes(absent.to_string().as_bytes())?;
        let result = run_scoped(&baseline, &snapshot, Limits::default(), Some(&mock))?;
        assert_eq!(
            result
                .report
                .records
                .get(1)
                .ok_or("absent-target record is missing")?
                .result,
            ResultState::Error
        );
    }
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions check scope and dependency refusals"
)]
fn scope_and_dependency_contracts_refuse_invalid_graphs_and_selection() -> TestResult {
    let dir = directory();
    let mut original = declaration(dir.path(), "text/1", "paragraph", "none")?;
    append_combination(&mut original, "SUMMARY", &["A"], "document", "any_fail")?;
    for invalid in [
        json!([]),
        json!(["missing"]),
        json!(["SUMMARY"]),
        json!(["A", "A"]),
    ] {
        let mut value = original.clone();
        *value
            .pointer_mut("/rules/1/check/rules")
            .ok_or("summary dependencies are absent")? = invalid;
        assert!(ValidatedBaseline::from_bytes(value.to_string().as_bytes(), dir.path()).is_err());
    }
    let mut forward = original.clone();
    let rules = forward
        .get_mut("rules")
        .and_then(Value::as_array_mut)
        .ok_or("rules are absent")?;
    let [first, second] = rules.as_mut_slice() else {
        return Err("expected exactly two rules".into());
    };
    std::mem::swap(first, second);
    assert!(ValidatedBaseline::from_bytes(forward.to_string().as_bytes(), dir.path()).is_err());
    for scope in [
        json!({"unit":"record","context":"none"}),
        json!({"unit":"function","context":"none"}),
        json!({"unit":"paragraph","context":"guess"}),
    ] {
        let mut value = original.clone();
        *value
            .pointer_mut("/rules/0/scope")
            .ok_or("scope is absent")? = scope;
        assert!(ValidatedBaseline::from_bytes(value.to_string().as_bytes(), dir.path()).is_err());
    }
    let mut value = original.clone();
    *value
        .pointer_mut("/rules/0/applicability/include")
        .ok_or("applicability include is absent")? = json!(["known-bad.txt"]);
    assert!(ValidatedBaseline::from_bytes(value.to_string().as_bytes(), dir.path()).is_err());
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions check complete input context and admission limits"
)]
fn complete_input_context_is_never_truncated_or_substituted() -> TestResult {
    let dir = directory();
    let baseline = validate(
        &declaration(dir.path(), "json/1", "record", "document")?,
        dir.path(),
    );
    assert!(
        Snapshot::scoped_input(
            b"{}",
            "data.json",
            &baseline,
            "default",
            "bytes",
            &Limits::default()
        )
        .is_err()
    );
    assert!(
        Snapshot::scoped_input(
            b"[{\"a\":1,\"a\":2}]",
            "data.json",
            &baseline,
            "default",
            "bytes",
            &Limits::default()
        )
        .is_err()
    );
    for limits in [
        Limits {
            targets: 1,
            ..Limits::default()
        },
        Limits {
            evidence_bytes: 5,
            ..Limits::default()
        },
    ] {
        assert!(
            Snapshot::scoped_input(
                b"[1,2]",
                "data.json",
                &baseline,
                "default",
                "bytes",
                &limits
            )
            .is_err()
        );
    }
    let snapshot = Snapshot::scoped_input(
        b"[1,2]",
        "data.json",
        &baseline,
        "default",
        "bytes",
        &Limits::default(),
    )?;
    let report = run_scoped(&baseline, &snapshot, Limits::default(), None)?.report;
    assert_eq!(report.records.len(), 2);
    for record in report.records {
        let frame: Value =
            serde_json::from_slice(&record.evidence.ok_or("record evidence is absent")?.bytes)?;
        assert_eq!(frame.get("context"), Some(&json!([1, 2])));
    }
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions check frozen source and baseline identity"
)]
fn frozen_scope_cannot_be_reused_after_source_or_baseline_changes() -> TestResult {
    let dir = directory();
    let mut value = declaration(dir.path(), "text/1", "paragraph", "none")?;
    let baseline = validate(&value, dir.path());
    let path = dir.path().join("notes.txt");
    std::fs::write(&path, "Original.")?;
    let snapshot = Snapshot::scoped_file(&path, &baseline, "default", "bytes", &Limits::default())?;
    std::fs::write(&path, "Changed.")?;
    let report = run_scoped(&baseline, &snapshot, Limits::default(), None)?.report;
    let [record] = report.records.as_slice() else {
        return Err("expected one frozen-source refusal".into());
    };
    assert_eq!(record.result, ResultState::Error);
    *value
        .pointer_mut("/rules/0/title")
        .ok_or("rule title is absent")? = json!("A different declaration");
    let changed = validate(&value, dir.path());
    assert!(
        scan(ScanRequest {
            baseline: &changed,
            snapshot: &snapshot,
            profile: "default",
            source_alias: "bytes",
            limits: Limits::default(),
            experimental: true,
            mock: None
        })
        .is_err()
    );
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions check JSON line identity and malformed record refusal"
)]
fn json_lines_preserve_source_lines_and_refuse_one_malformed_record() -> TestResult {
    let dir = directory();
    let mut value = declaration(dir.path(), "json-lines/1", "record", "document")?;
    *value
        .pointer_mut("/sources/bytes/media")
        .ok_or("source media is absent")? = json!(["application/x-ndjson"]);
    let baseline = validate(&value, dir.path());
    let input = b"{\"event\":1}\r\n\r\n{\"event\":2}\r\n";
    let snapshot = Snapshot::scoped_input(
        input,
        "events.jsonl",
        &baseline,
        "default",
        "bytes",
        &Limits::default(),
    )?;
    let report = run_scoped(&baseline, &snapshot, Limits::default(), None)?.report;
    let [first, second] = report.records.as_slice() else {
        return Err("expected two JSON line records".into());
    };
    assert_eq!(
        first.target.metadata.pointer("/location/line"),
        Some(&json!(1))
    );
    assert_eq!(
        second.target.metadata.pointer("/location/line"),
        Some(&json!(3))
    );
    let frame: Value = serde_json::from_slice(
        &first
            .evidence
            .as_ref()
            .ok_or("first line evidence is absent")?
            .bytes,
    )?;
    assert_eq!(
        frame.get("context"),
        Some(&json!([{"event":1},{"event":2}]))
    );
    for invalid in [b"{}\nnot-json\n".as_slice(), b"{}\n{\"id\":1,\"id\":2}\n"] {
        assert!(
            Snapshot::scoped_input(
                invalid,
                "events.jsonl",
                &baseline,
                "default",
                "bytes",
                &Limits::default()
            )
            .is_err()
        );
    }
    let baseline_path = dir.path().join("baseline.json");
    let input_path = dir.path().join("events.jsonl");
    let report_path = dir.path().join("report.json");
    std::fs::write(&baseline_path, value.to_string())?;
    std::fs::write(&input_path, input)?;
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_auditoad"))
        .args([
            "scan",
            "--profile",
            "default",
            "--source",
            "bytes",
            "--experimental",
            "--baseline",
        ])
        .arg(&baseline_path)
        .arg("--input")
        .arg(&input_path)
        .arg("--report")
        .arg(&report_path)
        .output()?;
    assert_eq!(
        output.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&std::fs::read(report_path)?)?;
    assert_eq!(report.get("target_count"), Some(&json!(2)));
    assert_eq!(report.pointer("/usage/provider_calls"), Some(&json!(0)));
    Ok(())
}

fn collection_declaration(root: &std::path::Path) -> TestResult<Value> {
    let mut value = declaration(root, "collection/1", "record", "none")?;
    *value
        .pointer_mut("/sources/bytes/media")
        .ok_or("source media is absent")? = json!(["application/vnd.auditoad.collection+json"]);
    let scope = value
        .pointer_mut("/rules/0/scope")
        .and_then(Value::as_object_mut)
        .ok_or("rule scope is absent")?;
    scope.insert("input".into(), json!("events"));
    scope.insert(
        "related".into(),
        json!([{
            "role":"process", "input":"processes", "unit":"record", "allow_empty":false,
            "on":[{"subject":"/host","related":"/host"},{"subject":"/process","related":"/id"}]
        }]),
    );
    Ok(value)
}

fn write_collection(root: &std::path::Path, inputs: Value) -> TestResult<std::path::PathBuf> {
    let path = root.join("inputs.json");
    std::fs::write(
        &path,
        json!({"schema":"auditoad-collection/1", "inputs":inputs}).to_string(),
    )?;
    Ok(path)
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions check complete nested units, escaped original locations and full-file provenance"
)]
fn collection_json_pointer_selects_nested_records_and_related_units() -> TestResult {
    let dir = directory();
    let mut value = collection_declaration(dir.path())?;
    value
        .pointer_mut("/sources/bytes")
        .and_then(Value::as_object_mut)
        .ok_or("collection source is absent")?
        .insert("include_provenance".into(), json!(true));
    *value
        .pointer_mut("/rules/0/scope/context")
        .ok_or("scope context is absent")? = json!("document");
    let baseline = validate(&value, dir.path());
    let rows = json!([{"host":"a","process":7},{"host":"b","process":8}]);
    let events = json!({"outside":"not selected","primary/review":{"~rows":rows}}).to_string();
    let peers = json!({"outside":false,"audit":{"peers":[
        {"host":"b","id":8},{"host":"a","id":7},{"host":"a","id":9}
    ]}})
    .to_string();
    std::fs::write(dir.path().join("events.json"), &events)?;
    std::fs::write(dir.path().join("processes.json"), &peers)?;
    let path = write_collection(
        dir.path(),
        json!({
            "events":{"adapter":"json/1","path":"events.json",
                "sha256":auditoad::sha256(events.as_bytes()),
                "json_pointer":"/primary~1review/~0rows"},
            "processes":{"adapter":"json/1","path":"processes.json",
                "sha256":auditoad::sha256(peers.as_bytes()),"json_pointer":"/audit/peers"}
        }),
    )?;
    let snapshot = Snapshot::collection_file(
        &path,
        None,
        &baseline,
        "default",
        "bytes",
        &Limits::default(),
    )?;
    let report = run_scoped(&baseline, &snapshot, Limits::default(), None)?.report;
    assert_eq!(report.records.len(), 2);
    assert_eq!(report.usage.provider_calls, 0);
    for (ordinal, record) in report.records.iter().enumerate() {
        let frame: Value = serde_json::from_slice(
            &record
                .evidence
                .as_ref()
                .ok_or("selected evidence is absent")?
                .bytes,
        )?;
        assert_eq!(frame.get("subject"), rows.get(ordinal));
        assert_eq!(frame.get("context"), Some(&rows));
        let selected = rows.get(ordinal).ok_or("selected row is absent")?;
        assert_eq!(
            frame.pointer("/related/process"),
            Some(&json!([{"host":selected.get("host"),"id":selected.get("process")}]))
        );
        assert_eq!(
            frame.pointer("/provenance/subject/location/pointer"),
            Some(&json!(format!("/primary~1review/~0rows/{ordinal}")))
        );
        assert_eq!(
            frame.pointer("/provenance/subject/input_sha256"),
            Some(&json!(auditoad::sha256(events.as_bytes())))
        );
        assert_eq!(
            frame.pointer("/provenance/related/process/0/input_sha256"),
            Some(&json!(auditoad::sha256(peers.as_bytes())))
        );
        assert_eq!(
            frame.pointer("/provenance/related/process/0/location/pointer"),
            Some(&json!(if ordinal == 0 {
                "/audit/peers/1"
            } else {
                "/audit/peers/0"
            }))
        );
        assert!(frame.pointer("/context/outside").is_none());
    }
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions check distinct same-file views, one physical input allowance and complete-file drift"
)]
fn collection_json_pointer_views_share_file_custody_and_budgets() -> TestResult {
    let dir = directory();
    let mut value = collection_declaration(dir.path())?;
    value
        .pointer_mut("/sources/bytes")
        .and_then(Value::as_object_mut)
        .ok_or("collection source is absent")?
        .insert("include_provenance".into(), json!(true));
    *value
        .pointer_mut("/rules/0/scope_kind")
        .ok_or("scope kind is absent")? = json!("whole");
    *value
        .pointer_mut("/rules/0/scope")
        .ok_or("scope is absent")? = json!({"input":"budget","unit":"document","context":"none"});
    let mut second = value.pointer("/rules/0").ok_or("rule is absent")?.clone();
    *second.get_mut("id").ok_or("rule id is absent")? = json!("B");
    *second
        .pointer_mut("/scope/input")
        .ok_or("second input is absent")? = json!("signal");
    value
        .get_mut("rules")
        .and_then(Value::as_array_mut)
        .ok_or("rules are absent")?
        .push(second);
    let baseline = validate(&value, dir.path());
    let ledger = json!({"canonical_partial":"retained".repeat(2048),
        "primary_research_review":{"budget":{"id":"budget","revision":"1"},
                                    "signal":{"id":"signal","revision":"1"}}});
    let original = ledger.to_string();
    std::fs::write(dir.path().join("ledger.json"), &original)?;
    let inputs = json!({
        "budget":{"adapter":"json/1","path":"ledger.json",
            "json_pointer":"/primary_research_review/budget","sha256":auditoad::sha256(original.as_bytes())},
        "signal":{"adapter":"json/1","path":"ledger.json",
            "json_pointer":"/primary_research_review/signal","sha256":auditoad::sha256(original.as_bytes())}
    });
    let path = write_collection(dir.path(), inputs.clone())?;
    let total = u64::try_from(
        std::fs::read(&path)?
            .len()
            .checked_add(original.len())
            .ok_or("input byte total overflow")?,
    )?;
    let limits = Limits {
        input_bytes: total,
        evidence_bytes: 8192,
        ..Limits::default()
    };
    let snapshot = Snapshot::collection_file(&path, None, &baseline, "default", "bytes", &limits)?;
    let report = run_scoped(&baseline, &snapshot, limits.clone(), None)?.report;
    assert_eq!(report.records.len(), 2);
    assert_eq!(report.usage.provider_calls, 0);
    for record in &report.records {
        let name = if record.rule.id == "A" {
            "budget"
        } else {
            "signal"
        };
        let evidence = &record
            .evidence
            .as_ref()
            .ok_or("row evidence is absent")?
            .bytes;
        let frame: Value = serde_json::from_slice(evidence)?;
        assert_eq!(
            frame.get("subject"),
            ledger.pointer(&format!("/primary_research_review/{name}"))
        );
        assert_eq!(
            frame.pointer("/provenance/subject/input_sha256"),
            Some(&json!(auditoad::sha256(original.as_bytes())))
        );
        assert_eq!(
            frame.pointer("/provenance/subject/location/pointer"),
            Some(&json!(format!("/primary_research_review/{name}")))
        );
        assert!(evidence.len() < original.len());
    }
    for refused in [
        Limits {
            input_bytes: total.checked_sub(1).ok_or("input total is zero")?,
            ..limits.clone()
        },
        Limits {
            evidence_bytes: 1,
            ..limits.clone()
        },
        Limits {
            targets: 1,
            ..limits.clone()
        },
    ] {
        assert!(
            Snapshot::collection_file(&path, None, &baseline, "default", "bytes", &refused)
                .is_err()
        );
    }
    let mut wrong_pin = inputs.clone();
    *wrong_pin
        .pointer_mut("/signal/sha256")
        .ok_or("second pin is absent")? = json!("0".repeat(64));
    write_collection(dir.path(), wrong_pin)?;
    assert!(
        Snapshot::collection_file(
            &path,
            None,
            &baseline,
            "default",
            "bytes",
            &Limits::default()
        )
        .is_err()
    );
    write_collection(dir.path(), inputs)?;
    let snapshot = Snapshot::collection_file(&path, None, &baseline, "default", "bytes", &limits)?;
    let mut changed = ledger;
    *changed
        .get_mut("canonical_partial")
        .ok_or("unselected content is absent")? = json!("changed outside both selected rows");
    std::fs::write(dir.path().join("ledger.json"), changed.to_string())?;
    let report = run_scoped(&baseline, &snapshot, limits, None)?.report;
    assert!(
        report
            .records
            .iter()
            .all(|record| record.result == ResultState::Error && record.evidence.is_none())
    );
    assert_eq!(report.usage.provider_calls, 0);
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions refuse unsupported, malformed, missing, duplicate and case-colliding declared views"
)]
fn collection_json_pointer_refuses_invalid_and_duplicate_views() -> TestResult {
    let dir = directory();
    let baseline = validate(&collection_declaration(dir.path())?, dir.path());
    std::fs::write(
        dir.path().join("events.json"),
        br#"[{"host":"a","process":7}]"#,
    )?;
    std::fs::write(
        dir.path().join("processes.json"),
        br#"[{"host":"a","id":7}]"#,
    )?;
    std::fs::write(dir.path().join("unused.json"), br#"{"rows":[],"scalar":1}"#)?;
    let original = json!({"events":{"adapter":"json/1","path":"events.json"},
        "processes":{"adapter":"json/1","path":"processes.json"}});
    for declaration in [
        json!({"adapter":"json/1","path":"unused.json","json_pointer":"/missing"}),
        json!({"adapter":"json/1","path":"unused.json","json_pointer":"rows"}),
        json!({"adapter":"json/1","path":"unused.json","json_pointer":"/rows~2"}),
        json!({"adapter":"json/1","path":"unused.json","json_pointer":"/rows~"}),
        json!({"adapter":"json/1","path":"unused.json","json_pointer":null}),
        json!({"adapter":"json/1","path":"unused.json","json_pointer":1}),
        json!({"adapter":"text/1","path":"unused.json","json_pointer":"/rows"}),
        json!({"adapter":"json-lines/1","path":"unused.json","json_pointer":"/rows"}),
        json!({"adapter":"json/1","unavailable":"not exported","json_pointer":"/rows"}),
    ] {
        let mut inputs = original.clone();
        inputs
            .as_object_mut()
            .ok_or("inputs are absent")?
            .insert("unused".into(), declaration.clone());
        let path = write_collection(dir.path(), inputs)?;
        assert!(
            Snapshot::collection_file(
                &path,
                None,
                &baseline,
                "default",
                "bytes",
                &Limits::default()
            )
            .is_err(),
            "{declaration}"
        );
    }
    for (left, right, second_path) in [
        (None, None, "unused.json"),
        (None, Some(""), "unused.json"),
        (Some("/rows"), None, "unused.json"),
        (Some("/rows"), Some("/rows"), "unused.json"),
        (Some("/rows"), Some("/scalar"), "UNUSED.json"),
    ] {
        let mut inputs = original.clone();
        for (name, pointer, path) in [("left", left, "unused.json"), ("right", right, second_path)]
        {
            let mut input = json!({"adapter":"json/1","path":path});
            if let Some(pointer) = pointer {
                input
                    .as_object_mut()
                    .ok_or("input is absent")?
                    .insert("json_pointer".into(), json!(pointer));
            }
            inputs
                .as_object_mut()
                .ok_or("inputs are absent")?
                .insert(name.into(), input);
        }
        let path = write_collection(dir.path(), inputs)?;
        assert!(
            Snapshot::collection_file(
                &path,
                None,
                &baseline,
                "default",
                "bytes",
                &Limits::default()
            )
            .is_err()
        );
    }
    let mut inputs = original;
    inputs.as_object_mut().ok_or("inputs are absent")?.insert(
        "unused".into(),
        json!({"adapter":"json/1","path":"unused.json","json_pointer":"/rows"}),
    );
    let path = write_collection(dir.path(), inputs)?;
    std::fs::write(
        dir.path().join("unused.json"),
        br#"{"rows":[],"outside":1,"outside":2}"#,
    )?;
    assert!(
        Snapshot::collection_file(
            &path,
            None,
            &baseline,
            "default",
            "bytes",
            &Limits::default()
        )
        .is_err()
    );
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions preserve default root evidence and distinguish empty, null and non-array selections"
)]
fn collection_json_pointer_preserves_root_frames_and_empty_refusals() -> TestResult {
    let dir = directory();
    let mut value = collection_declaration(dir.path())?;
    value
        .pointer_mut("/rules/0/scope")
        .and_then(Value::as_object_mut)
        .ok_or("scope is absent")?
        .remove("related");
    value
        .pointer_mut("/sources/bytes")
        .and_then(Value::as_object_mut)
        .ok_or("source is absent")?
        .insert("include_provenance".into(), json!(true));
    let baseline = validate(&value, dir.path());
    std::fs::write(
        dir.path().join("events.json"),
        br#"[{"id":"first"},{"id":"second"}]"#,
    )?;
    let mut original_frames = None;
    for pointer in [None, Some("")] {
        let mut input = json!({"adapter":"json/1","path":"events.json"});
        if let Some(pointer) = pointer {
            input
                .as_object_mut()
                .ok_or("input is absent")?
                .insert("json_pointer".into(), json!(pointer));
        }
        let path = write_collection(dir.path(), json!({"events":input}))?;
        let snapshot = Snapshot::collection_file(
            &path,
            None,
            &baseline,
            "default",
            "bytes",
            &Limits::default(),
        )?;
        let report = run_scoped(&baseline, &snapshot, Limits::default(), None)?.report;
        let frames = report
            .records
            .iter()
            .map(|record| {
                record
                    .evidence
                    .as_ref()
                    .map(|evidence| evidence.bytes.clone())
                    .ok_or("root evidence is absent")
            })
            .collect::<Result<Vec<_>, _>>()?;
        assert_eq!(frames.len(), 2);
        if pointer.is_none() {
            original_frames = Some(frames);
        } else {
            assert_eq!(Some(frames), original_frames);
        }
    }
    let path = write_collection(
        dir.path(),
        json!({"events":{"adapter":"json/1",
        "path":"events.json","json_pointer":"/rows"}}),
    )?;
    for rows in [json!({"id":"not an array"}), json!(null), json!(1)] {
        std::fs::write(
            dir.path().join("events.json"),
            json!({"rows":rows}).to_string(),
        )?;
        assert!(
            Snapshot::collection_file(
                &path,
                None,
                &baseline,
                "default",
                "bytes",
                &Limits::default()
            )
            .is_err()
        );
    }
    std::fs::write(dir.path().join("events.json"), br#"{"rows":[]}"#)?;
    let snapshot = Snapshot::collection_file(
        &path,
        None,
        &baseline,
        "default",
        "bytes",
        &Limits::default(),
    )?;
    let report = run_scoped(&baseline, &snapshot, Limits::default(), None)?.report;
    let [record] = report.records.as_slice() else {
        return Err("expected an empty-selection refusal".into());
    };
    assert_eq!(record.result, ResultState::Error);
    assert_eq!(report.outcome, auditoad::schema::Outcome::Unresolved);
    assert_eq!(
        record.target.metadata.pointer("/location/pointer"),
        Some(&json!("/rows"))
    );
    assert!(record.evidence.is_none());
    assert_eq!(report.usage.provider_calls, 0);
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions check actual text/JSON pins and unchanged unpinned evidence"
)]
fn collection_optional_pins_accept_actual_bytes_and_mixed_unpinned_inputs() -> TestResult {
    let dir = directory();
    let mut value = collection_declaration(dir.path())?;
    value
        .pointer_mut("/sources/bytes")
        .and_then(Value::as_object_mut)
        .ok_or("collection source is absent")?
        .insert("include_provenance".into(), json!(true));
    *value
        .pointer_mut("/rules/0/scope_kind")
        .ok_or("scope kind is absent")? = json!("whole");
    *value
        .pointer_mut("/rules/0/scope")
        .ok_or("scope is absent")? = json!({"input":"events","unit":"document","context":"none",
            "related":[{"role":"note","input":"note","unit":"document","on":[],"allow_empty":false}]});
    let baseline = validate(&value, dir.path());
    let events = "{\r\n  \"ready\": true, \"label\": \"Ω\"\r\n}\r\n";
    let note = "A complete note.\r\nSecond line: β.\r\n";
    std::fs::write(dir.path().join("events.json"), events)?;
    std::fs::write(dir.path().join("note.txt"), note)?;
    std::fs::write(dir.path().join("unselected.json"), b"{\"retained\":true}")?;
    let original = json!({
        "events":{"adapter":"json/1","path":"events.json","sha256":auditoad::sha256(events.as_bytes())},
        "note":{"adapter":"text/1","path":"note.txt","sha256":auditoad::sha256(note.as_bytes())},
        "unselected":{"adapter":"json/1","path":"unselected.json"}
    });
    let mut pinned_frame = None;
    for pinned in [true, false] {
        let mut inputs = original.clone();
        if !pinned {
            for input in ["events", "note"] {
                inputs
                    .get_mut(input)
                    .and_then(Value::as_object_mut)
                    .ok_or("input declaration is absent")?
                    .remove("sha256");
            }
        }
        let path = write_collection(dir.path(), inputs)?;
        let snapshot = Snapshot::collection_file(
            &path,
            None,
            &baseline,
            "default",
            "bytes",
            &Limits::default(),
        )?;
        let report = run_scoped(&baseline, &snapshot, Limits::default(), None)?.report;
        let [record] = report.records.as_slice() else {
            return Err("expected one text/JSON collection record".into());
        };
        assert_eq!(report.usage.provider_calls, 0);
        let bytes = &record
            .evidence
            .as_ref()
            .ok_or("collection evidence is absent")?
            .bytes;
        let frame: Value = serde_json::from_slice(bytes)?;
        assert_eq!(
            frame.get("subject"),
            Some(&serde_json::from_str::<Value>(events)?)
        );
        assert_eq!(frame.pointer("/related/note"), Some(&json!([note])));
        assert_eq!(
            frame.pointer("/provenance/subject/input_sha256"),
            Some(&json!(auditoad::sha256(events.as_bytes())))
        );
        assert_eq!(
            frame.pointer("/provenance/related/note/0/input_sha256"),
            Some(&json!(auditoad::sha256(note.as_bytes())))
        );
        assert!(frame.pointer("/related/unselected").is_none());
        if pinned {
            pinned_frame = Some(bytes.clone());
        } else {
            assert_eq!(Some(bytes), pinned_frame.as_ref());
        }
    }
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions reject all declared bad pins before scope preparation or dispatch"
)]
fn collection_optional_pins_refuse_bad_unused_unavailable_and_duplicate_declarations() -> TestResult
{
    let dir = directory();
    let baseline = validate(&collection_declaration(dir.path())?, dir.path());
    let events = br#"[{"host":"a","process":7}]"#;
    let processes = br#"[{"host":"a","id":7}]"#;
    let unused = b"Unused declared text input.\r\n";
    std::fs::write(dir.path().join("events.json"), events)?;
    std::fs::write(dir.path().join("processes.json"), processes)?;
    std::fs::write(dir.path().join("unused.txt"), unused)?;
    let original = json!({
        "events":{"adapter":"json/1","path":"events.json","sha256":auditoad::sha256(events)},
        "processes":{"adapter":"json/1","path":"processes.json","sha256":auditoad::sha256(processes)},
        "unused":{"adapter":"text/1","path":"unused.txt","sha256":auditoad::sha256(unused)}
    });
    let path = write_collection(dir.path(), original.clone())?;
    let _positive = Snapshot::collection_file(
        &path,
        None,
        &baseline,
        "default",
        "bytes",
        &Limits::default(),
    )?;
    for input in ["events", "processes", "unused"] {
        for pin in [
            json!(auditoad::sha256(b"different bytes")),
            json!(""),
            json!("a".repeat(63)),
            json!("A".repeat(64)),
            json!("g".repeat(64)),
            json!(true),
            json!(7),
        ] {
            let mut inputs = original.clone();
            *inputs
                .get_mut(input)
                .and_then(|declaration| declaration.get_mut("sha256"))
                .ok_or("source pin is absent")? = pin;
            write_collection(dir.path(), inputs)?;
            assert!(
                Snapshot::collection_file(
                    &path,
                    None,
                    &baseline,
                    "default",
                    "bytes",
                    &Limits::default(),
                )
                .is_err(),
                "bad pin accepted for {input}"
            );
        }
    }
    // This input is not selected by any rule. Its unavailable declaration still
    // cannot advertise a file pin, even when that pin has valid syntax.
    let mut unavailable = original;
    *unavailable
        .get_mut("unused")
        .ok_or("unused input is absent")? = json!({"adapter":"text/1","unavailable":"export not supplied","sha256":auditoad::sha256(unused)});
    write_collection(dir.path(), unavailable)?;
    assert!(
        Snapshot::collection_file(
            &path,
            None,
            &baseline,
            "default",
            "bytes",
            &Limits::default(),
        )
        .is_err()
    );
    let digest = auditoad::sha256(events);
    std::fs::write(
        &path,
        format!(
            "{{\"schema\":\"auditoad-collection/1\",\"inputs\":{{\"events\":{{\"adapter\":\"json/1\",\"path\":\"events.json\",\"sha256\":\"{digest}\",\"sha256\":\"{digest}\"}},\"processes\":{{\"adapter\":\"json/1\",\"path\":\"processes.json\"}}}}}}"
        ),
    )?;
    let duplicate = Snapshot::collection_file(
        &path,
        None,
        &baseline,
        "default",
        "bytes",
        &Limits::default(),
    )
    .err()
    .ok_or("duplicate identical pin keys were accepted")?;
    assert!(duplicate.message.contains("duplicate"));
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions refuse changed pinned files after freezing, including unused inputs"
)]
fn collection_optional_pins_do_not_admit_source_changes_after_freezing() -> TestResult {
    let dir = directory();
    let baseline = validate(&collection_declaration(dir.path())?, dir.path());
    let events = br#"[{"host":"a","process":7}]"#;
    let processes = br#"[{"host":"a","id":7}]"#;
    let unused = b"Unused declared text input.\r\n";
    let path = write_collection(
        dir.path(),
        json!({
            "events":{"adapter":"json/1","path":"events.json","sha256":auditoad::sha256(events)},
            "processes":{"adapter":"json/1","path":"processes.json","sha256":auditoad::sha256(processes)},
            "unused":{"adapter":"text/1","path":"unused.txt","sha256":auditoad::sha256(unused)}
        }),
    )?;
    for changed in ["events.json", "processes.json", "unused.txt"] {
        std::fs::write(dir.path().join("events.json"), events)?;
        std::fs::write(dir.path().join("processes.json"), processes)?;
        std::fs::write(dir.path().join("unused.txt"), unused)?;
        let snapshot = Snapshot::collection_file(
            &path,
            None,
            &baseline,
            "default",
            "bytes",
            &Limits::default(),
        )?;
        std::fs::write(dir.path().join(changed), b"[]")?;
        let report = run_scoped(&baseline, &snapshot, Limits::default(), None)?.report;
        let [record] = report.records.as_slice() else {
            return Err("expected one changed-file refusal".into());
        };
        assert_eq!(record.result, ResultState::Error, "{changed}");
        assert!(
            record
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains("changed"))
        );
        assert!(record.evidence.is_none());
        assert_eq!(report.usage.provider_calls, 0);
        assert!(
            Snapshot::collection_file(
                &path,
                None,
                &baseline,
                "default",
                "bytes",
                &Limits::default(),
            )
            .is_err()
        );
    }
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions check opt-in byte compatibility and actual selected-peer provenance"
)]
fn collection_provenance_preserves_default_frames_and_selected_peer_order() -> TestResult {
    let dir = directory();
    let original = collection_declaration(dir.path())?;
    let events = br#"[{"host":"a","process":7},{"host":"b","process":7}]"#;
    let processes = "[\r\n {\"host\":\"b\",\"id\":7,\"command\":\"βeta\"},\r\n {\"host\":\"a\",\"id\":7,\"command\":\"first\"},\r\n {\"host\":\"a\",\"id\":\"7\",\"command\":\"wrong type\"},\r\n {\"host\":\"a\",\"id\":7,\"command\":\"second\"},\r\n {\"host\":\"c\",\"id\":7,\"command\":\"unrelated\"}\r\n]\r\n";
    std::fs::write(dir.path().join("events.json"), events)?;
    std::fs::write(dir.path().join("processes.json"), processes)?;
    let path = write_collection(
        dir.path(),
        json!({"events":{"adapter":"json/1","path":"events.json"},
            "processes":{"adapter":"json/1","path":"processes.json"}}),
    )?;
    let subjects: Value = serde_json::from_slice(events)?;
    let peers: Value = serde_json::from_str(processes)?;
    let mut default_frames = Vec::new();
    for enabled in [None, Some(false), Some(true)] {
        let mut value = original.clone();
        if let Some(enabled) = enabled {
            value
                .pointer_mut("/sources/bytes")
                .and_then(Value::as_object_mut)
                .ok_or("collection source is absent")?
                .insert("include_provenance".into(), json!(enabled));
        }
        let baseline = validate(&value, dir.path());
        if enabled != Some(true) {
            assert!(
                serde_json::to_value(baseline.baseline())?
                    .pointer("/sources/bytes/include_provenance")
                    .is_none()
            );
        }
        let snapshot = Snapshot::collection_file(
            &path,
            None,
            &baseline,
            "default",
            "bytes",
            &Limits::default(),
        )?;
        let report = run_scoped(&baseline, &snapshot, Limits::default(), None)?.report;
        assert_eq!(report.records.len(), 2);
        assert_eq!(report.usage.provider_calls, 0);
        for (ordinal, record) in report.records.iter().enumerate() {
            let bytes = &record
                .evidence
                .as_ref()
                .ok_or("related evidence is absent")?
                .bytes;
            let frame: Value = serde_json::from_slice(bytes)?;
            let indices: &[usize] = if ordinal == 0 { &[1, 3] } else { &[0] };
            let selected_peers = indices
                .iter()
                .map(|&index| peers.get(index).cloned().ok_or("peer is absent"))
                .collect::<Result<Vec<_>, _>>()?;
            let expected = json!({"schema":"scoped-input/1",
                "scope":value.pointer("/rules/0/scope").ok_or("scope is absent")?,
                "subject":subjects.get(ordinal).ok_or("subject is absent")?,
                "related":{"process":selected_peers}});
            if enabled == Some(true) {
                let mut legacy = frame.clone();
                legacy
                    .as_object_mut()
                    .ok_or("frame is not an object")?
                    .remove("provenance");
                assert_eq!(legacy, expected);
                assert_eq!(
                    &serde_json::to_vec(&legacy)?,
                    default_frames
                        .get(ordinal)
                        .ok_or("default frame is absent")?
                );
                let mut metadata = record.target.metadata.clone();
                metadata
                    .as_object_mut()
                    .ok_or("target metadata is not an object")?
                    .remove("related");
                assert_eq!(frame.pointer("/provenance/subject"), Some(&metadata));
                assert_eq!(
                    frame.pointer("/provenance/subject/input_sha256"),
                    Some(&json!(auditoad::sha256(events)))
                );
                assert_eq!(
                    frame.pointer("/provenance/related"),
                    record.target.metadata.get("related")
                );
                let provenance = frame
                    .pointer("/provenance/related/process")
                    .and_then(Value::as_array)
                    .ok_or("peer provenance is absent")?;
                assert_eq!(provenance.len(), indices.len());
                for (item, &index) in provenance.iter().zip(indices) {
                    assert_eq!(item.get("input"), Some(&json!("processes")));
                    assert_eq!(
                        item.pointer("/location/pointer"),
                        Some(&json!(format!("/{index}")))
                    );
                    assert_eq!(
                        item.get("input_sha256"),
                        Some(&json!(auditoad::sha256(processes.as_bytes())))
                    );
                    assert_ne!(
                        item.get("input_sha256"),
                        Some(&json!(auditoad::sha256(&serde_json::to_vec(
                            peers.get(index).ok_or("peer is absent")?
                        )?)))
                    );
                }
            } else {
                assert!(frame.get("provenance").is_none());
                assert_eq!(frame, expected);
                if enabled.is_none() {
                    default_frames.push(bytes.clone());
                } else {
                    assert_eq!(
                        bytes,
                        default_frames
                            .get(ordinal)
                            .ok_or("default frame is absent")?
                    );
                }
            }
        }
    }
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions bind raw file hashes and keep missing or changed evidence unresolved"
)]
fn collection_provenance_compares_receipts_to_actual_files_and_requirements() -> TestResult {
    let dir = directory();
    let mut value = collection_declaration(dir.path())?;
    value
        .pointer_mut("/sources/bytes")
        .and_then(Value::as_object_mut)
        .ok_or("collection source is absent")?
        .insert("include_provenance".into(), json!(true));
    *value
        .pointer_mut("/rules/0/scope")
        .ok_or("scope is absent")? = json!({"input":"receipt","unit":"document","context":"none",
            "related":[{"role":"source","input":"source","unit":"document","on":[],"allow_empty":false}]});
    *value
        .pointer_mut("/rules/0/scope_kind")
        .ok_or("scope kind is absent")? = json!("whole");
    *value
        .pointer_mut("/rules/0/evaluator")
        .ok_or("evaluator is absent")? =
        json!({"kind":"json-pointer-compare","contract":"json-pointer-compare/1"});
    *value
        .pointer_mut("/rules/0/check")
        .ok_or("check is absent")? = json!({"kind":"json-pointer-compare/1","left":"/subject/source_sha256",
            "right":"/provenance/related/source/0/input_sha256","fail_when":"unequal"});
    let good = br#"{"subject":{"source_sha256":"same"},"provenance":{"related":{"source":[{"input_sha256":"same"}]}}}"#;
    let bad = br#"{"subject":{"source_sha256":"old"},"provenance":{"related":{"source":[{"input_sha256":"current"}]}}}"#;
    *value
        .pointer_mut("/rules/0/fixtures")
        .ok_or("fixtures are absent")? = json!({
        "pass":[fixture(dir.path(),"provenance-match.json",good,good)],
        "fail":[fixture(dir.path(),"provenance-mismatch.json",bad,bad)]});
    value.as_object_mut().ok_or("baseline is not an object")?.insert(
        "requirements".into(),
        json!([{"id":"SOURCE-CUSTODY","revision":"1","title":"Receipt identifies the supplied file bytes"}]),
    );
    value
        .pointer_mut("/rules/0")
        .and_then(Value::as_object_mut)
        .ok_or("rule is absent")?
        .insert("requirements".into(), json!({"SOURCE-CUSTODY":"1"}));
    let baseline = validate(&value, dir.path());
    let source = "{\r\n  \"text\": \"Ω\", \"count\": 7\r\n}\r\n";
    let raw_hash = auditoad::sha256(source.as_bytes());
    let parsed_source: Value = serde_json::from_str(source)?;
    let transformed_hash = auditoad::sha256(&serde_json::to_vec(&parsed_source)?);
    assert_ne!(raw_hash, transformed_hash);
    for (case, recorded, expected_result, expected_coverage) in [
        (
            "matched",
            Some(raw_hash.as_str()),
            ResultState::Pass,
            RequirementStatus::Satisfied,
        ),
        (
            "wrong",
            Some("different source"),
            ResultState::Fail,
            RequirementStatus::Finding,
        ),
        (
            "transformed",
            Some(transformed_hash.as_str()),
            ResultState::Fail,
            RequirementStatus::Finding,
        ),
        (
            "missing-hash",
            None,
            ResultState::NotEvaluated,
            RequirementStatus::Unresolved,
        ),
        (
            "missing-source",
            Some(raw_hash.as_str()),
            ResultState::Error,
            RequirementStatus::Unresolved,
        ),
        (
            "unavailable-source",
            Some(raw_hash.as_str()),
            ResultState::Error,
            RequirementStatus::Unresolved,
        ),
        (
            "missing-receipt",
            Some(raw_hash.as_str()),
            ResultState::Error,
            RequirementStatus::Unresolved,
        ),
        (
            "unavailable-receipt",
            Some(raw_hash.as_str()),
            ResultState::Error,
            RequirementStatus::Unresolved,
        ),
    ] {
        let mut receipt =
            json!({"provenance":{"related":{"source":[{"input_sha256":"invented"}]}}});
        if let Some(recorded) = recorded {
            receipt
                .as_object_mut()
                .ok_or("receipt is not an object")?
                .insert("source_sha256".into(), json!(recorded));
        }
        let receipt_bytes = serde_json::to_vec_pretty(&receipt)?;
        std::fs::write(dir.path().join("receipt.json"), &receipt_bytes)?;
        std::fs::write(dir.path().join("source.json"), source)?;
        let mut inputs = json!({});
        for (name, path) in [("receipt", "receipt.json"), ("source", "source.json")] {
            let missing = case == format!("missing-{name}");
            let unavailable = case == format!("unavailable-{name}");
            if !missing {
                inputs
                    .as_object_mut()
                    .ok_or("inputs are not an object")?
                    .insert(
                        name.into(),
                        if unavailable {
                            json!({"adapter":"json/1","unavailable":"export not supplied"})
                        } else {
                            json!({"adapter":"json/1","path":path})
                        },
                    );
            }
        }
        let path = write_collection(dir.path(), inputs)?;
        let snapshot = Snapshot::collection_file(
            &path,
            None,
            &baseline,
            "default",
            "bytes",
            &Limits::default(),
        )?;
        let report = run_scoped(&baseline, &snapshot, Limits::default(), None)?.report;
        let [record] = report.records.as_slice() else {
            return Err("expected one direct receipt/source comparison".into());
        };
        assert_eq!(record.result, expected_result, "{case}");
        assert_eq!(report.usage.provider_calls, 0);
        let [coverage] = report.requirements.as_slice() else {
            return Err("expected the source-custody requirement".into());
        };
        assert_eq!(coverage.status, expected_coverage, "{case}");
        assert_eq!(coverage.rules, ["A"]);
        if case.ends_with("receipt") {
            assert!(record.target.metadata.get("input_sha256").is_none());
        } else {
            assert_eq!(
                record.target.metadata.get("input_sha256"),
                Some(&json!(auditoad::sha256(&receipt_bytes)))
            );
        }
        if case.ends_with("source") {
            assert_eq!(
                record.target.metadata.pointer("/related/source"),
                Some(&json!([]))
            );
        } else {
            assert_eq!(
                record
                    .target
                    .metadata
                    .pointer("/related/source/0/input_sha256"),
                Some(&json!(raw_hash))
            );
        }
        if expected_result == ResultState::Error {
            assert!(record.evidence.is_none());
            assert!(
                record
                    .reason
                    .as_deref()
                    .is_some_and(|reason| reason.contains("unavailable"))
            );
        } else {
            let frame: Value = serde_json::from_slice(
                &record
                    .evidence
                    .as_ref()
                    .ok_or("comparison evidence is absent")?
                    .bytes,
            )?;
            assert_eq!(
                frame.pointer("/provenance/subject/input_sha256"),
                Some(&json!(auditoad::sha256(&receipt_bytes)))
            );
            assert_eq!(
                frame.pointer("/provenance/related/source/0/input_sha256"),
                Some(&json!(raw_hash))
            );
            assert_eq!(frame.pointer("/related/source/0"), Some(&parsed_source));
            assert_eq!(
                frame.pointer("/subject/provenance/related/source/0/input_sha256"),
                Some(&json!("invented"))
            );
            if expected_result == ResultState::NotEvaluated {
                assert!(record.reason.as_deref().is_some_and(|reason| {
                    reason.contains("required JSON comparison operand is absent")
                }));
            }
        }
        if case == "matched" {
            // Semantically equal JSON with different bytes cannot inherit the
            // frozen source hash or turn a changed-file read into a pass.
            std::fs::write(
                dir.path().join("source.json"),
                serde_json::to_vec(&parsed_source)?,
            )?;
            let changed = run_scoped(&baseline, &snapshot, Limits::default(), None)?.report;
            assert_eq!(
                changed
                    .records
                    .first()
                    .ok_or("changed record is absent")?
                    .result,
                ResultState::Error
            );
            assert_eq!(
                changed
                    .requirements
                    .first()
                    .ok_or("changed requirement is absent")?
                    .status,
                RequirementStatus::Unresolved
            );
            assert_eq!(changed.usage.provider_calls, 0);
        }
    }
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions restrict provenance opt-in to collections and preserve omitted false defaults"
)]
fn collection_provenance_flag_refuses_other_adapters_and_non_boolean_values() -> TestResult {
    let dir = directory();
    for adapter in [
        "raw-bytes/1",
        "inventory-json/1",
        "evidence-bundle/1",
        "text/1",
        "json/1",
        "json-lines/1",
    ] {
        let mut value = match adapter {
            "raw-bytes/1" => bytes_baseline(dir.path()),
            "inventory-json/1" => inventory_baseline(dir.path()),
            "evidence-bundle/1" => {
                serde_json::from_slice(include_bytes!("fixtures/bundle.baseline.json"))?
            }
            other => declaration(
                dir.path(),
                other,
                if other == "json-lines/1" {
                    "record"
                } else {
                    "document"
                },
                "none",
            )?,
        };
        if adapter == "json-lines/1" {
            *value
                .pointer_mut("/sources/bytes/media")
                .ok_or("JSON Lines media is absent")? = json!(["application/x-ndjson"]);
        }
        let alias = if adapter == "evidence-bundle/1" {
            "bundle"
        } else {
            "bytes"
        };
        let pointer = format!("/sources/{alias}");
        let _original = validate(&value, dir.path());
        value
            .pointer_mut(&pointer)
            .and_then(Value::as_object_mut)
            .ok_or("source is absent")?
            .insert("include_provenance".into(), json!(true));
        let error = ValidatedBaseline::from_bytes(value.to_string().as_bytes(), dir.path())
            .err()
            .ok_or("noncollection provenance was accepted")?;
        assert!(
            error
                .message
                .contains("include_provenance requires collection/1"),
            "{adapter}"
        );
        value
            .pointer_mut(&pointer)
            .and_then(Value::as_object_mut)
            .ok_or("source is absent")?
            .insert("include_provenance".into(), json!(false));
        let disabled = validate(&value, dir.path());
        assert!(
            serde_json::to_value(disabled.baseline())?
                .pointer(&format!("{pointer}/include_provenance"))
                .is_none()
        );
    }
    for invalid in [Value::Null, json!("true"), json!(1), json!({})] {
        let mut value = collection_declaration(dir.path())?;
        value
            .pointer_mut("/sources/bytes")
            .and_then(Value::as_object_mut)
            .ok_or("collection source is absent")?
            .insert("include_provenance".into(), invalid);
        assert!(ValidatedBaseline::from_bytes(value.to_string().as_bytes(), dir.path()).is_err());
    }
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions check related-key matching and dependent decisions"
)]
fn related_inputs_match_all_declared_keys_before_answers_are_combined() -> TestResult {
    let dir = directory();
    let mut value = collection_declaration(dir.path())?;
    let mut second = value
        .pointer("/rules/0")
        .and_then(Value::as_object)
        .ok_or("first rule is absent")?
        .clone();
    second.insert("id".into(), json!("B"));
    *second
        .get_mut("scope")
        .and_then(|scope| scope.get_mut("related"))
        .ok_or("related scope is absent")? = json!([{"role":"allowlist","input":"allowlist","unit":"document","on":[],"allow_empty":false}]);
    value
        .get_mut("rules")
        .and_then(Value::as_array_mut)
        .ok_or("rules are absent")?
        .push(Value::Object(second));
    append_combination(&mut value, "SAME-EVENT", &["A", "B"], "record", "all_fail")?;
    append_combination(
        &mut value,
        "SUMMARY",
        &["SAME-EVENT"],
        "document",
        "any_fail",
    )?;
    for pointer in ["/rules/2/scope", "/rules/3/scope"] {
        value
            .pointer_mut(pointer)
            .and_then(Value::as_object_mut)
            .ok_or("combined scope is absent")?
            .insert("input".into(), json!("events"));
    }
    *value
        .pointer_mut("/profiles/0/select")
        .ok_or("profile selection is absent")? = json!(["SUMMARY"]);
    let baseline = validate(&value, dir.path());
    std::fs::write(
        dir.path().join("events.json"),
        br#"[{"host":"a","process":7},{"host":"b","process":7}]"#,
    )?;
    std::fs::write(dir.path().join("processes.json"), br#"[{"host":"b","id":7,"command":"beta"},{"host":"a","id":7,"command":"alpha"},{"host":"a","id":"7","command":"wrong type"},{"host":"c","id":7,"command":"unrelated"}]"#)?;
    std::fs::write(dir.path().join("allowlist.json"), b"[]")?;
    let path = write_collection(
        dir.path(),
        json!({
            "events":{"adapter":"json/1","path":"events.json"},
            "processes":{"adapter":"json/1","path":"processes.json"},
            "allowlist":{"adapter":"json/1","path":"allowlist.json"}
        }),
    )?;
    let snapshot = Snapshot::collection_file(
        &path,
        None,
        &baseline,
        "default",
        "bytes",
        &Limits::default(),
    )?;
    let prepared = run_scoped(&baseline, &snapshot, Limits::default(), None)?;
    assert_eq!(prepared.report.records.len(), 7);
    for (record, expected) in prepared
        .report
        .records
        .iter()
        .take(2)
        .zip(["alpha", "beta"])
    {
        let frame: Value = serde_json::from_slice(
            &record
                .evidence
                .as_ref()
                .ok_or("related evidence is absent")?
                .bytes,
        )?;
        let peers = frame
            .pointer("/related/process")
            .and_then(Value::as_array)
            .ok_or("related process is absent")?;
        let [peer] = peers.as_slice() else {
            return Err("expected exactly one matching process".into());
        };
        assert_eq!(peer.get("command"), Some(&json!(expected)));
        assert_eq!(
            record.target.metadata.pointer("/related/process/0/input"),
            Some(&json!("processes"))
        );
        assert_eq!(record.target.metadata.get("input"), Some(&json!("events")));
    }
    for (scores, expected) in [
        ([0.99, 0.01, 0.01, 0.99], "pass"),
        ([0.99, 0.01, 0.99, 0.01], "fail"),
        ([0.99, 0.01, 0.5, 0.01], "review"),
    ] {
        let mock = script(&prepared.report, &scores)?;
        let result = run_scoped(&baseline, &snapshot, Limits::default(), Some(&mock))?;
        assert_eq!(result.report.records.len(), 7);
        assert_eq!(
            result
                .report
                .records
                .last()
                .ok_or("summary record is absent")?
                .observation
                .as_ref()
                .ok_or("summary observation is absent")?
                .get("suggested_result"),
            Some(&json!(expected))
        );
        assert_eq!(result.report.usage.provider_calls, 4);
    }
    *value
        .pointer_mut("/rules/1/scope/input")
        .ok_or("second rule input is absent")? = json!("processes");
    assert!(ValidatedBaseline::from_bytes(value.to_string().as_bytes(), dir.path()).is_err());
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions distinguish missing related input from an empty file"
)]
fn missing_input_is_a_named_gap_and_never_an_empty_allowlist() -> TestResult {
    let dir = directory();
    let mut value = collection_declaration(dir.path())?;
    *value
        .pointer_mut("/rules/0/scope/related")
        .ok_or("related scope is absent")? = json!([{"role":"allowlist","input":"allowlist","unit":"record","on":[],"allow_empty":true}]);
    append_combination(&mut value, "SUMMARY", &["A"], "document", "any_fail")?;
    value
        .pointer_mut("/rules/1/scope")
        .and_then(Value::as_object_mut)
        .ok_or("summary scope is absent")?
        .insert("input".into(), json!("events"));
    let baseline = validate(&value, dir.path());
    std::fs::write(dir.path().join("events.json"), b"[1]")?;
    std::fs::write(dir.path().join("allowlist.json"), b"[]")?;
    for input in [
        Some(json!({"adapter":"json/1","path":"allowlist.json"})),
        Some(json!({"adapter":"json/1","unavailable":"export not supplied"})),
        None,
    ] {
        let mut inputs = json!({"events":{"adapter":"json/1","path":"events.json"}});
        let available = input
            .as_ref()
            .and_then(|i| i.get("path"))
            .is_some_and(Value::is_string);
        if let Some(input) = input {
            inputs
                .as_object_mut()
                .ok_or("collection inputs are not an object")?
                .insert("allowlist".into(), input);
        }
        let path = write_collection(dir.path(), inputs)?;
        let snapshot = Snapshot::collection_file(
            &path,
            None,
            &baseline,
            "default",
            "bytes",
            &Limits::default(),
        )?;
        let report = run_scoped(&baseline, &snapshot, Limits::default(), None)?.report;
        let [answer, summary] = report.records.as_slice() else {
            return Err("expected answer and summary records".into());
        };
        assert_eq!(report.usage.provider_calls, 0);
        if available {
            let frame: Value = serde_json::from_slice(
                &answer
                    .evidence
                    .as_ref()
                    .ok_or("empty allowlist evidence is absent")?
                    .bytes,
            )?;
            assert_eq!(frame.pointer("/related/allowlist"), Some(&json!([])));
            let mock = script(&report, &[0.01])?;
            let result = run_scoped(&baseline, &snapshot, Limits::default(), Some(&mock))?;
            let [_, summary] = result.report.records.as_slice() else {
                return Err("expected answered and summary records".into());
            };
            assert_eq!(
                summary
                    .observation
                    .as_ref()
                    .ok_or("answered summary observation is absent")?
                    .get("suggested_result"),
                Some(&json!("pass"))
            );
        } else {
            assert_eq!(answer.result, ResultState::Error);
            assert!(
                answer
                    .reason
                    .as_ref()
                    .ok_or("missing allowlist refusal reason is absent")?
                    .contains("allowlist unavailable")
            );
            assert_eq!(
                summary
                    .observation
                    .as_ref()
                    .ok_or("refused summary observation is absent")?
                    .get("suggested_result"),
                Some(&json!("review"))
            );
        }
    }
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions check related keys, limits, and frozen source custody"
)]
fn related_evidence_refuses_incomplete_keys_limits_and_source_mutation() -> TestResult {
    let dir = directory();
    let value = collection_declaration(dir.path())?;
    let baseline = validate(&value, dir.path());
    std::fs::write(
        dir.path().join("events.json"),
        br#"[{"host":"a","process":7}]"#,
    )?;
    let path = write_collection(
        dir.path(),
        json!({"events":{"adapter":"json/1","path":"events.json"},"processes":{"adapter":"json/1","path":"processes.json"}}),
    )?;
    for peers in [
        r#"[{"host":"a"}]"#,
        r#"[{"host":"a","id":null}]"#,
        r#"[{"host":"a","id":"7"}]"#,
        r#"[]"#,
    ] {
        std::fs::write(dir.path().join("processes.json"), peers)?;
        let snapshot = Snapshot::collection_file(
            &path,
            None,
            &baseline,
            "default",
            "bytes",
            &Limits::default(),
        )?;
        let report = run_scoped(&baseline, &snapshot, Limits::default(), None)?.report;
        let [record] = report.records.as_slice() else {
            return Err("expected one related-key refusal".into());
        };
        assert_eq!(record.result, ResultState::Error);
        assert_eq!(report.usage.provider_calls, 0);
    }
    std::fs::write(
        dir.path().join("processes.json"),
        br#"[{"host":"a","id":7}]"#,
    )?;
    for limits in [
        Limits {
            targets: 0,
            ..Limits::default()
        },
        Limits {
            evidence_bytes: 1,
            ..Limits::default()
        },
        Limits {
            input_bytes: 1,
            ..Limits::default()
        },
        Limits {
            manifest_work: 1,
            ..Limits::default()
        },
    ] {
        assert!(
            Snapshot::collection_file(&path, None, &baseline, "default", "bytes", &limits).is_err()
        );
    }
    let snapshot = Snapshot::collection_file(
        &path,
        None,
        &baseline,
        "default",
        "bytes",
        &Limits::default(),
    )?;
    std::fs::write(
        dir.path().join("processes.json"),
        br#"[{"host":"a","id":8}]"#,
    )?;
    let report = run_scoped(&baseline, &snapshot, Limits::default(), None)?.report;
    let [record] = report.records.as_slice() else {
        return Err("expected one source-custody refusal".into());
    };
    assert_eq!(record.result, ResultState::Error);
    assert_eq!(report.usage.provider_calls, 0);
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions check inclusive byte-budget boundary"
)]
fn collection_input_budget_includes_manifest_and_every_file() -> TestResult {
    let dir = directory();
    let value = collection_declaration(dir.path())?;
    let baseline = validate(&value, dir.path());
    let events = br#"[{"host":"a","process":7}]"#;
    let peers = br#"[{"host":"a","id":7}]"#;
    std::fs::write(dir.path().join("events.json"), events)?;
    std::fs::write(dir.path().join("processes.json"), peers)?;
    let path = write_collection(
        dir.path(),
        json!({
        "events":{"adapter":"json/1","path":"events.json"},
        "processes":{"adapter":"json/1","path":"processes.json"}}),
    )?;
    let total = u64::try_from(
        std::fs::read(&path)?
            .len()
            .checked_add(events.len())
            .and_then(|total| total.checked_add(peers.len()))
            .ok_or("collection byte total overflow")?,
    )?;
    let limits = Limits {
        input_bytes: total,
        ..Limits::default()
    };
    let snapshot = Snapshot::collection_file(&path, None, &baseline, "default", "bytes", &limits)?;
    assert!(
        !run_scoped(&baseline, &snapshot, limits.clone(), None)?
            .report
            .records
            .is_empty()
    );
    assert!(
        Snapshot::collection_file(
            &path,
            None,
            &baseline,
            "default",
            "bytes",
            &Limits {
                input_bytes: total
                    .checked_sub(1)
                    .ok_or("collection byte total is zero")?,
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
    reason = "assertions check collection CLI output and path confinement"
)]
fn collection_cli_prepares_complete_files_and_confines_paths() -> TestResult {
    let dir = directory();
    let value = collection_declaration(dir.path())?;
    let baseline = validate(&value, dir.path());
    std::fs::write(
        dir.path().join("events.json"),
        br#"[{"host":"a","process":7}]"#,
    )?;
    std::fs::write(
        dir.path().join("processes.json"),
        br#"[{"host":"a","id":7}]"#,
    )?;
    let mut inputs = json!({"events":{"adapter":"json/1","path":"events.json"},"processes":{"adapter":"json/1","path":"processes.json"}});
    let path = write_collection(dir.path(), inputs.clone())?;
    let baseline_path = dir.path().join("baseline.json");
    let report_path = dir.path().join("report.json");
    std::fs::write(&baseline_path, value.to_string())?;
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_auditoad"))
        .args([
            "scan",
            "--profile",
            "default",
            "--source",
            "bytes",
            "--experimental",
            "--baseline",
        ])
        .arg(&baseline_path)
        .arg("--input")
        .arg(&path)
        .arg("--report")
        .arg(&report_path)
        .output()?;
    assert_eq!(
        output.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&std::fs::read(report_path)?)?;
    assert_eq!(report.get("target_count"), Some(&json!(1)));
    assert_eq!(report.pointer("/usage/provider_calls"), Some(&json!(0)));
    for bad in [
        "../events.json",
        "C:/events.json",
        "events.json/../events.json",
    ] {
        *inputs
            .pointer_mut("/processes/path")
            .ok_or("process path is absent")? = json!(bad);
        write_collection(dir.path(), inputs.clone())?;
        assert!(
            Snapshot::collection_file(
                &path,
                None,
                &baseline,
                "default",
                "bytes",
                &Limits::default()
            )
            .is_err()
        );
    }
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions check common scope contract across writing and reference inputs"
)]
fn collections_apply_the_same_scope_contract_to_writing_and_reference_documents() -> TestResult {
    let dir = directory();
    let mut value = collection_declaration(dir.path())?;
    *value
        .pointer_mut("/rules/0/scope")
        .ok_or("scope is absent")? = json!({"input":"draft","unit":"paragraph","context":"document",
        "related":[{"role":"brief","input":"brief","unit":"document","on":[],"allow_empty":false}]});
    let baseline = validate(&value, dir.path());
    std::fs::write(
        dir.path().join("draft.txt"),
        "First paragraph.\n\nSecond paragraph.",
    )?;
    std::fs::write(dir.path().join("brief.txt"), "Write for a first-time user.")?;
    let path = write_collection(
        dir.path(),
        json!({"draft":{"adapter":"text/1","path":"draft.txt"},"brief":{"adapter":"text/1","path":"brief.txt"}}),
    )?;
    let snapshot = Snapshot::collection_file(
        &path,
        None,
        &baseline,
        "default",
        "bytes",
        &Limits::default(),
    )?;
    let report = run_scoped(&baseline, &snapshot, Limits::default(), None)?.report;
    assert_eq!(report.records.len(), 2);
    for record in &report.records {
        let frame: Value = serde_json::from_slice(
            &record
                .evidence
                .as_ref()
                .ok_or("document evidence is absent")?
                .bytes,
        )?;
        assert_eq!(
            frame.get("context"),
            Some(&json!("First paragraph.\n\nSecond paragraph."))
        );
        assert_eq!(
            frame.pointer("/related/brief"),
            Some(&json!(["Write for a first-time user."]))
        );
        assert!(
            frame
                .get("subject")
                .and_then(Value::as_str)
                .ok_or("paragraph subject is absent")?
                .ends_with("paragraph.")
        );
    }
    Ok(())
}

fn consulting_declaration(root: &std::path::Path, run_when: &str) -> TestResult<Value> {
    let mut value = declaration(root, "json/1", "record", "none")?;
    let mut question = value
        .pointer("/rules/0")
        .and_then(Value::as_object)
        .ok_or("first rule is absent")?
        .clone();
    *value
        .pointer_mut("/rules/0/evaluator")
        .ok_or("first evaluator is absent")? =
        json!({"kind":"json-pointer-equals","contract":"json-pointer-equals/1"});
    *value
        .pointer_mut("/rules/0/check")
        .ok_or("first check is absent")? = json!({"kind":"json-pointer-equals/1","pointer":"/subject/kind",
        "expected":"exec","fail_when":"equal"});
    let candidate = br#"{"subject":{"kind":"exec"}}"#;
    let ordinary = br#"{"subject":{"kind":"dns"}}"#;
    *value
        .pointer_mut("/rules/0/fixtures")
        .ok_or("first fixtures are absent")? = json!({
        "fail":[fixture(root,"candidate.json",candidate,candidate)],
        "pass":[fixture(root,"ordinary.json",ordinary,ordinary)]});
    question.insert("id".into(), json!("B"));
    question.insert("consult".into(), json!({"rules":["A"],"run_when":run_when}));
    value
        .get_mut("rules")
        .and_then(Value::as_array_mut)
        .ok_or("rules are absent")?
        .push(Value::Object(question));
    Ok(value)
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions check consulted evidence and provider-call gating"
)]
fn consulted_answers_join_evidence_and_gate_questions_without_provider_calls() -> TestResult {
    let dir = directory();
    let input = br#"[{"kind":"exec"},{"kind":"dns"},{}]"#;
    let gated = validate(&consulting_declaration(dir.path(), "any_fail")?, dir.path());
    let snapshot = Snapshot::scoped_input(
        input,
        "records.json",
        &gated,
        "default",
        "bytes",
        &Limits::default(),
    )?;
    let prepared = run_scoped(&gated, &snapshot, Limits::default(), None)?;
    let mock = script(&prepared.report, &[0.95, 0.5, 0.5])?;
    let report = run_scoped(&gated, &snapshot, Limits::default(), Some(&mock))?.report;
    assert_eq!(report.usage.provider_calls, 1);
    let questions: Vec<_> = report.records.iter().filter(|r| r.rule.id == "B").collect();
    let [first, second, third] = questions.as_slice() else {
        return Err("expected three consulted answer records".into());
    };
    assert_eq!(
        first
            .observation
            .as_ref()
            .ok_or("first consulted observation is absent")?
            .get("suggested_result"),
        Some(&json!("fail")),
        "{:?} {:?}",
        first.result,
        first.reason
    );
    assert_eq!(
        second
            .observation
            .as_ref()
            .ok_or("second consulted observation is absent")?
            .get("suggested_result"),
        Some(&json!("pass"))
    );
    assert_eq!(
        third
            .observation
            .as_ref()
            .ok_or("third consulted observation is absent")?
            .get("suggested_result"),
        Some(&json!("review"))
    );
    for record in [second, third] {
        assert_eq!(record.result, ResultState::NotEvaluated);
        let observation = record
            .observation
            .as_ref()
            .ok_or("gated observation is absent")?;
        assert_eq!(observation.get("type"), Some(&json!("consult/1")));
        assert_eq!(observation.get("evaluated"), Some(&json!(false)));
        assert!(observation.get("request_bytes").is_none());
    }
    let frame: Value = serde_json::from_slice(
        &first
            .evidence
            .as_ref()
            .ok_or("consulted evidence is absent")?
            .bytes,
    )?;
    assert_eq!(frame.pointer("/subject/kind"), Some(&json!("exec")));
    let prior = frame
        .get("prior")
        .and_then(Value::as_array)
        .ok_or("prior answers are absent")?;
    let [prior] = prior.as_slice() else {
        return Err("expected exactly one consulted prior answer".into());
    };
    assert_eq!(prior.pointer("/rule/id"), Some(&json!("A")));
    assert!(prior.get("check_id").is_none());
    assert_eq!(prior.get("decision"), Some(&json!("fail")));
    assert_eq!(prior.pointer("/observation/value"), Some(&json!("equal")));

    let always = validate(&consulting_declaration(dir.path(), "always")?, dir.path());
    let snapshot = Snapshot::scoped_input(
        input,
        "records.json",
        &always,
        "default",
        "bytes",
        &Limits::default(),
    )?;
    let prepared = run_scoped(&always, &snapshot, Limits::default(), None)?;
    let mock = script(&prepared.report, &[0.95, 0.05, 0.5])?;
    let report = run_scoped(&always, &snapshot, Limits::default(), Some(&mock))?.report;
    assert_eq!(report.usage.provider_calls, 3);
    let unresolved = report
        .records
        .iter()
        .filter(|r| r.rule.id == "B")
        .nth(2)
        .ok_or("third unconditional answer is absent")?;
    let frame: Value = serde_json::from_slice(
        &unresolved
            .evidence
            .as_ref()
            .ok_or("unresolved evidence is absent")?
            .bytes,
    )?;
    let prior = frame
        .get("prior")
        .and_then(Value::as_array)
        .ok_or("unresolved prior answers are absent")?;
    let [prior] = prior.as_slice() else {
        return Err("expected one unresolved prior answer".into());
    };
    assert_eq!(prior.get("decision"), Some(&Value::Null));
    assert_eq!(prior.get("terminal_result"), Some(&json!("not_evaluated")));
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions check consultation contract refusals"
)]
fn consult_refuses_answer_rules_forward_references_and_non_json_frames() -> TestResult {
    let dir = directory();
    let refused = |value: &Value| {
        ValidatedBaseline::from_bytes(value.to_string().as_bytes(), dir.path()).is_err()
    };
    let mut forward = consulting_declaration(dir.path(), "any_fail")?;
    forward
        .pointer_mut("/rules/0")
        .and_then(Value::as_object_mut)
        .ok_or("first rule is absent")?
        .insert("consult".into(), json!({"rules":["B"]}));
    assert!(refused(&forward));
    let mut combined = consulting_declaration(dir.path(), "any_fail")?;
    append_combination(&mut combined, "C", &["A"], "record", "any_fail")?;
    combined
        .pointer_mut("/rules/2")
        .and_then(Value::as_object_mut)
        .ok_or("combined rule is absent")?
        .insert("consult".into(), json!({"rules":["B"]}));
    assert!(refused(&combined));
    let mut unknown = consulting_declaration(dir.path(), "any_fail")?;
    *unknown
        .pointer_mut("/rules/1/consult")
        .ok_or("second consultation is absent")? = json!({"rules":["Z"]});
    assert!(refused(&unknown));
    let mut empty = consulting_declaration(dir.path(), "any_fail")?;
    *empty
        .pointer_mut("/rules/1/consult")
        .ok_or("second consultation is absent")? = json!({"rules":[]});
    assert!(refused(&empty));
    let mut raw = mock_baseline(dir.path());
    let original = raw
        .pointer("/rules/0")
        .and_then(Value::as_object)
        .ok_or("raw first rule is absent")?;
    let original_id = original
        .get("id")
        .ok_or("raw first rule ID is absent")?
        .clone();
    let mut second = original.clone();
    second.insert("id".into(), json!("B"));
    second.insert("consult".into(), json!({"rules":[original_id]}));
    raw.get_mut("rules")
        .and_then(Value::as_array_mut)
        .ok_or("raw rules are absent")?
        .push(Value::Object(second));
    assert!(refused(&raw));
    Ok(())
}
