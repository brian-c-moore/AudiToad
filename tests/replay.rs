mod support;
use auditoad::{
    audit::{RunDefinition, RunOptions, run_file, run_one},
    sha256,
};
use serde_json::{Value, json};
use std::{fs, path::Path, process::Command};
use support::{bytes_baseline, directory};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn write(path: &Path, value: &Value) -> TestResult {
    fs::write(path, serde_json::to_vec_pretty(value)?)?;
    Ok(())
}

fn setup(root: &Path, backend: &str, kind: &str) -> TestResult<RunDefinition> {
    let mut baseline = bytes_baseline(root);
    *baseline
        .pointer_mut("/baseline/status")
        .ok_or("fixture status is absent")? = json!("draft");
    *baseline
        .pointer_mut("/sources/bytes")
        .ok_or("fixture source is absent")? = json!({"adapter":"text/1","media":["text/plain"]});
    *baseline
        .pointer_mut("/evidence/bytes")
        .ok_or("fixture evidence builder is absent")? =
        json!({"builder":"scoped-input/1","builder_revision":"r1"});
    let rule = baseline
        .pointer_mut("/rules/0")
        .and_then(Value::as_object_mut)
        .ok_or("fixture rule is absent")?;
    rule.insert("scope_kind".into(), json!("whole"));
    rule.insert("scope".into(), json!({"unit":"document","context":"none"}));
    rule.insert("fixtures".into(), json!({"pass":[],"fail":[]}));
    rule.insert("evaluator".into(), json!({"kind":"model","contract":kind}));
    let mut check = match kind {
        "yes-no/1" => {
            json!({"kind":kind,"instructions":"Is alpha present?","criteria_true":"alpha is present",
            "criteria_false":"alpha is absent","pass_below":0.1,"fail_at_or_above":0.9})
        }
        "choice/1" => json!({"kind":kind,"instructions":"Choose the source category.","options":{
            "a":{"description":"alpha","result":"fail"},"b":{"description":"other","result":"pass"},
            "c":{"description":"unknown","result":"review"}},
            "min_choice_probability":0.8,"min_confidence":0.8}),
        "extract/1" => json!({"kind":kind,"instructions":"Quote the word alpha.",
            "fields":{"quote":{"type":"quote","description":"The exact word."}}}),
        _ => return Err(format!("unsupported replay fixture contract {kind}").into()),
    };
    check
        .as_object_mut()
        .ok_or("fixture check is not an object")?
        .insert("state_projection".into(), json!({"source":"/subject"}));
    rule.insert("check".into(), check);
    *baseline
        .pointer_mut("/profiles/0/allowed_egress")
        .ok_or("fixture egress policy is absent")? = json!(["loopback"]);
    write(&root.join("baseline.json"), &baseline)?;
    write(
        &root.join("evaluators.json"),
        &json!({"schema":"auditoad-evaluators/1",
        "evaluators":{"default":{"backend":backend,"model":"test-model",
            "endpoint":"http://127.0.0.1:9/v1/test","key":{"file":"absent-secret"}}}}),
    )?;
    fs::write(root.join("source.txt"), "alpha\n")?;
    Ok(RunDefinition {
        name: "replay-test".into(),
        baseline: root.join("baseline.json"),
        input: root.join("source.txt"),
        report: root.join("prepared.json"),
        profile: None,
        source: None,
        project_root: None,
        evaluators: Some(root.join("evaluators.json")),
        labels: None,
        mock: None,
        replay: None,
        reuse: None,
    })
}

fn scan(definition: &RunDefinition) -> Result<auditoad::PublishedScan, auditoad::ScanError> {
    run_one(definition, &RunOptions::default(), |_| {}, |_| {})
}

// Synthetic protocol fixtures exercise the real decoders; these are never measured model runs.
fn transcript(definition: &RunDefinition, backend: &str, kind: &str) -> TestResult<Value> {
    scan(definition)?;
    let mut report: Value = serde_json::from_slice(&fs::read(&definition.report)?)?;
    report
        .as_object_mut()
        .ok_or("prepared report is not an object")?
        .insert(
            "test_fixture".into(),
            json!("synthetic transcript, not real inference"),
        );
    let observation = report
        .pointer_mut("/records/0/observation")
        .ok_or("prepared observation is absent")?;
    let body = if backend == "typesafe-jev" {
        let answer = if kind == "yes-no/1" {
            json!({"type":"noul","noul":0.95})
        } else {
            json!({"type":"choice","choice":"a","confidence":0.95,"probabilities":{"a":0.95,"b":0.04,"c":0.01}})
        };
        let question_id = observation
            .get("question_id")
            .and_then(Value::as_str)
            .ok_or("prepared question identity is absent")?;
        json!({"model":"test-model","answers":{question_id:answer},
            "usage":{"input_tokens":12,"output_tokens":3}})
    } else if kind == "extract/1" {
        json!({"model":"test-model","choices":[{"message":{"content":"{\"quote\":\"alpha\"}"}}]})
    } else {
        let (a, b) = if kind == "yes-no/1" {
            ("true", "false")
        } else {
            ("A", "B")
        };
        json!({"model":"test-model","choices":[{"logprobs":{"content":[{"top_logprobs":[
            {"token":a,"logprob":-0.01},{"token":b,"logprob":-5.0}]}]}}]})
    };
    response(observation, &body)?;
    // The importer must decode retained bytes, not trust a copied summary probability.
    observation
        .as_object_mut()
        .ok_or("prepared observation is not an object")?
        .insert("probability".into(), json!(0.0));
    Ok(report)
}

fn response(observation: &mut Value, body: &Value) -> TestResult {
    let text = body.to_string();
    let fields = observation
        .as_object_mut()
        .ok_or("response observation is not an object")?;
    fields.insert("http_status".into(), json!(200));
    fields.insert("response_sha256".into(), json!(sha256(text.as_bytes())));
    fields.insert(
        "response_bytes".into(),
        json!({"encoding":"utf-8","text":text}),
    );
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions check decoder results and retained custody"
)]
fn retained_bytes_use_each_installed_decoder_without_keys_or_network() -> TestResult {
    for (backend, kind) in [
        ("typesafe-jev", "yes-no/1"),
        ("typesafe-jev", "choice/1"),
        ("openai-compatible", "yes-no/1"),
        ("openai-compatible", "choice/1"),
        ("openai-compatible", "extract/1"),
    ] {
        let dir = directory();
        let mut definition = setup(dir.path(), backend, kind)?;
        let original = transcript(&definition, backend, kind)?;
        let replay = dir.path().join("retained.json");
        write(&replay, &original)?;
        definition.replay = Some(replay.clone());
        definition.report = dir.path().join("replayed.json");
        let result = scan(&definition)?;
        let [record] = result.scan.report.records.as_slice() else {
            return Err("expected one replayed record".into());
        };
        let observation = record
            .observation
            .as_ref()
            .ok_or("replayed observation is absent")?;
        assert_eq!(result.scan.exit_code, 2);
        assert_eq!(result.scan.report.usage.provider_calls, 1);
        assert_eq!(observation.get("mock"), Some(&json!(false)));
        assert_eq!(
            observation.pointer("/replay/report_sha256"),
            Some(&json!(sha256(&fs::read(replay)?)))
        );
        assert_eq!(
            observation
                .get("response_sha256")
                .ok_or("replayed response digest is absent")?,
            original
                .pointer("/records/0/observation/response_sha256")
                .ok_or("original response digest is absent")?
        );
        if kind == "extract/1" {
            assert_eq!(observation.pointer("/fields/quote"), Some(&json!("alpha")));
        } else {
            assert_eq!(
                observation.get("suggested_result"),
                Some(&json!("fail")),
                "{observation}"
            );
        }
        assert!(!dir.path().join("absent-secret").exists());
    }
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions require every custody and mode mutation to refuse without publication"
)]
fn replay_refuses_tampering_duplicates_changed_sources_and_live_mock_conflicts() -> TestResult {
    let dir = directory();
    let root = dir.path();
    let mut definition = setup(root, "typesafe-jev", "yes-no/1")?;
    let original = transcript(&definition, "typesafe-jev", "yes-no/1")?;
    let replay = root.join("retained.json");
    definition.replay = Some(replay.clone());
    definition.report = root.join("replayed.json");
    for mutation in [
        "source",
        "snapshot",
        "request",
        "response",
        "evidence",
        "duplicate",
        "mock",
    ] {
        let mut changed = original.clone();
        match mutation {
            "duplicate" => changed
                .get_mut("records")
                .and_then(Value::as_array_mut)
                .ok_or("retained records are absent")?
                .push(
                    original
                        .pointer("/records/0")
                        .ok_or("original record is absent")?
                        .clone(),
                ),
            other => {
                let (pointer, value) = match other {
                    "source" => ("/source/input_sha256", json!("0".repeat(64))),
                    "snapshot" => ("/source/snapshot_id", json!("changed")),
                    "request" => (
                        "/records/0/observation/request_bytes/text",
                        json!("changed"),
                    ),
                    "response" => (
                        "/records/0/observation/response_bytes/text",
                        json!("changed"),
                    ),
                    "evidence" => ("/records/0/evidence/bytes/text", json!("changed")),
                    "mock" => ("/records/0/observation/mock", json!(true)),
                    _ => return Err(format!("unrecognized replay mutation {other}").into()),
                };
                *changed
                    .pointer_mut(pointer)
                    .ok_or_else(|| format!("mutation field {pointer} is absent"))? = value;
            }
        }
        write(&replay, &changed)?;
        assert!(scan(&definition).is_err(), "{mutation}");
        assert!(!definition.report.exists());
    }
    let mut already_replayed = original.clone();
    already_replayed
        .pointer_mut("/records/0/observation")
        .and_then(Value::as_object_mut)
        .ok_or("retained observation is absent")?
        .insert("replay".into(), json!({}));
    write(&replay, &already_replayed)?;
    assert!(
        scan(&definition).is_err(),
        "replay provenance cannot be replayed again"
    );
    assert!(!definition.report.exists());
    write(&replay, &original)?;
    assert!(
        run_one(
            &definition,
            &RunOptions {
                live: true,
                ..RunOptions::default()
            },
            |_| {},
            |_| {}
        )
        .is_err()
    );
    definition.mock = Some(root.join("nonexistent-mock.json"));
    assert!(scan(&definition).is_err());
    definition.mock = None;
    definition.report = replay.clone();
    assert!(scan(&definition).is_err());
    assert_eq!(
        serde_json::from_slice::<Value>(&fs::read(replay)?)?,
        original
    );
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions distinguish exchange mismatch from decoder failure"
)]
fn changed_request_and_missing_model_refuse_and_retained_bad_answers_reach_the_decoder()
-> TestResult {
    let dir = directory();
    let root = dir.path();
    let mut definition = setup(root, "typesafe-jev", "yes-no/1")?;
    let original = transcript(&definition, "typesafe-jev", "yes-no/1")?;
    let replay = root.join("retained.json");
    definition.replay = Some(replay.clone());
    definition.report = root.join("replayed.json");
    write(&replay, &original)?;
    let mut baseline: Value = serde_json::from_slice(&fs::read(&definition.baseline)?)?;
    *baseline
        .pointer_mut("/rules/0/check/instructions")
        .ok_or("question is absent")? = json!("Changed question");
    write(&definition.baseline, &baseline)?;
    let result = scan(&definition)?;
    assert!(
        result
            .scan
            .report
            .records
            .first()
            .ok_or("mismatch record is absent")?
            .reason
            .as_ref()
            .ok_or("mismatch reason is absent")?
            .contains("exact request differs")
    );
    *baseline
        .pointer_mut("/rules/0/check/instructions")
        .ok_or("question is absent")? = json!("Is alpha present?");
    write(&definition.baseline, &baseline)?;
    let mut changed = original.clone();
    *changed
        .pointer_mut("/records/0/observation/evaluator/name")
        .ok_or("evaluator alias is absent")? = json!("other");
    write(&replay, &changed)?;
    let result = scan(&definition)?;
    assert!(
        result
            .scan
            .report
            .records
            .first()
            .ok_or("missing-exchange record is absent")?
            .reason
            .as_ref()
            .ok_or("missing-exchange reason is absent")?
            .contains("no retained exchange")
    );
    response(
        changed
            .pointer_mut("/records/0/observation")
            .ok_or("retained observation is absent")?,
        &json!({"model":"wrong-model","answers":{},"usage":{"input_tokens":1,"output_tokens":1}}),
    )?;
    *changed
        .pointer_mut("/records/0/observation/evaluator/name")
        .ok_or("evaluator alias is absent")? = json!("default");
    write(&replay, &changed)?;
    let result = scan(&definition)?;
    let [record] = result.scan.report.records.as_slice() else {
        return Err("expected one decoded record".into());
    };
    assert_eq!(record.result, auditoad::schema::ResultState::Error);
    assert!(
        record
            .observation
            .as_ref()
            .ok_or("decoder-error observation is absent")?
            .get("suggested_result")
            .is_none()
    );
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions check each member's replay, reuse accounting and duplicate refusal"
)]
fn replay_keeps_each_combined_model_and_refuses_duplicate_members() -> TestResult {
    let dir = directory();
    let root = dir.path();
    let mut definition = setup(root, "typesafe-jev", "yes-no/1")?;
    let mut retained = transcript(&definition, "typesafe-jev", "yes-no/1")?;
    let original = retained
        .pointer("/records/0/observation")
        .ok_or("original observation is absent")?
        .clone();
    let mut a = original.clone();
    *a.pointer_mut("/evaluator/name")
        .ok_or("member a alias is absent")? = json!("a");
    let mut b = original;
    *b.pointer_mut("/evaluator/name")
        .ok_or("member b alias is absent")? = json!("b");
    *retained
        .pointer_mut("/records/0/observation")
        .ok_or("original observation is absent")? =
        json!({"type":"combined-models/1","members":[a,b]});
    let model = json!({"backend":"typesafe-jev","model":"test-model",
        "endpoint":"http://127.0.0.1:9/v1/test","key":{"file":"absent-secret"}});
    write(
        definition
            .evaluators
            .as_ref()
            .ok_or("evaluator file is absent")?,
        &json!({"schema":"auditoad-evaluators/1",
        "evaluators":{"a":model,"b":model},"roles":{"default":{"ask":["a","b"],"combine":"agreement"}}}),
    )?;
    let replay = root.join("combined.json");
    definition.replay = Some(replay.clone());
    definition.report = root.join("replayed.json");
    write(&replay, &retained)?;
    let result = scan(&definition)?;
    let [record] = result.scan.report.records.as_slice() else {
        return Err("expected one combined replay record".into());
    };
    let observation = record
        .observation
        .as_ref()
        .ok_or("combined observation is absent")?;
    assert_eq!(
        observation.get("suggested_result"),
        Some(&json!("fail")),
        "{observation}"
    );
    assert_eq!(result.scan.report.usage.provider_calls, 2);
    assert_eq!(result.scan.report.usage.reused_exchanges, 0);
    for member in observation
        .get("members")
        .and_then(Value::as_array)
        .ok_or("combined members are absent")?
    {
        assert!(member.get("replay").is_some_and(Value::is_object));
        assert_eq!(member.get("mock"), Some(&json!(false)));
    }
    let rule_id = retained
        .pointer("/records/0/rule/id")
        .ok_or("retained rule identity is absent")?;
    let target_id = retained
        .pointer("/records/0/target/id")
        .ok_or("retained target identity is absent")?;
    let labels = json!({"schema":"auditoad-labels/1","labels":[{
        "rule":rule_id,
        "target":target_id,"violation":true}]});
    let score = auditoad::score(
        &serde_json::to_vec(&result.scan.report)?,
        labels.to_string().as_bytes(),
    )?;
    assert_eq!(score.pointer("/overall/correct"), Some(&json!(1)));
    for member in score
        .pointer("/cases/0/members")
        .and_then(Value::as_array)
        .ok_or("scored members are absent")?
    {
        assert!(member.get("replay").is_some_and(Value::is_object));
    }
    definition.replay = None;
    definition.reuse = Some(vec![root.join("combined.json")]);
    definition.report = root.join("reused.json");
    let result = scan(&definition)?;
    assert_eq!(result.scan.report.usage.provider_calls, 0);
    assert_eq!(result.scan.report.usage.reused_exchanges, 2);
    for name in ["a", "b"] {
        let usage = result
            .scan
            .report
            .model_usage
            .get(name)
            .ok_or_else(|| format!("usage for {name} is absent"))?;
        assert_eq!(usage.provider_calls, 0);
        assert_eq!(usage.reused_exchanges, 1);
    }
    // An incomplete retained arrangement reuses only the available member.
    retained
        .pointer_mut("/records/0/observation/members")
        .and_then(Value::as_array_mut)
        .ok_or("retained members are absent")?
        .pop()
        .ok_or("expected a removed member")?;
    write(&replay, &retained)?;
    definition.report = root.join("partial.json");
    let partial = scan(&definition)?;
    assert_eq!(partial.scan.report.usage.provider_calls, 0);
    assert_eq!(partial.scan.report.usage.reused_exchanges, 1);
    assert_eq!(
        partial
            .scan
            .report
            .model_usage
            .get("a")
            .ok_or("member a usage is absent")?
            .reused_exchanges,
        1
    );
    assert_eq!(
        partial
            .scan
            .report
            .model_usage
            .get("b")
            .ok_or("member b usage is absent")?
            .reused_exchanges,
        0
    );
    let duplicate = retained
        .pointer("/records/0/observation/members/0")
        .ok_or("retained member is absent")?
        .clone();
    retained
        .pointer_mut("/records/0/observation/members")
        .and_then(Value::as_array_mut)
        .ok_or("retained members are absent")?
        .push(duplicate);
    definition.reuse = None;
    definition.replay = Some(root.join("combined.json"));
    definition.report = root.join("duplicate.json");
    *retained
        .pointer_mut("/records/0/observation/members/1/evaluator/name")
        .ok_or("duplicate alias is absent")? = json!("a");
    write(&replay, &retained)?;
    assert!(
        scan(&definition)
            .err()
            .ok_or("duplicate replay member was accepted")?
            .message
            .contains("duplicate replay model")
    );
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions check helper custody, dependent evidence and invented-quote refusal"
)]
fn replayed_extraction_supplies_the_same_evidence_to_a_later_judge() -> TestResult {
    let dir = directory();
    let root = dir.path();
    let mut definition = setup(root, "openai-compatible", "extract/1")?;
    let mut baseline: Value = serde_json::from_slice(&fs::read(&definition.baseline)?)?;
    let mut judge = baseline
        .pointer("/rules/0")
        .and_then(Value::as_object)
        .ok_or("helper rule is absent")?
        .clone();
    judge.insert("id".into(), json!("JUDGE"));
    judge.insert(
        "consult".into(),
        json!({"rules":[baseline.pointer("/rules/0/id").ok_or("helper identity is absent")?]}),
    );
    *judge
        .get_mut("evaluator")
        .and_then(|v| v.get_mut("contract"))
        .ok_or("judge contract is absent")? = json!("yes-no/1");
    judge.insert(
        "check".into(),
        json!({"kind":"yes-no/1","instructions":"Does the extracted quote say alpha?",
        "criteria_true":"the quote is alpha","criteria_false":"the quote is different",
        "pass_below":0.1,"fail_at_or_above":0.9,
        "state_projection":{"source":"/subject","quote":"/prior/0/observation/fields/quote"}}),
    );
    baseline
        .get_mut("rules")
        .and_then(Value::as_array_mut)
        .ok_or("fixture rules are absent")?
        .push(Value::Object(judge));
    write(&definition.baseline, &baseline)?;
    let retained = transcript(&definition, "openai-compatible", "extract/1")?;
    let replay = root.join("retained.json");
    definition.replay = Some(replay.clone());
    definition.report = root.join("replayed.json");
    write(&replay, &retained)?;
    let partial = scan(&definition)?;
    assert_eq!(
        partial
            .scan
            .report
            .records
            .get(1)
            .ok_or("dependent record is absent")?
            .result,
        auditoad::schema::ResultState::Error
    );
    // Complete this explicitly synthetic fixture with the newly prepared dependent request.
    let mut complete = serde_json::to_value(&partial.scan.report)?;
    complete
        .as_object_mut()
        .ok_or("helper report is not an object")?
        .insert(
            "test_fixture".into(),
            json!("synthetic helper/judge transcript, not real inference"),
        );
    for record in complete
        .get_mut("records")
        .and_then(Value::as_array_mut)
        .ok_or("helper report records are absent")?
    {
        record
            .get_mut("observation")
            .and_then(Value::as_object_mut)
            .ok_or("helper observation is absent")?
            .remove("replay");
    }
    response(
        complete
            .pointer_mut("/records/1/observation")
            .ok_or("judge observation is absent")?,
        &json!({"model":"test-model","choices":[{"logprobs":{"content":[
        {"top_logprobs":[{"token":"true","logprob":-0.01},{"token":"false","logprob":-5.0}]}]}}]}),
    )?;
    write(&replay, &complete)?;
    let result = scan(&definition)?;
    let [helper, judge] = result.scan.report.records.as_slice() else {
        return Err("expected helper and judge records".into());
    };
    assert_eq!(result.scan.report.usage.provider_calls, 2);
    assert_eq!(
        helper
            .observation
            .as_ref()
            .and_then(|v| v.pointer("/fields/quote")),
        Some(&json!("alpha"))
    );
    assert_eq!(
        judge
            .observation
            .as_ref()
            .and_then(|v| v.get("suggested_result")),
        Some(&json!("fail")),
        "{:?}",
        judge.reason
    );
    assert_eq!(
        json!(
            judge
                .evidence
                .as_ref()
                .ok_or("judge evidence is absent")?
                .sha256
        ),
        *complete
            .pointer("/records/1/evidence/sha256")
            .ok_or("prepared judge digest is absent")?
    );
    // A correctly hashed but invented quote is still refused by the existing extraction decoder.
    response(
        complete
            .pointer_mut("/records/0/observation")
            .ok_or("helper observation is absent")?,
        &json!({"model":"test-model","choices":[{"message":{"content":"{\"quote\":\"invented\"}"}}]}),
    )?;
    write(&replay, &complete)?;
    let refused = scan(&definition)?;
    let [helper, judge] = refused.scan.report.records.as_slice() else {
        return Err("expected refused helper and judge records".into());
    };
    assert_eq!(refused.scan.report.usage.provider_calls, 1);
    assert_eq!(helper.result, auditoad::schema::ResultState::Error);
    assert!(judge.observation.is_none());
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions check public CLI replay and suite input custody"
)]
fn cli_and_suite_replay_keep_provenance_and_protect_the_retained_input() -> TestResult {
    let dir = directory();
    let root = dir.path();
    let definition = setup(root, "typesafe-jev", "yes-no/1")?;
    let original = transcript(&definition, "typesafe-jev", "yes-no/1")?;
    write(&root.join("retained.json"), &original)?;
    let output = Command::new(env!("CARGO_BIN_EXE_auditoad"))
        .current_dir(root)
        .args([
            "scan",
            "--baseline",
            "baseline.json",
            "--input",
            "source.txt",
            "--evaluators",
            "evaluators.json",
            "--replay",
            "retained.json",
            "--report",
            "cli.json",
        ])
        .output()?;
    assert_eq!(
        output.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let cli: Value = serde_json::from_slice(&fs::read(root.join("cli.json"))?)?;
    assert!(
        cli.pointer("/records/0/observation/replay")
            .is_some_and(Value::is_object)
    );
    let mut suite = json!({"schema":"auditoad-audit/1","report":"suite.json","evaluators":"evaluators.json",
        "runs":[{"name":"offline","baseline":"baseline.json","input":"source.txt","replay":"retained.json","report":"offline.json"}]});
    write(&root.join("audit.json"), &suite)?;
    let result = run_file(
        &root.join("audit.json"),
        &RunOptions::default(),
        |_, _| {},
        |_, _| {},
    )?;
    assert_eq!(result.exit_code, 2);
    *suite
        .get_mut("report")
        .ok_or("suite report destination is absent")? = json!("retained.json");
    write(&root.join("audit.json"), &suite)?;
    assert!(
        run_file(
            &root.join("audit.json"),
            &RunOptions::default(),
            |_, _| {},
            |_, _| {}
        )
        .is_err()
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&fs::read(root.join("retained.json"))?)?,
        original
    );
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions check original-only mixed reuse, one-hop custody and exact request identity"
)]
fn reuse_answers_identical_exchanges_without_a_call_and_prepares_the_rest() -> TestResult {
    let dir = directory();
    let root = dir.path();
    let mut definition = setup(root, "typesafe-jev", "yes-no/1")?;
    let original = transcript(&definition, "typesafe-jev", "yes-no/1")?;
    let retained = root.join("retained.json");
    write(&retained, &original)?;
    definition.reuse = Some(vec![retained.clone()]);
    definition.report = root.join("reused.json");
    let result = scan(&definition)?;
    let [record] = result.scan.report.records.as_slice() else {
        return Err("expected one reused record".into());
    };
    let observation = record
        .observation
        .as_ref()
        .ok_or("reused observation is absent")?;
    assert_eq!(
        observation.get("suggested_result"),
        Some(&json!("fail")),
        "{observation}"
    );
    assert_eq!(
        observation.pointer("/reuse/report_sha256"),
        Some(&json!(sha256(&fs::read(&retained)?)))
    );
    assert_eq!(result.scan.report.usage.provider_calls, 0);
    assert_eq!(result.scan.report.usage.reused_exchanges, 1);
    // A report holding only reused answers supplies no original live exchanges to either role.
    let reused: Value = serde_json::from_slice(&fs::read(&definition.report)?)?;
    write(&root.join("second.json"), &reused)?;
    definition.reuse = Some(vec![root.join("second.json")]);
    definition.report = root.join("refused.json");
    assert!(scan(&definition).is_err());
    definition.reuse = None;
    definition.replay = Some(root.join("second.json"));
    assert!(scan(&definition).is_err());
    definition.replay = None;
    // A changed question is not reused; without --live it is only prepared.
    let mut baseline: Value = serde_json::from_slice(&fs::read(&definition.baseline)?)?;
    *baseline
        .pointer_mut("/rules/0/check/instructions")
        .ok_or("question is absent")? = json!("Changed question");
    write(&definition.baseline, &baseline)?;
    definition.reuse = Some(vec![retained.clone()]);
    definition.report = root.join("changed.json");
    let result = scan(&definition)?;
    assert_eq!(result.scan.report.usage.reused_exchanges, 0);
    assert!(
        result
            .scan
            .report
            .records
            .first()
            .ok_or("prepared record is absent")?
            .reason
            .as_ref()
            .ok_or("preparation reason is absent")?
            .contains("live evaluation not enabled")
    );
    // Five distinct synthetic live exchanges supply three earlier origins and two fresh
    // origins in a later mixed report. Its three derived members must never become origins.
    definition.reuse = None;
    definition.report = root.join("single-prepared.json");
    let template = baseline
        .pointer("/rules/0")
        .ok_or("fixture rule is absent")?
        .clone();
    let mut rules = Vec::new();
    let mut originals = Vec::new();
    for ordinal in 0..5 {
        let mut rule = template.clone();
        *rule.get_mut("id").ok_or("fixture rule id is absent")? = json!(format!("BYTES-{ordinal}"));
        *rule
            .pointer_mut("/check/instructions")
            .ok_or("fixture question is absent")? =
            json!(format!("Is alpha present for case {ordinal}?"));
        *baseline
            .get_mut("rules")
            .ok_or("fixture rules are absent")? = json!([rule.clone()]);
        write(&definition.baseline, &baseline)?;
        originals.push(
            transcript(&definition, "typesafe-jev", "yes-no/1")?
                .pointer("/records/0")
                .ok_or("synthetic original record is absent")?
                .clone(),
        );
        rules.push(rule);
    }
    *baseline
        .get_mut("rules")
        .ok_or("fixture rules are absent")? = json!(rules);
    write(&definition.baseline, &baseline)?;
    let mut first = original.clone();
    *first
        .get_mut("records")
        .ok_or("original records are absent")? = json!(
        originals
            .get(..3)
            .ok_or("three original records are absent")?
    );
    let first_path = root.join("first-three.json");
    write(&first_path, &first)?;
    let first_sha256 = sha256(&fs::read(&first_path)?);
    let mixed_path = root.join("mixed.json");
    definition.reuse = Some(vec![first_path.clone()]);
    definition.report = mixed_path.clone();
    let mixed_preparation = scan(&definition)?;
    assert_eq!(mixed_preparation.scan.report.usage.provider_calls, 0);
    assert_eq!(mixed_preparation.scan.report.usage.reused_exchanges, 3);
    let mut mixed: Value = serde_json::from_slice(&fs::read(&mixed_path)?)?;
    mixed
        .as_object_mut()
        .ok_or("mixed report is not an object")?
        .insert(
            "test_fixture".into(),
            json!("synthetic transcript, not real inference"),
        );
    let records = mixed
        .get_mut("records")
        .and_then(Value::as_array_mut)
        .ok_or("mixed records are absent")?;
    for ordinal in 3..5 {
        *records
            .get_mut(ordinal)
            .ok_or("mixed fresh record is absent")? = originals
            .get(ordinal)
            .ok_or("synthetic fresh record is absent")?
            .clone();
    }
    write(&mixed_path, &mixed)?;
    let mixed_sha256 = sha256(&fs::read(&mixed_path)?);
    definition.reuse = None;
    definition.replay = Some(mixed_path.clone());
    definition.report = root.join("mixed-replay-refused.json");
    assert!(scan(&definition).is_err());
    assert!(!definition.report.exists());
    for marker in ["mock", "replay"] {
        let mut prohibited = mixed.clone();
        prohibited
            .pointer_mut("/records/0/observation")
            .and_then(Value::as_object_mut)
            .ok_or("derived observation is absent")?
            .insert(
                marker.into(),
                if marker == "mock" {
                    json!(true)
                } else {
                    json!({})
                },
            );
        let path = root.join("prohibited.json");
        write(&path, &prohibited)?;
        for replay in [false, true] {
            definition.replay = replay.then(|| path.clone());
            definition.reuse = (!replay).then(|| vec![path.clone()]);
            definition.report = root.join("prohibited-output.json");
            assert!(scan(&definition).is_err(), "{marker}, replay={replay}");
            assert!(!definition.report.exists());
        }
    }
    definition.replay = None;
    definition.reuse = Some(vec![mixed_path.clone()]);
    definition.report = root.join("mixed-subset.json");
    let subset = scan(&definition)?;
    assert_eq!(subset.scan.report.usage.provider_calls, 0);
    assert_eq!(subset.scan.report.usage.reused_exchanges, 2);
    for (ordinal, record) in subset.scan.report.records.iter().enumerate() {
        let observation = record
            .observation
            .as_ref()
            .ok_or("subset observation is absent")?;
        assert_eq!(observation.get("reuse").is_some(), ordinal >= 3);
        if ordinal >= 3 {
            assert_eq!(
                observation.pointer("/reuse/report_sha256"),
                Some(&json!(mixed_sha256))
            );
        }
    }
    definition.reuse = Some(vec![first_path, mixed_path]);
    definition.report = root.join("all-five.json");
    let all = scan(&definition)?;
    assert_eq!(all.scan.report.usage.provider_calls, 0);
    assert_eq!(all.scan.report.usage.reused_exchanges, 5);
    for (ordinal, record) in all.scan.report.records.iter().enumerate() {
        let observation = record
            .observation
            .as_ref()
            .ok_or("reused observation is absent")?;
        assert_eq!(
            observation.pointer("/reuse/report_sha256"),
            Some(&json!(if ordinal < 3 {
                &first_sha256
            } else {
                &mixed_sha256
            }))
        );
        let origin = originals
            .get(ordinal)
            .ok_or("original exchange is absent")?;
        assert_eq!(
            observation.pointer("/reuse/check_id"),
            origin.get("check_id")
        );
        assert_eq!(
            observation.get("response_sha256"),
            origin.pointer("/observation/response_sha256")
        );
    }
    definition.reuse = Some(vec![definition.report.clone()]);
    definition.report = root.join("all-reused-refused.json");
    assert!(scan(&definition).is_err());
    assert!(!definition.report.exists());
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions check retained response identity and provider alias policy"
)]
fn compatible_chat_replay_checks_response_identity_and_reuse_binds_alias_policy() -> TestResult {
    let dir = directory();
    let root = dir.path();
    let mut definition = setup(root, "openai-compatible", "yes-no/1")?;
    let original = transcript(&definition, "openai-compatible", "yes-no/1")?;
    let retained = root.join("retained.json");
    write(&retained, &original)?;
    definition.report = root.join("result.json");
    definition.reuse = Some(vec![retained.clone()]);
    assert_eq!(scan(&definition)?.scan.report.usage.reused_exchanges, 1);
    let evaluator_path = definition
        .evaluators
        .as_ref()
        .ok_or("evaluator file is absent")?;
    let mut providers: Value = serde_json::from_slice(&fs::read(evaluator_path)?)?;
    providers
        .pointer_mut("/evaluators/default")
        .and_then(Value::as_object_mut)
        .ok_or("provider definition is absent")?
        .insert("response_model".into(), json!("changed-r2"));
    write(evaluator_path, &providers)?;
    let prepared = scan(&definition)?;
    assert_eq!(prepared.scan.report.usage.reused_exchanges, 0);
    assert_eq!(prepared.scan.report.usage.provider_calls, 0);
    assert!(
        prepared
            .scan
            .report
            .records
            .first()
            .ok_or("prepared record is absent")?
            .reason
            .as_ref()
            .ok_or("preparation reason is absent")?
            .contains("live evaluation not enabled")
    );
    providers
        .pointer_mut("/evaluators/default")
        .and_then(Value::as_object_mut)
        .ok_or("provider definition is absent")?
        .remove("response_model");
    write(evaluator_path, &providers)?;
    definition.reuse = None;
    definition.replay = Some(retained.clone());
    for model in [Value::Null, json!("other-model")] {
        let mut tampered = original.clone();
        let observation = tampered
            .pointer_mut("/records/0/observation")
            .ok_or("retained observation is absent")?;
        let mut body: Value = serde_json::from_str(
            observation
                .pointer("/response_bytes/text")
                .and_then(Value::as_str)
                .ok_or("retained response text is absent")?,
        )?;
        *body
            .get_mut("model")
            .ok_or("response model identity is absent")? = model;
        response(observation, &body)?;
        write(&retained, &tampered)?;
        let refused = scan(&definition)?;
        let [record] = refused.scan.report.records.as_slice() else {
            return Err("expected one refused decoder record".into());
        };
        assert_eq!(record.result, auditoad::schema::ResultState::Error);
        assert!(
            record
                .reason
                .as_ref()
                .ok_or("decoder refusal reason is absent")?
                .contains("model identifier")
        );
        assert!(
            record
                .observation
                .as_ref()
                .ok_or("decoder refusal observation is absent")?
                .get("suggested_result")
                .is_none()
        );
    }
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions check the exact combined retained-input budget boundary"
)]
fn reuse_source_preparation_bounds_all_reports_together_without_partial_admission() -> TestResult {
    let dir = directory();
    let root = dir.path();
    let definition = setup(root, "typesafe-jev", "yes-no/1")?;
    let original = transcript(&definition, "typesafe-jev", "yes-no/1")?;
    let paths = [root.join("first.json"), root.join("second.json")];
    for path in &paths {
        write(path, &original)?;
    }
    let [first, _] = &paths;
    let bytes = fs::metadata(first)?.len();
    let total = bytes.checked_mul(2).ok_or("fixture budget overflow")?;
    let below_total = total.checked_sub(1).ok_or("fixture budget underflow")?;
    let evaluator_path = definition
        .evaluators
        .as_ref()
        .ok_or("evaluator file is absent")?;
    let configured = || auditoad::Evaluators::from_file(evaluator_path, false, 10);
    assert!(configured()?.with_reuse(&paths, total).is_ok());
    // Each file fits individually; only the combined canonical allowance refuses the collection.
    assert!(configured()?.with_reuse(&paths, below_total).is_err());
    assert!(configured()?.with_reuse(&[], bytes).is_err());
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions check reuse conflicts, explicit fresh evaluation and retained-input protection"
)]
fn reuse_refuses_conflicts_and_operators_can_force_fresh_answers() -> TestResult {
    let dir = directory();
    let root = dir.path();
    let mut definition = setup(root, "typesafe-jev", "yes-no/1")?;
    let original = transcript(&definition, "typesafe-jev", "yes-no/1")?;
    let retained = root.join("retained.json");
    write(&retained, &original)?;
    definition.report = root.join("out.json");
    definition.reuse = Some(vec![retained.clone()]);
    definition.replay = Some(retained.clone());
    assert!(scan(&definition).is_err());
    definition.replay = None;
    definition.reuse = Some(vec![retained.clone(), retained.clone()]);
    assert!(scan(&definition).is_err());
    let mut mocked = original.clone();
    *mocked
        .pointer_mut("/records/0/observation/mock")
        .ok_or("retained mock marker is absent")? = json!(true);
    write(&root.join("mocked.json"), &mocked)?;
    definition.reuse = Some(vec![root.join("mocked.json")]);
    assert!(scan(&definition).is_err());
    definition.reuse = Some(vec![retained.clone()]);
    definition.report = retained.clone();
    assert!(scan(&definition).is_err());
    definition.report = root.join("fresh.json");
    let fresh = run_one(
        &definition,
        &RunOptions {
            reuse: Some(Vec::new()),
            ..RunOptions::default()
        },
        |_| {},
        |_| {},
    )?;
    assert_eq!(fresh.scan.report.usage.reused_exchanges, 0);
    let mut suite = json!({"schema":"auditoad-audit/1","report":"suite.json","evaluators":"evaluators.json",
        "reuse":["retained.json"],
        "runs":[{"name":"inherits","baseline":"baseline.json","input":"source.txt","report":"a.json"},
                {"name":"fresh","baseline":"baseline.json","input":"source.txt","report":"b.json","reuse":[]}]});
    write(&root.join("audit.json"), &suite)?;
    let result = run_file(
        &root.join("audit.json"),
        &RunOptions::default(),
        |_, _| {},
        |_, _| {},
    )?;
    assert_eq!(
        result.report.pointer("/runs/0/usage/reused_exchanges"),
        Some(&json!(1))
    );
    assert!(
        result
            .report
            .pointer("/runs/1/usage")
            .ok_or("fresh run usage is absent")?
            .get("reused_exchanges")
            .is_none()
    );
    *suite
        .pointer_mut("/runs/1/report")
        .ok_or("fresh run destination is absent")? = json!("retained.json");
    write(&root.join("audit.json"), &suite)?;
    assert!(
        run_file(
            &root.join("audit.json"),
            &RunOptions::default(),
            |_, _| {},
            |_, _| {}
        )
        .is_err()
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&fs::read(&retained)?)?,
        original
    );
    Ok(())
}
