mod support;
use auditoad::{
    Evaluators, MockModel, ScanRequest, Snapshot, ValidatedBaseline, scan,
    scan_to_file_with_evaluators,
    schema::{Limits, Record, ResultState},
    sha256,
};
use serde_json::{Value, json};
use std::{fs, path::Path};
use support::directory;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn bundle(root: &Path) -> TestResult<std::path::PathBuf> {
    fs::write(
        root.join("code.txt"),
        "header\nopen(request.args['name'])\nfooter\n",
    )?;
    fs::write(
        root.join("policy.md"),
        "Files must not be opened by request data.\n",
    )?;
    let value = json!({"schema":"auditoad-evidence-bundle/1","files":{
        "code.txt":sha256(&fs::read(root.join("code.txt"))?),
        "policy.md":sha256(&fs::read(root.join("policy.md"))?)},
        "packets":[{"id":"case","kind":"code","scope_kind":"site",
        "parts":[{"role":"subject","path":"code.txt"},
        {"role":"policy","path":"policy.md"}]}]});
    let path = root.join("bundle.json");
    fs::write(&path, value.to_string())?;
    Ok(path)
}

fn question(id: &str, role: &str, text: &str) -> Value {
    json!({"id":id,"revision":"r1","source":"evidence","group":"TEST","risk":"low","scope_kind":"site",
        "title":id,"evidence":"parts","evaluator":{"kind":"model","contract":"yes-no/1","role":role},
        "check":{"kind":"yes-no/1","instructions":text,"criteria_true":"yes","criteria_false":"no",
            "pass_below":0.1,"fail_at_or_above":0.9,"max_request_bytes":null},
        "applicability":{"include":["code"],"exclude":[]},"falsifier":"test","fixtures":{"fail":[],"pass":[]}})
}

fn baseline(rules: Vec<Value>, root: &Path) -> TestResult<ValidatedBaseline> {
    let value = json!({"schema":"auditoad-baseline/1",
        "baseline":{"id":"cooperation","version":"1","title":"Cooperation","publisher":"tests","status":"draft"},
        "sources":{"evidence":{"adapter":"evidence-bundle/1","media":["application/vnd.auditoad.bundle+json"]}},
        "evidence":{"parts":{"builder":"declared-parts/1","builder_revision":"r1","required_roles":["subject","policy"]}},
        "groups":[{"id":"TEST","title":"Test"}],"rules":rules,
        "profiles":[{"id":"all","select":["*"],"block_on":["fail","review","error","not_evaluated"],"allowed_egress":["loopback"]}]});
    Ok(ValidatedBaseline::from_bytes(
        value.to_string().as_bytes(),
        root,
    )?)
}

fn evaluators(roles: Value, root: &Path) -> TestResult<Evaluators> {
    let model = |name: &str| json!({"backend":"openai-compatible","model":name,"endpoint":"http://127.0.0.1:9/v1/chat/completions"});
    let file = json!({"schema":"auditoad-evaluators/1",
        "evaluators":{"a":model("a"),"b":model("b")},"roles":roles});
    Ok(Evaluators::from_bytes(
        file.to_string().as_bytes(),
        root,
        false,
        30,
    )?)
}

fn request<'a>(
    baseline: &'a ValidatedBaseline,
    snapshot: &'a Snapshot,
    mock: &'a MockModel,
) -> ScanRequest<'a> {
    ScanRequest {
        baseline,
        profile: "all",
        source_alias: "evidence",
        snapshot,
        limits: Limits::default(),
        experimental: true,
        mock: Some(mock),
    }
}

fn instructions(record: &Record, baseline: &ValidatedBaseline) -> TestResult<String> {
    let rule = baseline
        .baseline()
        .rules
        .iter()
        .find(|r| r.id == record.rule.id)
        .ok_or("record's rule is absent from the test baseline")?;
    let text = match &rule.check {
        auditoad::schema::Check::YesNo { instructions, .. }
        | auditoad::schema::Check::Extract { instructions, .. } => instructions,
        _ => return Err("expected a yes-no or extraction test rule".into()),
    };
    Ok(sha256(text.as_bytes()))
}

fn reply(
    record: &Record,
    baseline: &ValidatedBaseline,
    model: &str,
    response: Value,
) -> TestResult<Value> {
    Ok(json!({"rule":record.rule.id,"revision":"r1","model":model,
        "evidence_sha256":record.evidence.as_ref().ok_or("reply evidence is absent")?.sha256,
        "instructions_sha256":instructions(record, baseline)?,"response":response}))
}

fn probability(value: f64) -> Value {
    json!({"kind":"probability","value":value})
}

fn mock(replies: Vec<Value>) -> TestResult<MockModel> {
    Ok(MockModel::from_bytes(
        json!({"schema":"auditoad-mock-model/1","replies":replies})
            .to_string()
            .as_bytes(),
    )?)
}

fn run(
    baseline: &ValidatedBaseline,
    snapshot: &Snapshot,
    evaluators: &Evaluators,
    mock: &MockModel,
    root: &Path,
) -> TestResult<auditoad::ScanResult> {
    Ok(scan_to_file_with_evaluators(
        request(baseline, snapshot, mock),
        &root.join("report.json"),
        evaluators,
    )?
    .scan)
}

fn suggested(record: &Record) -> TestResult<Value> {
    Ok(record
        .observation
        .as_ref()
        .and_then(|v| v.get("suggested_result"))
        .ok_or("record's suggested result is absent")?
        .clone())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions check helper custody, experimental propagation and malformed extraction refusal"
)]
fn image_helper_fields_keep_custody_and_local_decisions_remain_experimental() -> TestResult {
    let dir = directory();
    let root = dir.path();
    let path = bundle(root)?;
    let mut manifest: Value = serde_json::from_slice(&fs::read(&path)?)?;
    let image = support::png_header_fixture(100, 40);
    fs::write(root.join("screen.png"), &image)?;
    manifest
        .get_mut("files")
        .and_then(Value::as_object_mut)
        .ok_or("fixture files are absent")?
        .insert(
            "screen.png".into(),
            json!({"sha256":sha256(&image),"media":"image/png"}),
        );
    *manifest
        .pointer_mut("/packets/0/parts/0")
        .ok_or("fixture subject is absent")? = json!({"role":"subject","path":"screen.png",
        "region":{"x":0,"y":0,"width":40,"height":20}});
    fs::write(&path, manifest.to_string())?;
    let snapshot = Snapshot::bundle(&path, root, &Limits::default())?;
    let mut helper = question("OCR", "helper", "unused");
    *helper
        .pointer_mut("/evaluator/contract")
        .ok_or("helper contract is absent")? = json!("extract/1");
    *helper.get_mut("check").ok_or("helper check is absent")? = json!({"kind":"extract/1",
        "instructions":"Transcribe the text visible in the declared region.",
        "fields":{"text":{"type":"string","description":"Text visible in the declared image region."}},
        "state_projection":{"image":"/parts/0"}});
    let mut judge = question("JUDGE", "judge", "unused");
    *judge
        .get_mut("evaluator")
        .ok_or("judge evaluator is absent")? =
        json!({"kind":"json-pointer-equals","contract":"json-pointer-equals/1"});
    *judge.get_mut("check").ok_or("judge check is absent")? = json!({"kind":"json-pointer-equals/1","pointer":"/prior/0/observation/fields/text",
        "expected":"Encryption disabled","fail_when":"equal"});
    let fixture = |name: &str, text: &str| {
        let frame = json!({"prior":[{"observation":{"fields":{"text":text}}}]})
            .to_string()
            .into_bytes();
        support::fixture(root, name, &frame, &frame)
    };
    *judge
        .get_mut("fixtures")
        .ok_or("judge fixtures are absent")? = json!({"fail":[fixture("ocr-disabled.json","Encryption disabled")],
        "pass":[fixture("ocr-enabled.json","Encryption enabled")]});
    judge
        .as_object_mut()
        .ok_or("judge is not an object")?
        .insert("consult".into(), json!({"rules":["OCR"]}));
    let mut derived = judge.clone();
    for (pointer, replacement) in [
        ("/id", json!("DERIVED")),
        ("/consult", json!({"rules":["JUDGE"]})),
        ("/check/pointer", json!("/prior/0/observation/value")),
        ("/check/expected", json!("equal")),
    ] {
        *derived
            .pointer_mut(pointer)
            .ok_or_else(|| format!("derived field {pointer} is absent"))? = replacement;
    }
    let derived_fixture = |name: &str, value: &str| {
        let frame = json!({"prior":[{"observation":{"value":value}}]})
            .to_string()
            .into_bytes();
        support::fixture(root, name, &frame, &frame)
    };
    *derived
        .get_mut("fixtures")
        .ok_or("derived fixtures are absent")? = json!({"fail":[derived_fixture("derived-equal.json","equal")],
        "pass":[derived_fixture("derived-unequal.json","unequal")]});
    let mut gated = judge.clone();
    *gated.get_mut("id").ok_or("gated identity is absent")? = json!("GATED");
    *gated
        .get_mut("consult")
        .ok_or("gated consultation is absent")? = json!({"rules":["JUDGE"],"run_when":"any_fail"});
    let baseline = baseline(vec![helper, judge, derived, gated], root)?;
    let configured = Evaluators::from_bytes(
        json!({"schema":"auditoad-evaluators/1",
        "evaluators":{"ocr":{"backend":"auditoad-compatible","model":"ocr-control-r1",
            "endpoint":"http://127.0.0.1:9/evaluate","capabilities":["extract/1","image/png"]}},
        "roles":{"helper":{"use":"ocr"}}})
        .to_string()
        .as_bytes(),
        root,
        false,
        5,
    )?;
    let prepared = run(&baseline, &snapshot, &configured, &mock(vec![])?, root)?;
    let helper_record = prepared
        .report
        .records
        .first()
        .ok_or("prepared helper record is absent")?;
    let fields = json!({"kind":"extract","fields":{"text":"Encryption disabled"}});
    let helper_reply = reply(helper_record, &baseline, "ocr", fields)?;
    let script = mock(vec![helper_reply])?;
    let answered = run(&baseline, &snapshot, &configured, &script, root)?;
    let [_, judge, derived, _] = answered.report.records.as_slice() else {
        return Err("expected all four helper/judge records".into());
    };
    assert_eq!(answered.report.usage.provider_calls, 1);
    let evidence: Value = serde_json::from_slice(
        &judge
            .evidence
            .as_ref()
            .ok_or("judge evidence is absent")?
            .bytes,
    )?;
    assert_eq!(
        evidence.pointer("/parts/0/source_sha256"),
        Some(&json!(sha256(&image)))
    );
    assert_eq!(
        evidence.pointer("/prior/0/observation/fields/text"),
        Some(&json!("Encryption disabled"))
    );
    assert_eq!(evidence.pointer("/prior/0/rule/id"), Some(&json!("OCR")));
    assert_eq!(judge.result, ResultState::NotEvaluated);
    assert_eq!(suggested(judge)?, "fail");
    assert_eq!(derived.result, ResultState::NotEvaluated);
    assert_eq!(suggested(derived)?, "fail");
    assert_eq!(
        derived
            .observation
            .as_ref()
            .and_then(|v| v.get("experimental_inputs")),
        Some(&json!(true))
    );
    let enabled = reply(
        helper_record,
        &baseline,
        "ocr",
        json!({"kind":"extract","fields":{"text":"Encryption enabled"}}),
    )?;
    let passed = run(
        &baseline,
        &snapshot,
        &configured,
        &mock(vec![enabled])?,
        root,
    )?;
    let [_, tail @ ..] = passed.report.records.as_slice() else {
        return Err("passed helper record is absent".into());
    };
    assert_eq!(tail.len(), 3);
    for record in tail {
        assert_eq!(record.result, ResultState::NotEvaluated);
        assert_eq!(suggested(record)?, "pass");
        assert_eq!(
            record
                .observation
                .as_ref()
                .and_then(|v| v.get("experimental_inputs")),
            Some(&json!(true))
        );
    }
    assert_eq!(
        tail.last()
            .and_then(|r| r.observation.as_ref())
            .and_then(|v| v.get("evaluated")),
        Some(&json!(false))
    );
    assert_eq!(passed.exit_code, 2);
    let malformed = reply(
        helper_record,
        &baseline,
        "ocr",
        json!({"kind":"extract","fields":{"text":true}}),
    )?;
    let refused = run(
        &baseline,
        &snapshot,
        &configured,
        &mock(vec![malformed])?,
        root,
    )?;
    assert_eq!(refused.report.usage.provider_calls, 1);
    assert!(
        refused
            .report
            .records
            .get(1)
            .ok_or("refused judge record is absent")?
            .reason
            .as_ref()
            .ok_or("refused judge reason is absent")?
            .contains("required JSON Pointer")
    );
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions check exact syntax captures and prevent dispatch with missing helper state"
)]
fn syntax_helpers_feed_exact_captures_and_refuse_required_fields_when_incomplete() -> TestResult {
    let dir = directory();
    let root = dir.path();
    let path = bundle(root)?;
    let selected = "def selected(request):\n    return open(request.args['name'])";
    let source = format!("def unrelated():\n    return 'neighboring code marker'\n\n{selected}\n");
    fs::write(root.join("code.txt"), &source)?;
    let mut manifest: Value = serde_json::from_slice(&fs::read(&path)?)?;
    *manifest
        .pointer_mut("/files/code.txt")
        .ok_or("code pin is absent")? = json!(sha256(source.as_bytes()));
    fs::write(&path, manifest.to_string())?;
    let snapshot = Snapshot::bundle(&path, root, &Limits::default())?;
    let mut helper = question("SYNTAX", "helper", "unused");
    *helper
        .get_mut("evaluator")
        .ok_or("helper evaluator is absent")? = json!({"kind":"syntax","contract":"syntax/1"});
    *helper.get_mut("check").ok_or("helper check is absent")? = json!({"kind":"syntax/1","language":"python",
        "json_string_pointer":"/parts/0/text",
        "query":"((function_definition name: (identifier) @name) @code (#eq? @name \"selected\"))"});
    let mut judge = question(
        "JUDGE",
        "judge",
        "Does the selected function use request data as its filename?",
    );
    judge
        .as_object_mut()
        .ok_or("judge is not an object")?
        .insert("consult".into(), json!({"rules":["SYNTAX"]}));
    judge.get_mut("check").and_then(Value::as_object_mut).ok_or("judge check is absent")?.insert("state_projection".into(), json!({
        "syntax":"/prior/0/observation/fields", "syntax_identity":"/prior/0/observation/selected_sha256"}));
    let valid = baseline(vec![helper.clone(), judge.clone()], root)?;
    let prepared = scan(request(&valid, &snapshot, &mock(vec![])?))?;
    let [syntax, judge_record] = prepared.report.records.as_slice() else {
        return Err("expected syntax helper and judge records".into());
    };
    assert_eq!(syntax.result, ResultState::NotEvaluated);
    let captures = syntax
        .observation
        .as_ref()
        .and_then(|v| v.pointer("/fields/captures"))
        .and_then(Value::as_array)
        .ok_or("syntax captures are absent")?;
    let code = captures
        .iter()
        .find(|capture| capture.get("capture") == Some(&json!("code")))
        .ok_or("named function capture is absent")?;
    assert_eq!(code.get("text"), Some(&json!(selected)));
    let start = source.find(selected).ok_or("selected function is absent")?;
    let end = start
        .checked_add(selected.len())
        .ok_or("selected function byte range overflows")?;
    assert_eq!(code.get("start_byte"), Some(&json!(start)));
    assert_eq!(code.get("end_byte"), Some(&json!(end)));
    let consulted: Value = serde_json::from_slice(
        &judge_record
            .evidence
            .as_ref()
            .ok_or("consulted judge evidence is absent")?
            .bytes,
    )?;
    assert_eq!(
        consulted.pointer("/prior/0/observation/selected_sha256"),
        Some(&json!(sha256(source.as_bytes())))
    );
    let wire = support::report_text(
        judge_record
            .observation
            .as_ref()
            .and_then(|v| v.get("request_bytes"))
            .ok_or("judge request bytes are absent")?,
    );
    assert!(wire.contains("request.args"));
    assert!(!wire.contains("neighboring code marker"));
    assert!(!wire.contains("def unrelated"));
    let script = mock(vec![reply(judge_record, &valid, "a", probability(0.99))?])?;
    let configured = evaluators(json!({"judge":{"use":"a"}}), root)?;
    let answered = run(&valid, &snapshot, &configured, &script, root)?;
    assert_eq!(
        suggested(
            answered
                .report
                .records
                .get(1)
                .ok_or("answered judge record is absent")?
        )?,
        "fail"
    );
    assert_eq!(answered.report.usage.provider_calls, 1);
    let mut left = helper.clone();
    *left.get_mut("id").ok_or("left selector id is absent")? = json!("LEFT");
    *left
        .pointer_mut("/check/query")
        .ok_or("left selector query is absent")? = json!(
        "(import_statement) @imports ((function_definition name: (identifier) @name) @code (#eq? @name \"selected\"))"
    );
    let mut right = left.clone();
    *right.get_mut("id").ok_or("right selector id is absent")? = json!("RIGHT");
    let mut quote_helper = extract_rule();
    quote_helper
        .as_object_mut()
        .ok_or("quote helper is not an object")?
        .insert("consult".into(), json!({"rules":["LEFT","RIGHT"]}));
    let mut pair_judge = judge.clone();
    pair_judge
        .as_object_mut()
        .ok_or("paired judge is not an object")?
        .insert("consult".into(), json!({"rules":["LEFT","RIGHT","HELPER"]}));
    for rule in [&mut quote_helper, &mut pair_judge] {
        let check = rule
            .get_mut("check")
            .and_then(Value::as_object_mut)
            .ok_or("paired model check is absent")?;
        check.insert("state_projection".into(), json!({
            "code_a":{"pointer":"/prior/0/observation/fields/captures","capture":"code","optional":true},
            "code_b":{"pointer":"/prior/1/observation/fields/captures","capture":"code","optional":true},
            "imports_a":{"pointer":"/prior/0/observation/fields/captures","capture":"imports","optional":true},
            "imports_b":{"pointer":"/prior/1/observation/fields/captures","capture":"imports","optional":true}
        }));
        check.insert("state_required_any".into(), json!([["code_a", "code_b"]]));
    }
    pair_judge
        .pointer_mut("/check/state_projection")
        .and_then(Value::as_object_mut)
        .ok_or("paired judge projection is absent")?
        .insert(
            "context".into(),
            json!({"pointer":"/prior/2/observation/fields/name","optional":true}),
        );
    for (source, left_applies, complete, limited, helper_off) in [
        (
            format!("import json\n{selected}\n"),
            true,
            true,
            false,
            true,
        ),
        (
            format!("{selected}\nimport json\n"),
            false,
            true,
            false,
            true,
        ),
        (
            "import json\ndef unrelated():\n    return 1\n".into(),
            true,
            false,
            false,
            false,
        ),
        (
            "import json\nimport os\ndef unrelated():\n    return 1\n".into(),
            true,
            false,
            false,
            false,
        ),
        (
            "import json\nimport os\ndef unrelated():\n    return 1\n".into(),
            true,
            false,
            false,
            true,
        ),
        (
            format!("import json\n{selected}\n{selected}\n"),
            true,
            false,
            false,
            false,
        ),
        (
            "import json\ndef selected(:\n".into(),
            true,
            false,
            false,
            false,
        ),
        (
            format!("import json\n{selected}\n"),
            true,
            false,
            true,
            false,
        ),
    ] {
        fs::write(root.join("code.txt"), &source)?;
        *manifest
            .pointer_mut("/files/code.txt")
            .ok_or("paired source pin is absent")? = json!(sha256(source.as_bytes()));
        fs::write(&path, manifest.to_string())?;
        let snapshot = Snapshot::bundle(&path, root, &Limits::default())?;
        let mut selectors = [left.clone(), right.clone()];
        for (selector, applicable) in selectors.iter_mut().zip([left_applies, !left_applies]) {
            *selector
                .pointer_mut("/applicability/include")
                .ok_or("selector applicability is absent")? = if applicable {
                json!(["code"])
            } else {
                json!(["other"])
            };
            if limited {
                selector
                    .get_mut("check")
                    .and_then(Value::as_object_mut)
                    .ok_or("limited selector check is absent")?
                    .insert("limits".into(), json!({"nodes":1}));
            }
        }
        let mut rules = Vec::from(selectors);
        rules.extend([quote_helper.clone(), pair_judge.clone()]);
        let paired = baseline(rules, root)?;
        let configured = if helper_off {
            evaluators_off_helper(root)?
        } else {
            evaluators(json!({"helper":{"use":"a"},"judge":{"use":"b"}}), root)?
        };
        let initial = run(&paired, &snapshot, &configured, &mock(vec![])?, root)?;
        let judge_record = initial
            .report
            .records
            .last()
            .ok_or("paired judge record is absent")?;
        if complete {
            let wire = support::report_text(
                judge_record
                    .observation
                    .as_ref()
                    .and_then(|observation| observation.get("request_bytes"))
                    .ok_or("paired judge request is absent")?,
            );
            assert!(wire.contains("request.args"));
            let answered = run(
                &paired,
                &snapshot,
                &configured,
                &mock(vec![reply(judge_record, &paired, "b", probability(0.99))?])?,
                root,
            )?;
            assert_eq!(answered.report.usage.provider_calls, 1);
            assert_eq!(
                suggested(
                    answered
                        .report
                        .records
                        .last()
                        .ok_or("paired answer is absent")?
                )?,
                "fail"
            );
        } else {
            for record in initial
                .report
                .records
                .iter()
                .skip(2)
                .filter(|record| !helper_off || record.rule.id != "HELPER")
            {
                assert_eq!(record.result, ResultState::NotEvaluated);
                assert!(record.observation.is_none());
                assert!(
                    record
                        .reason
                        .as_deref()
                        .is_some_and(|reason| reason.contains("required state alternative group")
                            || reason.contains("multiple syntax captures"))
                );
            }
            assert_eq!(initial.report.usage.provider_calls, 0);
        }
    }
    fs::write(root.join("code.txt"), &source)?;
    *manifest
        .pointer_mut("/files/code.txt")
        .ok_or("restored source pin is absent")? = json!(sha256(source.as_bytes()));
    fs::write(&path, manifest.to_string())?;
    // A failed helper is not a successful empty extraction. Required state prevents dispatch.
    helper
        .get_mut("check")
        .and_then(Value::as_object_mut)
        .ok_or("helper check is absent")?
        .insert("limits".into(), json!({"nodes":1}));
    let limited = baseline(vec![helper.clone(), judge.clone()], root)?;
    let refused = run(&limited, &snapshot, &configured, &mock(vec![])?, root)?;
    let [helper_record, judge_record] = refused.report.records.as_slice() else {
        return Err("expected limited helper and judge records".into());
    };
    assert!(helper_record.observation.is_none());
    assert!(
        judge_record
            .reason
            .as_ref()
            .ok_or("limited judge reason is absent")?
            .contains("required state field")
    );
    assert_eq!(refused.report.usage.provider_calls, 0);
    helper
        .get_mut("check")
        .and_then(Value::as_object_mut)
        .ok_or("helper check is absent")?
        .remove("limits");
    *helper
        .pointer_mut("/check/json_string_pointer")
        .ok_or("helper source pointer is absent")? = json!("/parts/0/absent");
    let absent = baseline(vec![helper, judge], root)?;
    let refused = run(&absent, &snapshot, &configured, &mock(vec![])?, root)?;
    assert!(
        refused
            .report
            .records
            .first()
            .ok_or("absent-source helper record is absent")?
            .reason
            .as_ref()
            .ok_or("absent-source helper reason is absent")?
            .contains("absent")
    );
    assert_eq!(refused.report.usage.provider_calls, 0);
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions check stable provider question content and fresh audit identity"
)]
fn provider_requests_repeat_selected_content_without_reusing_audit_identity() -> TestResult {
    let dir = directory();
    let root = dir.path();
    let snapshot = Snapshot::bundle(&bundle(root)?, root, &Limits::default())?;
    let mut declaration = question("JUDGE", "judge", "Is the file name request data?");
    declaration
        .get_mut("check")
        .and_then(Value::as_object_mut)
        .ok_or("question check is absent")?
        .insert(
            "state_projection".into(),
            json!({"subject":"/parts/0/text"}),
        );
    let original = baseline(vec![declaration.clone()], root)?;
    let prepared = scan(request(&original, &snapshot, &mock(vec![])?))?;
    let script = mock(vec![reply(
        prepared
            .report
            .records
            .first()
            .ok_or("prepared judge record is absent")?,
        &original,
        "judge",
        probability(0.99),
    )?])?;
    for backend in ["typesafe-jev", "openai-compatible"] {
        let config = json!({"schema":"auditoad-evaluators/1",
            "evaluators":{"judge":{"backend":backend,"model":"test-model",
                "endpoint":"http://127.0.0.1:9/v1/test"}},
            "roles":{"judge":{"use":"judge"}}});
        let configured = Evaluators::from_bytes(config.to_string().as_bytes(), root, false, 30)?;
        let first = run(&original, &snapshot, &configured, &script, root)?;
        let second = run(&original, &snapshot, &configured, &script, root)?;
        let [a] = first.report.records.as_slice() else {
            return Err("expected one first audit record".into());
        };
        let [b] = second.report.records.as_slice() else {
            return Err("expected one second audit record".into());
        };
        assert_ne!(a.scan_id, b.scan_id);
        assert_ne!(a.check_id, b.check_id);
        let a = a
            .observation
            .as_ref()
            .ok_or("first audit observation is absent")?;
        let b = b
            .observation
            .as_ref()
            .ok_or("second audit observation is absent")?;
        for field in ["request_bytes", "request_sha256", "question_id"] {
            assert_eq!(
                a.get(field)
                    .ok_or_else(|| format!("first {field} is absent"))?,
                b.get(field)
                    .ok_or_else(|| format!("second {field} is absent"))?,
                "{backend} {field}"
            );
        }
        assert_eq!(
            a.get("question_id")
                .and_then(Value::as_str)
                .ok_or("question identity is absent")?
                .len(),
            64
        );
        assert_eq!(a.get("suggested_result"), Some(&json!("fail")));
        assert_eq!(b.get("suggested_result"), Some(&json!("fail")));
        for changed in ["instructions", "criteria_true", "state_projection"] {
            let mut variant = declaration.clone();
            let replacement = if changed == "state_projection" {
                json!({"subject":"/parts/1/text"})
            } else {
                json!("Changed question content")
            };
            variant
                .get_mut("check")
                .and_then(Value::as_object_mut)
                .ok_or("variant check is absent")?
                .insert(changed.into(), replacement);
            let variant = baseline(vec![variant], root)?;
            let result = run(&variant, &snapshot, &configured, &mock(vec![])?, root)?;
            let observation = result
                .report
                .records
                .first()
                .and_then(|r| r.observation.as_ref())
                .ok_or("variant observation is absent")?;
            for field in ["question_id", "request_sha256"] {
                assert_ne!(
                    a.get(field)
                        .ok_or_else(|| format!("original {field} is absent"))?,
                    observation
                        .get(field)
                        .ok_or_else(|| format!("variant {field} is absent"))?,
                    "{changed} {field}"
                );
            }
        }
    }
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions check local model ceilings, permitted overrides and global budget refusal"
)]
fn model_call_and_byte_ceilings_refuse_effects_and_overrides_restore_them() -> TestResult {
    let dir = directory();
    let root = dir.path();
    let snapshot = Snapshot::bundle(&bundle(root)?, root, &Limits::default())?;
    let baseline = baseline(
        vec![question("JUDGE", "judge", "Is the file name request data?")],
        root,
    )?;
    let prepared = scan(request(&baseline, &snapshot, &mock(vec![])?))?;
    let script = mock(vec![reply(
        prepared
            .report
            .records
            .first()
            .ok_or("prepared judge record is absent")?,
        &baseline,
        "a",
        probability(0.99),
    )?])?;
    for ceiling in [
        json!({"max_provider_calls":0}),
        json!({"max_evidence_bytes":0}),
    ] {
        let mut model = json!({"backend":"openai-compatible","model":"a","endpoint":"http://127.0.0.1:9/v1/chat/completions","timeout_seconds":4});
        model
            .as_object_mut()
            .ok_or("model fixture is not an object")?
            .extend(
                ceiling
                    .as_object()
                    .ok_or("ceiling fixture is not an object")?
                    .clone(),
            );
        let file = json!({"schema":"auditoad-evaluators/1","evaluators":{"a":model},"roles":{"judge":{"use":"a"}}});
        let mut evaluators = Evaluators::from_bytes(file.to_string().as_bytes(), root, false, 30)?;
        let refused = run(&baseline, &snapshot, &evaluators, &script, root)?;
        assert_eq!(refused.report.usage.provider_calls, 0);
        assert!(
            refused
                .report
                .records
                .first()
                .ok_or("ceiling-refused record is absent")?
                .reason
                .as_ref()
                .ok_or("ceiling refusal reason is absent")?
                .contains("ceiling refused")
        );
        assert_eq!(
            refused
                .report
                .model_usage
                .get("a")
                .ok_or("refused model usage is absent")?
                .provider_calls,
            0
        );
        evaluators.override_limits(Some(1), Some(1_000_000), Some(7))?;
        let accepted = run(&baseline, &snapshot, &evaluators, &script, root)?;
        assert_eq!(accepted.report.usage.provider_calls, 1);
        assert_eq!(
            suggested(
                accepted
                    .report
                    .records
                    .first()
                    .ok_or("accepted judge record is absent")?
            )?,
            "fail"
        );
        assert_eq!(
            accepted
                .report
                .model_usage
                .get("a")
                .ok_or("accepted model usage is absent")?
                .provider_calls,
            1
        );
        let mut global_refusal = request(&baseline, &snapshot, &script);
        global_refusal.limits.provider_calls = 0;
        let refused = scan_to_file_with_evaluators(
            global_refusal,
            &root.join("global-refusal.json"),
            &evaluators,
        )?
        .scan;
        assert_eq!(refused.report.usage.provider_calls, 0);
        assert_eq!(
            refused
                .report
                .model_usage
                .get("a")
                .ok_or("global-refused model usage is absent")?
                .provider_calls,
            0
        );
        assert_eq!(
            refused
                .report
                .records
                .first()
                .ok_or("global-refused record is absent")?
                .reason
                .as_deref(),
            Some("response/call budget refused")
        );
        assert!(evaluators.override_limits(None, None, Some(0)).is_err());
    }
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions check shared canonical model budget accounting at each boundary"
)]
fn shared_model_pools_admit_actual_use_and_report_refused_effects() -> TestResult {
    let dir = directory();
    let root = dir.path();
    let snapshot = Snapshot::bundle(&bundle(root)?, root, &Limits::default())?;
    let baseline = baseline(
        vec![question("JUDGE", "judge", "Is the name request data?")],
        root,
    )?;
    let prepared = scan(request(&baseline, &snapshot, &mock(vec![])?))?;
    let [judge] = prepared.report.records.as_slice() else {
        return Err("expected one prepared judge record".into());
    };
    let script = mock(vec![
        reply(judge, &baseline, "a", probability(0.99))?,
        reply(judge, &baseline, "b", probability(0.99))?,
    ])?;
    let mut evaluators = evaluators(
        json!({"judge":{"ask":["a","b"],"combine":"agreement"}}),
        root,
    )?;
    // Combined model ceilings exceed the shared allowance. Only actual use is delegated.
    evaluators.override_limits(Some(7), Some(1_000_000), None)?;
    for (shared_calls, a_calls, b_calls) in [(2, 1, 1), (1, 1, 0), (0, 0, 0)] {
        let mut options = request(&baseline, &snapshot, &script);
        options.limits.provider_calls = shared_calls;
        let result =
            scan_to_file_with_evaluators(options, &root.join("report.json"), &evaluators)?.scan;
        assert_eq!(result.report.usage.provider_calls, shared_calls);
        let a_usage = result
            .report
            .model_usage
            .get("a")
            .ok_or("member a usage is absent")?;
        let b_usage = result
            .report
            .model_usage
            .get("b")
            .ok_or("member b usage is absent")?;
        assert_eq!(a_usage.provider_calls, a_calls);
        assert_eq!(b_usage.provider_calls, b_calls);
        let [record] = result.report.records.as_slice() else {
            return Err("expected one pooled judge record".into());
        };
        assert_eq!(record.result, ResultState::NotEvaluated);
        // Local evidence and model pools account for all byte usage in this one-check profile.
        assert_eq!(
            result.report.usage.evidence_bytes,
            u64::try_from(
                record
                    .evidence
                    .as_ref()
                    .ok_or("pooled judge evidence is absent")?
                    .bytes
                    .len()
            )?
            .checked_add(a_usage.evidence_bytes)
            .and_then(|v| v.checked_add(b_usage.evidence_bytes))
            .ok_or("fixture byte total overflow")?
        );
        if shared_calls < 2 {
            assert_eq!(suggested(record)?, "review");
        } else {
            assert_eq!(suggested(record)?, "fail");
        }
    }
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions check finite role order, fallback cuts, combined uncertainty and explicit disabling"
)]
fn roles_use_one_model_combine_several_or_are_switched_off() -> TestResult {
    let dir = directory();
    let root = dir.path();
    let snapshot = Snapshot::bundle(&bundle(root)?, root, &Limits::default())?;
    let baseline = baseline(
        vec![question("JUDGE", "judge", "Is the file name request data?")],
        root,
    )?;
    let prepared = scan(request(&baseline, &snapshot, &mock(vec![])?))?;
    let [judge] = prepared.report.records.as_slice() else {
        return Err("expected one prepared judge record".into());
    };
    let script = |a: f64, b: f64| -> TestResult<MockModel> {
        mock(vec![
            reply(judge, &baseline, "a", probability(a))?,
            reply(judge, &baseline, "b", probability(b))?,
        ])
    };
    let cases = [
        (json!({"use":"a"}), (0.99, 0.01), json!("fail"), 1),
        (
            json!({"ask":["a","b"],"combine":"first_resolved"}),
            (0.5, 0.01),
            json!("pass"),
            2,
        ),
        (
            json!({"ask":["a","b"],"combine":"first_resolved"}),
            (0.99, 0.01),
            json!("fail"),
            1,
        ),
        (
            json!({"ask":["a","b"],"combine":"agreement"}),
            (0.99, 0.01),
            json!("review"),
            2,
        ),
        (
            json!({"ask":["a","b"],"combine":"agreement"}),
            (0.99, 0.95),
            json!("fail"),
            2,
        ),
        (
            json!({"ask":["a","b"],"combine":"any_fail"}),
            (0.99, 0.01),
            json!("fail"),
            2,
        ),
        (
            json!({"ask":["a","b"],"combine":"all_fail"}),
            (0.99, 0.01),
            json!("pass"),
            2,
        ),
        (
            json!({"ask":["a","b"],"combine":"all_fail"}),
            (0.99, 0.5),
            json!("review"),
            2,
        ),
    ];
    for (role, (a, b), expected, calls) in cases {
        let evaluators = evaluators(json!({ "judge": role }), root)?;
        let result = run(&baseline, &snapshot, &evaluators, &script(a, b)?, root)?;
        let [record] = result.report.records.as_slice() else {
            return Err("expected one role execution record".into());
        };
        assert_eq!(record.result, ResultState::NotEvaluated, "{role}");
        assert_eq!(suggested(record)?, expected, "{role}");
        assert_eq!(result.report.usage.provider_calls, calls, "{role}");
        if role.get("ask").is_some() {
            let observation = record
                .observation
                .as_ref()
                .ok_or("role execution observation is absent")?;
            assert_eq!(
                u64::try_from(
                    observation
                        .get("members")
                        .and_then(Value::as_array)
                        .ok_or("role member outcomes are absent")?
                        .len()
                )?,
                calls
            );
            assert_eq!(record.evaluator.version.split(':').count(), 2);
            let execution = observation
                .get("role_execution")
                .ok_or("finite role execution is absent")?;
            assert_eq!(execution.get("schema"), Some(&json!("finite-role/1")));
            assert_eq!(execution.get("completed"), Some(&json!(2)));
            let slots = execution
                .get("slots")
                .and_then(Value::as_array)
                .ok_or("role slots are absent")?;
            let [first, second] = slots.as_slice() else {
                return Err("expected both finite role slots".into());
            };
            assert_eq!(first.get("model"), Some(&json!("a")));
            assert_eq!(second.get("model"), Some(&json!("b")));
            assert_eq!(first.get("selected"), Some(&json!(true)));
            assert_eq!(second.get("selected"), Some(&json!(calls == 2)));
            if calls == 1 {
                assert_eq!(execution.get("cut"), Some(&json!(true)));
                assert!(
                    second
                        .get("reason")
                        .and_then(Value::as_str)
                        .ok_or("fallback refusal reason is absent")?
                        .contains("earlier configured member")
                );
            }
        }
    }
    let evaluators = evaluators(json!({"judge":{"off":true}}), root)?;
    let result = run(
        &baseline,
        &snapshot,
        &evaluators,
        &script(0.99, 0.99)?,
        root,
    )?;
    let [record] = result.report.records.as_slice() else {
        return Err("expected one disabled role record".into());
    };
    assert_eq!(result.report.usage.provider_calls, 0);
    assert_eq!(
        record.observation.as_ref().and_then(|v| v.get("disabled")),
        Some(&json!(true))
    );
    assert_eq!(record.evaluator.version, "off");
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions check complete applicability planning and all potential fallback calls"
)]
fn preparation_uses_execution_applicability_and_keeps_all_possible_fallback_calls() -> TestResult {
    let dir = directory();
    let root = dir.path();
    let snapshot = Snapshot::bundle(&bundle(root)?, root, &Limits::default())?;
    let mut unrelated = question("UNRELATED", "judge", "Is there a request value?");
    *unrelated
        .pointer_mut("/applicability/include")
        .ok_or("include declaration is absent")? = json!(["another-kind"]);
    let mut excluded = question("EXCLUDED", "judge", "Is there a request value?");
    *excluded
        .pointer_mut("/applicability/exclude")
        .ok_or("exclude declaration is absent")? = json!(["code"]);
    let baseline = baseline(
        vec![
            question("JUDGE", "judge", "Is the name request data?"),
            unrelated,
            excluded,
        ],
        root,
    )?;
    let empty = mock(vec![])?;
    let prepared = scan(request(&baseline, &snapshot, &empty))?;
    let script = mock(vec![reply(
        prepared
            .report
            .records
            .first()
            .ok_or("prepared applicable judge is absent")?,
        &baseline,
        "a",
        probability(0.99),
    )?])?;
    let evaluators = evaluators(
        json!({"judge":{"ask":["a","b"],"combine":"first_resolved"}}),
        root,
    )?;
    let mut options = request(&baseline, &snapshot, &script);
    options.limits.provider_calls = u64::MAX;
    let mut plans = Vec::new();
    let result = auditoad::scan_to_file_with_preparation(
        options,
        &root.join("report.json"),
        Some(&evaluators),
        |plan| plans.push(serde_json::to_value(plan)),
        |_| {},
    )?;
    let [plan] = plans.as_slice() else {
        return Err("expected one preparation callback".into());
    };
    let plan = plan.as_ref().map_err(|error| error.to_string())?;
    assert_eq!(plan.get("checks"), Some(&json!(3)));
    assert_eq!(plan.get("provider_calls_at_most"), Some(&json!(2)));
    assert_eq!(plan.pointer("/limits/provider_calls"), Some(&json!(2)));
    assert_eq!(plan.get("models"), Some(&json!({"a":1,"b":1})));
    assert_eq!(result.scan.report.work_count, 3);
    assert_eq!(
        result.scan.report.counts.get(&ResultState::Notapplicable),
        Some(&2)
    );
    assert_eq!(result.scan.report.usage.provider_calls, 1);
    assert_eq!(
        result
            .scan
            .report
            .model_usage
            .get("b")
            .ok_or("fallback model usage is absent")?
            .provider_calls,
        0
    );
    assert_eq!(
        suggested(
            result
                .scan
                .report
                .records
                .first()
                .ok_or("applicable judge record is absent")?
        )?,
        "fail"
    );
    Ok(())
}

#[test]
fn evaluator_files_refuse_unclear_or_unknown_role_strategies() {
    let dir = directory();
    let model =
        json!({"backend":"openai-compatible","model":"m","endpoint":"http://127.0.0.1:9/v1"});
    for role in [
        json!({"use":"missing"}),
        json!({"ask":["a"],"combine":"agreement"}),
        json!({"ask":["a","a"],"combine":"agreement"}),
        json!({"ask":["a","b"]}),
        json!({"use":"a","combine":"agreement"}),
        json!({"use":"a","off":true}),
        json!({}),
    ] {
        let file = json!({"schema":"auditoad-evaluators/1","evaluators":{"a":model,"b":model},
            "roles":{"judge":role}});
        assert!(
            Evaluators::from_bytes(file.to_string().as_bytes(), dir.path(), false, 30).is_err(),
            "{role}"
        );
    }
}

fn extract_rule() -> Value {
    json!({"id":"HELPER","revision":"r1","source":"evidence","group":"TEST","risk":"low","scope_kind":"site",
        "title":"Opened name","evidence":"parts","evaluator":{"kind":"model","contract":"extract/1","role":"helper"},
        "check":{"kind":"extract/1","instructions":"Quote the expression that names the opened file.",
            "fields":{"name":{"type":"quote","description":"The file-name expression, copied exactly."},
                "from_request":{"type":"boolean","description":"Whether it reads request data."}},
            "max_request_bytes":null},
        "applicability":{"include":["code"],"exclude":[]},"falsifier":"test","fixtures":{"fail":[],"pass":[]}})
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions check verbatim helper extraction, judge consultation and absent optional state"
)]
fn a_helper_extracts_checked_fields_that_a_judge_can_consult() -> TestResult {
    let dir = directory();
    let root = dir.path();
    let snapshot = Snapshot::bundle(&bundle(root)?, root, &Limits::default())?;
    let mut judge = question("JUDGE", "judge", "Does request data name the opened file?");
    judge
        .as_object_mut()
        .ok_or("judge is not an object")?
        .insert("consult".into(), json!({"rules":["HELPER"]}));
    judge
        .get_mut("check")
        .and_then(Value::as_object_mut)
        .ok_or("judge check is absent")?
        .insert(
            "state_projection".into(),
            json!({"name":{"pointer":"/prior/0/observation/fields/name","optional":true}}),
        );
    let baseline = baseline(vec![extract_rule(), judge], root)?;
    let fields = |name: &str| json!({"kind":"extract","fields":{"name":name,"from_request":true}});
    let roles = json!({"helper":{"use":"a"},"judge":{"use":"b"}});
    let evaluators = evaluators(roles, root)?;
    let prepared = scan(request(&baseline, &snapshot, &mock(vec![])?))?;
    let helper = prepared
        .report
        .records
        .first()
        .ok_or("prepared helper record is absent")?;
    let first = run(
        &baseline,
        &snapshot,
        &evaluators,
        &mock(vec![reply(
            helper,
            &baseline,
            "a",
            fields("request.args['name']"),
        )?])?,
        root,
    )?;
    let [extracted, judged] = first.report.records.as_slice() else {
        return Err("expected helper and judge records".into());
    };
    assert_eq!(extracted.result, ResultState::NotEvaluated);
    let observation = extracted
        .observation
        .as_ref()
        .ok_or("extracted observation is absent")?;
    assert_eq!(
        observation.pointer("/fields/name"),
        Some(&json!("request.args['name']"))
    );
    assert!(observation.get("suggested_result").is_none());
    let wire = support::report_text(
        judged
            .observation
            .as_ref()
            .and_then(|v| v.get("request_bytes"))
            .ok_or("judge request bytes are absent")?,
    );
    assert!(wire.contains("request.args"));
    assert!(!wire.contains("header"));
    assert!(!wire.contains("footer"));
    let script = mock(vec![
        reply(helper, &baseline, "a", fields("request.args['name']"))?,
        reply(judged, &baseline, "b", probability(0.97))?,
    ])?;
    let second = run(&baseline, &snapshot, &evaluators, &script, root)?;
    assert_eq!(
        suggested(
            second
                .report
                .records
                .get(1)
                .ok_or("answered judge record is absent")?
        )?,
        json!("fail")
    );
    let invented = run(
        &baseline,
        &snapshot,
        &evaluators,
        &mock(vec![reply(
            helper,
            &baseline,
            "a",
            fields("open(user_input)"),
        )?])?,
        root,
    )?;
    let invented_helper = invented
        .report
        .records
        .first()
        .ok_or("invented helper record is absent")?;
    assert_eq!(invented_helper.result, ResultState::Error);
    assert!(
        invented_helper
            .reason
            .as_ref()
            .ok_or("invented extraction refusal reason is absent")?
            .contains("verbatim")
    );
    let without_helper = evaluators_off_helper(root)?;
    let alone = run(&baseline, &snapshot, &without_helper, &mock(vec![])?, root)?;
    let record = alone
        .report
        .records
        .get(1)
        .ok_or("judge without helper is absent")?;
    let state: Value = serde_json::from_str(&support::report_text(
        record
            .observation
            .as_ref()
            .and_then(|v| v.get("request_bytes"))
            .ok_or("judge request bytes are absent")?,
    ))?;
    let content: Value = serde_json::from_str(
        state
            .pointer("/messages/1/content")
            .and_then(Value::as_str)
            .ok_or("judge message content is absent")?,
    )?;
    assert_eq!(content.pointer("/state/name"), Some(&Value::Null));
    Ok(())
}

fn evaluators_off_helper(root: &Path) -> TestResult<Evaluators> {
    evaluators(json!({"helper":{"off":true},"judge":{"use":"b"}}), root)
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions check consultation gating, declared fallback order and helper dependency refusal"
)]
fn consult_conditions_and_first_resolved_answers_choose_in_declared_order() -> TestResult {
    let dir = directory();
    let root = dir.path();
    let snapshot = Snapshot::bundle(&bundle(root)?, root, &Limits::default())?;
    let mut second = question("SECOND", "judge", "Second opinion?");
    second
        .as_object_mut()
        .ok_or("second question is not an object")?
        .insert(
            "consult".into(),
            json!({"rules":["FIRST"],"run_when":"any_unresolved"}),
        );
    let combined = json!({"id":"EITHER","revision":"r1","source":"evidence","group":"TEST","risk":"low",
        "scope_kind":"site","title":"Either","evidence":"answers","evaluator":{"kind":"answers","contract":"answers/1"},
        "check":{"kind":"answers/1","rules":["FIRST","SECOND"],"fail_when":"first_resolved","coverage":"First decision."},
        "applicability":{"include":["code"],"exclude":[]},"falsifier":"test","fixtures":{"fail":[],"pass":[]}});
    let mut declaration: Value = json!({"schema":"auditoad-baseline/1",
        "baseline":{"id":"gates","version":"1","title":"Gates","publisher":"tests","status":"draft"},
        "sources":{"evidence":{"adapter":"evidence-bundle/1","media":["application/vnd.auditoad.bundle+json"]}},
        "evidence":{"parts":{"builder":"declared-parts/1","builder_revision":"r1","required_roles":["subject","policy"]},
            "answers":{"builder":"answers/1","builder_revision":"r1"}},
        "groups":[{"id":"TEST","title":"Test"}],
        "rules":[question("FIRST","judge","First opinion?"), second, combined],
        "profiles":[{"id":"all","select":["*"],"block_on":["fail","review","error","not_evaluated"],"allowed_egress":["loopback"]}]});
    let baseline = ValidatedBaseline::from_bytes(declaration.to_string().as_bytes(), root)?;
    let evaluators = evaluators(json!({"judge":{"use":"a"}}), root)?;
    let prepared = scan(request(&baseline, &snapshot, &mock(vec![])?))?;
    let first = prepared
        .report
        .records
        .first()
        .ok_or("first prepared question is absent")?;
    let decided = run(
        &baseline,
        &snapshot,
        &evaluators,
        &mock(vec![reply(first, &baseline, "a", probability(0.01))?])?,
        root,
    )?;
    assert_eq!(decided.report.usage.provider_calls, 1);
    assert!(
        decided
            .report
            .records
            .get(1)
            .ok_or("gated question record is absent")?
            .reason
            .as_ref()
            .ok_or("gated consultation reason is absent")?
            .contains("consult condition")
    );
    assert_eq!(
        suggested(
            decided
                .report
                .records
                .get(2)
                .ok_or("decided combination is absent")?
        )?,
        json!("pass")
    );
    let unresolved = run(
        &baseline,
        &snapshot,
        &evaluators,
        &mock(vec![reply(first, &baseline, "a", probability(0.5))?])?,
        root,
    )?;
    let asked = unresolved
        .report
        .records
        .get(1)
        .ok_or("fallback question is absent")?;
    let script = mock(vec![
        reply(first, &baseline, "a", probability(0.5))?,
        reply(asked, &baseline, "a", probability(0.97))?,
    ])?;
    let fallback = run(&baseline, &snapshot, &evaluators, &script, root)?;
    assert_eq!(fallback.report.usage.provider_calls, 2);
    assert_eq!(
        suggested(
            fallback
                .report
                .records
                .get(2)
                .ok_or("fallback combination is absent")?
        )?,
        json!("fail")
    );
    declaration
        .pointer_mut("/rules/2/check")
        .and_then(Value::as_object_mut)
        .ok_or("combination check is absent")?
        .insert("resolution".into(), json!("decisive"));
    assert!(ValidatedBaseline::from_bytes(declaration.to_string().as_bytes(), root).is_err());
    *declaration
        .pointer_mut("/rules/2/check/resolution")
        .ok_or("combination resolution is absent")? = json!("all_answers");
    *declaration
        .pointer_mut("/rules/2/check/rules")
        .ok_or("combination dependencies are absent")? = json!(["FIRST"]);
    declaration
        .get_mut("rules")
        .and_then(Value::as_array_mut)
        .ok_or("declaration rules are absent")?
        .insert(0, extract_rule());
    *declaration
        .pointer_mut("/rules/3/check/rules")
        .ok_or("combination dependencies are absent after insertion")? = json!(["HELPER"]);
    assert!(ValidatedBaseline::from_bytes(declaration.to_string().as_bytes(), root).is_err());
    *declaration
        .pointer_mut("/rules/0/evaluator")
        .ok_or("helper evaluator is absent")? = json!({"kind":"syntax","contract":"syntax/1"});
    *declaration
        .pointer_mut("/rules/0/check")
        .ok_or("helper check is absent")? = json!({"kind":"syntax/1","language":"python",
        "json_string_pointer":"/parts/0/text","query":"(call) @call"});
    let refusal = ValidatedBaseline::from_bytes(declaration.to_string().as_bytes(), root)
        .err()
        .ok_or("syntax helper was accepted as an answer dependency")?;
    assert!(refusal.message.contains("syntax helper"));
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions distinguish consultation guards from ordered answer operands and preserve unresolved new judgments"
)]
fn gated_answer_combinations_keep_guard_and_fallback_roles_separate() -> TestResult {
    let dir = directory();
    let root = dir.path();
    let path = bundle(root)?;
    let mut local = question("LOCAL", "judge", "unused");
    *local
        .get_mut("evaluator")
        .ok_or("local evaluator is absent")? =
        json!({"kind":"syntax","contract":"python-constant-string/1"});
    *local.get_mut("check").ok_or("local check is absent")? = json!({"kind":"python-constant-string/1","json_string_pointer":"/parts/0/text",
        "query":"((function_definition name: (identifier) @_name body: (block (return_statement (_) @value))) @scope (#eq? @_name \"handler\"))"});
    let combination = |id: &str, rules: Value| {
        json!({"id":id,"revision":"r1","source":"evidence","group":"TEST","risk":"low",
        "scope_kind":"site","title":id,"evidence":"answers","evaluator":{"kind":"answers","contract":"answers/1"},
        "check":{"kind":"answers/1","rules":rules,"fail_when":"first_resolved","coverage":"Declared fallback order."},
        "applicability":{"include":["code"],"exclude":[]},"falsifier":"test","fixtures":{"fail":[],"pass":[]}})
    };
    let mut guarded = combination("GUARDED", json!(["LEGACY"]));
    guarded
        .as_object_mut()
        .ok_or("guarded combination is absent")?
        .insert(
            "consult".into(),
            json!({"rules":["LOCAL"],"run_when":"any_unresolved"}),
        );
    let declaration = json!({"schema":"auditoad-baseline/1",
        "baseline":{"id":"guarded-answers","version":"1","title":"Guarded answers","publisher":"tests","status":"draft"},
        "sources":{"evidence":{"adapter":"evidence-bundle/1","media":["application/vnd.auditoad.bundle+json"]}},
        "evidence":{"parts":{"builder":"declared-parts/1","builder_revision":"r1","required_roles":["subject","policy"]},"answers":{"builder":"answers/1","builder_revision":"r1"}},
        "groups":[{"id":"TEST","title":"Test"}],
        "rules":[local,question("NEW","judge","New semantic judgment?"),question("LEGACY","judge","Legacy semantic judgment?"),guarded,combination("FINAL",json!(["NEW","GUARDED"]))],
        "profiles":[{"id":"all","select":["*"],"block_on":["fail","review","error","not_evaluated"],"allowed_egress":["loopback"]}]});
    let evaluators = evaluators(json!({"judge":{"use":"a"}}), root)?;
    for (source, expected) in [
        ("def handler(incoming):\n    return 'fixed'\n", "review"),
        ("def handler(incoming):\n    return incoming\n", "fail"),
    ] {
        fs::write(root.join("code.txt"), source)?;
        let mut manifest: Value = serde_json::from_slice(&fs::read(&path)?)?;
        *manifest
            .pointer_mut("/files/code.txt")
            .ok_or("code pin is absent")? = json!(sha256(source.as_bytes()));
        fs::write(&path, manifest.to_string())?;
        let snapshot = Snapshot::bundle(&path, root, &Limits::default())?;
        let baseline = ValidatedBaseline::from_bytes(declaration.to_string().as_bytes(), root)?;
        let prepared = scan(request(&baseline, &snapshot, &mock(vec![])?))?;
        let new = prepared
            .report
            .records
            .iter()
            .find(|record| record.rule.id == "NEW")
            .ok_or("new question is absent")?;
        let old = prepared
            .report
            .records
            .iter()
            .find(|record| record.rule.id == "LEGACY")
            .ok_or("legacy question is absent")?;
        let script = mock(vec![
            reply(new, &baseline, "a", probability(0.5))?,
            reply(old, &baseline, "a", probability(0.99))?,
        ])?;
        let measured = run(&baseline, &snapshot, &evaluators, &script, root)?;
        let guarded = measured
            .report
            .records
            .iter()
            .find(|record| record.rule.id == "GUARDED")
            .ok_or("guarded answer is absent")?;
        let frame: Value = serde_json::from_slice(
            &guarded
                .evidence
                .as_ref()
                .ok_or("guarded evidence is absent")?
                .bytes,
        )?;
        assert_eq!(frame.pointer("/answers/0/rule/id"), Some(&json!("LEGACY")));
        assert_eq!(
            frame.get("answers").and_then(Value::as_array).map(Vec::len),
            Some(1)
        );
        assert_eq!(frame.pointer("/prior/0/rule/id"), Some(&json!("LOCAL")));
        assert_eq!(
            frame.get("prior").and_then(Value::as_array).map(Vec::len),
            Some(1)
        );
        let final_record = measured
            .report
            .records
            .iter()
            .find(|record| record.rule.id == "FINAL")
            .ok_or("final answer is absent")?;
        assert_eq!(suggested(final_record)?, json!(expected));
        assert_eq!(measured.report.usage.provider_calls, 2);

        // Reversing declaration order must reverse first_resolved, independently of
        // the canonical graph's edge enumeration order.
        let mut ordered = declaration.clone();
        *ordered
            .pointer_mut("/rules/4/check/rules")
            .ok_or("ordered dependencies are absent")? = json!(["LEGACY", "LOCAL"]);
        let ordered = ValidatedBaseline::from_bytes(ordered.to_string().as_bytes(), root)?;
        let ordered_run = run(&ordered, &snapshot, &evaluators, &script, root)?;
        let final_record = ordered_run
            .report
            .records
            .iter()
            .find(|record| record.rule.id == "FINAL")
            .ok_or("ordered final answer is absent")?;
        assert_eq!(suggested(final_record)?, json!("fail"));
    }
    for (pointer, replacement) in [
        ("/rules/3/consult/rules", json!(["FINAL"])),
        ("/rules/3/check/rules", json!(["FINAL"])),
        ("/rules/3/consult/rules", json!(["LOCAL", "LOCAL"])),
        ("/rules/3/check/rules", json!(["LEGACY", "LEGACY"])),
        ("/rules/3/consult/rules", json!(["ABSENT"])),
        ("/rules/0/scope_kind", json!("relation")),
        ("/rules/3/evidence", json!("parts")),
    ] {
        let mut invalid = declaration.clone();
        *invalid
            .pointer_mut(pointer)
            .ok_or("invalid mutation field is absent")? = replacement;
        assert!(
            ValidatedBaseline::from_bytes(invalid.to_string().as_bytes(), root).is_err(),
            "{pointer}"
        );
    }
    let mut wrong_source = declaration.clone();
    let source = wrong_source
        .pointer("/sources/evidence")
        .ok_or("source is absent")?
        .clone();
    wrong_source
        .get_mut("sources")
        .and_then(Value::as_object_mut)
        .ok_or("sources are absent")?
        .insert("other".into(), source);
    *wrong_source
        .pointer_mut("/rules/0/source")
        .ok_or("local source is absent")? = json!("other");
    assert!(ValidatedBaseline::from_bytes(wrong_source.to_string().as_bytes(), root).is_err());
    let mut shared = declaration;
    *shared
        .pointer_mut("/rules/3/check/rules")
        .ok_or("shared operand is absent")? = json!(["LOCAL"]);
    assert!(ValidatedBaseline::from_bytes(shared.to_string().as_bytes(), root).is_ok());
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions check each model and simulated policy while retaining missing-label uncertainty"
)]
fn scores_compare_each_model_and_simulated_policies_from_one_combined_run() -> TestResult {
    let dir = directory();
    let root = dir.path();
    let snapshot = Snapshot::bundle(&bundle(root)?, root, &Limits::default())?;
    let baseline = baseline(
        vec![question("JUDGE", "judge", "Is the file name request data?")],
        root,
    )?;
    let prepared = scan(request(&baseline, &snapshot, &mock(vec![])?))?;
    let [judge] = prepared.report.records.as_slice() else {
        return Err("expected one prepared scoring record".into());
    };
    let script = mock(vec![
        reply(judge, &baseline, "a", probability(0.99))?,
        reply(judge, &baseline, "b", probability(0.5))?,
    ])?;
    let evaluators = evaluators(
        json!({"judge":{"ask":["a","b"],"combine":"agreement"}}),
        root,
    )?;
    run(&baseline, &snapshot, &evaluators, &script, root)?;
    let report = fs::read(root.join("report.json"))?;
    let labels = json!({"schema":"auditoad-labels/1","labels":[
        {"rule":"JUDGE","target":"case","violation":true},
        {"rule":"ABSENT","target":"case","violation":false}]})
    .to_string()
    .into_bytes();
    let summary = auditoad::score(&report, &labels)?;
    for (pointer, expected) in [
        ("/overall/total", json!(2)),
        ("/overall/unresolved_negative", json!(1)),
        ("/rules/ABSENT/unresolved_negative", json!(1)),
        ("/labelled_records", json!(1)),
        ("/labels_expected", json!(2)),
        ("/label_coverage_complete", json!(false)),
        ("/overall/unresolved_positive", json!(1)),
        ("/models/a/true_positive", json!(1)),
        ("/models/b/unresolved_positive", json!(1)),
        ("/policies/first_resolved/true_positive", json!(1)),
        ("/policies/any_fail/true_positive", json!(1)),
        ("/policies/agreement/unresolved_positive", json!(1)),
    ] {
        assert_eq!(summary.pointer(pointer), Some(&expected), "{pointer}");
    }
    assert_eq!(
        summary
            .get("labels_without_records")
            .and_then(Value::as_array)
            .ok_or("missing-label outcomes are absent")?
            .len(),
        1
    );
    let duplicate = json!({"schema":"auditoad-labels/1","labels":[
        {"rule":"JUDGE","target":"case","violation":true},
        {"rule":"JUDGE","target":"case","violation":false}]})
    .to_string()
    .into_bytes();
    assert!(auditoad::score(&report, &duplicate).is_err());
    fs::write(root.join("labels.json"), &labels)?;
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_auditoad"))
        .arg("score")
        .arg("--report")
        .arg(root.join("report.json"))
        .arg("--labels")
        .arg(root.join("labels.json"))
        .output()?;
    assert_eq!(output.status.code(), Some(2));
    let printed: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(printed.get("label_coverage_complete"), Some(&json!(false)));
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions check duplicate refusal and uncertainty for missing or failed answers"
)]
fn scoring_refuses_duplicate_records_and_preserves_missing_and_failed_answers() -> TestResult {
    let labels = json!({"schema":"auditoad-labels/1","labels":[
        {"rule":"R","target":"one","violation":true},
        {"rule":"R","target":"two","violation":false}]});
    let mut report = json!({"schema":"auditoad-report/2","records":[
        {"rule":{"id":"R"},"target":{"id":"one"},"result":"fail"},
        {"rule":{"id":"R"},"target":{"id":"two"},"result":"pass"}]});
    let score = |report: &serde_json::Value, labels: &serde_json::Value| {
        auditoad::score(report.to_string().as_bytes(), labels.to_string().as_bytes())
    };
    let complete = score(&report, &labels)?;
    assert_eq!(complete.pointer("/overall/correct"), Some(&json!(2)));
    assert_eq!(complete.get("label_coverage_complete"), Some(&json!(true)));
    report
        .get_mut("records")
        .and_then(Value::as_array_mut)
        .ok_or("fixture records are absent")?
        .pop()
        .ok_or("missing-record mutation has no record to remove")?;
    let truncated = score(&report, &labels)?;
    for (pointer, expected) in [
        ("/overall/total", json!(2)),
        ("/overall/correct", json!(1)),
        ("/overall/unresolved_negative", json!(1)),
        ("/label_coverage_complete", json!(false)),
    ] {
        assert_eq!(truncated.pointer(pointer), Some(&expected), "{pointer}");
    }
    let repeated = report
        .pointer("/records/0")
        .ok_or("retained fixture record is absent")?
        .clone();
    report
        .get_mut("records")
        .and_then(Value::as_array_mut)
        .ok_or("fixture records are absent")?
        .push(repeated);
    assert!(score(&report, &labels).is_err());
    // Duplicate unlabelled records are malformed too; subset labels cannot hide them.
    for record in report
        .get_mut("records")
        .and_then(Value::as_array_mut)
        .ok_or("duplicate fixture records are absent")?
    {
        *record
            .pointer_mut("/rule/id")
            .ok_or("duplicate rule identity is absent")? = json!("UNLABELLED");
    }
    assert!(score(&report, &labels).is_err());
    *report
        .get_mut("records")
        .ok_or("fixture records are absent")? = json!([]);
    let empty = score(&report, &labels)?;
    assert_eq!(
        empty.pointer("/overall/unresolved_positive"),
        Some(&json!(1))
    );
    assert_eq!(
        empty.pointer("/overall/unresolved_negative"),
        Some(&json!(1))
    );
    assert_eq!(empty.get("labelled_records"), Some(&json!(0)));
    assert!(score(&report, &json!({"schema":"auditoad-labels/1","labels":[]})).is_err());
    *report
        .get_mut("records")
        .ok_or("fixture records are absent")? = json!([
        {"rule":{"id":"R"},"target":{"id":"one"},"result":"error",
         "observation":{"suggested_result":"fail"}}]);
    let failed = score(&report, &labels)?;
    assert_eq!(failed.pointer("/overall/correct"), Some(&json!(0)));
    assert_eq!(
        failed.pointer("/overall/unresolved_positive"),
        Some(&json!(1))
    );
    Ok(())
}
