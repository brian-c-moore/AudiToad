mod support;
use auditoad::{
    ValidatedBaseline,
    audit::{RunDefinition, RunOptions, run_file, run_one},
};
use serde_json::{Value, json};
use std::{fs, path::Path, process::Command};
use support::{bytes_baseline, directory};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn write(path: &Path, value: &Value) -> std::io::Result<()> {
    fs::write(path, value.to_string())
}
fn definition(root: &Path) -> RunDefinition {
    RunDefinition {
        name: "test".into(),
        baseline: root.join("baseline.json"),
        input: root.join("input.txt"),
        report: root.join("report.json"),
        profile: None,
        source: None,
        project_root: None,
        evaluators: None,
        labels: None,
        mock: None,
        replay: None,
        reuse: None,
    }
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions check explicit defaults, overrides and ambiguity refusal"
)]
fn default_profile_and_source_resolve_with_explicit_overrides_and_ambiguity_refusal() -> TestResult
{
    let dir = directory();
    let root = dir.path();
    let mut value = bytes_baseline(root);
    let mut second = value
        .pointer("/profiles/0")
        .ok_or("fixture profile is absent")?
        .clone();
    *second.get_mut("id").ok_or("profile identity is absent")? = json!("second");
    value
        .get_mut("profiles")
        .and_then(Value::as_array_mut)
        .ok_or("fixture profiles are absent")?
        .push(second);
    fs::write(root.join("input.txt"), b"bad")?;
    let mut run = definition(root);
    write(&run.baseline, &value)?;
    assert!(
        run_one(&run, &RunOptions::default(), |_| {}, |_| {})
            .err()
            .ok_or("ambiguous profile was accepted")?
            .message
            .contains("profile")
    );
    value
        .as_object_mut()
        .ok_or("fixture baseline is not an object")?
        .insert("default_profile".into(), json!("second"));
    write(&run.baseline, &value)?;
    let result = run_one(&run, &RunOptions::default(), |_| {}, |_| {})?;
    assert_eq!(result.scan.report.profile, "second");
    assert_eq!(result.scan.exit_code, 1);
    run.profile = Some("default".into());
    assert_eq!(
        run_one(&run, &RunOptions::default(), |_| {}, |_| {})?
            .scan
            .report
            .profile,
        "default"
    );
    let source = value
        .pointer("/sources/bytes")
        .ok_or("fixture source is absent")?
        .clone();
    value
        .get_mut("sources")
        .and_then(Value::as_object_mut)
        .ok_or("fixture sources are absent")?
        .insert("other".into(), source);
    write(&run.baseline, &value)?;
    assert!(
        run_one(&run, &RunOptions::default(), |_| {}, |_| {})
            .err()
            .ok_or("ambiguous source was accepted")?
            .message
            .contains("ambiguous")
    );
    run.source = Some("bytes".into());
    assert!(run_one(&run, &RunOptions::default(), |_| {}, |_| {}).is_ok());
    *value
        .get_mut("default_profile")
        .ok_or("default profile is absent")? = json!("absent");
    assert!(ValidatedBaseline::from_bytes(value.to_string().as_bytes(), root).is_err());
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions check ordinary CLI preparation and explicit live refusal"
)]
fn ordinary_cli_prepares_a_draft_bundle_without_redundant_flags() -> TestResult {
    let dir = directory();
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let output = Command::new(env!("CARGO_BIN_EXE_auditoad"))
        .current_dir(root)
        .args([
            "scan",
            "--baseline",
            "examples/shipping-policy/baseline.json",
            "--input",
            "examples/shipping-policy/bundle.json",
            "--report",
        ])
        .arg(dir.path().join("report.json"))
        .env_remove("AUDITOAD_EVALUATORS")
        .output()?;
    assert_eq!(
        output.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("at most 1 model calls"));
    let report: Value = serde_json::from_slice(&fs::read(dir.path().join("report.json"))?)?;
    assert_eq!(report.get("experimental"), Some(&json!(true)));
    assert_eq!(report.pointer("/usage/provider_calls"), Some(&json!(0)));
    let live = Command::new(env!("CARGO_BIN_EXE_auditoad"))
        .current_dir(root)
        .args([
            "scan",
            "--baseline",
            "examples/shipping-policy/baseline.json",
            "--input",
            "examples/shipping-policy/bundle.json",
            "--live",
            "--report",
        ])
        .arg(dir.path().join("live.json"))
        .env_remove("AUDITOAD_EVALUATORS")
        .output()?;
    assert_eq!(live.status.code(), Some(3));
    assert!(!dir.path().join("live.json").exists());
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions check installed question-review assets and default local preparation from another directory"
)]
fn ordinary_cli_reviews_a_baseline_from_an_unrelated_directory() -> TestResult {
    let dir = directory();
    let input =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/shipping-policy/baseline.json");
    let output = Command::new(env!("CARGO_BIN_EXE_auditoad"))
        .current_dir(dir.path())
        .args(["baseline", "review"])
        .arg(&input)
        .env_remove("AUDITOAD_EVALUATORS")
        .output()?;
    assert_eq!(
        output.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report_bytes = fs::read(dir.path().join("review.json"))?;
    let report: Value = serde_json::from_slice(&report_bytes)?;
    assert_eq!(report.pointer("/usage/provider_calls"), Some(&json!(0)));
    let text = String::from_utf8(report_bytes)?;
    assert!(text.contains("SHIPPING-FREE-THRESHOLD"));
    assert!(text.contains(&auditoad::sha256(&fs::read(&input)?)));
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions check standalone question-set CLI handling and input overwrite refusal"
)]
fn ordinary_cli_reviews_a_question_set_and_protects_its_input() -> TestResult {
    let dir = directory();
    let input = dir.path().join("questions.json");
    write(
        &input,
        &json!({"schema":"auditoad-question-set/1","id":"chapter-review",
            "declared_context":{"subject":"one paragraph"},
            "questions":[{"id":"narrator","instructions":"Does the paragraph identify its narrator?",
                "criteria_true":"The paragraph identifies its narrator.",
                "criteria_false":"The paragraph does not identify its narrator."}]}),
    )?;
    let original = fs::read(&input)?;
    let output = Command::new(env!("CARGO_BIN_EXE_auditoad"))
        .current_dir(dir.path())
        .args([
            "baseline",
            "review",
            "questions.json",
            "--report",
            "result.json",
        ])
        .env_remove("AUDITOAD_EVALUATORS")
        .output()?;
    assert_eq!(
        output.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&fs::read(dir.path().join("result.json"))?)?;
    assert_eq!(report.pointer("/usage/provider_calls"), Some(&json!(0)));
    assert!(report.to_string().contains("narrator"));
    let overwrite = Command::new(env!("CARGO_BIN_EXE_auditoad"))
        .current_dir(dir.path())
        .args([
            "baseline",
            "review",
            "questions.json",
            "--report",
            "questions.json",
        ])
        .env_remove("AUDITOAD_EVALUATORS")
        .output()?;
    assert_eq!(overwrite.status.code(), Some(3));
    assert_eq!(fs::read(&input)?, original);
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions check shared operator settings route live consent and bounded input refusal"
)]
fn ordinary_cli_review_requires_live_configuration_and_honors_input_ceiling() -> TestResult {
    let dir = directory();
    let input =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/shipping-policy/baseline.json");
    let live = Command::new(env!("CARGO_BIN_EXE_auditoad"))
        .current_dir(dir.path())
        .args(["baseline", "review"])
        .arg(&input)
        .args(["--live", "--report", "live.json"])
        .env_remove("AUDITOAD_EVALUATORS")
        .output()?;
    assert_eq!(live.status.code(), Some(3));
    assert!(!dir.path().join("live.json").exists());
    let bounded = Command::new(env!("CARGO_BIN_EXE_auditoad"))
        .current_dir(dir.path())
        .args(["baseline", "review"])
        .arg(&input)
        .args(["--max-input-bytes", "1", "--report", "bounded.json"])
        .env_remove("AUDITOAD_EVALUATORS")
        .output()?;
    assert_eq!(bounded.status.code(), Some(2));
    assert!(!dir.path().join("bounded.json").exists());
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions check review-only explicit egress replacement and disallowed live origin refusal before HTTP"
)]
fn ordinary_cli_review_routes_explicit_egress_without_implicit_endpoint_permissions() -> TestResult
{
    let dir = directory();
    let input =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/shipping-policy/baseline.json");
    let evaluators = dir.path().join("evaluators.json");
    for (endpoint, report) in [
        ("http://127.0.0.1:9/evaluate", "local.json"),
        ("https://review.example.test/evaluate", "remote.json"),
    ] {
        write(
            &evaluators,
            &json!({"schema":"auditoad-evaluators/1","evaluators":{
                "default":{"backend":"auditoad-compatible","model":"review-model","endpoint":endpoint}}}),
        )?;
        let output = Command::new(env!("CARGO_BIN_EXE_auditoad"))
            .current_dir(dir.path())
            .args(["baseline", "review"])
            .arg(&input)
            .arg("--evaluators")
            .arg(&evaluators)
            .args([
                "--allowed-egress",
                "loopback",
                "--allowed-egress",
                "https://review.example.test",
                "--report",
                report,
            ])
            .env_remove("AUDITOAD_EVALUATORS")
            .output()?;
        assert_eq!(
            output.status.code(),
            Some(2),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let prepared: Value = serde_json::from_slice(&fs::read(dir.path().join(report))?)?;
        assert_eq!(prepared.pointer("/usage/provider_calls"), Some(&json!(0)));
    }
    let refused = Command::new(env!("CARGO_BIN_EXE_auditoad"))
        .current_dir(dir.path())
        .args(["baseline", "review"])
        .arg(&input)
        .arg("--evaluators")
        .arg(&evaluators)
        .args([
            "--allowed-egress",
            "loopback",
            "--live",
            "--report",
            "refused.json",
        ])
        .env_remove("AUDITOAD_EVALUATORS")
        .output()?;
    assert_eq!(refused.status.code(), Some(3));
    assert!(String::from_utf8_lossy(&refused.stderr).contains("allowed_egress"));
    assert!(!dir.path().join("refused.json").exists());
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions check filename-only product inputs from their ordinary working directory"
)]
fn filename_only_input_defaults_its_root_to_the_current_directory() -> TestResult {
    let dir = directory();
    for (example, input) in [
        ("related-events", "inputs.json"),
        ("shipping-policy", "bundle.json"),
    ] {
        let report = dir.path().join(format!("{example}.json"));
        let output = Command::new(env!("CARGO_BIN_EXE_auditoad"))
            .current_dir(
                Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("examples")
                    .join(example),
            )
            .args([
                "scan",
                "--baseline",
                "baseline.json",
                "--input",
                input,
                "--report",
            ])
            .arg(&report)
            .env_remove("AUDITOAD_EVALUATORS")
            .output()?;
        assert_eq!(
            output.status.code(),
            Some(2),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let report: Value = serde_json::from_slice(&fs::read(report)?)?;
        assert_eq!(report.pointer("/usage/provider_calls"), Some(&json!(0)));
    }
    Ok(())
}

fn suite(root: &Path) -> std::io::Result<Value> {
    write(&root.join("baseline.json"), &bytes_baseline(root))?;
    fs::write(root.join("first.txt"), b"bad")?;
    fs::write(root.join("second.txt"), b"good")?;
    Ok(
        json!({"schema":"auditoad-audit/1","report":"suite.json","runs":[
        {"name":"first","baseline":"baseline.json","input":"first.txt","report":"first.json"},
        {"name":"second","baseline":"baseline.json","input":"second.txt","report":"second.json"}]}),
    )
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions check complete suite execution, missing-label coverage and score custody"
)]
fn suite_runs_all_members_and_scores_missing_labels_without_hiding_them() -> TestResult {
    let dir = directory();
    let root = dir.path();
    let mut value = suite(root)?;
    write(
        &root.join("labels.json"),
        &json!({"schema":"auditoad-labels/1","labels":[
        {"rule":"BYTES-1","target":"input/0","violation":true},
        {"rule":"BYTES-1","target":"missing","violation":false}]}),
    )?;
    value
        .pointer_mut("/runs/0")
        .and_then(Value::as_object_mut)
        .ok_or("first run is absent")?
        .insert("labels".into(), json!("labels.json"));
    write(&root.join("audit.json"), &value)?;
    let result = run_file(
        &root.join("audit.json"),
        &RunOptions::default(),
        |_, _| {},
        |_, _| {},
    )?;
    assert_eq!(result.exit_code, 2);
    assert_eq!(
        result.report.pointer("/runs/0/score/overall/total"),
        Some(&json!(2))
    );
    assert_eq!(
        result
            .report
            .pointer("/runs/0/score/label_coverage_complete"),
        Some(&json!(false))
    );
    assert_eq!(result.report.pointer("/runs/1/exit_code"), Some(&json!(0)));
    assert_eq!(result.report.get("exit_counts"), Some(&json!([1, 0, 1, 0])));
    assert!(root.join("first.json").is_file());
    assert!(root.join("second.json").is_file());
    let published = fs::read(root.join("first.json"))?;
    let standalone_score = auditoad::score(&published, &fs::read(root.join("labels.json"))?)?;
    assert_eq!(
        result.report.pointer("/runs/0/score"),
        Some(&standalone_score)
    );
    assert_eq!(
        result
            .report
            .pointer("/runs/0/score/report_sha256")
            .ok_or("score report digest is absent")?,
        result
            .report
            .pointer("/runs/0/receipt/report_sha256")
            .ok_or("receipt report digest is absent")?
    );
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions check that a changed later input remains unresolved while later runs continue"
)]
fn changed_later_input_is_recorded_as_unresolved_and_the_suite_continues() -> TestResult {
    let dir = directory();
    let root = dir.path();
    let mut value = suite(root)?;
    fs::write(root.join("third.txt"), b"good")?;
    value.get_mut("runs").and_then(Value::as_array_mut).ok_or("suite runs are absent")?.push(json!({"name":"third","baseline":"baseline.json","input":"third.txt","report":"third.json"}));
    write(&root.join("audit.json"), &value)?;
    let mut mutation = None;
    let outcome = run_file(
        &root.join("audit.json"),
        &RunOptions::default(),
        |_, _| {},
        |name, _| {
            if name == "first" {
                mutation = Some(fs::write(root.join("second.txt"), b"changed"));
            }
        },
    );
    mutation.ok_or("first run never invoked the mutation callback")??;
    let result = outcome?;
    assert_eq!(result.exit_code, 2);
    assert_eq!(
        result
            .report
            .get("runs")
            .and_then(Value::as_array)
            .ok_or("suite outcomes are absent")?
            .len(),
        3
    );
    assert!(
        result
            .report
            .pointer("/runs/1/error")
            .and_then(Value::as_str)
            .ok_or("changed input outcome is absent")?
            .contains("changed")
    );
    assert_eq!(result.report.pointer("/runs/2/exit_code"), Some(&json!(0)));
    assert!(!root.join("second.json").exists());
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions check pre-dispatch custody and duplicate/mode refusal for the complete suite"
)]
fn suite_refuses_cross_run_overwrites_duplicate_names_destinations_and_file_consent() -> TestResult
{
    let dir = directory();
    let root = dir.path();
    let good = suite(root)?;
    for changed in ["input", "fixture", "same-output", "same-name", "live"] {
        let mut value = good.clone();
        match changed {
            "live" => {
                value
                    .as_object_mut()
                    .ok_or("suite is not an object")?
                    .insert("live".into(), json!(true));
            }
            other => {
                let (pointer, replacement) = match other {
                    "input" => ("/runs/0/report", json!("second.txt")),
                    "fixture" => ("/report", json!("pass.txt")),
                    "same-output" => ("/runs/1/report", json!("first.json")),
                    "same-name" => ("/runs/1/name", json!("first")),
                    _ => return Err(format!("unrecognized suite mutation {other}").into()),
                };
                *value
                    .pointer_mut(pointer)
                    .ok_or_else(|| format!("mutation field {pointer} is absent"))? = replacement;
            }
        }
        write(&root.join("audit.json"), &value)?;
        let mut invoked = false;
        let result = run_file(
            &root.join("audit.json"),
            &RunOptions::default(),
            |_, _| invoked = true,
            |_, _| {},
        );
        assert!(result.is_err(), "{changed}");
        assert!(!invoked, "must refuse before scan: {changed}");
        assert_eq!(fs::read(root.join("second.txt"))?, b"good");
        assert_eq!(fs::read(root.join("pass.txt"))?, b"good");
        assert!(!root.join("first.json").exists());
    }
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions check readable label identity, missing cases and ambiguity refusal"
)]
fn readable_label_selectors_preserve_missing_cases_and_refuse_ambiguity() -> TestResult {
    let report = json!({"schema":"auditoad-report/2","source":{"metadata":{}},"records":[
        {"rule":{"id":"R"},"target":{"id":"case","kind":"application/vnd.auditoad.bundle+json","metadata":{}},"result":"fail"},
        {"rule":{"id":"E"},"target":{"id":"generated-id","metadata":{"input":"events","location":{"line":3}}},"result":"pass"}]});
    let labels = json!({"schema":"auditoad-labels/1","labels":[
        {"rule":"R","packet":"case","violation":true},
        {"rule":"E","input":"events","line":3,"violation":false},
        {"rule":"E","input":"events","line":4,"violation":true}]});
    let score = |report: &Value, labels: &Value| {
        auditoad::score(report.to_string().as_bytes(), labels.to_string().as_bytes())
    };
    let result = score(&report, &labels)?;
    for (pointer, expected) in [
        ("/overall/correct", json!(2)),
        ("/overall/total", json!(3)),
        ("/overall/resolved_accuracy", json!(1.0)),
        ("/overall/decision_coverage", json!(2.0 / 3.0)),
        ("/dataset", Value::Null),
        ("/label_coverage_complete", json!(false)),
        ("/cases/0/target", json!("case")),
        ("/cases/1/target", json!("generated-id")),
        ("/cases/2/comparison", json!("unresolved")),
        ("/cases/2/missing", json!(true)),
    ] {
        assert_eq!(result.pointer(pointer), Some(&expected), "{pointer}");
    }
    let mut ambiguous = report.clone();
    let mut other = report
        .pointer("/records/1")
        .ok_or("source label record is absent")?
        .clone();
    *other
        .pointer_mut("/target/id")
        .ok_or("target identity is absent")? = json!("another");
    ambiguous
        .get_mut("records")
        .and_then(Value::as_array_mut)
        .ok_or("report records are absent")?
        .push(other);
    assert!(score(&ambiguous, &labels).is_err());
    let mut duplicate = labels.clone();
    duplicate
        .get_mut("labels")
        .and_then(Value::as_array_mut)
        .ok_or("fixture labels are absent")?
        .push(json!({"rule":"R","target":"case","violation":true}));
    assert!(score(&report, &duplicate).is_err());

    let mut declared = labels.clone();
    declared
        .as_object_mut()
        .ok_or("labels are not an object")?
        .insert(
            "dataset".into(),
            json!({"id":"controls","revision":"r1","split":"development",
        "notes":"These labels have already been inspected."}),
        );
    let tagged = score(&report, &declared)?;
    assert_eq!(
        tagged.get("dataset").ok_or("score dataset is absent")?,
        declared
            .get("dataset")
            .ok_or("declared dataset is absent")?
    );
    for field in ["cases", "overall"] {
        assert_eq!(
            tagged
                .get(field)
                .ok_or_else(|| format!("tagged {field} is absent"))?,
            result
                .get(field)
                .ok_or_else(|| format!("original {field} is absent"))?
        );
    }
    assert_ne!(
        tagged
            .get("labels_sha256")
            .ok_or("tagged labels digest is absent")?,
        result
            .get("labels_sha256")
            .ok_or("original labels digest is absent")?
    );
    for (field, value) in [
        ("id", " "),
        ("revision", ""),
        ("split", "test"),
        ("notes", ""),
    ] {
        let mut invalid = declared.clone();
        *invalid
            .get_mut("dataset")
            .and_then(|v| v.get_mut(field))
            .ok_or_else(|| format!("dataset field {field} is absent"))? = json!(value);
        assert!(score(&report, &invalid).is_err());
    }
    let empty = json!({"schema":"auditoad-report/2","records":[]});
    let unresolved = score(&empty, &declared)?;
    assert_eq!(
        unresolved.pointer("/overall/decision_coverage"),
        Some(&json!(0.0))
    );
    assert_eq!(
        unresolved.pointer("/overall/resolved_accuracy"),
        Some(&Value::Null)
    );
    assert_eq!(unresolved.pointer("/overall/unresolved"), Some(&json!(3)));
    let mut wrong = report.clone();
    *wrong
        .pointer_mut("/records/0/result")
        .ok_or("record result is absent")? = json!("pass");
    let mixed = score(&wrong, &declared)?;
    assert_eq!(
        mixed.pointer("/overall/resolved_accuracy"),
        Some(&json!(0.5))
    );
    assert_eq!(
        mixed.pointer("/overall/decision_coverage"),
        Some(&json!(2.0 / 3.0))
    );
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions check rule isolation, packet metadata, source-name fallback and explicit input precedence"
)]
fn readable_label_selectors_keep_rule_isolation_and_input_fallbacks() -> TestResult {
    let report = json!({"schema":"auditoad-report/2","source":{"metadata":{"name":"events"}},"records":[
        {"rule":{"id":"R"},"target":{"id":"derived-packet","metadata":{"packet":"case"}},"result":"fail"},
        {"rule":{"id":"OTHER-PACKET"},"target":{"id":"other-packet","metadata":{"packet":"case"}},"result":"pass"},
        {"rule":{"id":"E"},"target":{"id":"fallback-line","metadata":{"location":{"line":3}}},"result":"pass"},
        {"rule":{"id":"E"},"target":{"id":"explicit-line","metadata":{"input":"other-events","location":{"line":3}}},"result":"fail"},
        {"rule":{"id":"OTHER-LINE"},"target":{"id":"other-line","metadata":{"location":{"line":3}}},"result":"fail"}]});
    let labels = json!({"schema":"auditoad-labels/1","labels":[
        {"rule":"R","packet":"case","violation":true},
        {"rule":"E","input":"events","line":3,"violation":false},
        {"rule":"ABSENT","packet":"case","violation":false}]});
    let summary = auditoad::score(report.to_string().as_bytes(), labels.to_string().as_bytes())?;
    for (pointer, expected) in [
        ("/overall/correct", json!(2)),
        ("/overall/unresolved_negative", json!(1)),
        ("/unlabelled_records", json!(3)),
        ("/cases/0/target", json!("derived-packet")),
        ("/cases/1/target", json!("fallback-line")),
        ("/cases/2/missing", json!(true)),
        ("/label_coverage_complete", json!(false)),
    ] {
        assert_eq!(summary.pointer(pointer), Some(&expected), "{pointer}");
    }
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions check paired regression, uncertainty, missing records and changed request identities"
)]
fn paired_scores_retain_regressions_uncertainty_and_changed_requests() -> TestResult {
    let labels = json!({"schema":"auditoad-labels/1","labels":[
        {"rule":"R","target":"improves","violation":true},
        {"rule":"R","target":"regresses","violation":false},
        {"rule":"R","target":"lost","violation":true},
        {"rule":"R","target":"error","violation":true},
        {"rule":"R","target":"same","violation":false}]});
    let reference = json!({"schema":"auditoad-report/2","scan_id":"before",
        "baseline":{"id":"example","version":"1"},
        "source":{"binding":"json-lines/1","input_sha256":"a".repeat(64),"snapshot_id":"snapshot"},
        "records":[
        {"rule":{"id":"R"},"target":{"id":"same"},"result":"pass",
         "observation":{"request_sha256":"1".repeat(64),"mock":false}},
        {"rule":{"id":"R"},"target":{"id":"error"},"result":"review"},
        {"rule":{"id":"R"},"target":{"id":"regresses"},"result":"pass"},
        {"rule":{"id":"R"},"target":{"id":"lost"},"result":"fail"},
        {"rule":{"id":"R"},"target":{"id":"improves"},"result":"pass",
         "evidence":{"sha256":"2".repeat(64)}}]});
    let mut candidate = reference.clone();
    for (pointer, replacement) in [
        ("/scan_id", json!("after")),
        ("/baseline/version", json!("2")),
        (
            "/records/0/observation/request_sha256",
            json!("3".repeat(64)),
        ),
        ("/records/0/observation/mock", json!(true)),
        ("/records/1/result", json!("error")),
        ("/records/2/result", json!("fail")),
        ("/records/4/result", json!("fail")),
        ("/records/4/evidence/sha256", json!("4".repeat(64))),
    ] {
        *candidate
            .pointer_mut(pointer)
            .ok_or_else(|| format!("candidate field {pointer} is absent"))? = replacement;
    }
    let failed = candidate
        .pointer_mut("/records/1")
        .and_then(Value::as_object_mut)
        .ok_or("candidate error record is absent")?;
    failed.insert("reason".into(), json!("provider refused"));
    failed.insert("observation".into(), json!({"suggested_result":"fail"}));
    let records = candidate
        .get_mut("records")
        .and_then(Value::as_array_mut)
        .ok_or("candidate records are absent")?;
    if records.get(3).is_none() {
        return Err("lost-record mutation has no record to remove".into());
    }
    records.remove(3);
    let compare = |candidate: &Value| {
        auditoad::compare_scores(
            reference.to_string().as_bytes(),
            candidate.to_string().as_bytes(),
            labels.to_string().as_bytes(),
        )
    };
    let result = compare(&candidate)?;
    assert_eq!(
        result
            .get("cases")
            .and_then(Value::as_array)
            .ok_or("comparison cases are absent")?
            .len(),
        5
    );
    for (pointer, expected) in [
        ("/label_coverage_complete", json!(false)),
        ("/cases/0/reference/comparison", json!("wrong")),
        ("/cases/0/candidate/comparison", json!("correct")),
        ("/cases/0/same_recorded_evidence", json!(false)),
        ("/cases/1/reference/comparison", json!("correct")),
        ("/cases/1/candidate/comparison", json!("wrong")),
        ("/cases/2/record_presence_changed", json!(true)),
        ("/cases/2/candidate/comparison", json!("unresolved")),
        ("/cases/3/decision_changed", json!(false)),
        ("/cases/3/candidate/decision", json!("unresolved")),
        ("/cases/3/candidate/reason", json!("provider refused")),
        ("/cases/4/decision_changed", json!(false)),
        ("/cases/4/same_recorded_request", json!(false)),
        ("/cases/4/candidate/mock", json!(true)),
        ("/cases/3/same_recorded_request", Value::Null),
    ] {
        assert_eq!(result.pointer(pointer), Some(&expected), "{pointer}");
    }
    for (field, value) in [
        ("binding", json!("text/1")),
        ("input_sha256", json!("b".repeat(64))),
        ("snapshot_id", json!("different-frozen-files")),
    ] {
        let mut changed = candidate.clone();
        *changed
            .get_mut("source")
            .and_then(|v| v.get_mut(field))
            .ok_or_else(|| format!("source identity {field} is absent"))? = value;
        assert!(compare(&changed).is_err(), "{field}");
    }
    *candidate
        .get_mut("source")
        .ok_or("candidate source is absent")? = Value::Null;
    assert!(compare(&candidate).is_err());
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions check comparison CLI exit codes and exact printed case outcomes"
)]
fn score_cli_compares_reports_without_provider_calls() -> TestResult {
    let dir = directory();
    let root = dir.path();
    let report = json!({"schema":"auditoad-report/2",
        "source":{"binding":"text/1","input_sha256":"a".repeat(64),"snapshot_id":"snapshot"},
        "records":[{"rule":{"id":"R"},"target":{"id":"one"},"result":"fail"}]});
    write(&root.join("reference.json"), &report)?;
    write(&root.join("candidate.json"), &report)?;
    write(
        &root.join("labels.json"),
        &json!({"schema":"auditoad-labels/1",
        "labels":[{"rule":"R","target":"one","violation":true}]}),
    )?;
    let command = || {
        Command::new(env!("CARGO_BIN_EXE_auditoad"))
            .current_dir(root)
            .args([
                "score",
                "--report",
                "candidate.json",
                "--labels",
                "labels.json",
                "--compare",
                "reference.json",
            ])
            .output()
    };
    let result = command()?;
    assert_eq!(result.status.code(), Some(0));
    let result: Value = serde_json::from_slice(&result.stdout)?;
    assert_eq!(result.get("schema"), Some(&json!("auditoad-comparison/1")));
    assert_eq!(
        result.pointer("/cases/0/decision_changed"),
        Some(&json!(false))
    );
    write(
        &root.join("candidate.json"),
        &json!({"schema":"auditoad-report/2",
        "source":report.get("source").ok_or("reference source is absent")?,"records":[]}),
    )?;
    assert_eq!(command()?.status.code(), Some(2));
    let mut changed = report.clone();
    *changed
        .pointer_mut("/source/input_sha256")
        .ok_or("source digest is absent")? = json!("b".repeat(64));
    write(&root.join("candidate.json"), &changed)?;
    assert_eq!(command()?.status.code(), Some(3));
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions check pre-dispatch credential and label-input protection"
)]
fn suite_protects_credentials_without_reading_them_and_keeps_labels_out_of_evidence() -> TestResult
{
    let dir = directory();
    let root = dir.path();
    let mut value = suite(root)?;
    write(
        &root.join("models.json"),
        &json!({"schema":"auditoad-evaluators/1",
        "evaluators":{"unused":{"backend":"openai-compatible","model":"test",
        "endpoint":"http://127.0.0.1:9/v1/chat/completions","key":{"file":"absent-key.txt"}}}}),
    )?;
    value
        .as_object_mut()
        .ok_or("suite is not an object")?
        .insert("evaluators".into(), json!("models.json"));
    *value
        .get_mut("report")
        .ok_or("suite report destination is absent")? = json!("absent-key.txt");
    write(&root.join("audit.json"), &value)?;
    let error = run_file(
        &root.join("audit.json"),
        &RunOptions::default(),
        |_, _| {},
        |_, _| {},
    )
    .err()
    .ok_or("credential-overlapping report was accepted")?;
    assert!(error.message.contains("overlaps"), "{}", error.message);
    assert!(!root.join("absent-key.txt").exists());
    assert!(!root.join("first.json").exists());

    *value
        .get_mut("report")
        .ok_or("suite report destination is absent")? = json!("suite.json");
    value
        .pointer_mut("/runs/0")
        .and_then(Value::as_object_mut)
        .ok_or("first run is absent")?
        .insert("labels".into(), json!("second.txt"));
    write(
        &root.join("second.txt"),
        &json!({"schema":"auditoad-labels/1","labels":[
        {"rule":"BYTES-1","target":"input/0","violation":true}]}),
    )?;
    write(&root.join("audit.json"), &value)?;
    let error = run_file(
        &root.join("audit.json"),
        &RunOptions::default(),
        |_, _| {},
        |_, _| {},
    )
    .err()
    .ok_or("labels overlapping evidence were accepted")?;
    assert!(
        error.message.contains("labels overlap"),
        "{}",
        error.message
    );
    assert!(!root.join("first.json").exists());
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions check all scoring buckets and the exact combined input budget"
)]
fn score_file_preparation_bounds_combined_inputs_and_keeps_every_outcome_bucket() -> TestResult {
    let dir = directory();
    let root = dir.path();
    let rows = [
        (true, "fail"),
        (false, "fail"),
        (false, "pass"),
        (true, "pass"),
        (true, "error"),
        (false, "not_evaluated"),
    ];
    let records: Vec<_> = rows.iter().enumerate().map(|(index, (_, result))| {
        json!({"rule":{"id":"R"},"target":{"id":format!("case-{index}")},"result":result})
    }).collect();
    let labels: Vec<_> = rows.iter().enumerate().map(|(index, (violation, _))| {
        json!({"rule":"R","target":format!("case-{index}"),"violation":violation})
    }).collect();
    let report = json!({"schema":"auditoad-report/2","records":records});
    let labels = json!({"schema":"auditoad-labels/1","labels":labels});
    let report_path = root.join("report.json");
    let labels_path = root.join("labels.json");
    write(&report_path, &report)?;
    write(&labels_path, &labels)?;
    let total_bytes = fs::metadata(&report_path)?
        .len()
        .checked_add(fs::metadata(&labels_path)?.len())
        .ok_or("fixture byte total overflow")?;
    let below_total = total_bytes
        .checked_sub(1)
        .ok_or("fixture byte total underflow")?;
    let summary = auditoad::score_files(&report_path, &labels_path, None, total_bytes)?;
    assert_eq!(summary.get("label_coverage_complete"), Some(&json!(true)));
    assert_eq!(summary.pointer("/overall/total"), Some(&json!(6)));
    for bucket in [
        "true_positive",
        "false_positive",
        "true_negative",
        "false_negative",
        "unresolved_positive",
        "unresolved_negative",
    ] {
        assert_eq!(
            summary.get("overall").and_then(|v| v.get(bucket)),
            Some(&json!(1)),
            "{bucket}"
        );
    }
    assert_eq!(summary.pointer("/overall/correct"), Some(&json!(2)));
    assert_eq!(summary.pointer("/overall/wrong"), Some(&json!(2)));
    assert_eq!(summary.pointer("/overall/unresolved"), Some(&json!(2)));
    assert_eq!(
        summary.pointer("/overall/resolved_accuracy"),
        Some(&json!(0.5))
    );
    assert!(auditoad::score_files(&report_path, &labels_path, None, below_total).is_err());
    let refused = Command::new(env!("CARGO_BIN_EXE_auditoad"))
        .args(["score", "--report"])
        .arg(&report_path)
        .arg("--labels")
        .arg(&labels_path)
        .arg("--max-input-bytes")
        .arg(below_total.to_string())
        .output()?;
    assert_eq!(refused.status.code(), Some(3));
    assert!(refused.stdout.is_empty());
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions check explicit evaluator precedence without live access"
)]
fn cli_evaluator_override_takes_precedence_over_environment_without_live_access() -> TestResult {
    let dir = directory();
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    for explicit in [false, true] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_auditoad"));
        command
            .current_dir(root)
            .args([
                "scan",
                "--baseline",
                "examples/shipping-policy/baseline.json",
                "--input",
                "examples/shipping-policy/bundle.json",
                "--report",
            ])
            .arg(dir.path().join("report.json"))
            .env("AUDITOAD_EVALUATORS", dir.path().join("missing.json"));
        if explicit {
            command.args(["--evaluators", "examples/evaluators.json"]);
        }
        let output = command.output()?;
        assert_eq!(
            output.status.code(),
            Some(if explicit { 2 } else { 3 }),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let report: Value = serde_json::from_slice(&fs::read(dir.path().join("report.json"))?)?;
    assert_eq!(report.pointer("/usage/provider_calls"), Some(&json!(0)));
    assert_eq!(
        report.pointer("/model_usage/jev/provider_calls"),
        Some(&json!(0))
    );
    let mut run = definition(dir.path());
    run.labels = Some(dir.path().join("labels.json"));
    assert!(
        run_one(&run, &RunOptions::default(), |_| {}, |_| {})
            .err()
            .ok_or("run_one accepted a scoring-only labels argument")?
            .message
            .contains("does not score")
    );
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions check receipt retention after scoring refusal and continued suite execution"
)]
fn scoring_refusal_retains_the_scan_receipt_and_continues_the_suite() -> TestResult {
    let dir = directory();
    let root = dir.path();
    let example = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/shipping-policy");
    let mut value = suite(root)?;
    let first = value
        .pointer_mut("/runs/0")
        .and_then(Value::as_object_mut)
        .ok_or("first run is absent")?;
    first.insert("baseline".into(), json!(example.join("baseline.json")));
    first.insert("input".into(), json!(example.join("bundle.json")));
    first.insert("labels".into(), json!("labels.json"));
    write(
        &root.join("labels.json"),
        &json!({"schema":"auditoad-labels/1","labels":[
        {"rule":"SHIPPING-FREE-THRESHOLD","packet":"shipping-fee","violation":true},
        {"rule":"SHIPPING-FREE-THRESHOLD","target":"shipping-fee","violation":true}]}),
    )?;
    write(&root.join("audit.json"), &value)?;
    let result = run_file(
        &root.join("audit.json"),
        &RunOptions::default(),
        |_, _| {},
        |_, _| {},
    )?;
    assert_eq!(result.exit_code, 3);
    assert_eq!(result.report.pointer("/runs/0/exit_code"), Some(&json!(3)));
    assert!(
        result
            .report
            .pointer("/runs/0/error")
            .and_then(Value::as_str)
            .ok_or("scoring refusal is absent")?
            .contains("duplicate label")
    );
    assert_eq!(
        result.report.pointer("/runs/0/receipt/report_sha256"),
        Some(&json!(auditoad::sha256(&fs::read(
            root.join("first.json")
        )?)))
    );
    assert_eq!(result.report.pointer("/runs/1/exit_code"), Some(&json!(0)));
    Ok(())
}
