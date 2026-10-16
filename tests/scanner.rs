mod support;
use auditoad::{
    MockModel, ScanRequest, Snapshot, ValidatedBaseline, scan, scan_to_file,
    schema::{Limits, Outcome, RequirementStatus, ResultState},
};
use serde_json::{Value, json};
use support::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions distinguish inclusive numeric bounds, violations and absent or mistyped evidence"
)]
fn json_number_range_checks_inclusive_bounds_without_treating_missing_values_as_passes()
-> TestResult {
    let dir = directory();
    let mut content = inventory_baseline(dir.path());
    *content
        .pointer_mut("/rules/0/evaluator")
        .ok_or("evaluator absent")? =
        json!({"kind":"json-number-range","contract":"json-number-range/1"});
    *content
        .pointer_mut("/rules/0/check")
        .ok_or("check absent")? = json!({"kind":"json-number-range/1",
        "pointer":"/facts/edge","minimum":0.2,"maximum":0.3,"fail_when_outside":true});
    let good = br#"{"id":"shape","kind":"host.property","facts":{"edge":0.25}}"#;
    let bad = br#"{"id":"shape","kind":"host.property","facts":{"edge":0.5}}"#;
    *content
        .pointer_mut("/rules/0/fixtures")
        .ok_or("fixtures absent")? = json!({
        "pass":[fixture(dir.path(),"edge-pass.json",good,good)],
        "fail":[fixture(dir.path(),"edge-fail.json",bad,bad)]});
    let baseline = ValidatedBaseline::from_bytes(&serde_json::to_vec(&content)?, dir.path())?;
    for (facts, expected) in [
        (json!({"edge":0.2}), ResultState::Pass),
        (json!({"edge":0.3}), ResultState::Pass),
        (json!({"edge":0.1}), ResultState::Fail),
        (json!({"edge":0.31}), ResultState::Fail),
        (json!({}), ResultState::NotEvaluated),
        (json!({"edge":"0.25"}), ResultState::NotEvaluated),
    ] {
        let input = serde_json::to_vec(
            &json!({"schema":"auditoad-inventory/1","snapshot_id":"bounds",
            "items":[{"id":"shape","kind":"host.property","facts":facts}]}),
        )?;
        let snapshot = Snapshot::inventory(&input, &Limits::default())?;
        let result = run(&baseline, &snapshot, Limits::default());
        assert_eq!(result.report.fixture_usage.checks, 2);
        assert_eq!(
            result
                .report
                .records
                .first()
                .ok_or("range record absent")?
                .result,
            expected
        );
    }
    *content
        .pointer_mut("/rules/0/check/minimum")
        .ok_or("minimum absent")? = json!(0.4);
    assert!(ValidatedBaseline::from_bytes(&serde_json::to_vec(&content)?, dir.path()).is_err());
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions require applicable evidence before a scan can clear"
)]
fn empty_or_inapplicable_evidence_never_clears_the_selected_audit() -> TestResult {
    let dir = directory();
    let mut content = inventory_baseline(dir.path());
    *content
        .pointer_mut("/rules/0/applicability/include")
        .ok_or("fixture applicability is absent")? = json!(["host.property"]);
    let baseline = validate(&content, dir.path());
    for (items, applicable) in [
        (json!([]), false),
        (
            json!([{"id":"other","kind":"scanner.result","facts":{}}]),
            false,
        ),
        (
            json!([{"id":"disk","kind":"host.property","facts":{"encrypted":true}}]),
            true,
        ),
    ] {
        let snapshot = Snapshot::inventory(
            json!({
                "schema":"auditoad-inventory/1","snapshot_id":"scope-r1","items":items,
            })
            .to_string()
            .as_bytes(),
            &Limits::default(),
        )?;
        let result = run(&baseline, &snapshot, Limits::default());
        assert_eq!(result.report.usage.provider_calls, 0);
        assert_eq!(
            result.report.records.len(),
            items
                .as_array()
                .ok_or("inventory fixture items are not an array")?
                .len()
        );
        if applicable {
            assert_eq!(result.report.outcome, Outcome::Clear);
            assert_eq!(result.exit_code, 0);
            assert_eq!(
                result
                    .report
                    .records
                    .first()
                    .ok_or("applicable record is absent")?
                    .result,
                ResultState::Pass
            );
            assert!(result.report.outcome_reason.is_none());
        } else {
            assert_eq!(result.report.outcome, Outcome::Unresolved);
            assert_eq!(result.exit_code, 2);
            assert!(
                result
                    .report
                    .outcome_reason
                    .as_ref()
                    .ok_or("empty/inapplicable outcome reason is absent")?
                    .contains("no applicable checks")
            );
            assert_eq!(
                result.report.counts.get(&ResultState::Notapplicable),
                Some(&u64::try_from(result.report.records.len())?)
            );
        }
    }
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions check exact baseline byte admission and preserve semantic validation"
)]
fn explicit_baseline_bound_preserves_default_and_semantic_validation() -> TestResult {
    let dir = directory();
    let mut bytes = bytes_baseline(dir.path()).to_string().into_bytes();
    bytes.resize(2_097_153, b' ');
    let limit = u64::try_from(bytes.len())?;
    let below_limit = limit.checked_sub(1).ok_or("fixture byte limit underflow")?;
    let path = dir.path().join("large.json");
    std::fs::write(&path, &bytes)?;
    assert!(ValidatedBaseline::from_bytes(&bytes, dir.path()).is_err());
    assert!(ValidatedBaseline::from_file(&path).is_err());
    assert!(ValidatedBaseline::from_bytes_with_limit(&bytes, dir.path(), below_limit).is_err());
    assert!(ValidatedBaseline::from_file_with_limit(&path, below_limit).is_err());
    let memory = ValidatedBaseline::from_bytes_with_limit(&bytes, dir.path(), limit)?;
    let file = ValidatedBaseline::from_file_with_limit(&path, limit)?;
    assert_eq!(memory.baseline().rules.len(), file.baseline().rules.len());
    *bytes.first_mut().ok_or("baseline fixture is empty")? = b'[';
    std::fs::write(&path, &bytes)?;
    assert!(ValidatedBaseline::from_bytes_with_limit(&bytes, dir.path(), limit).is_err());
    assert!(ValidatedBaseline::from_file_with_limit(&path, limit).is_err());
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions check the entire declared vocabulary and Markdown exclusions"
)]
fn vocabulary_example_checks_all_terms_and_excludes_context_and_code() -> TestResult {
    let dir = directory();
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/no-slop/baseline.json");
    let baseline = ValidatedBaseline::from_file(&path)?;
    let mut cases = Vec::new();
    for (id, count) in [("WORDS-01", 44), ("WORDS-02", 11), ("WORDS-04", 6)] {
        let rule = baseline
            .baseline()
            .rules
            .iter()
            .find(|r| r.id == id)
            .ok_or_else(|| format!("vocabulary rule {id} is absent"))?;
        let auditoad::schema::Check::Markdown {
            predicate: auditoad::schema::MarkdownPredicate::ForbiddenTerms { terms },
            ..
        } = &rule.check
        else {
            return Err(format!("{id} must use the local vocabulary predicate").into());
        };
        assert_eq!(terms.len(), count);
        for term in terms {
            cases.push((format!("{term}."), Some(id)));
        }
    }
    cases.extend([
        ("A VERY clear result.".into(), Some("WORDS-04")),
        ("It’s worth remembering the date.".into(), Some("WORDS-02")),
        ("A ro**bu**st result.".into(), Some("WORDS-01")),
        ("# An innovative device\n".into(), Some("WORDS-01")),
        (
            "- Keep\n  in mind that it closes early.\n".into(),
            Some("WORDS-02"),
        ),
        ("A v&#101;ry clear result.".into(), Some("WORDS-04")),
        (
            "Every delivery arrived at the fosterling's realmstone.".into(),
            None,
        ),
        ("veryé évery very\u{301}".into(), None),
        ("`very robust ultimately`".into(), None),
        ("```\nvery robust ultimately\n```".into(), None),
        ("![very robust ultimately](picture.png)".into(), None),
        (
            "[Plain](https://example.org/robust \"very ultimately\")".into(),
            None,
        ),
        ("Keep in mind. That is enough.".into(), None),
        ("Let's take `code` a look at it.".into(), None),
        ("Pave\n\nthe way.".into(), None),
        ("".into(), None),
    ]);
    let policy = "The context contains robust, very and ultimately.";
    std::fs::write(dir.path().join("policy.md"), policy)?;
    for (text, failed) in cases {
        std::fs::write(dir.path().join("article.md"), &text)?;
        let bundle_path = dir.path().join("bundle.json");
        std::fs::write(&bundle_path, json!({
            "schema":"auditoad-evidence-bundle/1",
            "files":{"article.md":auditoad::sha256(text.as_bytes()),"policy.md":auditoad::sha256(policy.as_bytes())},
            "packets":[{"id":"article","kind":"writing","scope_kind":"site","parts":[
                {"role":"policy","path":"policy.md"},{"role":"subject","path":"article.md"}]}]
        }).to_string())?;
        let snapshot = Snapshot::bundle(&bundle_path, dir.path(), &Limits::default())?;
        let result = scan(ScanRequest {
            baseline: &baseline,
            profile: "vocabulary",
            source_alias: "evidence",
            snapshot: &snapshot,
            limits: Limits::default(),
            experimental: true,
            mock: None,
        })?;
        assert_eq!(result.report.usage.provider_calls, 0);
        assert_eq!(result.report.records.len(), 3);
        for record in result.report.records {
            assert_eq!(
                record.result,
                if failed == Some(record.rule.id.as_str()) {
                    ResultState::Fail
                } else {
                    ResultState::Pass
                },
                "{}: {text}",
                record.rule.id
            );
        }
    }
    let mut invalid = support::bytes_baseline(dir.path());
    *invalid
        .pointer_mut("/rules/0/evaluator")
        .ok_or("fixture evaluator is absent")? = json!({"kind":"markdown","contract":"markdown/1"});
    for terms in [
        json!([]),
        json!([""]),
        json!([" "]),
        json!(["!!!"]),
        json!(["very!"]),
    ] {
        *invalid
            .pointer_mut("/rules/0/check")
            .ok_or("fixture check is absent")? =
            json!({"kind":"markdown/1","predicate":{"kind":"forbidden_terms","terms":terms}});
        assert!(ValidatedBaseline::from_bytes(invalid.to_string().as_bytes(), dir.path()).is_err());
    }
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions check exact UTF-8 punctuation counts in byte and declared-span profiles"
)]
fn punctuation_example_checks_exact_utf8_count_at_the_boundary() -> TestResult {
    let dir = directory();
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("examples/no-slop/punctuation.baseline.json");
    let baseline = ValidatedBaseline::from_file(&path)?;
    let mixed = ValidatedBaseline::from_file(&path.with_file_name("baseline.json"))?;
    let kind = &mixed
        .baseline()
        .rules
        .iter()
        .find(|r| r.id == "FORMAT-05")
        .ok_or("mixed punctuation rule is absent")?
        .applicability
        .include
        .first()
        .ok_or("punctuation applicability kind is absent")?;
    let policy = "The brief — not the article — contains extra punctuation.";
    std::fs::write(dir.path().join("brief.md"), policy)?;
    for (text, expected) in [
        ("No dash.", ResultState::Pass),
        ("One — dash.", ResultState::Pass),
        ("Two — separated — dashes.", ResultState::Fail),
        ("——", ResultState::Fail),
        ("Three — — — dashes.", ResultState::Fail),
        ("Hyphens -- and en dashes – –.", ResultState::Pass),
        (r"Escaped text \u2014 \u2014.", ResultState::Pass),
        ("Quoted: `— —`", ResultState::Fail),
    ] {
        let limits = Limits::default();
        let source = Snapshot::raw_bytes(text.as_bytes().to_vec(), "document.md", &limits)?;
        let result = scan(ScanRequest {
            baseline: &baseline,
            profile: "all",
            source_alias: "document",
            snapshot: &source,
            limits,
            experimental: false,
            mock: None,
        })?;
        assert_eq!(
            result
                .report
                .records
                .first()
                .ok_or("punctuation record is absent")?
                .result,
            expected,
            "{text}"
        );
        assert_eq!(result.report.usage.provider_calls, 0);

        std::fs::write(dir.path().join("article.md"), text)?;
        let bundle_path = dir.path().join("bundle.json");
        std::fs::write(&bundle_path, json!({
            "schema":"auditoad-evidence-bundle/1",
            "files":{"article.md":auditoad::sha256(text.as_bytes()), "brief.md":auditoad::sha256(policy.as_bytes())},
            "packets":[{"id":"new-article","kind":kind,"scope_kind":"site","parts":[
                {"role":"policy","path":"brief.md"},{"role":"subject","path":"article.md"}]}]
        }).to_string())?;
        let snapshot = Snapshot::bundle(&bundle_path, dir.path(), &Limits::default())?;
        let result = scan(ScanRequest {
            baseline: &mixed,
            profile: "format",
            source_alias: "evidence",
            snapshot: &snapshot,
            limits: Limits::default(),
            experimental: true,
            mock: None,
        })?;
        let record = result
            .report
            .records
            .iter()
            .find(|r| r.rule.id == "FORMAT-05")
            .ok_or("mixed-profile punctuation record is absent")?;
        assert_eq!(record.result, expected, "mixed baseline: {text}");
        assert_eq!(
            record
                .observation
                .as_ref()
                .and_then(|v| v.get("selected_sha256")),
            Some(&json!(auditoad::sha256(text.as_bytes())))
        );
        assert_eq!(result.report.usage.provider_calls, 0);
    }
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions check Markdown admission, retained evidence and exact outcome exits"
)]
fn markdown_predicates_use_normal_admission_evidence_and_exit_status() -> TestResult {
    let dir = directory();
    for (predicate, pass, fail) in [
        (
            json!({"kind":"prose_bold"}),
            "# **Heading**\n\n- **List label**: details.\n",
            "Keep **the original receipt**.",
        ),
        (
            json!({"kind":"list_length","forbidden_length":3}),
            "- one\n- two\n",
            "- one\n- two\n- three\n",
        ),
        (
            json!({"kind":"paragraph_sentence_lengths","shorter_than":3,"longer_than":6}),
            "Stop now. One two three four five six seven.",
            "Stop now.",
        ),
    ] {
        let mut value = bytes_baseline(dir.path());
        *value
            .pointer_mut("/rules/0/evaluator")
            .ok_or("fixture evaluator is absent")? =
            json!({"kind":"markdown","contract":"markdown/1"});
        *value
            .pointer_mut("/rules/0/check")
            .ok_or("fixture check is absent")? = json!({"kind":"markdown/1","predicate":predicate});
        *value
            .pointer_mut("/rules/0/fixtures")
            .ok_or("fixture examples are absent")? = json!({
            "pass":[fixture(dir.path(), "pass.md", pass.as_bytes(), pass.as_bytes())],
            "fail":[fixture(dir.path(), "fail.md", fail.as_bytes(), fail.as_bytes())],
        });
        let baseline = validate(&value, dir.path());
        for (text, expected, code) in [
            (pass.as_bytes(), ResultState::Pass, 0),
            (fail.as_bytes(), ResultState::Fail, 1),
            (&[0xff], ResultState::NotEvaluated, 2),
        ] {
            let source = Snapshot::raw_bytes(text.to_vec(), "document.md", &Limits::default())?;
            let result = run(&baseline, &source, Limits::default());
            assert_eq!(result.exit_code, code);
            let [record] = result.report.records.as_slice() else {
                return Err("expected one Markdown record".into());
            };
            assert_eq!(record.result, expected);
            assert_eq!(record.evaluator.binding, "markdown");
            assert_eq!(
                record
                    .evidence
                    .as_ref()
                    .ok_or("Markdown evidence is absent")?
                    .bytes,
                text
            );
            assert_eq!(result.report.fixture_usage.checks, 2);
            assert_eq!(result.report.usage.provider_calls, 0);
        }
        let mut invalid = value.clone();
        invalid
            .pointer_mut("/rules/0/check")
            .and_then(Value::as_object_mut)
            .ok_or("Markdown check is absent")?
            .insert("json_string_pointer".into(), json!("/subject"));
        assert!(ValidatedBaseline::from_bytes(invalid.to_string().as_bytes(), dir.path()).is_err());
        for predicate in [
            json!({"kind":"list_length","forbidden_length":0}),
            json!({"kind":"paragraph_sentence_lengths","shorter_than":1,"longer_than":6}),
            json!({"kind":"paragraph_sentence_lengths","shorter_than":7,"longer_than":6}),
        ] {
            invalid = value.clone();
            *invalid
                .pointer_mut("/rules/0/check/predicate")
                .ok_or("Markdown predicate is absent")? = predicate;
            assert!(
                ValidatedBaseline::from_bytes(invalid.to_string().as_bytes(), dir.path()).is_err()
            );
        }
    }
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions check shared byte/inventory record, identity and coverage contracts"
)]
fn both_domains_share_the_same_record_and_coverage_contract() -> TestResult {
    let dir = directory();
    let limits = Limits::default();
    let bytes = validate(&bytes_baseline(dir.path()), dir.path());
    for (input, expected, code) in [
        (b"bad".as_slice(), ResultState::Fail, 1),
        (b"good".as_slice(), ResultState::Pass, 0),
    ] {
        let source = Snapshot::raw_bytes(input.to_vec(), "input.txt", &limits)?;
        let result = run(&bytes, &source, limits.clone());
        assert_eq!(result.exit_code, code);
        let [record] = result.report.records.as_slice() else {
            return Err("expected one byte-policy record".into());
        };
        assert_eq!(record.result, expected);
        assert_eq!(record.check_id.len(), 64);
        assert_eq!(result.report.counts.get(&expected), Some(&1));
        assert_eq!(
            auditoad::sha256(&result.report.manifest_bytes),
            result.report.manifest_sha256
        );
        assert_eq!(
            record
                .evidence
                .as_ref()
                .ok_or("byte-policy evidence is absent")?
                .bytes,
            input
        );
        assert_eq!(result.report.fixture_usage.checks, 2);
    }
    let baseline = validate(&inventory_baseline(dir.path()), dir.path());
    let source = inventory(
        json!([
            {"id":"disk/a","kind":"host.property","facts":{"encrypted":true}},
            {"id":"disk/b","kind":"host.property","facts":{"encrypted":false}},
            {"id":"disk/c","kind":"host.property","facts":{}},
            {"id":"elsewhere","kind":"other","facts":{}}
        ]),
        &limits,
    );
    let result = run(&baseline, &source, limits);
    assert_eq!(result.exit_code, 2); // unresolved dominates finding
    assert_eq!(result.report.outcome, Outcome::Unresolved);
    assert_eq!(result.report.target_count, 4);
    assert_eq!(result.report.work_count, 4);
    for state in [
        ResultState::Pass,
        ResultState::Fail,
        ResultState::NotEvaluated,
        ResultState::Notapplicable,
    ] {
        assert_eq!(result.report.counts.get(&state), Some(&1));
    }
    assert_eq!(result.report.usage.checks, 3);
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions check legacy input custody and current output schemas"
)]
fn legacy_inventory_and_baseline_inputs_preserve_identity_and_emit_auditoad_records() -> TestResult
{
    let dir = directory();
    for prefix in ["auditoad", "checkwarden"] {
        let mut declaration = inventory_baseline(dir.path());
        *declaration
            .get_mut("schema")
            .ok_or("fixture schema is absent")? = json!(format!("{prefix}-baseline/1"));
        let encoded = declaration.to_string().into_bytes();
        let baseline = ValidatedBaseline::from_bytes(&encoded, dir.path())?;
        let input = json!({
            "schema": format!("{prefix}-inventory/1"), "snapshot_id": "migration",
            "items": [{"id":"disk", "kind":"host.property", "facts":{"encrypted":true}}]
        })
        .to_string()
        .into_bytes();
        let snapshot = Snapshot::inventory(&input, &Limits::default())?;
        let result = run(&baseline, &snapshot, Limits::default());
        assert_eq!(result.exit_code, 0);
        assert_eq!(result.report.schema, "auditoad-report/2");
        let [record] = result.report.records.as_slice() else {
            return Err("expected one legacy inventory record".into());
        };
        assert_eq!(record.schema, "auditoad-result/1");
        assert_eq!(record.baseline.sha256, auditoad::sha256(&encoded));
        assert_eq!(record.source.input_sha256, auditoad::sha256(&input));
        *declaration
            .get_mut("schema")
            .ok_or("fixture schema is absent")? = json!(format!("{prefix}-baseline/2"));
        assert!(
            ValidatedBaseline::from_bytes(declaration.to_string().as_bytes(), dir.path()).is_err()
        );
    }
    Ok(())
}

#[test]
fn check_and_evidence_limits_record_every_tail_unit_without_evaluation() {
    let dir = directory();
    let baseline = validate(&inventory_baseline(dir.path()), dir.path());
    let source = inventory(
        json!([
            {"id":"a","kind":"host.property","facts":{"encrypted":true}},
            {"id":"b","kind":"host.property","facts":{"encrypted":true}}
        ]),
        &Limits::default(),
    );
    let result = run(
        &baseline,
        &source,
        Limits {
            checks: 1,
            ..Limits::default()
        },
    );
    assert_eq!(result.report.counts.get(&ResultState::Pass), Some(&1));
    assert_eq!(
        result.report.counts.get(&ResultState::NotEvaluated),
        Some(&1)
    );
    assert_eq!(result.report.usage.checks, 1);
    let result = run(
        &baseline,
        &source,
        Limits {
            evidence_bytes: 0,
            ..Limits::default()
        },
    );
    assert_eq!(
        result.report.counts.get(&ResultState::NotEvaluated),
        Some(&2)
    );
    assert_eq!(result.report.usage.evidence_bytes, 0);
    assert!(
        result
            .report
            .records
            .iter()
            .all(|r| r.observation.is_none())
    );
}

#[test]
fn empty_inventory_is_an_explicit_zero_work_report() {
    let dir = directory();
    let baseline = validate(&inventory_baseline(dir.path()), dir.path());
    let source = inventory(json!([]), &Limits::default());
    let result = run(&baseline, &source, Limits::default());
    assert_eq!(result.exit_code, 2);
    let report = result.report;
    assert_eq!(report.target_count, 0);
    assert_eq!(report.work_count, 0);
    assert_eq!(report.outcome, Outcome::Unresolved);
    assert!(
        report
            .outcome_reason
            .as_deref()
            .is_some_and(|reason| reason.contains("no applicable checks"))
    );
    assert!(report.counts.values().all(|v| *v == 0));
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions distinguish advisory findings from explicit exclusions"
)]
fn advisory_findings_still_say_finding_and_exclusions_stay_explicit() -> TestResult {
    let dir = directory();
    let mut value = bytes_baseline(dir.path());
    *value
        .pointer_mut("/profiles/0/block_on")
        .ok_or("profile block policy is absent")? = json!(["error", "not_evaluated"]);
    let source = Snapshot::raw_bytes(b"bad".to_vec(), "input.txt", &Limits::default())?;
    let result = run(&validate(&value, dir.path()), &source, Limits::default());
    assert_eq!(result.exit_code, 0);
    assert_eq!(result.report.outcome, Outcome::Finding);
    *value
        .pointer_mut("/rules/0/applicability/exclude")
        .ok_or("exclusion declaration is absent")? = json!(["input.txt"]);
    let result = run(&validate(&value, dir.path()), &source, Limits::default());
    let [record] = result.report.records.as_slice() else {
        return Err("expected one excluded record".into());
    };
    assert_eq!(record.result, ResultState::Notapplicable);
    assert!(record.reason.is_some());
    assert_eq!(result.report.usage.checks, 0);
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions require a frozen file mutation to remain an unresolved error"
)]
fn frozen_file_mutation_is_error() -> TestResult {
    let dir = directory();
    let baseline = validate(&bytes_baseline(dir.path()), dir.path());
    let path = dir.path().join("target.txt");
    std::fs::write(&path, b"good")?;
    let source = Snapshot::from_file("raw-bytes/1", &path, &Limits::default())?;
    std::fs::write(&path, b"bad")?;
    let result = run(&baseline, &source, Limits::default());
    assert_eq!(result.exit_code, 2);
    let [record] = result.report.records.as_slice() else {
        return Err("expected one mutated-file record".into());
    };
    assert_eq!(record.result, ResultState::Error);
    assert!(
        record
            .reason
            .as_ref()
            .ok_or("mutated-file refusal reason is absent")?
            .contains("changed")
    );
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions require complete manifest refusal and prohibit source truncation"
)]
fn structural_limit_refuses_whole_manifest_and_source_never_truncates() -> TestResult {
    let dir = directory();
    let baseline = validate(&bytes_baseline(dir.path()), dir.path());
    let source = Snapshot::raw_bytes(b"good".to_vec(), "target", &Limits::default())?;
    let error = scan(ScanRequest {
        baseline: &baseline,
        profile: "default",
        source_alias: "bytes",
        snapshot: &source,
        limits: Limits {
            manifest_work: 0,
            ..Limits::default()
        },
        experimental: false,
        mock: None,
    })
    .err()
    .ok_or("zero manifest allowance was accepted")?;
    assert_eq!(error.exit_code, 2);
    assert!(
        Snapshot::raw_bytes(
            b"good".to_vec(),
            "target",
            &Limits {
                targets: 0,
                ..Limits::default()
            }
        )
        .is_err()
    );
    assert!(
        Snapshot::raw_bytes(
            b"good".to_vec(),
            "target",
            &Limits {
                input_bytes: 3,
                ..Limits::default()
            }
        )
        .is_err()
    );
    let bad = br#"{"schema":"auditoad-inventory/1","snapshot_id":"x","items":[{"id":"same","kind":"host.property","facts":{}},{"id":"same","kind":"host.property","facts":{}}]}"#;
    assert!(Snapshot::inventory(bad, &Limits::default()).is_err());
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions require each ambiguous, unknown and unsupported declaration to refuse"
)]
fn validation_refuses_ambiguous_unknown_and_unsupported_declarations() -> TestResult {
    let dir = directory();
    let good = bytes_baseline(dir.path());
    let mut cases = Vec::new();
    let mut v = good.clone();
    v.as_object_mut()
        .ok_or("fixture baseline is not an object")?
        .insert("unexpected".into(), json!(true));
    cases.push(v);
    for (pointer, replacement) in [
        ("/rules/0/revision", json!("")),
        ("/profiles/0/block_on", json!(["fail"])),
        ("/profiles/0/select", json!(["NO-SUCH-RULE"])),
        ("/profiles/0/select", json!(["*", "*"])),
        ("/profiles/0/allowed_egress", json!(["jev"])),
        ("/rules/0/scope_kind", json!("relation")),
        ("/evidence/bytes/builder_revision", json!("r2")),
        ("/rules/0/check/source", json!("include \"forbidden-file\"")),
        ("/rules/0/check/rule_name", json!("absent")),
        ("/rules/0/fixtures/fail/0/path", json!("../outside")),
    ] {
        let mut v = good.clone();
        *v.pointer_mut(pointer)
            .ok_or_else(|| format!("mutation field {pointer} is absent"))? = replacement;
        cases.push(v);
    }
    let mut v = good.clone();
    let rule = v
        .pointer("/rules/0")
        .ok_or("fixture rule is absent")?
        .clone();
    v.get_mut("rules")
        .and_then(Value::as_array_mut)
        .ok_or("fixture rules are absent")?
        .push(rule);
    cases.push(v);
    let mut v = inventory_baseline(dir.path());
    *v.pointer_mut("/rules/0/check/pointer")
        .ok_or("inventory predicate pointer is absent")? = json!("/bad~9pointer");
    cases.push(v);
    for value in cases {
        assert!(
            ValidatedBaseline::from_bytes(value.to_string().as_bytes(), dir.path()).is_err(),
            "accepted {value}"
        );
    }
    let encoded = good.to_string();
    let duplicate = encoded.replacen("{", "{\"schema\":\"auditoad-baseline/1\",", 1);
    assert!(ValidatedBaseline::from_bytes(duplicate.as_bytes(), dir.path()).is_err());
    assert!(ValidatedBaseline::from_bytes(&[0xff, 0xfe], dir.path()).is_err());
    Ok(())
}

/// Three rules: BYTES-1 applies to the disk, BYTES-2 applies to no supplied item and
/// BYTES-3 sits outside the profile's selected group.
fn requirement_baseline(root: &std::path::Path) -> Result<Value, Box<dyn std::error::Error>> {
    let mut value = inventory_baseline(root);
    let rule = value
        .pointer("/rules/0")
        .ok_or("fixture rule is absent")?
        .clone();
    let mut unsupported = rule.clone();
    *unsupported.pointer_mut("/id").ok_or("rule id is absent")? = json!("BYTES-2");
    *unsupported
        .pointer_mut("/applicability/include")
        .ok_or("rule applicability is absent")? = json!(["scanner.result"]);
    let mut unselected = rule;
    *unselected.pointer_mut("/id").ok_or("rule id is absent")? = json!("BYTES-3");
    *unselected
        .pointer_mut("/group")
        .ok_or("rule group is absent")? = json!("OTHER");
    let rules = value
        .get_mut("rules")
        .and_then(Value::as_array_mut)
        .ok_or("fixture rules are absent")?;
    rules.extend([unsupported, unselected]);
    for (index, links) in [
        json!({"R-OK":"2","R-STALE":"1","R-OUT":"1"}),
        json!({"R-UNSUPPORTED":"1"}),
        json!({"R-UNASKED":"1"}),
    ]
    .into_iter()
    .enumerate()
    {
        rules
            .get_mut(index)
            .and_then(Value::as_object_mut)
            .ok_or("fixture rule is absent")?
            .insert("requirements".into(), links);
    }
    value
        .get_mut("groups")
        .and_then(Value::as_array_mut)
        .ok_or("fixture groups are absent")?
        .push(json!({"id":"OTHER","title":"Other policy"}));
    value
        .as_object_mut()
        .ok_or("fixture baseline is not an object")?
        .insert(
            "requirements".into(),
            json!([
                {"id":"R-OK","revision":"2","title":"Disks are encrypted","reference":"Policy 4.1"},
                {"id":"R-MISSING","revision":"1","title":"Backups are retained"},
                {"id":"R-UNASKED","revision":"1","title":"Other policy holds"},
                {"id":"R-STALE","revision":"2","title":"Encryption uses current keys"},
                {"id":"R-UNSUPPORTED","revision":"1","title":"Scanner results are clean"},
                {"id":"R-OUT","revision":"1","title":"Outside this profile"}
            ]),
        );
    let profile = value
        .pointer_mut("/profiles/0")
        .and_then(Value::as_object_mut)
        .ok_or("fixture profile is absent")?;
    profile.insert("select".into(), json!(["BYTES/*"]));
    profile.insert(
        "requirements".into(),
        json!(["R-OK", "R-MISSING", "R-UNASKED", "R-STALE", "R-UNSUPPORTED"]),
    );
    Ok(value)
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions name each requirement status and the blocking outcome"
)]
fn requirement_coverage_reports_every_blocker_and_profile_scope() -> TestResult {
    let dir = directory();
    let baseline = validate(&requirement_baseline(dir.path())?, dir.path());
    let source = inventory(
        json!([{"id":"disk","kind":"host.property","facts":{"encrypted":true}}]),
        &Limits::default(),
    );
    let result = run(&baseline, &source, Limits::default());
    let statuses: Vec<_> = result
        .report
        .requirements
        .iter()
        .map(|r| (r.id.as_str(), r.status))
        .collect();
    assert_eq!(
        statuses,
        [
            ("R-OK", RequirementStatus::Satisfied),
            ("R-MISSING", RequirementStatus::Missing),
            ("R-UNASKED", RequirementStatus::Unasked),
            ("R-STALE", RequirementStatus::Stale),
            ("R-UNSUPPORTED", RequirementStatus::Unsupported),
            ("R-OUT", RequirementStatus::NotRequired),
        ]
    );
    assert_eq!(result.report.outcome, Outcome::Unresolved);
    assert_eq!(result.exit_code, 2);
    assert_eq!(
        result.report.outcome_reason.as_deref(),
        Some(
            "required checks blocked: R-MISSING missing, R-UNASKED unasked, R-STALE stale, R-UNSUPPORTED unsupported"
        )
    );
    let satisfied = result
        .report
        .requirements
        .first()
        .ok_or("requirement coverage is absent")?;
    assert_eq!(satisfied.rules, ["BYTES-1"]);
    assert_eq!(satisfied.counts.get(&ResultState::Pass), Some(&1));
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions require a decided check before a requirement clears"
)]
fn requirement_coverage_clears_only_when_every_required_check_decides() -> TestResult {
    let dir = directory();
    let mut value = inventory_baseline(dir.path());
    value
        .as_object_mut()
        .ok_or("fixture baseline is not an object")?
        .insert(
            "requirements".into(),
            json!([{"id":"R-ENC","revision":"1","title":"Disks are encrypted"}]),
        );
    value
        .pointer_mut("/rules/0")
        .and_then(Value::as_object_mut)
        .ok_or("fixture rule is absent")?
        .insert("requirements".into(), json!({"R-ENC":"1"}));
    let baseline = validate(&value, dir.path());
    let disk = |id: &str, encrypted: bool| json!({"id":id,"kind":"host.property","facts":{"encrypted":encrypted}});
    for (items, limits, outcome, exit, status) in [
        (
            json!([disk("a", true)]),
            Limits::default(),
            Outcome::Clear,
            0,
            RequirementStatus::Satisfied,
        ),
        (
            json!([disk("a", false)]),
            Limits::default(),
            Outcome::Finding,
            1,
            RequirementStatus::Finding,
        ),
        (
            json!([disk("a", true), disk("b", true)]),
            Limits {
                checks: 1,
                ..Limits::default()
            },
            Outcome::Unresolved,
            2,
            RequirementStatus::Unresolved,
        ),
    ] {
        let result = run(&baseline, &inventory(items, &Limits::default()), limits);
        assert_eq!((result.report.outcome, result.exit_code), (outcome, exit));
        let [coverage] = result.report.requirements.as_slice() else {
            return Err("expected one requirement".into());
        };
        assert_eq!(coverage.status, status);
        assert_eq!(
            result
                .report
                .outcome_reason
                .as_deref()
                .is_some_and(|reason| reason.contains("R-ENC unresolved")),
            status == RequirementStatus::Unresolved
        );
    }
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions require every unknown or ambiguous requirement link to refuse"
)]
fn requirement_links_must_name_declared_requirements() -> TestResult {
    let dir = directory();
    let good = requirement_baseline(dir.path())?;
    validate(&good, dir.path());
    let mut cases = Vec::new();
    for (pointer, replacement) in [
        ("/rules/0/requirements", json!({"R-NONE":"1"})),
        ("/rules/0/requirements/R-OK", json!("")),
        ("/requirements/1/id", json!("R-OK")),
        ("/requirements/0/revision", json!("")),
        ("/profiles/0/requirements", json!(["R-NONE"])),
        ("/profiles/0/requirements", json!([])),
        ("/profiles/0/requirements", json!(["R-OK", "R-OK"])),
    ] {
        let mut v = good.clone();
        *v.pointer_mut(pointer)
            .ok_or_else(|| format!("mutation field {pointer} is absent"))? = replacement;
        cases.push(v);
    }
    let mut v = good;
    v.pointer_mut("/requirements/0")
        .and_then(Value::as_object_mut)
        .ok_or("fixture requirement is absent")?
        .insert("required".into(), json!(true));
    cases.push(v);
    for value in cases {
        assert!(
            ValidatedBaseline::from_bytes(value.to_string().as_bytes(), dir.path()).is_err(),
            "accepted {value}"
        );
    }
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions require exact fixture custody and reject contradictory labels"
)]
fn altered_or_mislabeled_fixtures_cannot_admit_the_rule() -> TestResult {
    let dir = directory();
    let value = bytes_baseline(dir.path());
    let baseline = validate(&value, dir.path());
    let source = Snapshot::raw_bytes(b"good".to_vec(), "input", &Limits::default())?;
    std::fs::write(dir.path().join("fail.txt"), b"good")?;
    let run = |baseline: &ValidatedBaseline| {
        scan(ScanRequest {
            baseline,
            profile: "default",
            source_alias: "bytes",
            snapshot: &source,
            limits: Limits::default(),
            experimental: false,
            mock: None,
        })
    };
    assert!(
        run(&baseline)
            .err()
            .ok_or("altered fixture was admitted")?
            .message
            .contains("digest")
    );
    let mut wrong = bytes_baseline(dir.path());
    let passes = wrong
        .pointer("/rules/0/fixtures/pass")
        .ok_or("pass fixtures are absent")?
        .clone();
    *wrong
        .pointer_mut("/rules/0/fixtures/fail")
        .ok_or("fail fixtures are absent")? = passes;
    assert!(
        run(&validate(&wrong, dir.path()))
            .err()
            .ok_or("contradictory fixture labels were admitted")?
            .message
            .contains("contradicts")
    );
    Ok(())
}

fn mock_script(kind: Value) -> Result<MockModel, Box<dyn std::error::Error>> {
    Ok(MockModel::from_bytes(json!({"schema":"auditoad-mock-model/1","replies":[{
        "rule":"BYTES-1","revision":"r1","evidence_sha256":auditoad::sha256(b"good"),
        "instructions_sha256":auditoad::sha256(b"Does this input violate the supplied policy?"),"response":kind
    }]}).to_string().as_bytes())?)
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions retain each simulated probability as experimental observation"
)]
fn mock_decision_regions_are_observations_and_never_clear_an_audit() -> TestResult {
    let dir = directory();
    let baseline = validate(&mock_baseline(dir.path()), dir.path());
    let source = Snapshot::raw_bytes(b"good".to_vec(), "target", &Limits::default())?;
    for (probability, suggested) in [(0.01, "pass"), (0.5, "review"), (0.99, "fail")] {
        let mock = mock_script(json!({"kind":"probability","value":probability}))?;
        let result = scan(ScanRequest {
            baseline: &baseline,
            profile: "default",
            source_alias: "bytes",
            snapshot: &source,
            limits: Limits::default(),
            experimental: true,
            mock: Some(&mock),
        })?;
        assert_eq!(result.exit_code, 2);
        let [record] = result.report.records.as_slice() else {
            return Err("expected one simulated decision record".into());
        };
        assert_eq!(record.result, ResultState::NotEvaluated);
        let observation = record
            .observation
            .as_ref()
            .ok_or("simulated observation is absent")?;
        assert_eq!(observation.get("suggested_result"), Some(&json!(suggested)));
        let request = report_text(
            observation
                .get("request_bytes")
                .ok_or("simulated request bytes are absent")?,
        );
        assert_eq!(
            Some(&json!(auditoad::sha256(request.as_bytes()))),
            observation.get("request_sha256")
        );
        assert_eq!(result.report.usage.provider_calls, 1);
    }
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions require every provider failure or stale/duplicate reply to remain unresolved"
)]
fn provider_failures_stale_and_duplicate_replies_never_pass() -> TestResult {
    let dir = directory();
    let baseline = validate(&mock_baseline(dir.path()), dir.path());
    let source = Snapshot::raw_bytes(b"good".to_vec(), "target", &Limits::default())?;
    for kind in [
        "timeout",
        "unavailable",
        "stale_check",
        "stale_generation",
        "wrong_version",
        "duplicate",
    ] {
        let mock = mock_script(json!({"kind":kind}))?;
        let result = scan(ScanRequest {
            baseline: &baseline,
            profile: "default",
            source_alias: "bytes",
            snapshot: &source,
            limits: Limits::default(),
            experimental: true,
            mock: Some(&mock),
        })?;
        assert_eq!(result.exit_code, 2);
        assert_eq!(
            result
                .report
                .records
                .first()
                .ok_or("provider-failure record is absent")?
                .result,
            ResultState::Error,
            "{kind}"
        );
        assert_eq!(result.report.usage.provider_calls, 1);
    }
    let mock = mock_script(json!({"kind":"probability","value":0.01}))?;
    let result = scan(ScanRequest {
        baseline: &baseline,
        profile: "default",
        source_alias: "bytes",
        snapshot: &source,
        limits: Limits {
            provider_calls: 0,
            ..Limits::default()
        },
        experimental: true,
        mock: Some(&mock),
    })?;
    assert_eq!(
        result
            .report
            .records
            .first()
            .ok_or("budget-refused record is absent")?
            .result,
        ResultState::NotEvaluated
    );
    assert_eq!(result.report.usage.provider_calls, 0);
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions check fresh scan identity and distinct full target identities"
)]
fn exact_check_identity_changes_between_invocations_and_does_not_truncate_target_ids() -> TestResult
{
    let dir = directory();
    let baseline = validate(&inventory_baseline(dir.path()), dir.path());
    let source = inventory(
        json!([
            {"id":"same-prefix-aaaaaaaa","kind":"host.property","facts":{"encrypted":true}},
            {"id":"same-prefix-bbbbbbbb","kind":"host.property","facts":{"encrypted":true}}
        ]),
        &Limits::default(),
    );
    let first = run(&baseline, &source, Limits::default());
    let second = run(&baseline, &source, Limits::default());
    assert_ne!(first.report.scan_id, second.report.scan_id);
    let [first_a, first_b] = first.report.records.as_slice() else {
        return Err("expected both first-scan targets".into());
    };
    let [second_a, _] = second.report.records.as_slice() else {
        return Err("expected both second-scan targets".into());
    };
    assert_ne!(first_a.check_id, first_b.check_id);
    assert_ne!(first_a.check_id, second_a.check_id);
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions bind publication to exact report bytes and retain unresolved write failure"
)]
fn publication_receipt_binds_exact_bytes_and_failure_is_unresolved() -> TestResult {
    let dir = directory();
    let baseline = validate(&bytes_baseline(dir.path()), dir.path());
    let source = Snapshot::raw_bytes(b"good".to_vec(), "target", &Limits::default())?;
    let request = || ScanRequest {
        baseline: &baseline,
        profile: "default",
        source_alias: "bytes",
        snapshot: &source,
        limits: Limits::default(),
        experimental: false,
        mock: None,
    };
    let output = dir.path().join("report.json");
    std::fs::write(&output, b"old report")?;
    let published = scan_to_file(request(), &output)?;
    assert_eq!(
        published.receipt.report_sha256,
        auditoad::sha256(&std::fs::read(&output)?)
    );
    let error = scan_to_file(request(), &dir.path().join("absent-parent/report.json"))
        .err()
        .ok_or("publication to an absent parent succeeded")?;
    assert_eq!(error.exit_code, 2);
    assert!(!dir.path().join("absent-parent/report.json").exists());
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions check CLI/library agreement and invalid-command exit status"
)]
fn cli_and_library_agree_and_invalid_requests_have_exit_three() -> TestResult {
    let dir = directory();
    let value = bytes_baseline(dir.path());
    let path = dir.path().join("baseline.json");
    std::fs::write(&path, value.to_string())?;
    let input = dir.path().join("target.txt");
    std::fs::write(&input, b"bad")?;
    let output = dir.path().join("report.json");
    let status = std::process::Command::new(env!("CARGO_BIN_EXE_auditoad"))
        .args(["scan", "--baseline"])
        .arg(&path)
        .args(["--profile", "default", "--source", "raw-bytes/1", "--input"])
        .arg(&input)
        .arg("--report")
        .arg(&output)
        .output()?;
    assert_eq!(
        status.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&status.stderr)
    );
    let report: Value = serde_json::from_slice(&std::fs::read(&output)?)?;
    assert_eq!(report.get("outcome"), Some(&json!("finding")));
    assert_eq!(report.pointer("/counts/fail"), Some(&json!(1)));
    let status = std::process::Command::new(env!("CARGO_BIN_EXE_auditoad"))
        .arg("unknown-command")
        .output()?;
    assert_eq!(status.status.code(), Some(3));
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions require protected fixture and inventory bytes to survive refused publication"
)]
fn publication_refuses_fixture_and_inventory_input_destinations() -> TestResult {
    let dir = directory();
    let value = inventory_baseline(dir.path());
    let path = dir.path().join("baseline.json");
    std::fs::write(&path, value.to_string())?;
    let baseline = ValidatedBaseline::from_file(&path)?;
    let input = dir.path().join("inventory.json");
    std::fs::write(
        &input,
        br#"{"schema":"auditoad-inventory/1","snapshot_id":"s","items":[]}"#,
    )?;
    let source = Snapshot::from_file("inventory-json/1", &input, &Limits::default())?;
    for destination in [&path, &input, &dir.path().join("fail.json")] {
        let before = std::fs::read(destination)?;
        let error = scan_to_file(
            ScanRequest {
                baseline: &baseline,
                profile: "default",
                source_alias: "bytes",
                snapshot: &source,
                limits: Limits::default(),
                experimental: false,
                mock: None,
            },
            destination,
        )
        .err()
        .ok_or("publication overwrote a protected input")?;
        assert_eq!(error.exit_code, 3);
        assert_eq!(std::fs::read(destination)?, before);
    }
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions check deterministic and experimental public CLI outcomes"
)]
fn deterministic_and_mock_inputs_run_through_the_public_cli() -> TestResult {
    let dir = directory();
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    for (profile, source, input, expected) in [
        (
            "bytes",
            "raw-bytes/1",
            "tests/fixtures/fixtures/marker-present.txt",
            1,
        ),
        (
            "bytes",
            "raw-bytes/1",
            "tests/fixtures/fixtures/marker-absent.txt",
            0,
        ),
        (
            "inventory",
            "inventory-json/1",
            "tests/fixtures/inventory.json",
            2,
        ),
    ] {
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_auditoad"))
            .current_dir(root)
            .args([
                "scan",
                "--baseline",
                "tests/fixtures/controls.baseline.json",
                "--profile",
                profile,
                "--source",
                source,
                "--input",
                input,
                "--report",
            ])
            .arg(dir.path().join("report.json"))
            .output()?;
        assert_eq!(
            output.status.code(),
            Some(expected),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_auditoad"))
        .current_dir(root)
        .args([
            "scan",
            "--baseline",
            "tests/fixtures/mock.baseline.json",
            "--profile",
            "development",
            "--source",
            "raw-bytes/1",
            "--input",
            "tests/fixtures/fixtures/marker-absent.txt",
            "--mock",
            "tests/fixtures/mock.responses.json",
            "--experimental",
            "--report",
        ])
        .arg(dir.path().join("mock-report.json"))
        .output()?;
    assert_eq!(
        output.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value =
        serde_json::from_slice(&std::fs::read(dir.path().join("mock-report.json"))?)?;
    assert_eq!(
        report.pointer("/records/0/observation/suggested_result"),
        Some(&json!("pass"))
    );
    assert_eq!(
        report.pointer("/records/0/result"),
        Some(&json!("not_evaluated"))
    );
    Ok(())
}
