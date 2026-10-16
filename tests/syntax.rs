mod support;
use auditoad::{
    ScanRequest, Snapshot, ValidatedBaseline, scan,
    schema::{Limits, ResultState},
    sha256,
};
use serde_json::{Value, json};
use std::path::Path;
use support::{bytes_baseline, directory};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn declaration(root: &Path, language: &str, query: &str) -> TestResult<Value> {
    let mut value = bytes_baseline(root);
    *value
        .pointer_mut("/baseline/status")
        .ok_or("baseline status is absent")? = json!("draft");
    *value
        .pointer_mut("/rules/0/evaluator")
        .ok_or("evaluator is absent")? = json!({"kind":"syntax","contract":"syntax/1"});
    *value
        .pointer_mut("/rules/0/check")
        .ok_or("check is absent")? = json!({"kind":"syntax/1","language":language,"query":query});
    *value
        .pointer_mut("/rules/0/fixtures")
        .ok_or("fixtures are absent")? = json!({"pass":[],"fail":[]});
    Ok(value)
}

fn evaluate(
    value: &Value,
    source: &[u8],
    root: &Path,
    limits: Limits,
) -> TestResult<auditoad::ScanResult> {
    let baseline = ValidatedBaseline::from_bytes(value.to_string().as_bytes(), root)?;
    let path = root.join("source.txt");
    std::fs::write(&path, source)?;
    let snapshot = Snapshot::from_file("raw-bytes/1", &path, &limits)?;
    Ok(scan(ScanRequest {
        baseline: &baseline,
        profile: "default",
        source_alias: "bytes",
        snapshot: &snapshot,
        limits,
        experimental: true,
        mock: None,
    })?)
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions check six grammars, exact captures and Unicode byte spans"
)]
fn grammars_capture_syntax_without_comments_and_preserve_unicode_offsets() -> TestResult {
    let dir = directory();
    for (language, query, source, captures) in [
        (
            "bash",
            "(command_name) @name",
            "# fake() café\nprintf 'é'\n",
            vec!["printf"],
        ),
        (
            "zsh",
            "(command_name) @name",
            "# fake() café\nprint -r -- ${name:u}\n",
            vec!["print"],
        ),
        (
            "powershell",
            "(command_name) @name",
            "# Invoke-Fake café\nWrite-Output 'é'\n",
            vec!["Write-Output"],
        ),
        (
            "python",
            "(call function: (identifier) @name)",
            "# fake() café\nx = 'é'\nprint(x)\n",
            vec!["print"],
        ),
        (
            "rust",
            "(call_expression function: (identifier) @name)",
            "// fake() café\nfn main() { let é = 1; consume(é); }\n",
            vec!["consume"],
        ),
        (
            "tlaplus",
            "(operator_definition name: (identifier) @name)",
            "---- MODULE Sample ----\n\\* Fake == café\nActual == TRUE\n====\n",
            vec!["Actual"],
        ),
    ] {
        let value = declaration(dir.path(), language, query)?;
        let run = evaluate(&value, source.as_bytes(), dir.path(), Limits::default())?;
        let [record] = run.report.records.as_slice() else {
            return Err("expected exactly one syntax record".into());
        };
        assert_eq!(record.result, ResultState::NotEvaluated);
        let observation = record
            .observation
            .as_ref()
            .ok_or("syntax observation is absent")?;
        assert_eq!(
            observation.get("complete"),
            Some(&json!(true)),
            "{language}: {observation}"
        );
        assert_eq!(
            observation.get("selected_sha256"),
            Some(&json!(sha256(source.as_bytes())))
        );
        assert_eq!(
            observation.get("query_sha256"),
            Some(&json!(sha256(query.as_bytes())))
        );
        assert!(observation.get("suggested_result").is_none());
        let found = observation
            .pointer("/fields/captures")
            .and_then(Value::as_array)
            .ok_or("syntax captures are absent")?;
        assert_eq!(
            found
                .iter()
                .map(|v| v
                    .get("text")
                    .and_then(Value::as_str)
                    .ok_or("capture text is absent"))
                .collect::<Result<Vec<_>, _>>()?,
            captures,
            "{language}"
        );
        for capture in found {
            let start = usize::try_from(
                capture
                    .get("start_byte")
                    .and_then(Value::as_u64)
                    .ok_or("capture start is absent")?,
            )?;
            let end = usize::try_from(
                capture
                    .get("end_byte")
                    .and_then(Value::as_u64)
                    .ok_or("capture end is absent")?,
            )?;
            assert_eq!(
                source
                    .get(start..end)
                    .ok_or("capture is not a valid UTF-8 byte range")?,
                capture
                    .get("text")
                    .and_then(Value::as_str)
                    .ok_or("capture text is absent")?
            );
        }
        let repeated = evaluate(&value, source.as_bytes(), dir.path(), Limits::default())?;
        let [repeated] = repeated.report.records.as_slice() else {
            return Err("expected one repeated syntax record".into());
        };
        assert_eq!(record.observation, repeated.observation);
    }
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions check incomplete parse diagnostics for every grammar"
)]
fn recovered_trees_never_supply_complete_fields() -> TestResult {
    let dir = directory();
    for (language, source) in [
        ("bash", "if true; then\n"),
        ("zsh", "if true; then\n"),
        ("powershell", "function Broken {\n"),
        ("python", "def broken(:\n"),
        ("rust", "fn broken() {\n"),
        ("tlaplus", "---- MODULE Broken ----\nSpec == /\\\n====\n"),
    ] {
        let value = declaration(dir.path(), language, "(_) @node")?;
        let run = evaluate(&value, source.as_bytes(), dir.path(), Limits::default())?;
        let [record] = run.report.records.as_slice() else {
            return Err("expected one incomplete syntax record".into());
        };
        assert_eq!(record.result, ResultState::NotEvaluated);
        let observation = record
            .observation
            .as_ref()
            .ok_or("incomplete parse observation is absent")?;
        assert_eq!(
            observation.get("complete"),
            Some(&json!(false)),
            "{language}: {observation}"
        );
        assert!(observation.get("fields").is_none());
        assert!(
            !observation
                .get("diagnostics")
                .and_then(Value::as_array)
                .ok_or("incomplete parse diagnostics are absent")?
                .is_empty(),
            "{language}"
        );
    }
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions check original Verus operators, Unicode spans and unrelated parse-error refusal"
)]
fn verus_preserves_original_operator_captures_and_refuses_incomplete_source() -> TestResult {
    let dir = directory();
    let query = "(function_item name: (identifier) @name (#eq? @name \"extensional\")) @function";
    let source = "// café keeps offsets in original UTF-8\nverus! {\nspec fn extensional(a: Seq<int>, b: Seq<int>) -> bool { a =~= b && a =~~= b }\n}\n";
    let value = declaration(dir.path(), "verus", query)?;
    let run = evaluate(&value, source.as_bytes(), dir.path(), Limits::default())?;
    let [record] = run.report.records.as_slice() else {
        return Err("expected one Verus syntax record".into());
    };
    assert_eq!(record.result, ResultState::NotEvaluated);
    let observation = record
        .observation
        .as_ref()
        .ok_or("Verus observation is absent")?;
    assert_eq!(observation.get("complete"), Some(&json!(true)));
    assert_eq!(
        observation.get("selected_sha256"),
        Some(&json!(sha256(source.as_bytes())))
    );
    assert_eq!(
        observation.get("grammar"),
        Some(&json!(
            "tree-sitter-verus/0c939ef2ec0a188c3cf24518474fb8082db02ec4"
        ))
    );
    let captures = observation
        .pointer("/fields/captures")
        .and_then(Value::as_array)
        .ok_or("Verus captures are absent")?;
    let function = captures
        .iter()
        .find(|capture| capture.get("capture") == Some(&json!("function")))
        .ok_or("named Verus function is absent")?;
    let start = usize::try_from(
        function
            .get("start_byte")
            .and_then(Value::as_u64)
            .ok_or("capture start is absent")?,
    )?;
    let end = usize::try_from(
        function
            .get("end_byte")
            .and_then(Value::as_u64)
            .ok_or("capture end is absent")?,
    )?;
    let selected = function
        .get("text")
        .and_then(Value::as_str)
        .ok_or("capture text is absent")?;
    assert_eq!(source.get(start..end), Some(selected));
    assert!(selected.contains("a =~= b") && selected.contains("a =~~= b"));
    for (language, candidate) in [
        ("rust", source.to_owned()),
        ("verus", format!("{source}\nfn broken( {{\n")),
        ("verus", source.replace("a =~= b", "a ?~= b")),
    ] {
        let value = declaration(dir.path(), language, query)?;
        let refused = evaluate(&value, candidate.as_bytes(), dir.path(), Limits::default())?;
        let [record] = refused.report.records.as_slice() else {
            return Err("expected one incomplete syntax record".into());
        };
        let observation = record
            .observation
            .as_ref()
            .ok_or("incomplete observation is absent")?;
        assert_eq!(record.result, ResultState::NotEvaluated);
        assert_eq!(
            observation.get("complete"),
            Some(&json!(false)),
            "{language}: {observation}"
        );
        assert!(observation.get("fields").is_none());
        assert!(
            !observation
                .get("diagnostics")
                .and_then(Value::as_array)
                .ok_or("parse diagnostics are absent")?
                .is_empty()
        );
    }
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions check query, zero-limit and admission refusals"
)]
fn unsupported_queries_and_admission_are_refused() -> TestResult {
    let dir = directory();
    for query in [
        "(imaginary_node) @x",
        "(identifier)",
        "((identifier) @x (#is? local))",
        "((identifier) @x (#set! injection.language rust))",
        "((identifier) @x (#unknown? @x))",
    ] {
        let value = declaration(dir.path(), "python", query)?;
        assert!(
            ValidatedBaseline::from_bytes(value.to_string().as_bytes(), dir.path()).is_err(),
            "{query}"
        );
    }
    for limit in [
        "input_bytes",
        "nodes",
        "captures",
        "output_bytes",
        "timeout_ms",
        "match_limit",
    ] {
        let mut value = declaration(dir.path(), "python", "(identifier) @x")?;
        value
            .pointer_mut("/rules/0/check")
            .and_then(Value::as_object_mut)
            .ok_or("syntax check is absent")?
            .insert("limits".into(), json!({limit:0}));
        assert!(ValidatedBaseline::from_bytes(value.to_string().as_bytes(), dir.path()).is_err());
    }
    let mut value = declaration(dir.path(), "python", "(identifier) @x")?;
    *value
        .pointer_mut("/baseline/status")
        .ok_or("baseline status is absent")? = json!("admitted");
    assert!(ValidatedBaseline::from_bytes(value.to_string().as_bytes(), dir.path()).is_err());
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions distinguish resource and source refusals from an empty query"
)]
fn resource_refusals_and_invalid_sources_do_not_look_like_empty_queries() -> TestResult {
    let dir = directory();
    for (limit, amount, reason) in [
        ("input_bytes", 1, "input byte"),
        ("nodes", 1, "node limit"),
        ("captures", 1, "capture limit"),
        ("output_bytes", 1, "output byte"),
    ] {
        let mut value = declaration(dir.path(), "python", "(identifier) @x")?;
        value
            .pointer_mut("/rules/0/check")
            .and_then(Value::as_object_mut)
            .ok_or("syntax check is absent")?
            .insert("limits".into(), json!({limit:amount}));
        let run = evaluate(&value, b"first = second\n", dir.path(), Limits::default())?;
        let [record] = run.report.records.as_slice() else {
            return Err("expected one resource refusal".into());
        };
        assert_eq!(record.result, ResultState::NotEvaluated);
        assert!(record.observation.is_none(), "{limit}");
        assert!(
            record
                .reason
                .as_ref()
                .ok_or("resource refusal reason is absent")?
                .contains(reason),
            "{:?}",
            record.reason
        );
    }
    let value = declaration(dir.path(), "python", "(identifier) @x")?;
    let run = evaluate(&value, b"\xff", dir.path(), Limits::default())?;
    let [record] = run.report.records.as_slice() else {
        return Err("expected one UTF-8 refusal".into());
    };
    assert!(
        record
            .reason
            .as_ref()
            .ok_or("UTF-8 refusal reason is absent")?
            .contains("UTF-8")
    );
    let run = evaluate(
        &value,
        b"x = 1\n",
        dir.path(),
        Limits {
            evidence_bytes: 16,
            ..Limits::default()
        },
    )?;
    let [record] = run.report.records.as_slice() else {
        return Err("expected one evidence-budget refusal".into());
    };
    assert!(
        record
            .reason
            .as_ref()
            .ok_or("evidence-budget refusal reason is absent")?
            .contains("cumulative evidence")
    );
    assert!(record.observation.is_none());
    let run = evaluate(&value, b"# comment only\n", dir.path(), Limits::default())?;
    let [record] = run.report.records.as_slice() else {
        return Err("expected one comment-only observation".into());
    };
    assert_eq!(
        record
            .observation
            .as_ref()
            .ok_or("comment-only observation is absent")?
            .pointer("/fields/captures"),
        Some(&json!([]))
    );
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions check timeout and match-limit refusal without partial output"
)]
fn timeout_and_query_match_limit_refuse_partial_results() -> TestResult {
    let dir = directory();
    let mut value = declaration(dir.path(), "python", "(_) @node")?;
    value
        .pointer_mut("/rules/0/check")
        .and_then(Value::as_object_mut)
        .ok_or("syntax check is absent")?
        .insert("limits".into(), json!({"timeout_ms":1}));
    let run = evaluate(
        &value,
        "x = 1\n".repeat(20_000).as_bytes(),
        dir.path(),
        Limits::default(),
    )?;
    let [record] = run.report.records.as_slice() else {
        return Err("expected one timeout refusal".into());
    };
    assert!(record.observation.is_none());
    let reason = record
        .reason
        .as_ref()
        .ok_or("timeout refusal reason is absent")?;
    assert!(reason.contains("time") || reason.contains("interrupted"));
    let mut value = declaration(
        dir.path(),
        "python",
        "(module (expression_statement) @first (expression_statement)* @rest)",
    )?;
    value
        .pointer_mut("/rules/0/check")
        .and_then(Value::as_object_mut)
        .ok_or("syntax check is absent")?
        .insert("limits".into(), json!({"match_limit":1}));
    let run = evaluate(
        &value,
        "x = 1\n".repeat(16).as_bytes(),
        dir.path(),
        Limits::default(),
    )?;
    let [record] = run.report.records.as_slice() else {
        return Err("expected one match-limit refusal".into());
    };
    assert!(record.observation.is_none());
    assert!(
        record
            .reason
            .as_ref()
            .ok_or("match-limit refusal reason is absent")?
            .contains("match limit")
    );
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions check public CLI captures and local source relationships without provider calls"
)]
fn public_example_runs_syntax_and_local_source_relationships_through_the_cli() -> TestResult {
    let dir = directory();
    let product = Path::new(env!("CARGO_MANIFEST_DIR"));
    for (profile, count) in [("syntax", 6), ("review", 2), ("formal", 1)] {
        let report = dir.path().join(format!("{profile}.json"));
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_auditoad"))
            .current_dir(product.join("examples/language-helpers"))
            .args([
                "scan",
                "--baseline",
                "baseline.json",
                "--profile",
                profile,
                "--input",
                "inputs.json",
                "--report",
            ])
            .arg(&report)
            .output()?;
        assert_eq!(
            output.status.code(),
            Some(2),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let document: Value = serde_json::from_slice(&std::fs::read(report)?)?;
        assert_eq!(document.pointer("/usage/provider_calls"), Some(&json!(0)));
        let mut records = Vec::new();
        for record in document
            .get("records")
            .and_then(Value::as_array)
            .ok_or("CLI records are absent")?
        {
            if record.get("result").ok_or("CLI record result is absent")? != "notapplicable" {
                records.push(record);
            }
        }
        assert_eq!(records.len(), count);
        for record in &records {
            let syntax = record
                .pointer("/evaluator/binding")
                .ok_or("CLI evaluator binding is absent")?
                == "syntax";
            assert_eq!(
                record.get("result"),
                Some(&json!(if syntax { "not_evaluated" } else { "fail" }))
            );
            if syntax {
                assert_eq!(
                    record.pointer("/observation/complete"),
                    Some(&json!(true)),
                    "{record}"
                );
                assert_eq!(
                    record
                        .pointer("/observation/fields/captures")
                        .and_then(Value::as_array)
                        .ok_or("CLI syntax captures are absent")?
                        .len(),
                    match record.pointer("/rule/id").and_then(Value::as_str) {
                        Some("TLAPLUS") => 6,
                        Some("PY-PATH-SYNTAX") => 3,
                        _ => 2,
                    }
                );
            }
        }
        if profile == "review" {
            let [_, comparison] = records.as_slice() else {
                return Err("expected syntax and local-comparison records".into());
            };
            let frame: Value = serde_json::from_str(
                comparison
                    .pointer("/evidence/bytes/text")
                    .and_then(Value::as_str)
                    .ok_or("consulted CLI evidence text is absent")?,
            )?;
            let prior = frame
                .get("prior")
                .and_then(Value::as_array)
                .ok_or("consulted prior evidence is absent")?;
            let [prior] = prior.as_slice() else {
                return Err("expected exactly one consulted prior record".into());
            };
            assert_eq!(prior.pointer("/observation/complete"), Some(&json!(true)));
            assert_eq!(prior.get("decision"), Some(&Value::Null));
            assert_eq!(
                comparison.pointer("/observation/left"),
                Some(&json!("path"))
            );
            assert_eq!(
                comparison.pointer("/observation/right"),
                Some(&json!("path"))
            );
        } else if profile == "formal" {
            let [relation] = records.as_slice() else {
                return Err("expected one local TLA+ relation record".into());
            };
            assert_eq!(
                relation.pointer("/observation/complete"),
                Some(&json!(true))
            );
            assert_eq!(
                relation.pointer("/observation/fields/relation/value"),
                Some(&json!(true))
            );
            assert_eq!(
                relation.pointer("/observation/fields/relation/operator"),
                Some(&json!("Spec"))
            );
            assert_eq!(
                relation.pointer("/observation/fields/relation/operands/reference"),
                Some(&json!("Progress"))
            );
        }
    }
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions check the public Python query's identifier scope and ambiguity refusals"
)]
fn public_python_relationship_query_preserves_its_exact_supported_shapes() -> TestResult {
    let dir = directory();
    let product = Path::new(env!("CARGO_MANIFEST_DIR"));
    let example: Value = serde_json::from_slice(&std::fs::read(
        product.join("examples/language-helpers/baseline.json"),
    )?)?;
    let check = example
        .get("rules")
        .and_then(Value::as_array)
        .ok_or("public rules are absent")?
        .iter()
        .find(|rule| rule.get("id") == Some(&json!("PY-PATH-SYNTAX")))
        .and_then(|rule| rule.get("check"))
        .ok_or("public Python relationship query is absent")?;
    let query = check
        .get("query")
        .and_then(Value::as_str)
        .ok_or("public Python query text is absent")?;
    let mut value = declaration(dir.path(), "python", query)?;
    value
        .pointer_mut("/rules/0/check")
        .and_then(Value::as_object_mut)
        .ok_or("syntax check is absent")?
        .insert(
            "limits".into(),
            check
                .get("limits")
                .ok_or("public query limits are absent")?
                .clone(),
        );
    for (source, captures, complete) in [
        (
            "def read_text(path):\n    return open(path).read()\n",
            Some(3),
            true,
        ),
        (
            "def read_text(path):\n    return open(path)\n",
            Some(3),
            true,
        ),
        (
            "def read_text(path):\n    path = 'fixed'\n    return open(path).read()\n",
            Some(3),
            true,
        ),
        (
            "def read_text(path):\n    return open(other).read()\ndef other_function(other):\n    return 1\n",
            Some(3),
            true,
        ),
        (
            "def read_text(path):\n    return open(path + '.txt').read()\n",
            Some(0),
            true,
        ),
        (
            "def read_text(path, mode):\n    return open(path).read()\n",
            None,
            true,
        ),
        (
            "def first(path):\n    return open(path).read()\ndef second(other):\n    return open(other)\n",
            None,
            true,
        ),
        ("def read_text(:\n", None, false),
    ] {
        let result = evaluate(&value, source.as_bytes(), dir.path(), Limits::default())?;
        let [record] = result.report.records.as_slice() else {
            return Err("expected one public-query record".into());
        };
        assert_eq!(record.result, ResultState::NotEvaluated);
        assert_eq!(result.report.usage.provider_calls, 0);
        if let Some(expected) = captures {
            let observation = record
                .observation
                .as_ref()
                .ok_or("query observation is absent")?;
            assert_eq!(observation.get("complete"), Some(&json!(complete)));
            assert_eq!(observation.get("captures_retained"), Some(&json!(expected)));
            if expected == 3 {
                assert_eq!(
                    observation.pointer("/fields/captures/0/capture"),
                    Some(&json!("parameter"))
                );
                assert_eq!(
                    observation.pointer("/fields/captures/1/capture"),
                    Some(&json!("callee"))
                );
                assert_eq!(
                    observation.pointer("/fields/captures/2/capture"),
                    Some(&json!("argument"))
                );
            }
        } else if complete {
            assert!(record.observation.is_none());
            assert!(
                record
                    .reason
                    .as_deref()
                    .is_some_and(|reason| reason.contains("capture limit"))
            );
        } else {
            let observation = record
                .observation
                .as_ref()
                .ok_or("parse refusal is absent")?;
            assert_eq!(observation.get("complete"), Some(&json!(false)));
            assert!(observation.get("fields").is_none());
        }
    }
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions check the public TLA+ singleton-operand binding and malformed or unavailable peers"
)]
fn public_tla_relationship_requires_one_operand_object_with_both_names() -> TestResult {
    let dir = directory();
    let product = Path::new(env!("CARGO_MANIFEST_DIR"));
    let example = product.join("examples/language-helpers");
    let baseline =
        ValidatedBaseline::from_bytes(&std::fs::read(example.join("baseline.json"))?, &example)?;
    std::fs::write(
        dir.path().join("source.tla"),
        "---- MODULE M ----\nProgress == TRUE\nSpec == TRUE /\\ Progress\n====\n",
    )?;
    for (case, operands, expected) in [
        (
            "singleton object",
            Some(json!({"operator":"Spec","reference":"Progress"})),
            ResultState::Fail,
        ),
        (
            "one-element array",
            Some(json!([{"operator":"Spec","reference":"Progress"}])),
            ResultState::NotEvaluated,
        ),
        (
            "two-element array",
            Some(
                json!([{"operator":"Spec","reference":"Progress"},{"operator":"Spec","reference":"Progress"}]),
            ),
            ResultState::NotEvaluated,
        ),
        (
            "missing reference",
            Some(json!({"operator":"Spec"})),
            ResultState::NotEvaluated,
        ),
        (
            "malformed operator name",
            Some(json!({"operator":"Spec!Other","reference":"Progress"})),
            ResultState::NotEvaluated,
        ),
        ("unavailable peer", None, ResultState::Error),
    ] {
        let operand_input = if let Some(value) = operands {
            std::fs::write(dir.path().join("operands.json"), value.to_string())?;
            json!({"adapter":"json/1","path":"operands.json"})
        } else {
            json!({"adapter":"json/1","unavailable":"operand document was not supplied"})
        };
        let manifest = dir.path().join("inputs.json");
        std::fs::write(
            &manifest,
            json!({"schema":"auditoad-collection/1","inputs":{
                "tlaplus":{"adapter":"text/1","path":"source.tla"},
                "tlaplus-operands":operand_input
            }})
            .to_string(),
        )?;
        let limits = Limits::default();
        let snapshot =
            Snapshot::collection_file(&manifest, None, &baseline, "formal", "code", &limits)?;
        let result = scan(ScanRequest {
            baseline: &baseline,
            profile: "formal",
            source_alias: "code",
            snapshot: &snapshot,
            limits,
            experimental: true,
            mock: None,
        })?;
        let [record] = result.report.records.as_slice() else {
            return Err("expected one public TLA+ relation record".into());
        };
        assert_eq!(record.result, expected, "{case}: {:?}", record.reason);
        assert_eq!(result.report.usage.provider_calls, 0, "{case}");
        if matches!(expected, ResultState::NotEvaluated | ResultState::Error) {
            assert!(record.reason.is_some(), "{case}");
            assert!(record.observation.is_none(), "{case}");
            if expected == ResultState::Error {
                assert!(record.evidence.is_none(), "{case}");
                assert!(
                    record
                        .reason
                        .as_deref()
                        .is_some_and(|reason| reason.contains("unavailable")),
                    "{case}"
                );
            } else {
                assert!(record.evidence.is_some(), "{case}");
            }
        }
    }
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions check exact TLA proof and fairness captures and byte spans"
)]
fn tla_proof_and_fairness_captures_preserve_syntax_without_resolving_it() -> TestResult {
    let dir = directory();
    let source = r#"---- MODULE Source ----
EXTENDS Naturals, TLAPS
VARIABLE done
(* Fake == WF_done(Idle)
   (* THEOREM Bogus == FALSE OMITTED *) café *)
Label == "WF_done(Idle) OMITTED"
Finish == done' = TRUE
Progress == WF_done(Finish)
Selected == Progress
Other == INSTANCE Unknown WITH x <- done
Alias == Other!Progress
LEMMA Helper == TRUE
  OMITTED
THEOREM Result == TRUE
  BY Helper
====
"#;
    let query = r#"
        (operator_definition name: (identifier) @name definition: (_) @body)
        (fairness) @fairness
        (theorem name: (identifier) @theorem proof: (terminal_proof) @leaf)
    "#;
    let value = declaration(dir.path(), "tlaplus", query)?;
    let run = evaluate(&value, source.as_bytes(), dir.path(), Limits::default())?;
    let [record] = run.report.records.as_slice() else {
        return Err("expected one TLA capture record".into());
    };
    let observation = record
        .observation
        .as_ref()
        .ok_or("TLA observation is absent")?;
    assert_eq!(
        observation.get("complete"),
        Some(&json!(true)),
        "{observation}"
    );
    assert_eq!(run.report.usage.provider_calls, 0);
    let captures = observation
        .pointer("/fields/captures")
        .and_then(Value::as_array)
        .ok_or("TLA captures are absent")?;
    let mut named = Vec::new();
    for capture in captures {
        named.push((
            capture
                .get("capture")
                .and_then(Value::as_str)
                .ok_or("capture name is absent")?,
            capture
                .get("text")
                .and_then(Value::as_str)
                .ok_or("capture text is absent")?,
        ));
    }
    let texts = |name: &str| -> Vec<&str> {
        named
            .iter()
            .filter_map(|(capture, text)| (*capture == name).then_some(*text))
            .collect()
    };
    assert_eq!(
        texts("name"),
        ["Label", "Finish", "Progress", "Selected", "Alias"]
    );
    assert_eq!(texts("fairness"), ["WF_done(Finish)"]);
    assert_eq!(texts("theorem"), ["Helper", "Result"]);
    assert_eq!(texts("leaf"), ["OMITTED", "BY Helper"]);
    assert!(texts("body").contains(&"Other!Progress"));
    // An unknown module instance is grammatical: syntax does not resolve its definitions.
    assert!(observation.get("suggested_result").is_none());
    for capture in captures {
        let start = usize::try_from(
            capture
                .get("start_byte")
                .and_then(Value::as_u64)
                .ok_or("capture start is absent")?,
        )?;
        let end = usize::try_from(
            capture
                .get("end_byte")
                .and_then(Value::as_u64)
                .ok_or("capture end is absent")?,
        )?;
        assert_eq!(
            source
                .get(start..end)
                .ok_or("capture is not a valid UTF-8 byte range")?,
            capture
                .get("text")
                .and_then(Value::as_str)
                .ok_or("capture text is absent")?
        );
    }
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions check exact text-predicate selection"
)]
fn built_in_text_predicates_filter_without_inventing_runtime_meaning() -> TestResult {
    let dir = directory();
    let value = declaration(
        dir.path(),
        "python",
        "((call function: (identifier) @name) (#eq? @name \"open\"))",
    )?;
    let run = evaluate(
        &value,
        b"print('open(file)')\nopen(file)\n",
        dir.path(),
        Limits::default(),
    )?;
    let [record] = run.report.records.as_slice() else {
        return Err("expected one text-predicate record".into());
    };
    let captures = record
        .observation
        .as_ref()
        .ok_or("text-predicate observation is absent")?
        .pointer("/fields/captures")
        .and_then(Value::as_array)
        .ok_or("text-predicate captures are absent")?;
    let [capture] = captures.as_slice() else {
        return Err("expected exactly one text-predicate capture".into());
    };
    assert_eq!(capture.get("text"), Some(&json!("open")));
    Ok(())
}

fn relation_declaration(root: &Path, kind: &str) -> TestResult<Value> {
    let mut value = support::inventory_baseline(root);
    let (predicate, positive, negative) = match kind {
        "direct_alias" => (
            json!({"kind":kind,"reference_pointer":"/facts/reference"}),
            "B",
            "FALSE",
        ),
        "positive_conjunct" => (
            json!({"kind":kind,"reference_pointer":"/facts/reference"}),
            "B /\\ TRUE",
            "B \\/ TRUE",
        ),
        "weak_fairness" => (
            json!({"kind":kind,"action_pointer":"/facts/action","subscript_pointer":"/facts/subscript"}),
            "WF_x(F)",
            "SF_x(F)",
        ),
        _ => return Err(format!("unsupported relation fixture kind: {kind}").into()),
    };
    let frame = |body: &str| {
        relation_item(&format!(
            "---- MODULE M ----\nCONSTANT B\nVARIABLE x\nF == x' = x\nA == {body}\n===="
        ))
        .to_string()
        .into_bytes()
    };
    let good = frame(negative);
    let bad = frame(positive);
    *value
        .pointer_mut("/rules/0/evaluator")
        .ok_or("relation evaluator is absent")? =
        json!({"kind":"tlaplus-relation","contract":"tlaplus-relation/1"});
    *value
        .pointer_mut("/rules/0/check")
        .ok_or("relation check is absent")? = json!({"kind":"tlaplus-relation/1","json_string_pointer":"/facts/source","operator_pointer":"/facts/operator","predicate":predicate,"fail_when":true});
    *value
        .pointer_mut("/rules/0/fixtures")
        .ok_or("relation fixtures are absent")? = json!({"pass":[support::fixture(root,"relation-negative.json",&good,&good)],"fail":[support::fixture(root,"relation-positive.json",&bad,&bad)]});
    Ok(value)
}

fn relation_item(source: &str) -> Value {
    json!({"id":"case","kind":"host.property","facts":{"source":source,"operator":"A","reference":"B","action":"F","subscript":"x"}})
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions check written relation shapes and exact witness spans"
)]
fn tla_relations_decide_written_shapes_and_retain_exact_witnesses() -> TestResult {
    let dir = directory();
    for (kind, cases) in [
        (
            "direct_alias",
            vec![
                ("B", true),
                ("( (* café *) (B))", true),
                ("B /\\ TRUE", false),
                ("\"B\"", false),
                ("Bridge", false),
            ],
        ),
        (
            "positive_conjunct",
            vec![
                ("B /\\ TRUE", true),
                ("TRUE /\\ (B /\\ TRUE)", true),
                ("/\\ TRUE\n     /\\ B", true),
                ("TRUE \\/ B", false),
                ("~B", false),
                ("TRUE => B", false),
                ("TRUE /\\ (B \\/ TRUE)", false),
                ("\"B\" = \"B\"", false),
            ],
        ),
        (
            "weak_fairness",
            vec![
                ("WF_x(F)", true),
                ("(WF_x( F ))", true),
                ("SF_x(F)", false),
                ("WF_y(F)", false),
                ("WF_x(G)", false),
                ("\"WF_x(F)\"", false),
            ],
        ),
    ] {
        let value = relation_declaration(dir.path(), kind)?;
        let baseline = support::validate(&value, dir.path());
        for (body, expected) in cases {
            let source = format!(
                "---- MODULE M ----\nCONSTANT B\nVARIABLE x, y\nF == x' = x\nG == UNCHANGED x\nBridge == B\n\\* A == B; café\nA == {body}\n===="
            );
            let snapshot = support::inventory(json!([relation_item(&source)]), &Limits::default());
            let run = support::run(&baseline, &snapshot, Limits::default());
            let [record] = run.report.records.as_slice() else {
                return Err("expected one relation record".into());
            };
            assert_eq!(
                record.result,
                if expected {
                    ResultState::Fail
                } else {
                    ResultState::Pass
                },
                "{kind}: {body}: {record:?}"
            );
            assert_eq!(run.report.usage.provider_calls, 0);
            let relation = record
                .observation
                .as_ref()
                .ok_or("relation observation is absent")?
                .pointer("/fields/relation")
                .ok_or("relation field is absent")?;
            assert_eq!(relation.get("value"), Some(&json!(expected)));
            for field in ["definition", "witness"] {
                let span = relation.get(field).ok_or("relation span field is absent")?;
                if span.is_null() {
                    assert!(!expected);
                    continue;
                }
                let start = usize::try_from(
                    span.get("start_byte")
                        .and_then(Value::as_u64)
                        .ok_or("relation span start is absent")?,
                )?;
                let end = usize::try_from(
                    span.get("end_byte")
                        .and_then(Value::as_u64)
                        .ok_or("relation span end is absent")?,
                )?;
                assert_eq!(
                    source
                        .get(start..end)
                        .ok_or("relation span is not a valid UTF-8 byte range")?,
                    span.get("text")
                        .and_then(Value::as_str)
                        .ok_or("relation span text is absent")?
                );
            }
        }
    }
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions check ambiguous, malformed, and over-limit relation refusals"
)]
fn tla_relations_refuse_ambiguous_incomplete_and_over_limit_inputs() -> TestResult {
    let dir = directory();
    let value = relation_declaration(dir.path(), "direct_alias")?;
    let baseline = support::validate(&value, dir.path());
    for source in [
        "---- MODULE M ----\nCONSTANT B\nOther == B\n====",
        "---- MODULE M ----\nCONSTANT B\nA == B\nA == FALSE\n====",
        "---- MODULE M ----\nCONSTANT B\nA(x) == B\n====",
        "---- MODULE M ----\nA == /\\\n====",
        "---- MODULE M ----\n---- MODULE Nested ----\nA == TRUE\n====\n====",
        "---- MODULE M ----\nA == TRUE\n====\n---- MODULE N ----\nA == FALSE\n====",
    ] {
        let snapshot = support::inventory(json!([relation_item(source)]), &Limits::default());
        let run = support::run(&baseline, &snapshot, Limits::default());
        let [record] = run.report.records.as_slice() else {
            return Err("expected one malformed relation refusal".into());
        };
        assert_eq!(record.result, ResultState::NotEvaluated, "{source}");
    }
    for replacement in [Value::Null, json!(false), json!("M!A"), json!("")] {
        let mut item = relation_item("---- MODULE M ----\nA == TRUE\n====");
        *item
            .pointer_mut("/facts/operator")
            .ok_or("relation operator is absent")? = replacement;
        let snapshot = support::inventory(json!([item]), &Limits::default());
        let run = support::run(&baseline, &snapshot, Limits::default());
        let [record] = run.report.records.as_slice() else {
            return Err("expected one invalid-operator refusal".into());
        };
        assert_eq!(record.result, ResultState::NotEvaluated);
    }
    let mut bounded = value.clone();
    bounded
        .pointer_mut("/rules/0/check")
        .and_then(Value::as_object_mut)
        .ok_or("relation check is absent")?
        .insert("limits".into(), json!({"nodes":200}));
    let bounded = support::validate(&bounded, dir.path());
    let source = format!(
        "---- MODULE M ----\nA == {}\n====",
        std::iter::repeat_n("TRUE", 100)
            .collect::<Vec<_>>()
            .join(" /\\ ")
    );
    let snapshot = support::inventory(json!([relation_item(&source)]), &Limits::default());
    let run = support::run(&bounded, &snapshot, Limits::default());
    let [record] = run.report.records.as_slice() else {
        return Err("expected one node-limit refusal".into());
    };
    assert_eq!(record.result, ResultState::NotEvaluated);
    assert!(
        record
            .reason
            .as_ref()
            .ok_or("node-limit refusal reason is absent")?
            .contains("node limit")
    );
    let mut invalid = value;
    *invalid
        .pointer_mut("/rules/0/check/operator_pointer")
        .ok_or("operator pointer is absent")? = json!("facts/operator");
    assert!(ValidatedBaseline::from_bytes(invalid.to_string().as_bytes(), dir.path()).is_err());
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions check every externally labelled relation without a provider"
)]
fn public_formal_relations_example_matches_every_external_label_without_a_provider() -> TestResult {
    let dir = directory();
    let example = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/formal-relations");
    let report = dir.path().join("relations.json");
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_auditoad"))
        .current_dir(&example)
        .args([
            "scan",
            "--baseline",
            "baseline.json",
            "--input",
            "inputs.json",
            "--report",
        ])
        .arg(&report)
        .output()?;
    assert_eq!(
        output.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let document: Value = serde_json::from_slice(&std::fs::read(&report)?)?;
    assert_eq!(document.pointer("/usage/provider_calls"), Some(&json!(0)));
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_auditoad"))
        .current_dir(example)
        .args(["score", "--report"])
        .arg(report)
        .args(["--labels", "labels.json"])
        .output()?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let score: Value = serde_json::from_slice(&output.stdout)?;
    let cases = score
        .get("cases")
        .and_then(Value::as_array)
        .ok_or("scored relation cases are absent")?;
    assert_eq!(cases.len(), 28);
    for case in cases {
        assert_eq!(case.get("comparison"), Some(&json!("correct")), "{case}");
    }
    Ok(())
}

fn constant_string_declaration(root: &Path, query: &str) -> TestResult<Value> {
    let mut value = declaration(root, "python", query)?;
    *value
        .pointer_mut("/rules/0/evaluator/contract")
        .ok_or("evaluator contract is absent")? = json!("python-constant-string/1");
    *value
        .pointer_mut("/rules/0/check")
        .ok_or("check is absent")? = json!({"kind":"python-constant-string/1","query":query});
    Ok(value)
}

const STRING_RETURN_QUERY: &str = "((function_definition name: (identifier) @_name body: (block (return_statement (_) @value))) @scope (#eq? @_name \"handler\"))";

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions bind each exact constant to the complete selected expression and preserve unknown alternatives"
)]
fn python_constant_strings_record_exact_list_results_and_immutable_copies() -> TestResult {
    let dir = directory();
    let value = constant_string_declaration(dir.path(), STRING_RETURN_QUERY)?;
    for (source, expression, constant, proven) in [
        (
            "def handler(incoming):\n    lst = []\n    lst.append('safe')\n    lst.append(incoming)\n    lst.append('moresafe')\n    lst.pop(0)\n    return lst[1]\n",
            "lst[1]",
            Some("moresafe"),
            true,
        ),
        (
            "def handler(incoming):\n    lst = []\n    lst.append('safe')\n    lst.append(incoming)\n    lst.append('moresafe')\n    lst.pop(0)\n    return lst[0]\n",
            "lst[0]",
            None,
            false,
        ),
        (
            "def handler(incoming):\n    original = 'fixed'\n    immutable_copy = original\n    original = incoming\n    return immutable_copy\n",
            "immutable_copy",
            Some("fixed"),
            true,
        ),
        (
            "def handler(incoming):\n    values = ['fixed', incoming]\n    copied = values.copy()\n    values.pop(0)\n    return copied[0]\n",
            "copied[0]",
            Some("fixed"),
            true,
        ),
        (
            "def handler(incoming):\n    if incoming:\n        answer = 'first'\n    else:\n        answer = 'second'\n    return answer\n",
            "answer",
            None,
            true,
        ),
        (
            "def handler(incoming):\n    if incoming:\n        answer = 'same'\n    else:\n        answer = 'same'\n    return answer\n",
            "answer",
            Some("same"),
            true,
        ),
        (
            "def handler(incoming):\n    return 'first' + 'second'\n",
            "'first' + 'second'",
            None,
            true,
        ),
    ] {
        let run = evaluate(&value, source.as_bytes(), dir.path(), Limits::default())?;
        let [record] = run.report.records.as_slice() else {
            return Err("expected one exact-constant result".into());
        };
        let observation = record
            .observation
            .as_ref()
            .ok_or("exact-constant observation is absent")?;
        let values = observation
            .pointer("/fields/constant_string/values")
            .and_then(Value::as_array)
            .ok_or("selected constant values are absent")?;
        let [selected] = values.as_slice() else {
            return Err("expected one selected value".into());
        };
        assert_eq!(
            selected.get("expression"),
            Some(&json!(expression)),
            "{source}"
        );
        assert_eq!(selected.get("constant"), Some(&json!(constant)), "{source}");
        assert_eq!(selected.get("proven"), Some(&json!(proven)), "{source}");
        assert_eq!(
            selected.get("source_authored"),
            Some(&json!(proven)),
            "{source}"
        );
        let start = usize::try_from(
            selected
                .get("start_byte")
                .and_then(Value::as_u64)
                .ok_or("selected start is absent")?,
        )?;
        let end = usize::try_from(
            selected
                .get("end_byte")
                .and_then(Value::as_u64)
                .ok_or("selected end is absent")?,
        )?;
        assert_eq!(source.get(start..end), Some(expression));
        assert_eq!(
            record.result,
            if proven {
                ResultState::Pass
            } else {
                ResultState::NotEvaluated
            }
        );
    }
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions distinguish proved string content from unresolved propagation and aliases"
)]
fn python_constant_strings_preserve_order_branches_and_mutable_identity() -> TestResult {
    let dir = directory();
    let value = constant_string_declaration(dir.path(), STRING_RETURN_QUERY)?;
    for (source, expected) in [
        ("def handler(incoming):\n    return 'literal'\n", true),
        (
            "def handler(incoming):\n    renamed = 'fixed'\n    copy = renamed\n    return copy\n",
            true,
        ),
        (
            "def handler(incoming):\n    renamed = incoming\n    renamed = 'fixed'\n    return renamed\n",
            true,
        ),
        (
            "def handler(incoming):\n    renamed = 'fixed'\n    renamed = incoming\n    return renamed\n",
            false,
        ),
        (
            "def handler(incoming):\n    values = ['fixed', incoming]\n    return values[0]\n",
            true,
        ),
        (
            "def handler(incoming):\n    values = ['fixed', incoming]\n    return values[1]\n",
            false,
        ),
        (
            "def handler(incoming):\n    values = ['first', 'second']\n    return values[incoming]\n",
            false,
        ),
        (
            "def handler(incoming):\n    values = ['first', 'second']\n    if incoming:\n        pass\n    return values[0]\n",
            false,
        ),
        (
            "def handler(incoming):\n    values = []\n    values.append('fixed')\n    values.append(incoming)\n    values.pop(1)\n    return values[0]\n",
            true,
        ),
        (
            "def handler(incoming):\n    values = []\n    values.append('fixed')\n    values.append(incoming)\n    values.pop(0)\n    return values[0]\n",
            false,
        ),
        (
            "def handler(incoming):\n    values = ['fixed', incoming]\n    copied = values.copy()\n    values.pop(0)\n    return copied[0]\n",
            true,
        ),
        (
            "def handler(incoming):\n    values = ['fixed', incoming]\n    alias = values\n    alias.pop(0)\n    return values[0]\n",
            false,
        ),
        (
            "def handler(incoming):\n    if incoming:\n        answer = 'first'\n    else:\n        answer = 'second'\n    return answer\n",
            true,
        ),
        (
            "def handler(incoming):\n    if incoming:\n        answer = incoming\n    else:\n        answer = 'fixed'\n    return answer\n",
            false,
        ),
        (
            "def handler(incoming):\n    if False:\n        answer = incoming\n    else:\n        answer = 'fixed'\n    return answer\n",
            true,
        ),
        (
            "def handler(incoming):\n    answer = 'first'\n    answer += 'second'\n    return answer\n",
            true,
        ),
        (
            "def handler(incoming):\n    answer = 'first'\n    answer += incoming\n    return answer\n",
            false,
        ),
        (
            "def handler(incoming):\n    answer = 'fixed'\n    return f'prefix {answer}'\n",
            true,
        ),
        (
            "def handler(incoming):\n    return f'prefix {incoming}'\n",
            false,
        ),
        (
            "def handler(incoming):\n    answer = 'fixed'\n    unknown()\n    return answer\n",
            false,
        ),
        (
            "def handler(incoming):\n    answer = 'fixed'\n    (answer := incoming)\n    return answer\n",
            false,
        ),
        (
            "def handler(incoming):\n    answer = 'fixed'\n    def unused(value=unknown()):\n        pass\n    return answer\n",
            false,
        ),
        (
            "def handler(incoming):\n    def unused():\n        return incoming\n    return 'fixed'\n",
            true,
        ),
        (
            "def handler(incoming):\n    return incoming\n    return 'fixed'\n",
            false,
        ),
        (
            "def handler(incoming):\n    return helper('fixed')\n",
            false,
        ),
        ("def handler(incoming):\n    return b'fixed'\n", false),
        (
            "def handler(incoming):\n    for item in incoming:\n        answer = item\n    return 'fixed'\n",
            false,
        ),
        (
            "def handler(incoming):\n    if incoming:\n        for item in incoming:\n            answer = item\n    else:\n        answer = 'fixed'\n    return answer\n",
            false,
        ),
        (
            "def handler(incoming):\n    if incoming:\n        answer = 'fixed'\n    elif incoming == 'other':\n        answer = incoming\n    else:\n        answer = 'other fixed'\n    return answer\n",
            false,
        ),
    ] {
        let run = evaluate(&value, source.as_bytes(), dir.path(), Limits::default())?;
        let [record] = run.report.records.as_slice() else {
            return Err("expected one constant-string result".into());
        };
        assert_eq!(
            record.result,
            if expected {
                ResultState::Pass
            } else {
                ResultState::NotEvaluated
            },
            "{source}: {:?}",
            record.observation
        );
        let observation = record
            .observation
            .as_ref()
            .ok_or("constant-string observation is absent")?;
        assert_eq!(observation.get("complete"), Some(&json!(true)), "{source}");
        assert!(observation.pointer("/fields/captures").is_some());
        assert_eq!(
            observation.pointer("/fields/constant_string/proven"),
            Some(&json!(expected)),
            "{source}"
        );
        assert_eq!(run.report.usage.provider_calls, 0);
    }
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions check every selected complete argument and fail-closed evidence boundaries"
)]
fn python_constant_strings_refuse_second_sinks_ambiguous_and_partial_evidence() -> TestResult {
    let dir = directory();
    let query = "((function_definition name: (identifier) @_name body: (block (expression_statement (call function: (identifier) @_callee arguments: (argument_list . (_) @value))))) @scope (#eq? @_name \"handler\") (#eq? @_callee \"sink\"))";
    let value = constant_string_declaration(dir.path(), query)?;
    for (source, expected) in [
        (
            "def handler(incoming):\n    sink('first')\n    sink('second')\n",
            true,
        ),
        (
            "def handler(incoming):\n    sink('first')\n    sink(incoming)\n",
            false,
        ),
        (
            "def handler(incoming):\n    sink(f'fixed {unknown.part}')\n",
            false,
        ),
        ("def handler(incoming):\n    pass\n", false),
        (
            "def handler(incoming):\n    sink('first')\ndef handler(incoming):\n    sink('second')\n",
            false,
        ),
    ] {
        let run = evaluate(&value, source.as_bytes(), dir.path(), Limits::default())?;
        let [record] = run.report.records.as_slice() else {
            return Err("expected one argument-origin result".into());
        };
        assert_eq!(
            record.result,
            if expected {
                ResultState::Pass
            } else {
                ResultState::NotEvaluated
            },
            "{source}: {:?}",
            record.observation
        );
    }
    let receiver_query = "((function_definition name: (identifier) @_name body: (block (expression_statement (call arguments: (argument_list . (_) @value))))) @scope (#eq? @_name \"handler\"))";
    let receiver_value = constant_string_declaration(dir.path(), receiver_query)?;
    let run = evaluate(
        &receiver_value,
        b"def handler(incoming):\n    answer = 'fixed'\n    receiver().sink(answer)\n",
        dir.path(),
        Limits::default(),
    )?;
    let [record] = run.report.records.as_slice() else {
        return Err("expected one computed-receiver refusal".into());
    };
    assert_eq!(record.result, ResultState::NotEvaluated);
    for bounds in [
        json!({"input_bytes":1}),
        json!({"nodes":1}),
        json!({"captures":1}),
        json!({"output_bytes":1}),
    ] {
        let mut bounded = value.clone();
        bounded
            .pointer_mut("/rules/0/check")
            .and_then(Value::as_object_mut)
            .ok_or("constant-string check is absent")?
            .insert("limits".into(), bounds);
        let run = evaluate(
            &bounded,
            b"def handler(incoming):\n    sink('fixed')\n",
            dir.path(),
            Limits::default(),
        )?;
        let [record] = run.report.records.as_slice() else {
            return Err("expected one resource refusal".into());
        };
        assert_eq!(record.result, ResultState::NotEvaluated);
        assert!(record.observation.is_none());
    }
    let run = evaluate(
        &value,
        b"def handler(:\n sink('fixed')\n",
        dir.path(),
        Limits::default(),
    )?;
    let [record] = run.report.records.as_slice() else {
        return Err("expected one malformed-source refusal".into());
    };
    assert_eq!(record.result, ResultState::NotEvaluated);
    assert!(
        record
            .observation
            .as_ref()
            .and_then(|o| o.pointer("/fields/captures"))
            .is_none()
    );
    let mut invalid = value;
    *invalid
        .pointer_mut("/rules/0/check/query")
        .ok_or("query is absent")? = json!("(identifier) @value");
    assert!(ValidatedBaseline::from_bytes(invalid.to_string().as_bytes(), dir.path()).is_err());
    Ok(())
}
