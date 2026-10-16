mod support;
use auditoad::{
    MockModel, ScanRequest, Snapshot, ValidatedBaseline, scan, scan_to_file,
    scan_to_file_with_progress,
    schema::{Limits, ResultState},
    sha256,
};
use serde_json::{Value, json};
use std::{fs, path::Path};
use support::{directory, report_text};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn request<'a>(baseline: &'a ValidatedBaseline, snapshot: &'a Snapshot) -> ScanRequest<'a> {
    ScanRequest {
        baseline,
        profile: "experiment",
        source_alias: "bundle",
        snapshot,
        limits: Limits::default(),
        experimental: true,
        mock: None,
    }
}

fn bundle_baseline(scope: &str) -> TestResult<ValidatedBaseline> {
    let mut value: serde_json::Value = serde_json::from_slice(&fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/bundle.baseline.json"),
    )?)?;
    *value
        .pointer_mut("/evidence/context/required_roles")
        .ok_or("fixture roles are absent")? = if scope == "relation" {
        json!(["subject", "peer", "policy"])
    } else {
        json!(["subject", "policy"])
    };
    *value
        .pointer_mut("/rules/0/scope_kind")
        .ok_or("fixture scope kind is absent")? = json!(scope);
    Ok(ValidatedBaseline::from_bytes(
        value.to_string().as_bytes(),
        Path::new("."),
    )?)
}

fn bundle_manifest(root: &Path, scope: &str) -> TestResult<(std::path::PathBuf, Value)> {
    fs::write(
        root.join("model.tla"),
        "header\r\nCapacityBound == used <= capacity\r\nfooter\r\n",
    )?;
    fs::write(root.join("model.cfg"), "INVARIANT CapacityBound\n")?;
    fs::write(root.join("policy.md"), "Check the configured invariant.\n")?;
    fs::write(root.join("unrelated.md"), "Unrelated evidence marker.\n")?;
    let value = json!({"schema":"auditoad-evidence-bundle/1","files":{
        "model.tla":sha256(&fs::read(root.join("model.tla"))?),
        "model.cfg":sha256(&fs::read(root.join("model.cfg"))?),
        "policy.md":sha256(&fs::read(root.join("policy.md"))?),
        "unrelated.md":sha256(&fs::read(root.join("unrelated.md"))?)},
        "packets":[{"id":"case-1","kind":"formal-model","scope_kind":scope,
        "parts":[{"role":"subject","path":"model.tla"},
        {"role":"peer","path":"model.cfg"},{"role":"policy","path":"policy.md"},
        {"role":"unrelated","path":"unrelated.md"}]}]});
    let path = root.join("bundle.json");
    fs::write(&path, value.to_string())?;
    Ok((path, value))
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions check complete UTF-8 custody and strict refusal of retired selectors"
)]
fn complete_text_files_keep_exact_bytes_and_refuse_line_selectors() -> TestResult {
    let dir = directory();
    let (path, mut original) = bundle_manifest(dir.path(), "whole")?;
    let baseline = bundle_baseline("whole")?;
    for text in ["", "Ålpha\r\nβeta\r\n", "single Ω", "\n"] {
        fs::write(dir.path().join("model.tla"), text)?;
        *original
            .pointer_mut("/files/model.tla")
            .ok_or("source pin is absent")? = json!(sha256(text.as_bytes()));
        fs::write(&path, original.to_string())?;
        let snapshot = Snapshot::bundle(&path, dir.path(), &Limits::default())?;
        let result = scan(request(&baseline, &snapshot))?;
        let [record] = result.report.records.as_slice() else {
            return Err("expected one complete-file record".into());
        };
        let frame: Value = serde_json::from_slice(
            &record
                .evidence
                .as_ref()
                .ok_or("complete-file evidence is absent")?
                .bytes,
        )?;
        let subject = frame.pointer("/parts/0").ok_or("subject is absent")?;
        assert_eq!(subject.get("text"), Some(&json!(text)));
        assert_eq!(subject.get("byte_start"), Some(&json!(0)));
        assert_eq!(subject.get("byte_end"), Some(&json!(text.len())));
        assert_eq!(subject.get("whole_file"), Some(&json!(true)));
        assert_eq!(
            subject.get("source_sha256"),
            Some(&json!(sha256(text.as_bytes())))
        );
        assert!(subject.get("line_start").is_none());
        assert!(subject.get("line_end").is_none());
    }
    for schema in [
        "auditoad-evidence-bundle/1",
        "checkwarden-evidence-bundle/1",
    ] {
        for selectors in [
            json!({"start_line":1}),
            json!({"end_line":1}),
            json!({"start_line":1,"end_line":1}),
            json!({"start_line":null}),
            json!({"end_line":null}),
        ] {
            let mut altered = original.clone();
            *altered.get_mut("schema").ok_or("bundle schema is absent")? = json!(schema);
            let subject = altered
                .pointer_mut("/packets/0/parts/0")
                .and_then(Value::as_object_mut)
                .ok_or("subject declaration is absent")?;
            subject.extend(
                selectors
                    .as_object()
                    .ok_or("selectors are not an object")?
                    .clone(),
            );
            fs::write(&path, altered.to_string())?;
            let error = Snapshot::bundle(&path, dir.path(), &Limits::default())
                .err()
                .ok_or("retired line selector was accepted")?;
            assert!(error.message.contains("unknown field"), "{selectors}");
        }
    }
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions check complete preparation and target/path refusal"
)]
fn multi_packet_preparation_is_complete_or_refused() -> TestResult {
    let dir = directory();
    let (path, mut manifest) = bundle_manifest(dir.path(), "site")?;
    let mut second = manifest
        .pointer("/packets/0")
        .ok_or("fixture packet is absent")?
        .clone();
    *second.get_mut("id").ok_or("packet identity is absent")? = json!("case-2");
    manifest
        .get_mut("packets")
        .and_then(Value::as_array_mut)
        .ok_or("fixture packets are absent")?
        .push(second);
    fs::write(&path, manifest.to_string())?;
    let limits = Limits {
        targets: 2,
        ..Limits::default()
    };
    let snapshot = Snapshot::bundle(&path, dir.path(), &limits)?;
    let baseline = bundle_baseline("site")?;
    let result = scan(request(&baseline, &snapshot))?;
    let [first, second] = result.report.records.as_slice() else {
        return Err("expected both bundle records".into());
    };
    assert_eq!(first.target.id, "case-1");
    assert_eq!(second.target.id, "case-2");
    assert!(
        Snapshot::bundle(
            &path,
            dir.path(),
            &Limits {
                targets: 1,
                ..limits
            }
        )
        .is_err()
    );
    *manifest
        .pointer_mut("/packets/1/parts/0/path")
        .ok_or("second subject path is absent")? = json!("unlisted.tla");
    fs::write(&path, manifest.to_string())?;
    assert!(Snapshot::bundle(&path, dir.path(), &limits).is_err());
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions check exact image bytes, declared region and changed-pin refusal"
)]
fn image_bundles_retain_original_bytes_regions_and_recheck_pins() -> TestResult {
    let dir = directory();
    let (path, mut manifest) = bundle_manifest(dir.path(), "site")?;
    let image = support::png_header_fixture(100, 40);
    fs::write(dir.path().join("screen.png"), &image)?;
    manifest
        .get_mut("files")
        .and_then(Value::as_object_mut)
        .ok_or("file declarations are absent")?
        .insert(
            "screen.png".into(),
            json!({"sha256":sha256(&image),"media":"image/png"}),
        );
    *manifest
        .pointer_mut("/packets/0/parts/0")
        .ok_or("subject declaration is absent")? = json!({"role":"subject","path":"screen.png",
        "region":{"x":5,"y":6,"width":20,"height":10}});
    fs::write(&path, manifest.to_string())?;
    let snapshot = Snapshot::bundle(&path, dir.path(), &Limits::default())?;
    let baseline = bundle_baseline("site")?;
    let result = scan(request(&baseline, &snapshot))?;
    let [record] = result.report.records.as_slice() else {
        return Err("expected one image record".into());
    };
    let frame: serde_json::Value = serde_json::from_slice(
        &record
            .evidence
            .as_ref()
            .ok_or("image evidence is absent")?
            .bytes,
    )?;
    let subject = frame.pointer("/parts/0").ok_or("image subject is absent")?;
    assert_eq!(subject.get("media"), Some(&json!("image/png")));
    assert_eq!(subject.get("source_sha256"), Some(&json!(sha256(&image))));
    assert_eq!(
        subject.get("region").ok_or("evidence region is absent")?,
        manifest
            .pointer("/packets/0/parts/0/region")
            .ok_or("declared region is absent")?
    );
    assert_eq!(subject.pointer("/bytes/encoding"), Some(&json!("hex")));
    let hex = subject
        .pointer("/bytes/data")
        .and_then(Value::as_str)
        .ok_or("retained image hex is absent")?;
    let (chunks, remainder) = hex.as_bytes().as_chunks::<2>();
    assert!(
        remainder.is_empty(),
        "retained hex must contain complete byte pairs"
    );
    let retained = chunks
        .iter()
        .map(|pair| -> TestResult<u8> { Ok(u8::from_str_radix(std::str::from_utf8(pair)?, 16)?) })
        .collect::<TestResult<Vec<_>>>()?;
    assert_eq!(retained, image);
    assert_eq!(subject.get("whole_file"), Some(&json!(false)));
    assert_eq!(
        subject.get("image_validation"),
        Some(&json!("png-header-only/1"))
    );
    let location = record
        .target
        .metadata
        .pointer("/locations/0")
        .ok_or("image target location is absent")?;
    assert_eq!(location.get("path"), Some(&json!("screen.png")));
    assert_eq!(
        location
            .get("region")
            .ok_or("image location region is absent")?,
        subject
            .get("region")
            .ok_or("image evidence region is absent")?
    );
    assert!(location.get("bytes").is_none());
    fs::write(
        dir.path().join("screen.png"),
        support::png_header_fixture(101, 40),
    )?;
    let changed = scan(request(&baseline, &snapshot))?;
    assert_eq!(
        changed
            .report
            .records
            .first()
            .ok_or("changed-image record is absent")?
            .result,
        ResultState::Error
    );
    assert_eq!(changed.report.usage.provider_calls, 0);
    assert!(Snapshot::bundle(&path, dir.path(), &Limits::default()).is_err());
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions bind JPEG dimension-header custody, pin drift and malformed marker refusal"
)]
fn jpeg_bundles_retain_original_bytes_and_refuse_changed_or_truncated_headers() -> TestResult {
    let dir = directory();
    let (path, mut manifest) = bundle_manifest(dir.path(), "site")?;
    // Header-only controls, deliberately without entropy-coded pixel data.
    let image =
        b"\xff\xd8\xff\xc0\x00\x11\x08\x02\x00\x02\x00\x03\x01\x11\x00\x02\x11\x00\x03\x11\x00";
    fs::write(dir.path().join("screen.jpg"), image)?;
    manifest
        .get_mut("files")
        .and_then(Value::as_object_mut)
        .ok_or("files absent")?
        .insert(
            "screen.jpg".into(),
            json!({"sha256":sha256(image),"media":"image/jpeg"}),
        );
    *manifest
        .pointer_mut("/packets/0/parts/0")
        .ok_or("subject absent")? = json!({"role":"subject","path":"screen.jpg"});
    fs::write(&path, serde_json::to_vec(&manifest)?)?;
    let snapshot = Snapshot::bundle(&path, dir.path(), &Limits::default())?;
    let baseline = bundle_baseline("site")?;
    let result = scan(request(&baseline, &snapshot))?;
    let evidence = result
        .report
        .records
        .first()
        .and_then(|record| record.evidence.as_ref())
        .ok_or("JPEG evidence absent")?;
    let frame: Value = serde_json::from_slice(&evidence.bytes)?;
    assert_eq!(frame.pointer("/parts/0/media"), Some(&json!("image/jpeg")));
    assert_eq!(
        frame.pointer("/parts/0/source_sha256"),
        Some(&json!(sha256(image)))
    );
    assert_eq!(frame.pointer("/parts/0/width"), Some(&json!(512)));
    assert_eq!(frame.pointer("/parts/0/height"), Some(&json!(512)));
    assert_eq!(
        frame.pointer("/parts/0/bytes"),
        Some(&json!({"encoding":"hex","data":"ffd8ffc00011080200020003011100021100031100"}))
    );
    assert_eq!(
        frame.pointer("/parts/0/image_validation"),
        Some(&json!("jpeg-header-only/1"))
    );
    fs::write(dir.path().join("screen.jpg"), b"\xff\xd8\xff\xe0\x00\x00")?;
    assert_eq!(
        scan(request(&baseline, &snapshot))?
            .report
            .records
            .first()
            .ok_or("drift record absent")?
            .result,
        ResultState::Error
    );
    *manifest
        .pointer_mut("/files/screen.jpg/sha256")
        .ok_or("pin absent")? = json!(sha256(b"\xff\xd8\xff\xe0\x00\x00"));
    fs::write(&path, serde_json::to_vec(&manifest)?)?;
    assert!(Snapshot::bundle(&path, dir.path(), &Limits::default()).is_err());
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions check each invalid region/header/selector and the complete frame limit"
)]
fn image_regions_headers_selectors_and_complete_frame_limits_refuse() -> TestResult {
    let dir = directory();
    let (path, mut original) = bundle_manifest(dir.path(), "site")?;
    let image = support::png_header_fixture(100, 40);
    fs::write(dir.path().join("screen.png"), &image)?;
    original
        .get_mut("files")
        .and_then(Value::as_object_mut)
        .ok_or("file declarations are absent")?
        .insert(
            "screen.png".into(),
            json!({"sha256":sha256(&image),"media":"image/png"}),
        );
    *original
        .pointer_mut("/packets/0/parts/0")
        .ok_or("subject declaration is absent")? = json!({"role":"subject","path":"screen.png",
        "region":{"x":5,"y":6,"width":20,"height":10}});
    for region in [
        json!({"x":99,"y":0,"width":2,"height":1}),
        json!({"x":0,"y":39,"width":1,"height":2}),
        json!({"x":0,"y":0,"width":0,"height":1}),
        json!({"x":4294967295_u64,"y":0,"width":2,"height":1}),
    ] {
        let mut altered = original.clone();
        *altered
            .pointer_mut("/packets/0/parts/0/region")
            .ok_or("region declaration is absent")? = region;
        fs::write(&path, altered.to_string())?;
        assert!(
            Snapshot::bundle(&path, dir.path(), &Limits::default())
                .err()
                .ok_or("invalid region was accepted")?
                .message
                .contains("region")
        );
    }
    let mut altered = original.clone();
    altered
        .pointer_mut("/packets/0/parts/0")
        .and_then(Value::as_object_mut)
        .ok_or("image subject declaration is absent")?
        .insert("start_line".into(), json!(1));
    fs::write(&path, altered.to_string())?;
    assert!(
        Snapshot::bundle(&path, dir.path(), &Limits::default())
            .err()
            .ok_or("image text selector was accepted")?
            .message
            .contains("unknown field `start_line`")
    );
    altered = original.clone();
    altered
        .pointer_mut("/packets/0/parts/1")
        .and_then(Value::as_object_mut)
        .ok_or("text part declaration is absent")?
        .insert(
            "region".into(),
            original
                .pointer("/packets/0/parts/0/region")
                .ok_or("declared image region is absent")?
                .clone(),
        );
    fs::write(&path, altered.to_string())?;
    assert!(
        Snapshot::bundle(&path, dir.path(), &Limits::default())
            .err()
            .ok_or("text image-region selector was accepted")?
            .message
            .contains("image regions")
    );
    for malformed in [
        vec![],
        image
            .get(..32)
            .ok_or("header fixture is shorter than 32 bytes")?
            .to_vec(),
        support::png_header_fixture(0, 40),
        support::png_header_fixture(u32::MAX, 40),
        b"not a PNG image".to_vec(),
    ] {
        altered = original.clone();
        *altered
            .pointer_mut("/files/screen.png/sha256")
            .ok_or("image pin is absent")? = json!(sha256(&malformed));
        fs::write(dir.path().join("screen.png"), &malformed)?;
        fs::write(&path, altered.to_string())?;
        assert!(Snapshot::bundle(&path, dir.path(), &Limits::default()).is_err());
    }
    fs::write(dir.path().join("screen.png"), &image)?;
    fs::write(&path, original.to_string())?;
    let limits = Limits {
        evidence_bytes: 100,
        ..Limits::default()
    };
    assert!(
        Snapshot::bundle(&path, dir.path(), &limits)
            .err()
            .ok_or("incomplete frame budget was accepted")?
            .message
            .contains("frames")
    );
    let mut scoped = serde_json::to_value(bundle_baseline("site")?.baseline())?;
    let rule = scoped
        .pointer_mut("/rules/0")
        .and_then(Value::as_object_mut)
        .ok_or("scoped rule is absent")?;
    rule.insert("scope_kind".into(), json!("whole"));
    rule.insert("scope".into(), json!({"unit":"document","context":"none"}));
    *scoped
        .pointer_mut("/evidence/context")
        .ok_or("scoped evidence builder is absent")? =
        json!({"builder":"scoped-input/1","builder_revision":"r1"});
    let scoped = ValidatedBaseline::from_bytes(scoped.to_string().as_bytes(), dir.path())?;
    original
        .pointer_mut("/packets/0/parts/0")
        .and_then(Value::as_object_mut)
        .ok_or("image part declaration is absent")?
        .remove("region");
    fs::write(&path, original.to_string())?;
    let error = Snapshot::scoped_bundle(
        &path,
        dir.path(),
        &scoped,
        "experiment",
        "bundle",
        &Limits::default(),
    )
    .err()
    .ok_or("scoped image was admitted as UTF-8 text")?;
    assert!(error.message.contains("UTF-8 subject"));
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions check pinned relation endpoints and exclusion of unrelated evidence"
)]
fn bundles_retain_pinned_relation_endpoints_and_only_question_roles() -> TestResult {
    let dir = directory();
    let (path, _) = bundle_manifest(dir.path(), "relation")?;
    let snapshot = Snapshot::bundle(&path, dir.path(), &Limits::default())?;
    let baseline = bundle_baseline("relation")?;
    let result = scan(request(&baseline, &snapshot))?;
    assert_eq!(result.report.usage.provider_calls, 0);
    let [record] = result.report.records.as_slice() else {
        return Err("expected one relation record".into());
    };
    let frame: serde_json::Value = serde_json::from_slice(
        &record
            .evidence
            .as_ref()
            .ok_or("relation evidence is absent")?
            .bytes,
    )?;
    assert_eq!(
        frame
            .get("parts")
            .and_then(Value::as_array)
            .ok_or("relation parts are absent")?
            .len(),
        3
    );
    assert_eq!(
        frame.pointer("/parts/0/text"),
        Some(&json!(
            "header\r\nCapacityBound == used <= capacity\r\nfooter\r\n"
        ))
    );
    let source = fs::read(dir.path().join("model.tla"))?;
    assert!(frame.pointer("/parts/0/line_start").is_none());
    assert!(frame.pointer("/parts/0/line_end").is_none());
    assert_eq!(frame.pointer("/parts/0/byte_start"), Some(&json!(0)));
    assert_eq!(
        frame.pointer("/parts/0/byte_end"),
        Some(&json!(source.len()))
    );
    assert_eq!(
        frame.pointer("/parts/0/source_sha256"),
        Some(&json!(sha256(&source)))
    );
    assert_eq!(frame.pointer("/parts/0/whole_file"), Some(&json!(true)));
    assert_eq!(frame.pointer("/parts/1/path"), Some(&json!("model.cfg")));
    let wire = report_text(
        record
            .observation
            .as_ref()
            .and_then(|v| v.get("request_bytes"))
            .ok_or("request bytes are absent")?,
    );
    assert!(wire.contains("footer"));
    assert!(!wire.contains("Unrelated evidence marker"));
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions check equivalent legacy media/schema custody and actual evaluation"
)]
fn legacy_bundle_inputs_keep_evidence_and_do_not_skip_checks() -> TestResult {
    let dir = directory();
    let (path, original) = bundle_manifest(dir.path(), "relation")?;
    let mut evidence = None;
    for input_prefix in ["auditoad", "checkwarden"] {
        let mut manifest = original.clone();
        *manifest
            .get_mut("schema")
            .ok_or("fixture schema is absent")? =
            json!(format!("{input_prefix}-evidence-bundle/1"));
        fs::write(&path, manifest.to_string())?;
        let snapshot = Snapshot::bundle(&path, dir.path(), &Limits::default())?;
        for media_prefix in ["auditoad", "checkwarden"] {
            let mut declaration = serde_json::to_value(bundle_baseline("relation")?.baseline())?;
            *declaration
                .pointer_mut("/sources/bundle/media")
                .ok_or("bundle media declaration is absent")? =
                json!([format!("application/vnd.{media_prefix}.bundle+json")]);
            let baseline =
                ValidatedBaseline::from_bytes(declaration.to_string().as_bytes(), dir.path())?;
            let result = scan(request(&baseline, &snapshot))?;
            let [record] = result.report.records.as_slice() else {
                return Err("expected one legacy relation record".into());
            };
            assert_eq!(record.result, ResultState::NotEvaluated);
            assert!(record.observation.is_some());
            let current = &record
                .evidence
                .as_ref()
                .ok_or("legacy relation evidence is absent")?
                .bytes;
            if let Some(expected) = &evidence {
                assert_eq!(expected, current);
            }
            evidence = Some(current.clone());
        }
    }
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions require identity, role and scope refusal before provider dispatch"
)]
fn bundle_identity_evidence_and_scope_fail_before_provider_dispatch() -> TestResult {
    let dir = directory();
    let (path, original) = bundle_manifest(dir.path(), "relation")?;
    let baseline = bundle_baseline("relation")?;
    let mock = MockModel::from_bytes(br#"{"schema":"auditoad-mock-model/1","replies":[]}"#)?;
    for mutation in ["role", "scope", "changed"] {
        let mut value = original.clone();
        match mutation {
            "role" => {
                *value
                    .pointer_mut("/packets/0/parts/2/role")
                    .ok_or("policy role is absent")? = json!("other")
            }
            "scope" => {
                *value
                    .pointer_mut("/packets/0/scope_kind")
                    .ok_or("packet scope is absent")? = json!("site")
            }
            "changed" => {}
            other => return Err(format!("unrecognized bundle mutation {other}").into()),
        }
        fs::write(&path, value.to_string())?;
        let snapshot = Snapshot::bundle(&path, dir.path(), &Limits::default())?;
        if mutation == "changed" {
            fs::write(dir.path().join("model.cfg"), "INVARIANT Different\n")?;
        }
        let mut req = request(&baseline, &snapshot);
        req.mock = Some(&mock);
        let result = scan(req)?;
        assert_eq!(
            result
                .report
                .records
                .first()
                .ok_or("refused bundle record is absent")?
                .result,
            ResultState::Error
        );
        assert_eq!(result.report.usage.provider_calls, 0);
    }
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions distinguish an unrelated file change from a selected policy change"
)]
fn bundle_packets_recheck_only_the_files_they_select() -> TestResult {
    let dir = directory();
    let (path, mut value) = bundle_manifest(dir.path(), "relation")?;
    fs::write(dir.path().join("other.md"), "Another packet's file.\n")?;
    value
        .get_mut("files")
        .and_then(Value::as_object_mut)
        .ok_or("file declarations are absent")?
        .insert(
            "other.md".into(),
            json!(sha256(&fs::read(dir.path().join("other.md"))?)),
        );
    fs::write(&path, value.to_string())?;
    let snapshot = Snapshot::bundle(&path, dir.path(), &Limits::default())?;
    fs::write(dir.path().join("other.md"), "Changed after the freeze.\n")?;
    let baseline = bundle_baseline("relation")?;
    let result = scan(request(&baseline, &snapshot))?;
    let [record] = result.report.records.as_slice() else {
        return Err("expected one relation record".into());
    };
    assert_eq!(record.result, ResultState::NotEvaluated);
    assert!(record.evidence.is_some());
    fs::write(dir.path().join("policy.md"), "A different policy.\n")?;
    let result = scan(request(&baseline, &snapshot))?;
    assert_eq!(
        result
            .report
            .records
            .first()
            .ok_or("changed policy record is absent")?
            .result,
        ResultState::Error
    );
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions require post-scan source stability before report publication"
)]
fn source_change_during_a_scan_refuses_the_report() -> TestResult {
    let dir = directory();
    let (path, _) = bundle_manifest(dir.path(), "relation")?;
    let snapshot = Snapshot::bundle(&path, dir.path(), &Limits::default())?;
    let baseline = bundle_baseline("relation")?;
    let destination = dir.path().join("report.json");
    let mut mutation = None;
    let outcome =
        scan_to_file_with_progress(request(&baseline, &snapshot), &destination, None, |_| {
            mutation = Some(fs::write(
                dir.path().join("policy.md"),
                "Changed during the scan.\n",
            ));
        });
    mutation.ok_or("source mutation callback was not invoked")??;
    let error = outcome.err().ok_or("changed source was published")?;
    assert!(error.message.contains("source changed during the scan"));
    assert!(!destination.exists());
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions check each pin/relation/path mutation and canonical budget refusal"
)]
fn bundle_rejects_bad_pins_relations_and_budget_exhaustion() -> TestResult {
    let dir = directory();
    let (path, original) = bundle_manifest(dir.path(), "relation")?;
    for mutation in [
        "pin",
        "peer",
        "same-peer",
        "path",
        "duplicate",
        "alias",
        "trailing-dot",
    ] {
        let mut value = original.clone();
        match mutation {
            "alias" | "trailing-dot" => {
                let alias = if mutation == "alias" {
                    "./model.tla"
                } else {
                    "model.tla."
                };
                let pin = value
                    .pointer("/files/model.tla")
                    .ok_or("model pin is absent")?
                    .clone();
                value
                    .get_mut("files")
                    .and_then(Value::as_object_mut)
                    .ok_or("file declarations are absent")?
                    .insert(alias.into(), pin);
                *value
                    .pointer_mut("/packets/0/parts/1")
                    .ok_or("peer declaration is absent")? = json!({"role":"peer","path":alias});
            }
            "duplicate" => {
                let packet = value
                    .pointer("/packets/0")
                    .ok_or("fixture packet is absent")?
                    .clone();
                value
                    .get_mut("packets")
                    .and_then(Value::as_array_mut)
                    .ok_or("fixture packets are absent")?
                    .push(packet);
            }
            other => {
                let (pointer, replacement) = match other {
                    "pin" => ("/files/model.tla", json!("0".repeat(64))),
                    "peer" => ("/packets/0/parts/1/role", json!("other")),
                    "same-peer" => ("/packets/0/parts/1/path", json!("model.tla")),
                    "path" => ("/packets/0/parts/0/path", json!("../elsewhere")),
                    _ => return Err(format!("unrecognized bundle mutation {other}").into()),
                };
                *value
                    .pointer_mut(pointer)
                    .ok_or_else(|| format!("mutation field {pointer} is absent"))? = replacement;
            }
        }
        fs::write(&path, value.to_string())?;
        assert!(
            Snapshot::bundle(&path, dir.path(), &Limits::default()).is_err(),
            "{mutation}"
        );
    }
    fs::write(&path, original.to_string())?;
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
            manifest_work: 3,
            ..Limits::default()
        },
    ] {
        assert!(Snapshot::bundle(&path, dir.path(), &limits).is_err());
    }
    let mut whole = original;
    *whole
        .pointer_mut("/packets/0/scope_kind")
        .ok_or("packet scope is absent")? = json!("whole");
    *whole
        .pointer_mut("/packets/0/parts/0")
        .ok_or("subject declaration is absent")? = json!({"role":"subject","path":"model.tla"});
    fs::write(&path, whole.to_string())?;
    let snapshot = Snapshot::bundle(&path, dir.path(), &Limits::default())?;
    let baseline = bundle_baseline("whole")?;
    assert!(
        scan(request(&baseline, &snapshot))?
            .report
            .records
            .first()
            .ok_or("whole bundle record is absent")?
            .evidence
            .is_some()
    );
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions check exact prepared questions and mock protocol frames for every packet"
)]
fn prepared_and_mock_wire_frames_retain_declared_evidence() -> TestResult {
    let dir = directory();
    let root = dir.path();
    let (path, mut manifest) = bundle_manifest(root, "relation")?;
    let packet = manifest
        .pointer("/packets/0")
        .and_then(Value::as_object)
        .ok_or("fixture packet is absent")?
        .clone();
    *manifest
        .get_mut("packets")
        .ok_or("fixture packets are absent")? = json!(["a", "b", "c", "d"].map(|id| {
        let mut fields = packet.clone();
        fields.insert("id".into(), json!(id));
        Value::Object(fields)
    }));
    fs::write(&path, manifest.to_string())?;
    let snapshot = Snapshot::bundle(&path, root, &Limits::default())?;
    let baseline = bundle_baseline("relation")?;
    let prepared = scan(request(&baseline, &snapshot))?;
    assert_eq!(prepared.report.records.len(), 4);
    assert_eq!(prepared.exit_code, 2);
    assert_eq!(prepared.report.usage.provider_calls, 0);
    let [rule] = baseline.baseline().rules.as_slice() else {
        return Err("expected one bundle rule".into());
    };
    let auditoad::schema::Check::YesNo { instructions, .. } = &rule.check else {
        return Err("expected a yes-no question".into());
    };
    let mut replies = Vec::new();
    for (i, r) in prepared.report.records.iter().enumerate() {
        let bytes = &r
            .evidence
            .as_ref()
            .ok_or("prepared evidence is absent")?
            .bytes;
        let observation = r
            .observation
            .as_ref()
            .ok_or("prepared observation is absent")?;
        let wire: Value = serde_json::from_str(&report_text(
            observation
                .get("request_bytes")
                .ok_or("prepared request bytes are absent")?,
        ))?;
        let question_id = observation
            .get("question_id")
            .and_then(Value::as_str)
            .ok_or("prepared question identity is absent")?;
        assert_eq!(
            wire.get("questions")
                .and_then(|v| v.get(question_id))
                .and_then(|v| v.get("type")),
            Some(&json!("yes-no"))
        );
        replies.push(
            json!({"rule":r.rule.id,"revision":r.rule.revision,"target":r.target.id,
            "evidence_sha256":sha256(bytes),
            "instructions_sha256":sha256(instructions.as_bytes()),
            "response":{"kind":"probability","value":if i==1 || i==2 {0.99} else {0.01}}}),
        );
    }
    let mock = MockModel::from_bytes(
        json!({"schema":"auditoad-mock-model/1","replies":replies})
            .to_string()
            .as_bytes(),
    )?;
    let mut req = request(&baseline, &snapshot);
    req.mock = Some(&mock);
    let observed = scan(req)?;
    assert_eq!(observed.exit_code, 2);
    assert_eq!(observed.report.usage.provider_calls, 4);
    for (index, record) in observed.report.records.into_iter().enumerate() {
        assert_eq!(record.result, ResultState::NotEvaluated);
        let observation = record.observation.ok_or("mock observation is absent")?;
        let decoded: serde_json::Value = serde_json::from_str(&report_text(
            observation
                .get("response_bytes")
                .ok_or("mock response bytes are absent")?,
        ))?;
        assert!(decoded.get("model").is_none());
        let question_id = observation
            .get("question_id")
            .and_then(Value::as_str)
            .ok_or("mock question identity is absent")?;
        assert_eq!(
            decoded
                .get("answers")
                .and_then(|v| v.get(question_id))
                .and_then(|v| v.get("type")),
            Some(&json!("yes-no"))
        );
        assert_eq!(
            observation.get("suggested_result"),
            Some(&json!(if index == 1 || index == 2 {
                "fail"
            } else {
                "pass"
            }))
        );
    }
    Ok(())
}

#[test]
fn legacy_mock_schema_names_are_refused() {
    for schema in ["auditoad-mock-jev/1", "checkwarden-mock-jev/1"] {
        let script = json!({"schema":schema,"replies":[]});
        assert!(MockModel::from_bytes(script.to_string().as_bytes()).is_err());
    }
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions check policy input protection and zero calls after mutation"
)]
fn changed_policy_and_output_overwrite_do_not_clear() -> TestResult {
    let dir = directory();
    let (path, _) = bundle_manifest(dir.path(), "relation")?;
    let snapshot = Snapshot::bundle(&path, dir.path(), &Limits::default())?;
    let baseline = bundle_baseline("relation")?;
    assert!(scan_to_file(request(&baseline, &snapshot), &dir.path().join("policy.md")).is_err());
    fs::write(dir.path().join("policy.md"), "changed policy")?;
    let scan = scan(request(&baseline, &snapshot))?;
    assert_eq!(
        scan.report
            .records
            .first()
            .ok_or("changed policy record is absent")?
            .result,
        ResultState::Error
    );
    assert_eq!(scan.report.usage.provider_calls, 0);
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions check exact request limits without evidence loss or provider calls"
)]
fn request_size_refusal_issues_no_call_and_keeps_declared_evidence() -> TestResult {
    let dir = directory();
    let (path, _) = bundle_manifest(dir.path(), "relation")?;
    let snapshot = Snapshot::bundle(&path, dir.path(), &Limits::default())?;
    let mock = MockModel::from_bytes(br#"{"schema":"auditoad-mock-model/1","replies":[]}"#)?;
    let baseline = bundle_baseline("relation")?;
    let mut req = request(&baseline, &snapshot);
    req.mock = Some(&mock);
    req.limits.request_bytes = 1;
    let result = scan(req)?;
    let [record] = result.report.records.as_slice() else {
        return Err("expected one request-limited record".into());
    };
    assert_eq!(record.result, ResultState::NotEvaluated);
    assert!(
        record
            .reason
            .as_ref()
            .ok_or("request refusal reason is absent")?
            .contains("1-byte limit")
    );
    assert!(record.observation.is_none());
    assert!(
        record
            .evidence
            .as_ref()
            .ok_or("limited request evidence is absent")?
            .bytes
            .len()
            > 1
    );
    assert_eq!(result.report.usage.provider_calls, 0);
    let mut declaration = serde_json::to_value(baseline.baseline())?;
    *declaration
        .pointer_mut("/rules/0/check/max_request_bytes")
        .ok_or("request limit declaration is absent")? = json!(1);
    let restricted = ValidatedBaseline::from_bytes(declaration.to_string().as_bytes(), dir.path())?;
    let mut req = request(&restricted, &snapshot);
    req.mock = Some(&mock);
    let result = scan(req)?;
    assert!(
        result
            .report
            .records
            .first()
            .ok_or("per-rule request-limited record is absent")?
            .reason
            .as_ref()
            .ok_or("per-rule request refusal reason is absent")?
            .contains("1-byte limit")
    );
    assert_eq!(result.report.usage.provider_calls, 0);
    let mut req = request(&baseline, &snapshot);
    req.mock = Some(&mock);
    let admitted = scan(req)?;
    assert_eq!(admitted.report.usage.provider_calls, 1);
    assert_eq!(
        admitted
            .report
            .records
            .first()
            .ok_or("admitted request record is absent")?
            .result,
        ResultState::Error
    );
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions check complete rule/packet order and each rule's declared evidence"
)]
fn bundle_rules_execute_in_declared_order_without_answer_dependencies() -> TestResult {
    let dir = directory();
    let root = dir.path();
    let (path, mut manifest) = bundle_manifest(root, "site")?;
    let packet = manifest
        .pointer("/packets/0")
        .and_then(Value::as_object)
        .ok_or("fixture packet is absent")?
        .clone();
    let targets = ["a", "b", "c", "d", "e"];
    *manifest
        .get_mut("packets")
        .ok_or("fixture packets are absent")? = json!(targets.map(|id| {
        let mut value = packet.clone();
        value.insert("id".into(), json!(id));
        Value::Object(value)
    }));
    fs::write(&path, manifest.to_string())?;
    let mut declaration = serde_json::to_value(bundle_baseline("site")?.baseline())?;
    declaration
        .get_mut("evidence")
        .and_then(Value::as_object_mut)
        .ok_or("evidence declarations are absent")?
        .insert(
            "subject".into(),
            json!({"builder":"declared-parts/1",
        "builder_revision":"r1","required_roles":["subject"]}),
        );
    let rule = declaration
        .pointer("/rules/0")
        .and_then(Value::as_object)
        .ok_or("fixture rule is absent")?
        .clone();
    *declaration
        .get_mut("rules")
        .ok_or("fixture rules are absent")? = json!(
        (0..6)
            .map(|index| {
                let mut value = rule.clone();
                value.insert("id".into(), json!(format!("TEST-{index}")));
                value.insert(
                    "evidence".into(),
                    json!(if index % 2 == 0 { "subject" } else { "context" }),
                );
                Value::Object(value)
            })
            .collect::<Vec<_>>()
    );
    let baseline = ValidatedBaseline::from_bytes(declaration.to_string().as_bytes(), root)?;
    let snapshot = Snapshot::bundle(&path, root, &Limits::default())?;
    let result = scan(ScanRequest {
        baseline: &baseline,
        profile: "experiment",
        source_alias: "bundle",
        snapshot: &snapshot,
        limits: Limits::default(),
        experimental: true,
        mock: None,
    })?;
    assert_eq!(result.report.records.len(), 30);
    assert_eq!(result.report.usage.provider_calls, 0);
    let groups = result.report.records.chunks_exact(targets.len());
    assert!(groups.remainder().is_empty());
    assert_eq!(groups.len(), baseline.baseline().rules.len());
    for (records, rule) in groups.zip(&baseline.baseline().rules) {
        for (record, target) in records.iter().zip(targets) {
            assert_eq!(record.rule.id, rule.id);
            assert_eq!(record.target.id, target);
            let bytes = &record
                .evidence
                .as_ref()
                .ok_or("ordered bundle evidence is absent")?
                .bytes;
            let evidence: Value = serde_json::from_slice(bytes)?;
            assert_eq!(
                evidence
                    .get("parts")
                    .and_then(Value::as_array)
                    .ok_or("ordered evidence parts are absent")?
                    .len(),
                if rule.evidence == "subject" { 1 } else { 2 }
            );
            assert!(evidence.get("rule_id").is_none());
            assert!(!std::str::from_utf8(bytes)?.contains("README"));
        }
    }
    let (pairs, remainder) = baseline.baseline().rules.as_chunks::<2>();
    if !remainder.is_empty() {
        return Err("expected a complete rule pair".into());
    }
    for [first, second] in pairs {
        assert_eq!(
            serde_json::to_value(&first.check)?,
            serde_json::to_value(&second.check)?
        );
    }
    Ok(())
}
