#![allow(dead_code)]
use auditoad::{ScanRequest, ScanResult, Snapshot, ValidatedBaseline, scan, schema::Limits};
use serde_json::{Value, json};
use std::path::Path;

/// Decodes a report byte field written as UTF-8 text.
#[track_caller]
#[expect(
    clippy::panic,
    reason = "test assertion helper requires the exact UTF-8 report representation"
)]
pub fn report_text(value: &Value) -> String {
    assert_eq!(value.get("encoding"), Some(&json!("utf-8")), "{value}");
    match value.get("text").and_then(Value::as_str) {
        Some(text) => text.to_owned(),
        None => panic!("expected UTF-8 report text, received {value}"),
    }
}

#[track_caller]
#[expect(
    clippy::panic,
    reason = "test setup requires a writable generated directory; failure must fail the calling test with the I/O cause"
)]
pub fn directory() -> tempfile::TempDir {
    // Reuse Cargo's generated boundary so source checkouts can remain read-only.
    let target = std::env::var_os("CARGO_TARGET_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join("target"));
    let created = std::fs::create_dir_all(&target);
    assert!(
        created.is_ok(),
        "could not create test target {}: {created:?}",
        target.display()
    );
    match tempfile::Builder::new()
        .prefix(".auditoad-test-")
        .tempdir_in(target)
    {
        Ok(directory) => directory,
        Err(error) => panic!("could not create a confined test directory: {error}"),
    }
}

/// Dimension-header control only, without compressed pixels or CRC validation. It tests lossless
/// custody and region bounds, not PNG decoding, OCR or visual accuracy.
pub fn png_header_fixture(width: u32, height: u32) -> Vec<u8> {
    let mut bytes = b"\x89PNG\r\n\x1a\n\x00\x00\x00\x0dIHDR".to_vec();
    bytes.extend(width.to_be_bytes());
    bytes.extend(height.to_be_bytes());
    bytes.extend([8, 6, 0, 0, 0, 0, 0, 0, 0]);
    bytes
}

#[track_caller]
pub fn fixture(root: &Path, name: &str, bytes: &[u8], evidence: &[u8]) -> Value {
    let written = std::fs::write(root.join(name), bytes);
    assert!(
        written.is_ok(),
        "could not write test fixture {name}: {written:?}"
    );
    json!({"path": name, "corpus_revision": "controls-r1", "source_sha256": auditoad::sha256(bytes), "evidence_sha256": auditoad::sha256(evidence)})
}

pub fn bytes_baseline(root: &Path) -> Value {
    json!({
        "schema": "auditoad-baseline/1",
        "baseline": {"id":"bytes-policy","version":"1","title":"Known byte predicate","publisher":"tests","status":"admitted"},
        "sources": {"bytes":{"adapter":"raw-bytes/1","media":["application/octet-stream"]}},
        "evidence": {"bytes":{"builder":"bytes/1","builder_revision":"r1"}},
        "groups": [{"id":"BYTES","title":"Byte policy"}],
        "rules": [{"id":"BYTES-1","revision":"r1","source":"bytes","group":"BYTES","risk":"low","scope_kind":"site","title":"Forbidden byte marker",
            "evidence":"bytes","evaluator":{"kind":"yara-x","contract":"yara-x/1.20.0"},
            "check":{"kind":"yara-x/1.20.0","source":"rule violation { strings: $a = \"bad\" condition: $a }","rule_name":"violation","fail_when":"match"},
            "applicability":{"include":["*"],"exclude":[]},"falsifier":"Input contains the exact ASCII marker bad",
            "fixtures":{"fail":[fixture(root,"fail.txt",b"bad",b"bad")],"pass":[fixture(root,"pass.txt",b"good",b"good")]}}],
        "profiles":[{"id":"default","select":["*"],"block_on":["fail","review","error","not_evaluated"],"allowed_egress":[]}]
    })
}

#[expect(
    clippy::panic,
    reason = "fixture adaptation asserts the locally constructed bytes baseline shape"
)]
pub fn inventory_baseline(root: &Path) -> Value {
    let mut value = bytes_baseline(root);
    for (pointer, replacement) in [
        ("/baseline/id", json!("inventory-policy")),
        (
            "/sources/bytes",
            json!({"adapter":"inventory-json/1","media":["host.property"]}),
        ),
        (
            "/evidence/bytes",
            json!({"builder":"item-json/1","builder_revision":"r1"}),
        ),
        (
            "/rules/0/evaluator",
            json!({"kind":"json-pointer-equals","contract":"json-pointer-equals/1"}),
        ),
        (
            "/rules/0/check",
            json!({"kind":"json-pointer-equals/1","pointer":"/facts/encrypted","expected":true,"fail_when":"unequal"}),
        ),
    ] {
        match value.pointer_mut(pointer) {
            Some(field) => *field = replacement,
            None => panic!("bytes baseline fixture is missing {pointer}"),
        }
    }
    let bad = br#"{"id":"disk","kind":"host.property","facts":{"encrypted":false}}"#;
    let good = br#"{"id":"disk","kind":"host.property","facts":{"encrypted":true}}"#;
    match value.pointer_mut("/rules/0/fixtures") {
        Some(field) => {
            *field = json!({"fail":[fixture(root,"fail.json",bad,bad)],"pass":[fixture(root,"pass.json",good,good)]})
        }
        None => panic!("bytes baseline fixture is missing /rules/0/fixtures"),
    }
    value
}

#[expect(
    clippy::panic,
    reason = "fixture adaptation asserts the locally constructed bytes baseline shape"
)]
pub fn mock_baseline(root: &Path) -> Value {
    let mut value = bytes_baseline(root);
    for (pointer, replacement) in [
        ("/baseline/status", json!("draft")),
        (
            "/rules/0/evaluator",
            json!({"kind":"mock-model","contract":"yes-no/1"}),
        ),
        (
            "/rules/0/check",
            json!({"kind":"mock-model/1","instructions":"Does this input violate the supplied policy?","pass_below":0.1,"fail_at_or_above":0.9}),
        ),
        ("/rules/0/fixtures", json!({"fail":[],"pass":[]})),
    ] {
        match value.pointer_mut(pointer) {
            Some(field) => *field = replacement,
            None => panic!("bytes baseline fixture is missing {pointer}"),
        }
    }
    value
}

#[track_caller]
#[expect(
    clippy::panic,
    reason = "test assertion helper requires the supplied positive baseline to validate and reports the actual rejection"
)]
pub fn validate(value: &Value, root: &Path) -> ValidatedBaseline {
    match ValidatedBaseline::from_bytes(value.to_string().as_bytes(), root) {
        Ok(baseline) => baseline,
        Err(error) => panic!("positive test baseline was rejected: {error}"),
    }
}

#[track_caller]
#[expect(
    clippy::panic,
    reason = "test assertion helper requires the positive scan to complete and reports its actual refusal"
)]
pub fn run(baseline: &ValidatedBaseline, snapshot: &Snapshot, limits: Limits) -> ScanResult {
    match scan(ScanRequest {
        baseline,
        profile: "default",
        source_alias: "bytes",
        snapshot,
        limits,
        experimental: false,
        mock: None,
    }) {
        Ok(result) => result,
        Err(error) => panic!("positive test scan was refused: {error}"),
    }
}

#[track_caller]
#[expect(
    clippy::panic,
    reason = "test assertion helper requires the supplied positive inventory to prepare and reports its actual rejection"
)]
pub fn inventory(items: Value, limits: &Limits) -> Snapshot {
    let bytes = json!({"schema":"auditoad-inventory/1","snapshot_id":"snapshot-1","items":items})
        .to_string()
        .into_bytes();
    match Snapshot::inventory(&bytes, limits) {
        Ok(snapshot) => snapshot,
        Err(error) => panic!("positive test inventory was rejected: {error}"),
    }
}
