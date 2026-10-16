//! Immutable retained exchanges. Execution, admission and decoding remain with the scanner.
use crate::{
    ScanError, json,
    schema::SourceIdentity,
    source::{read_bounded, same_path, sha256, unlinked_path},
};
use automation_structures::{Budget, Sequential};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};

struct Exchange {
    evaluator: Value,
    evidence_sha256: String,
    request: Vec<u8>,
    response: Vec<u8>,
    status: u16,
    check_id: String,
}

/// One original live exchange read from a retained report.
struct Retained {
    rule: String,
    target: String,
    exchange: Exchange,
}

pub(crate) struct Replay {
    pub(crate) input_path: PathBuf,
    report_sha256: String,
    source: Value,
    exchanges: BTreeMap<(String, String, String), Exchange>,
}

fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str, String> {
    value[key]
        .as_str()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| format!("replay lacks {key}"))
}

fn bytes(value: &Value) -> Result<Vec<u8>, String> {
    if value.as_object().is_none_or(|object| object.len() != 2) {
        return Err("replay byte field must have an encoding and payload".into());
    }
    match value["encoding"].as_str() {
        Some("utf-8") => value["text"]
            .as_str()
            .map(|s| s.as_bytes().to_vec())
            .ok_or("replay lacks UTF-8 text".into()),
        Some("hex") => {
            let encoded = value["data"]
                .as_str()
                .ok_or("replay lacks hexadecimal data")?;
            if !encoded.len().is_multiple_of(2) || !encoded.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err("invalid replay hexadecimal bytes".into());
            }
            (0..encoded.len())
                .step_by(2)
                .map(|i| {
                    let end = i
                        .checked_add(2)
                        .ok_or("hexadecimal byte offset overflows")?;
                    let pair = encoded
                        .get(i..end)
                        .ok_or("invalid hexadecimal byte boundary")?;
                    u8::from_str_radix(pair, 16).map_err(|e| e.to_string())
                })
                .collect()
        }
        _ => Err("unknown replay byte encoding".into()),
    }
}

fn bound_bytes(value: &Value, body: &str, digest: &str) -> Result<Vec<u8>, String> {
    let bytes = bytes(&value[body])?;
    if text(value, digest)? != sha256(&bytes) {
        return Err(format!("replay {body} hash differs"));
    }
    Ok(bytes)
}

fn evaluator_identity(value: &Value) -> Result<Value, String> {
    // Execution ceilings may differ on replay; backend/model/endpoint and decoding policy may not.
    Ok(
        json!({"name":text(value,"name")?, "backend":text(value,"backend")?,
        "model":text(value,"model")?, "endpoint":text(value,"endpoint")?,
        "response_model":value["response_model"],
        "capabilities":value["capabilities"],
        "choice_probability_sum_tolerance":value["choice_probability_sum_tolerance"]}),
    )
}

/// Original live exchanges of a retained report, in record order. Reuse may skip reused
/// members of a mixed report; replay refuses them. Neither role admits mocks or replays,
/// and reused response bytes are never imported as another live origin.
fn retained(report: &Value, skip_reused: bool) -> Result<Vec<Retained>, String> {
    if report["schema"] != "auditoad-report/2" {
        return Err("replay requires auditoad-report/2".into());
    }
    let records = report["records"].as_array().ok_or("replay lacks records")?;
    let mut pairs = BTreeSet::new();
    let mut found = Vec::new();
    for record in records {
        let rule = text(&record["rule"], "id")?;
        let target = text(&record["target"], "id")?;
        if !pairs.insert((rule, target)) {
            return Err("duplicate replay rule/target".into());
        }
        if record.pointer("/evaluator/binding").and_then(Value::as_str) != Some("model") {
            continue;
        }
        let observation = &record["observation"];
        let members: Vec<&Value> = if observation["type"] == "combined-models/1" {
            observation["members"]
                .as_array()
                .ok_or("replay lacks combined members")?
                .iter()
                .collect()
        } else {
            vec![observation]
        };
        for member in members {
            // Unasked, failed-transport and prepared questions supply no response to reuse.
            if member.get("response_bytes").is_none() {
                continue;
            }
            if member["mock"] != false
                || member.get("replay").is_some()
                || (!skip_reused && member.get("reuse").is_some())
            {
                return Err(
                    "replay and reuse require original live exchanges, not mocks, replays or reused answers"
                        .into(),
                );
            }
            if member.get("reuse").is_some() {
                continue;
            }
            let evidence = bound_bytes(&record["evidence"], "bytes", "sha256")?;
            let request = bound_bytes(member, "request_bytes", "request_sha256")?;
            let response = bound_bytes(member, "response_bytes", "response_sha256")?;
            if !Budget::new(crate::evaluators::RESPONSE_LIMIT).try_allocate(response.len() as u64) {
                return Err("replay response exceeds the installed response limit".into());
            }
            let status = member["http_status"]
                .as_u64()
                .filter(|s| (100..=599).contains(s))
                .ok_or("replay lacks a valid HTTP status")?;
            let status = u16::try_from(status).map_err(|_| "replay HTTP status exceeds u16")?;
            found.push(Retained {
                rule: rule.to_owned(),
                target: target.to_owned(),
                exchange: Exchange {
                    evaluator: evaluator_identity(&member["evaluator"])?,
                    evidence_sha256: sha256(&evidence),
                    request,
                    response,
                    status,
                    check_id: text(record, "check_id")?.to_owned(),
                },
            });
        }
    }
    Ok(found)
}

impl Replay {
    pub(crate) fn provenance(&self) -> Value {
        json!({"report_sha256":self.report_sha256,"scope":"local replay of retained bytes; no new HTTP request"})
    }
    pub(crate) fn from_file(path: &Path, limit: u64) -> Result<Self, ScanError> {
        let path = unlinked_path(path).map_err(ScanError::invalid)?;
        let bytes = read_bounded(&path, limit).map_err(ScanError::invalid)?;
        Self::from_bytes(&bytes, path).map_err(ScanError::invalid)
    }

    fn from_bytes(bytes: &[u8], input_path: PathBuf) -> Result<Self, String> {
        let report = json::parse_value(bytes)?;
        let source = report
            .get("source")
            .ok_or("replay lacks source identity")?
            .clone();
        let found = retained(&report, false)?;
        for field in ["binding", "input_sha256", "snapshot_id"] {
            text(&source, field)?;
        }
        let mut exchanges = BTreeMap::new();
        for Retained {
            rule,
            target,
            exchange,
        } in found
        {
            let key = (rule, target, text(&exchange.evaluator, "name")?.to_owned());
            if exchanges.insert(key, exchange).is_some() {
                return Err("duplicate replay model exchange".into());
            }
        }
        if exchanges.is_empty() {
            return Err("replay has no retained live exchanges".into());
        }
        Ok(Self {
            input_path,
            report_sha256: sha256(bytes),
            source,
            exchanges,
        })
    }

    pub(crate) fn validate_source(&self, source: &SourceIdentity) -> Result<(), ScanError> {
        if self.source.get("binding").and_then(Value::as_str) != Some(source.binding.as_str())
            || self.source.get("input_sha256").and_then(Value::as_str)
                != Some(source.input_sha256.as_str())
            || self.source.get("snapshot_id").and_then(Value::as_str)
                != Some(source.snapshot_id.as_str())
        {
            return Err(ScanError::invalid(
                "replay source binding, input bytes or frozen snapshot differs",
            ));
        }
        Ok(())
    }

    pub(crate) fn response(
        &self,
        rule: &str,
        target: &str,
        evaluator: &Value,
        evidence: &[u8],
        request: &[u8],
    ) -> Result<(u16, Vec<u8>, Value), String> {
        let identity = evaluator_identity(evaluator)?;
        let key = (
            rule.to_owned(),
            target.to_owned(),
            text(&identity, "name")?.to_owned(),
        );
        let retained = self
            .exchanges
            .get(&key)
            .ok_or("replay has no retained exchange for this rule, target and model")?;
        if retained.evaluator != identity
            || retained.evidence_sha256 != sha256(evidence)
            || retained.request != request
        {
            return Err(
                "replay evaluator, complete evidence or exact request differs; no response reused"
                    .into(),
            );
        }
        let mut provenance = self.provenance();
        let object = json::object_mut(&mut provenance)?;
        object.insert("check_id".into(), json!(retained.check_id));
        object.insert("response_sha256".into(), json!(sha256(&retained.response)));
        Ok((retained.status, retained.response.clone(), provenance))
    }
}

/// Retained answers that a scan may reuse instead of asking again. Identity is the exchange
/// content: evaluator identity, complete evidence and exact request bytes. Rule and target
/// names do not matter, so a revised baseline or another input reuses only byte-identical
/// questions; anything else is asked or prepared as usual.
pub(crate) struct Reuse {
    pub(crate) input_paths: Vec<PathBuf>,
    exchanges: BTreeMap<(String, String), Vec<(Exchange, String)>>,
}

impl Reuse {
    /// `limit` bounds all source-report bytes together; refusal exposes no partial collection.
    pub(crate) fn from_files(paths: &[PathBuf], limit: u64) -> Result<Self, ScanError> {
        if paths.is_empty() {
            return Err(ScanError::invalid(
                "reuse requires at least one source report",
            ));
        }
        let mut input_paths: Vec<PathBuf> = Vec::new();
        let mut exchanges: BTreeMap<(String, String), Vec<(Exchange, String)>> = BTreeMap::new();
        let mut steps =
            Sequential::new(paths.len(), 1, 0).map_err(|e| ScanError::invalid(e.to_string()))?;
        let mut bytes_owner = Budget::new(limit);
        while !steps.is_done() {
            if !steps.begin_step() {
                return Err(ScanError::unresolved(
                    "reuse source preparation refused begin_step",
                ));
            }
            let path = paths
                .get(steps.completed())
                .ok_or_else(|| ScanError::unresolved("reuse source step has no input"))?;
            let path = unlinked_path(path).map_err(ScanError::invalid)?;
            if input_paths.iter().any(|seen| same_path(seen, &path)) {
                return Err(ScanError::invalid("reuse sources must be distinct files"));
            }
            let bytes = read_bounded(&path, bytes_owner.available()).map_err(ScanError::invalid)?;
            if !bytes_owner.try_allocate(bytes.len() as u64) {
                return Err(ScanError::unresolved(
                    "combined reuse source byte allowance refused",
                ));
            }
            let report = json::parse_value(&bytes).map_err(ScanError::invalid)?;
            let found = retained(&report, true).map_err(ScanError::invalid)?;
            if found.is_empty() {
                return Err(ScanError::invalid(format!(
                    "reuse source has no retained live exchanges: {}",
                    path.display()
                )));
            }
            let report_sha256 = sha256(&bytes);
            for Retained { exchange, .. } in found {
                let entries = exchanges
                    .entry((exchange.evidence_sha256.clone(), sha256(&exchange.request)))
                    .or_default();
                // The first retained answer for an identity wins, in source order.
                if !entries
                    .iter()
                    .any(|(kept, _)| kept.evaluator == exchange.evaluator)
                {
                    entries.push((exchange, report_sha256.clone()));
                }
            }
            input_paths.push(path);
            if !steps.complete_step(0) || steps.completed() != input_paths.len() {
                return Err(ScanError::unresolved(
                    "reuse source preparation correspondence failed",
                ));
            }
        }
        Ok(Self {
            input_paths,
            exchanges,
        })
    }

    /// The retained status, response and provenance for an identical exchange, if any.
    pub(crate) fn response(
        &self,
        evaluator: &Value,
        evidence: &[u8],
        request: &[u8],
    ) -> Option<(u16, Vec<u8>, Value)> {
        let identity = evaluator_identity(evaluator).ok()?;
        let (kept, report_sha256) = self
            .exchanges
            .get(&(sha256(evidence), sha256(request)))?
            .iter()
            .find(|(kept, _)| kept.evaluator == identity && kept.request == request)?;
        Some((
            kept.status,
            kept.response.clone(),
            json!({"report_sha256":report_sha256,"check_id":kept.check_id,
                "response_sha256":sha256(&kept.response),
                "scope":"retained live answer to an identical evaluator, evidence and request; no new HTTP request"}),
        ))
    }
}
