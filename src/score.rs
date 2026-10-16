//! Scores a report's decisions against labels kept outside the scan: per rule, per model and
//! per combination policy, so evaluator files and question designs can be compared.
use crate::{
    ScanError, json,
    source::{read_bounded, sha256},
};
use automation_structures::{Budget, Sequential};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::path::Path;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Labels {
    schema: String,
    dataset: Option<Dataset>,
    labels: Vec<Label>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Dataset {
    id: String,
    revision: String,
    split: DatasetSplit,
    #[serde(skip_serializing_if = "Option::is_none")]
    notes: Option<String>,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum DatasetSplit {
    Development,
    Calibration,
    Holdout,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Label {
    rule: String,
    target: Option<String>,
    packet: Option<String>,
    input: Option<String>,
    line: Option<u64>,
    /// Whether the rule's condition, conventionally a violation, holds for this target.
    violation: bool,
}

fn parse_labels(bytes: &[u8]) -> Result<Labels, ScanError> {
    let labels: Labels = json::parse(bytes).map_err(ScanError::invalid)?;
    if labels.schema != "auditoad-labels/1" || labels.labels.is_empty() {
        return Err(ScanError::invalid(
            "score requires auditoad-labels/1 and at least one label",
        ));
    }
    if labels.dataset.as_ref().is_some_and(|dataset| {
        dataset.id.trim().is_empty()
            || dataset.revision.trim().is_empty()
            || dataset
                .notes
                .as_ref()
                .is_some_and(|notes| notes.trim().is_empty())
    }) {
        return Err(ScanError::invalid(
            "dataset id, revision and supplied notes must be nonempty",
        ));
    }
    let mut seen = std::collections::BTreeSet::new();
    for label in &labels.labels {
        let valid = match (&label.target, &label.packet, &label.input, label.line) {
            (Some(target), None, None, None) => !target.is_empty(),
            (None, Some(packet), None, None) => !packet.is_empty(),
            (None, None, Some(input), Some(line)) => !input.is_empty() && line > 0,
            _ => false,
        };
        if !valid || label.rule.is_empty() {
            return Err(ScanError::invalid(
                "label requires rule and exactly one of target, packet, or input with a positive line",
            ));
        }
        let selector = (
            &label.rule,
            &label.target,
            &label.packet,
            &label.input,
            label.line,
        );
        if !seen.insert(selector) {
            return Err(ScanError::invalid("duplicate label selector"));
        }
    }
    Ok(labels)
}

pub(crate) fn validate_labels(bytes: &[u8]) -> Result<(), ScanError> {
    parse_labels(bytes).map(|_| ())
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Decision {
    Pass,
    Fail,
    Unresolved,
}

fn decision(value: &Value) -> Decision {
    match value.as_str() {
        Some("pass") => Decision::Pass,
        Some("fail") => Decision::Fail,
        _ => Decision::Unresolved,
    }
}

#[derive(Default)]
struct Tally {
    /// Classified domain leaves, not a competing mutable aggregate.
    decisions: Vec<(bool, Decision)>,
}

impl Tally {
    fn add(&mut self, violation: bool, decision: Decision) {
        self.decisions.push((violation, decision));
    }

    fn count(&self, selected: impl Fn(bool, Decision) -> bool) -> Result<u64, ScanError> {
        crate::scan::reduce(
            self.decisions
                .iter()
                .map(|&(violation, decision)| u64::from(selected(violation, decision)))
                .collect(),
        )
    }

    /// Only a fail counts as a reported finding, so an unresolved answer counts as not
    /// reported in the rates, as the OWASP Benchmark scorecard does.
    fn summary(&self) -> Result<Value, ScanError> {
        let total = self.count(|_, _| true)?;
        let true_positive = self.count(|v, d| v && d == Decision::Fail)?;
        let false_positive = self.count(|v, d| !v && d == Decision::Fail)?;
        let true_negative = self.count(|v, d| !v && d == Decision::Pass)?;
        let false_negative = self.count(|v, d| v && d == Decision::Pass)?;
        let unresolved_positive = self.count(|v, d| v && d == Decision::Unresolved)?;
        let unresolved_negative = self.count(|v, d| !v && d == Decision::Unresolved)?;
        let positives =
            crate::scan::reduce(vec![true_positive, false_negative, unresolved_positive])?;
        let negatives =
            crate::scan::reduce(vec![true_negative, false_positive, unresolved_negative])?;
        let correct = crate::scan::reduce(vec![true_positive, true_negative])?;
        let wrong = crate::scan::reduce(vec![false_positive, false_negative])?;
        let unresolved = crate::scan::reduce(vec![unresolved_positive, unresolved_negative])?;
        let resolved = crate::scan::reduce(vec![correct, wrong])?;
        if crate::scan::reduce(vec![resolved, unresolved])? != total {
            return Err(ScanError::unresolved(
                "score reductions disagree with labelled coverage",
            ));
        }
        let rate = |part: u64, whole: u64| (whole != 0).then(|| part as f64 / whole as f64);
        let tpr = rate(true_positive, positives);
        let fpr = rate(false_positive, negatives);
        let mut value = json!({"total":total,"true_positive":true_positive,"false_positive":false_positive,
            "true_negative":true_negative,"false_negative":false_negative,"unresolved_positive":unresolved_positive,
            "unresolved_negative":unresolved_negative,"correct":correct,"wrong":wrong,"unresolved":unresolved});
        let fields = json::object_mut(&mut value).map_err(ScanError::unresolved)?;
        fields.insert("resolved_accuracy".into(), json!(rate(correct, resolved)));
        fields.insert("decision_coverage".into(), json!(rate(resolved, total)));
        fields.insert("true_positive_rate".into(), json!(tpr));
        fields.insert("false_positive_rate".into(), json!(fpr));
        fields.insert("scorecard".into(), json!(tpr.zip(fpr).map(|(t, f)| t - f)));
        Ok(value)
    }
}

const POLICIES: [&str; 4] = ["first_resolved", "agreement", "any_fail", "all_fail"];

/// Load scoring inputs under one cumulative byte allowance and canonical finite progression.
/// The optional reference is compared on the same source/label identity contract as byte scoring.
pub fn score_files(
    report: &Path,
    labels: &Path,
    reference: Option<&Path>,
    max_bytes: u64,
) -> Result<Value, ScanError> {
    let mut paths = vec![report, labels];
    paths.extend(reference);
    let mut steps =
        Sequential::new(paths.len(), 1, 0).map_err(|e| ScanError::invalid(e.to_string()))?;
    let mut bytes_owner = Budget::new(max_bytes);
    let mut loaded = Vec::new();
    while !steps.is_done() {
        if !steps.begin_step() {
            return Err(ScanError::unresolved(
                "score input preparation refused begin_step",
            ));
        }
        let path = paths
            .get(steps.completed())
            .ok_or_else(|| ScanError::unresolved("score input step has no path binding"))?;
        let bytes = read_bounded(path, bytes_owner.available()).map_err(ScanError::invalid)?;
        if !bytes_owner.try_allocate(bytes.len() as u64) {
            return Err(ScanError::unresolved(
                "combined score input byte allowance refused",
            ));
        }
        loaded.push(bytes);
        if !steps.complete_step(0) || steps.completed() != loaded.len() {
            return Err(ScanError::unresolved(
                "score input preparation correspondence failed",
            ));
        }
    }
    match (reference, loaded.as_slice()) {
        (Some(_), [report, labels, reference]) => compare_scores(reference, report, labels),
        (None, [report, labels]) => score(report, labels),
        _ => Err(ScanError::unresolved(
            "score inputs do not match the admitted paths",
        )),
    }
}

fn policy(name: &str, members: &[Decision]) -> Result<Decision, ScanError> {
    let failed = crate::scan::reduce(
        members
            .iter()
            .map(|d| u64::from(*d == Decision::Fail))
            .collect(),
    )?;
    let passed = crate::scan::reduce(
        members
            .iter()
            .map(|d| u64::from(*d == Decision::Pass))
            .collect(),
    )?;
    let resolved = crate::scan::reduce(vec![failed, passed])? == members.len() as u64;
    Ok(match name {
        "first_resolved" => members
            .iter()
            .copied()
            .find(|d| *d != Decision::Unresolved)
            .unwrap_or(Decision::Unresolved),
        "agreement" if resolved && failed == 0 => Decision::Pass,
        "agreement" if resolved && passed == 0 => Decision::Fail,
        "any_fail" if failed != 0 => Decision::Fail,
        "any_fail" if resolved => Decision::Pass,
        "all_fail" if passed != 0 => Decision::Pass,
        "all_fail" if resolved => Decision::Fail,
        _ => Decision::Unresolved,
    })
}

fn member_name(observation: &Value) -> Option<String> {
    observation
        .pointer("/evaluator/name")
        .and_then(Value::as_str)
        .map(String::from)
}

fn comparison(violation: bool, decided: Decision) -> &'static str {
    match decided {
        Decision::Unresolved => "unresolved",
        Decision::Fail if violation => "correct",
        Decision::Pass if !violation => "correct",
        _ => "wrong",
    }
}

fn recorded_digest(value: &Value) -> Option<&str> {
    value.as_str().filter(|s| {
        s.len() == 64
            && s.bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    })
}

/// Scores one report against one labels file.
pub fn score(report: &[u8], labels: &[u8]) -> Result<Value, ScanError> {
    let parsed: Value = json::parse(report).map_err(ScanError::invalid)?;
    let declared = parse_labels(labels)?;
    if parsed.get("schema").and_then(Value::as_str) != Some("auditoad-report/2")
        || declared.schema != "auditoad-labels/1"
    {
        return Err(ScanError::invalid(
            "score requires an auditoad-report/2 report and an auditoad-labels/1 file",
        ));
    }
    let records = parsed
        .get("records")
        .and_then(Value::as_array)
        .ok_or_else(|| ScanError::invalid("report has no records"))?;
    // Borrow a rule projection of the frozen report; selector and duplicate
    // validation below remain the authority over matching records.
    let mut records_by_rule = BTreeMap::<&str, Vec<&Value>>::new();
    for record in records {
        if let Some(rule) = record.pointer("/rule/id").and_then(Value::as_str) {
            records_by_rule.entry(rule).or_default().push(record);
        }
    }
    let mut resolved = Vec::new();
    let mut unmatched = Vec::new();
    let mut cases: Vec<Value> = declared
        .labels
        .iter()
        .map(|label| {
            json!({"label":label,"target":label.target,"decision":"unresolved",
            "comparison":"unresolved","missing":true,"reason":"no matching report record"})
        })
        .collect();
    for (index, label) in declared.labels.iter().enumerate() {
        let target = if let Some(target) = &label.target {
            Some(target.clone())
        } else {
            let matches: Vec<_> = records_by_rule
                .get(label.rule.as_str())
                .into_iter()
                .flatten()
                .copied()
                .filter(|r| {
                    r.pointer("/rule/id").and_then(Value::as_str) == Some(label.rule.as_str())
                })
                .filter(|r| {
                    if let Some(packet) = &label.packet {
                        r.pointer("/target/metadata/packet").and_then(Value::as_str)
                            == Some(packet.as_str())
                            || (r
                                .pointer("/target/kind")
                                .and_then(Value::as_str)
                                .is_some_and(|k| k.contains("bundle+json"))
                                && r.pointer("/target/id").and_then(Value::as_str)
                                    == Some(packet.as_str()))
                    } else {
                        let input = r
                            .pointer("/target/metadata/input")
                            .and_then(Value::as_str)
                            .or_else(|| {
                                parsed
                                    .pointer("/source/metadata/name")
                                    .and_then(Value::as_str)
                            });
                        input == label.input.as_deref()
                            && r.pointer("/target/metadata/location/line")
                                .and_then(Value::as_u64)
                                == label.line
                    }
                })
                .collect();
            if matches.len() > 1 {
                return Err(ScanError::invalid(format!(
                    "label selector is ambiguous for {}; use an exact target ID",
                    label.rule
                )));
            }
            matches
                .first()
                .and_then(|r| r.pointer("/target/id").and_then(Value::as_str))
                .map(String::from)
        };
        if let Some(target) = target {
            let case = cases
                .get_mut(index)
                .ok_or_else(|| ScanError::unresolved("label has no case binding"))?;
            json::object_mut(case)
                .map_err(ScanError::unresolved)?
                .insert("target".into(), json!(target));
            resolved.push((index, label.rule.clone(), target, label.violation));
        } else {
            unmatched.push(label);
        }
    }
    let mut expected = BTreeMap::new();
    for (index, rule, target, violation) in &resolved {
        if expected
            .insert((rule.as_str(), target.as_str()), (*index, *violation))
            .is_some()
        {
            return Err(ScanError::invalid(format!(
                "duplicate label for {} on {}",
                rule, target
            )));
        }
    }
    let (mut overall, mut rules, mut models, mut policies) = (
        Tally::default(),
        BTreeMap::<String, Tally>::new(),
        BTreeMap::<String, Tally>::new(),
        BTreeMap::<&str, Tally>::new(),
    );
    let (mut unlabelled, mut seen) = (Vec::new(), BTreeMap::new());
    for record in records {
        let (Some(rule), Some(target)) = (
            record.pointer("/rule/id").and_then(Value::as_str),
            record.pointer("/target/id").and_then(Value::as_str),
        ) else {
            return Err(ScanError::invalid(
                "report record lacks a rule or target identity",
            ));
        };
        if seen.insert((rule, target), ()).is_some() {
            return Err(ScanError::invalid(format!(
                "duplicate report record for {rule} on {target}"
            )));
        }
        let Some(&(index, violation)) = expected.get(&(rule, target)) else {
            unlabelled.push(1);
            continue;
        };
        let observation = &record["observation"];
        let decided = match record["result"].as_str() {
            Some("pass") => Decision::Pass,
            Some("fail") => Decision::Fail,
            Some("not_evaluated" | "review") => decision(&observation["suggested_result"]),
            _ => Decision::Unresolved,
        };
        let case = cases
            .get_mut(index)
            .ok_or_else(|| ScanError::unresolved("record has no labelled case binding"))?;
        let case = json::object_mut(case).map_err(ScanError::unresolved)?;
        case.insert("missing".into(), json!(false));
        case.insert("decision".into(), json!(decided));
        case.insert("comparison".into(), json!(comparison(violation, decided)));
        case.insert(
            "terminal_result".into(),
            record
                .get("result")
                .ok_or_else(|| ScanError::invalid("report record has no terminal result"))?
                .clone(),
        );
        case.insert("reason".into(), json!(record.get("reason")));
        case.insert(
            "evidence_sha256".into(),
            json!(record.pointer("/evidence/sha256")),
        );
        for field in [
            "suggested_result",
            "probability",
            "choice",
            "confidence",
            "request_sha256",
            "mock",
            "replay",
            "reuse",
        ] {
            case.insert(field.into(), json!(observation.get(field)));
        }
        overall.add(violation, decided);
        rules
            .entry(rule.into())
            .or_default()
            .add(violation, decided);
        if observation["type"] == "combined-models/1" {
            case.insert("members".into(), Value::Array(
                observation["members"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .map(|member| {
                        json!({"evaluator":member["evaluator"],"mock":member["mock"],
                        "replay":member["replay"],"reuse":member["reuse"],"request_sha256":member["request_sha256"],
                        "suggested_result":member["suggested_result"]})
                    })
                    .collect(),
            ));
            let members: Vec<Decision> = observation["members"]
                .as_array()
                .map(|m| m.iter().map(|o| decision(&o["suggested_result"])).collect())
                .unwrap_or_default();
            for member in observation["members"].as_array().into_iter().flatten() {
                if let Some(name) = member_name(member) {
                    models
                        .entry(name)
                        .or_default()
                        .add(violation, decision(&member["suggested_result"]));
                }
            }
            let every_model_answered =
                observation["role_models"].as_u64() == Some(members.len() as u64);
            if every_model_answered && members.len() > 1 {
                for name in POLICIES {
                    policies
                        .entry(name)
                        .or_default()
                        .add(violation, policy(name, &members)?);
                }
            }
        } else if let Some(name) = member_name(observation) {
            models.entry(name).or_default().add(violation, decided);
        }
    }
    let mut missing: Vec<_> = expected
        .keys()
        .filter(|key| !seen.contains_key(*key))
        .map(|(rule, target)| json!({"rule":rule,"target":target}))
        .collect();
    let labelled_records = overall.count(|_, _| true)?;
    for label in &unmatched {
        overall.add(label.violation, Decision::Unresolved);
        rules
            .entry(label.rule.clone())
            .or_default()
            .add(label.violation, Decision::Unresolved);
        missing.push(serde_json::to_value(label).map_err(|e| ScanError::invalid(e.to_string()))?);
    }
    for (&(rule, target), &(_, violation)) in &expected {
        if !seen.contains_key(&(rule, target)) {
            overall.add(violation, Decision::Unresolved);
            rules
                .entry(rule.into())
                .or_default()
                .add(violation, Decision::Unresolved);
        }
    }
    let map = |tallies: BTreeMap<String, Tally>| {
        tallies
            .into_iter()
            .map(|(name, tally)| tally.summary().map(|summary| (name, summary)))
            .collect::<Result<BTreeMap<_, _>, ScanError>>()
    };
    let policies = policies
        .into_iter()
        .map(|(name, tally)| tally.summary().map(|summary| (name, summary)))
        .collect::<Result<BTreeMap<_, _>, ScanError>>()?;
    let unlabelled = crate::scan::reduce(unlabelled)?;
    Ok(
        json!({"schema":"auditoad-score/1","report_sha256":sha256(report),
        "scan_id":parsed.get("scan_id"),"baseline":parsed.get("baseline"),"profile":parsed.get("profile"),
        "source":{"binding":parsed.pointer("/source/binding"),"input_sha256":parsed.pointer("/source/input_sha256"),"snapshot_id":parsed.pointer("/source/snapshot_id")},
        "usage":parsed.get("usage"),"model_usage":parsed.get("model_usage"),"cases":cases,
        "labels_sha256":sha256(labels),"dataset":declared.dataset,"labelled_records":labelled_records,
        "labels_expected":declared.labels.len(),"label_coverage_complete":missing.is_empty(),
        "unlabelled_records":unlabelled,"labels_without_records":missing,
        "overall":overall.summary()?,"rules":map(rules)?,"models":map(models)?,
        "policies":policies,
        "scope":"Overall and rule totals include every supplied label; missing records count as unresolved. Model rows cover recorded model observations only. A policy row is simulated from combined runs in which every model answered; it is not a separate run. Complete label coverage does not establish coverage of an entire audit subject."}),
    )
}

/// Compare labelled decisions on identical source bytes. Derived evidence may legitimately
/// change with the questions or fresh child identities; its recorded hashes remain visible.
pub fn compare_scores(
    reference: &[u8],
    candidate: &[u8],
    labels: &[u8],
) -> Result<Value, ScanError> {
    let mut reference = score(reference, labels)?;
    let mut candidate = score(candidate, labels)?;
    let source = reference
        .get("source")
        .ok_or_else(|| ScanError::invalid("reference score has no source identity"))?;
    let binding = source.get("binding").and_then(Value::as_str);
    if binding.is_none_or(str::is_empty)
        || source
            .get("input_sha256")
            .and_then(recorded_digest)
            .is_none()
        || source
            .get("snapshot_id")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
        || Some(source) != candidate.get("source")
    {
        return Err(ScanError::invalid(
            "paired scores require the same source binding, snapshot identity and full input SHA-256",
        ));
    }
    let before = json::object_mut(&mut reference)
        .map_err(ScanError::unresolved)?
        .remove("cases")
        .ok_or_else(|| ScanError::unresolved("reference score has no cases"))?;
    let after = json::object_mut(&mut candidate)
        .map_err(ScanError::unresolved)?
        .remove("cases")
        .ok_or_else(|| ScanError::unresolved("candidate score has no cases"))?;
    let same_recorded_hash = |a: &Value, b: &Value, key: &str| {
        a.get(key)
            .and_then(recorded_digest)
            .zip(b.get(key).and_then(recorded_digest))
            .map(|(a, b)| a == b)
    };
    let before = before
        .as_array()
        .ok_or_else(|| ScanError::unresolved("reference cases are not an array"))?;
    let after = after
        .as_array()
        .ok_or_else(|| ScanError::unresolved("candidate cases are not an array"))?;
    if before.len() != after.len() {
        return Err(ScanError::unresolved("paired score case coverage differs"));
    }
    let cases: Vec<_> = before
        .iter()
        .zip(after)
        .map(|(a, b)| {
            json!({"label":a["label"],"reference":a,"candidate":b,
            "decision_changed":a["decision"] != b["decision"],
            "record_presence_changed":a["missing"] != b["missing"],
            "same_recorded_request":same_recorded_hash(a,b,"request_sha256"),
            "same_recorded_evidence":same_recorded_hash(a,b,"evidence_sha256")})
        })
        .collect();
    Ok(
        json!({"schema":"auditoad-comparison/1","labels_sha256":sha256(labels),
        "label_coverage_complete":reference.get("label_coverage_complete") == Some(&Value::Bool(true)) && candidate.get("label_coverage_complete") == Some(&Value::Bool(true)),
        "reference":reference,"candidate":candidate,"cases":cases,
        "scope":"Paired retained decisions on the same source snapshot and label selectors. Baseline/evaluator changes and recorded identities remain visible; matching input does not establish equivalent questions, complete subject coverage, independent labels or fresh inference. Null identity comparisons mean no valid comparable hashes were recorded."}),
    )
}
