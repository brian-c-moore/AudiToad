//! Finite scan coordination using published Automation Structures.
use crate::{
    ScanError, ValidatedBaseline,
    baseline::selected_indices,
    evaluator::{self, MockModel, ProviderRequest},
    evaluators::{Combine, Evaluators},
    schema::*,
    source::{
        Snapshot, digest_fields, fixture_path, read_target, same_path, sha256, unlinked_path,
    },
};
use automation_structures::{
    ActuationPass, AuditSink, Budget, FederatedBudget, Reduction, ResourceRegistry, Sequential,
};
use serde::Serialize;
use serde_json::json;
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Write,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

/// One finite scan; the source alias resolves within the selected baseline.
pub struct ScanRequest<'a> {
    pub baseline: &'a ValidatedBaseline,
    pub profile: &'a str,
    pub source_alias: &'a str,
    pub snapshot: &'a Snapshot,
    pub limits: Limits,
    pub experimental: bool,
    pub mock: Option<&'a MockModel>,
}

pub struct ScanResult {
    pub report: Report,
    pub exit_code: u8,
}
pub struct PublishedScan {
    pub scan: ScanResult,
    pub receipt: PublicationReceipt,
}

/// Finite work known before any provider call. Conditional roles can use fewer calls.
#[derive(Debug, Serialize)]
pub struct Preparation {
    pub targets: usize,
    pub checks: usize,
    pub provider_calls_at_most: u64,
    pub models: BTreeMap<String, u64>,
    pub limits: Limits,
    pub evidence_sizes_depend_on_answers: bool,
}

#[derive(Serialize)]
struct Work {
    rule: usize,
    target: usize,
    check_id: String,
    applicable: bool,
}

// Test mutations omit owner calls to exercise the runtime correspondence checks.
// These variants are absent from release builds.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Fault {
    None,
    #[cfg(test)]
    Registry,
    #[cfg(test)]
    Budget,
    #[cfg(test)]
    Sequential,
    #[cfg(test)]
    Audit,
    #[cfg(test)]
    Reduction,
    #[cfg(test)]
    Effect,
}

fn charge(owner: &mut Budget, _fault: Fault) -> bool {
    #[cfg(test)]
    if _fault == Fault::Budget {
        return true;
    }
    owner.try_allocate(1)
}

fn begin(owner: &mut Sequential, _fault: Fault) -> bool {
    #[cfg(test)]
    if _fault == Fault::Sequential {
        return true;
    }
    owner.begin_step()
}

fn append(owner: &mut AuditSink, ordinal: u64, _fault: Fault) -> bool {
    #[cfg(test)]
    if _fault == Fault::Audit {
        return true;
    }
    owner.try_record(ordinal)
}

fn effect_allocation(owner: &mut ActuationPass, _fault: Fault) -> Result<(), ScanError> {
    #[cfg(test)]
    if _fault == Fault::Effect {
        return Ok(());
    }
    owner
        .allocate(0, 0)
        .map_err(|e| ScanError::unresolved(e.to_string()))
}

fn coupling(accepted: bool, message: &str) -> Result<(), ScanError> {
    if accepted {
        Ok(())
    } else {
        Err(ScanError::unresolved(message))
    }
}

fn register(ids: &[&str]) -> Result<ResourceRegistry, ScanError> {
    let mut seen = BTreeSet::new();
    for id in ids {
        coupling(
            seen.insert(*id),
            "duplicate full identity before ordinal registration",
        )?;
    }
    let mut registry = ResourceRegistry::new();
    for (index, _) in ids.iter().enumerate() {
        let ordinal =
            u64::try_from(index).map_err(|_| ScanError::unresolved("ordinal overflow"))?;
        coupling(
            registry.insert(ordinal, ordinal).is_none(),
            "registry replaced a live ordinal",
        )?;
        coupling(
            registry.get(ordinal) == Some(ordinal),
            "registry lookup disagrees with immutable identity table",
        )?;
    }
    Ok(registry)
}

pub(crate) fn reduce(values: Vec<u64>) -> Result<u64, ScanError> {
    reduce_bound(values, Fault::None)
}

fn reduce_bound(values: Vec<u64>, _fault: Fault) -> Result<u64, ScanError> {
    let mut owner = Reduction::new(values).map_err(|e| ScanError::unresolved(e.to_string()))?;
    #[cfg(test)]
    if _fault == Fault::Reduction {
        return Ok(owner.result());
    }
    while !owner.is_complete() {
        owner
            .process_next()
            .map_err(|e| ScanError::unresolved(e.to_string()))?;
    }
    Ok(owner.result())
}

fn reused_usage(
    reused: &[String],
    model_budgets: BTreeMap<String, (usize, Budget, Budget)>,
    calls: &FederatedBudget,
    bytes: &FederatedBudget,
    fault: Fault,
) -> Result<(u64, BTreeMap<String, Usage>), ScanError> {
    let total = reduce_bound(reused.iter().map(|_| 1).collect(), fault)?;
    let models: BTreeMap<String, Usage> = model_budgets
        .into_iter()
        .map(|(name, (pool, call_permission, byte_permission))| {
            coupling(
                calls.pool_capacity(pool) == Some(call_permission.allocated())
                    && bytes.pool_capacity(pool) == Some(byte_permission.allocated())
                    && calls.pool_capacity(pool) == calls.pool_allocated(pool)
                    && bytes.pool_capacity(pool) == bytes.pool_allocated(pool),
                "model delegation permission correspondence failed",
            )?;
            let count = reduce(
                reused
                    .iter()
                    .map(|member| u64::from(member == &name))
                    .collect(),
            )?;
            Ok((
                name,
                Usage {
                    checks: 0,
                    provider_calls: calls
                        .pool_allocated(pool)
                        .ok_or_else(|| ScanError::unresolved("model call pool absent"))?,
                    evidence_bytes: bytes
                        .pool_allocated(pool)
                        .ok_or_else(|| ScanError::unresolved("model byte pool absent"))?,
                    reused_exchanges: count,
                },
            ))
        })
        .collect::<Result<_, ScanError>>()?;
    coupling(
        reduce(
            models
                .values()
                .map(|usage| usage.reused_exchanges)
                .collect(),
        )? == total,
        "reuse reductions disagree with declared model coverage",
    )?;
    Ok((total, models))
}

// Bind the existing delegation composition to an independent model permission ceiling.
// No balance, capacity predicate or aggregate is implemented here. Pool 0 has no model ceiling.
fn admit_pool(
    owner: &mut FederatedBudget,
    pool: usize,
    amount: u64,
    mut permission: Option<&mut Budget>,
) -> Result<bool, ScanError> {
    coupling(
        owner.pool_capacity(pool) == owner.pool_allocated(pool)
            && owner.pool_capacity(pool).is_some()
            && permission
                .as_ref()
                .is_none_or(|ceiling| owner.pool_capacity(pool) == Some(ceiling.allocated())),
        "federation delegation correspondence failed",
    )?;
    if amount == 0 {
        return Ok(true);
    }
    if permission
        .as_mut()
        .is_some_and(|ceiling| !ceiling.try_allocate(amount))
    {
        return Ok(false);
    }
    if !owner.try_delegate(pool, amount) {
        if let Some(ceiling) = permission {
            ceiling
                .release(amount)
                .map_err(|e| ScanError::unresolved(e.to_string()))?;
        }
        return Ok(false);
    }
    coupling(
        owner.try_allocate(pool, amount)
            && owner.pool_capacity(pool) == owner.pool_allocated(pool)
            && permission
                .as_ref()
                .is_none_or(|ceiling| owner.pool_capacity(pool) == Some(ceiling.allocated())),
        "federation consumption correspondence failed",
    )?;
    Ok(true)
}

pub(crate) fn applies(rule: &Rule, key: &str) -> bool {
    let matched = |patterns: &[String]| patterns.iter().any(|p| p == "*" || p == key);
    matched(&rule.applicability.include) && !matched(&rule.applicability.exclude)
}

fn answers_evidence(
    baseline: &ValidatedBaseline,
    work: &Work,
    manifest: &[Work],
    records: &[Record],
    snapshot: &Snapshot,
) -> Result<Vec<u8>, String> {
    let answers = prerequisite_answers(baseline, work, manifest, records, snapshot, false)?;
    serde_json::to_vec(&json!({"schema":"answers/1","answers":answers})).map_err(|e| e.to_string())
}

/// Adds the committed answers of consulted rules to an evaluated rule's JSON frame.
fn consulted_evidence(
    frame: Vec<u8>,
    baseline: &ValidatedBaseline,
    work: &Work,
    manifest: &[Work],
    records: &[Record],
    snapshot: &Snapshot,
) -> Result<Vec<u8>, String> {
    let mut value: serde_json::Value = crate::json::parse(&frame)?;
    let object = value
        .as_object_mut()
        .ok_or("consulted evidence requires a JSON object frame")?;
    if object.contains_key("prior") {
        return Err("evidence frame already has a prior field".into());
    }
    let prior = prerequisite_answers(baseline, work, manifest, records, snapshot, true)?;
    object.insert("prior".into(), json!(prior));
    serde_json::to_vec(&value).map_err(|e| e.to_string())
}

/// Resolves a gated rule from its consulted answers without evaluating it.
fn consult_gate(rule: &Rule, bytes: &[u8]) -> Result<Option<Observation>, ScanError> {
    let Some(gate) = rule
        .consult
        .as_ref()
        .map(|consult| consult.run_when)
        .filter(|gate| *gate != ConsultGate::Always)
    else {
        return Ok(None);
    };
    let frame: serde_json::Value = crate::json::parse(bytes).map_err(ScanError::unresolved)?;
    let prior = frame
        .get("prior")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| ScanError::unresolved("missing consulted answers"))?;
    let failed = reduce(
        prior
            .iter()
            .map(|a| u64::from(a["decision"] == "fail"))
            .collect(),
    )?;
    let passed = reduce(
        prior
            .iter()
            .map(|a| u64::from(a["decision"] == "pass"))
            .collect(),
    )?;
    let unresolved = reduce(
        prior
            .iter()
            .map(|a| u64::from(a["decision"] != "pass" && a["decision"] != "fail"))
            .collect(),
    )?;
    coupling(
        reduce(vec![passed, failed, unresolved])? == prior.len() as u64,
        "consult reduction coverage disagrees",
    )?;
    let open = match gate {
        ConsultGate::Always => true,
        ConsultGate::AnyFail => failed != 0,
        ConsultGate::AnyPass => passed != 0,
        ConsultGate::AnyUnresolved => unresolved != 0,
        ConsultGate::AllResolved => unresolved == 0,
    };
    if open {
        return Ok(None);
    }
    let mut observation = json!({"type":"consult/1","run_when":gate,"evaluated":false,
        "passed":passed,"failed":failed,"unresolved":unresolved});
    if gate != ConsultGate::AnyFail {
        return Ok(Some((
            ResultState::NotEvaluated,
            Some(observation),
            Some("the consult condition was not met; the question was not asked".into()),
        )));
    }
    let suggested = if unresolved == 0 && passed != 0 {
        ResultState::Pass
    } else {
        ResultState::Review
    };
    crate::json::object_mut(&mut observation)
        .map_err(ScanError::unresolved)?
        .insert("suggested_result".into(), json!(suggested));
    let semantic = matches!(
        rule.check,
        Check::YesNo { .. }
            | Check::Choice { .. }
            | Check::Extract { .. }
            | Check::Box { .. }
            | Check::MockModel { .. }
    );
    Ok(Some(if suggested == ResultState::Pass && !semantic {
        (ResultState::Pass, Some(observation), None)
    } else if suggested == ResultState::Pass {
        (
            ResultState::NotEvaluated,
            Some(observation),
            Some("no consulted rule reported a candidate; the question was not asked".into()),
        )
    } else {
        (
            ResultState::NotEvaluated,
            Some(observation),
            Some("consulted answers are unresolved; the question was not asked".into()),
        )
    }))
}

fn prerequisite_answers(
    baseline: &ValidatedBaseline,
    work: &Work,
    manifest: &[Work],
    records: &[Record],
    snapshot: &Snapshot,
    observations: bool,
) -> Result<Vec<serde_json::Value>, String> {
    let mut answers = Vec::new();
    let parent = &snapshot
        .targets
        .get(work.target)
        .ok_or("prerequisite subject target is not bound")?
        .identity
        .metadata;
    let rule = baseline
        .content
        .rules
        .get(work.rule)
        .ok_or("prerequisite dependent rule is not bound")?;
    let declared = if observations {
        &rule
            .consult
            .as_ref()
            .ok_or("consult prerequisites are absent")?
            .rules
    } else if let Check::Answers { rules, .. } = &rule.check {
        rules
    } else {
        return Err("answer prerequisites require an answers check".into());
    };
    // The shared graph admits every prerequisite edge; each frame selects its declared
    // role and order. A consultation gate must not become a combination operand.
    for id in declared {
        let dependency = baseline
            .content
            .rules
            .iter()
            .position(|candidate| candidate.id == *id)
            .ok_or("declared prerequisite rule is absent")?;
        if !baseline.dependencies.contains(dependency, work.rule) {
            return Err("declared prerequisite has no admitted graph edge".into());
        }
        let mut required = Vec::new();
        for (ordinal, candidate) in manifest.iter().enumerate() {
            if candidate.rule != dependency {
                continue;
            }
            let metadata = &snapshot
                .targets
                .get(candidate.target)
                .ok_or("prerequisite candidate target is not bound")?
                .identity
                .metadata;
            let matches = if rule.scope.is_none() {
                candidate.target == work.target
            } else {
                (parent.get("packet").is_none() || metadata.get("packet") == parent.get("packet"))
                    && (parent
                        .pointer("/scope/unit")
                        .and_then(serde_json::Value::as_str)
                        == Some("document")
                        || (metadata.get("ordinal") == parent.get("ordinal")
                            && metadata.get("input") == parent.get("input")))
            };
            if matches {
                required.push((ordinal, candidate));
            }
        }
        if required.is_empty() {
            return Err("dependency has no work in the complete scope".into());
        }
        for (ordinal, required) in required {
            let record = records
                .get(ordinal)
                .filter(|r| r.check_id == required.check_id)
                .ok_or("dependency has no matching committed answer")?;
            let decision = match record.result {
                ResultState::Pass | ResultState::Fail => Some(record.result),
                ResultState::NotEvaluated
                    if matches!(
                        record.evaluator.binding.as_str(),
                        "model" | "mock-model" | "answers"
                    ) || record
                        .observation
                        .as_ref()
                        .is_some_and(|o| o["experimental_inputs"] == true) =>
                {
                    record
                        .observation
                        .as_ref()
                        .and_then(|o| o.get("suggested_result"))
                        .and_then(|v| serde_json::from_value::<ResultState>(v.clone()).ok())
                        .filter(|s| matches!(s, ResultState::Pass | ResultState::Fail))
                }
                _ => None,
            };
            let mut answer = json!({"check_id":record.check_id,"rule":record.rule,"target":record.target.id,
                "terminal_result":record.result,"decision":decision,
                "evidence_sha256":record.evidence.as_ref().map(|e| &e.sha256)});
            if matches!(
                record.evaluator.binding.as_str(),
                "model" | "mock-model" | "answers"
            ) || record
                .observation
                .as_ref()
                .is_some_and(|o| o["experimental_inputs"] == true)
            {
                crate::json::object_mut(&mut answer)?.insert("experimental".into(), json!(true));
            }
            if observations {
                // Consulted evidence must hash identically across scans: omit the per-scan check
                // ID and timing. Provider exchanges stay on the consulted record, named by hash.
                if let Some(fields) = answer.as_object_mut() {
                    fields.remove("check_id");
                }
                let mut observation = record.observation.clone().unwrap_or(json!(null));
                consultation_content(&mut observation);
                crate::json::object_mut(&mut answer)?.insert("observation".into(), observation);
            }
            answers.push(answer);
        }
    }
    Ok(answers)
}

/// Qualification of supplied prerequisite content, reduced from already committed evidence.
/// A helper's transport success or a deterministic consumer cannot admit that derivation.
fn experimental_inputs(bytes: &[u8]) -> Result<bool, ScanError> {
    let frame: serde_json::Value = crate::json::parse(bytes).map_err(ScanError::unresolved)?;
    let prior = frame
        .get("prior")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| ScanError::unresolved("missing consulted qualification evidence"))?;
    Ok(reduce(
        prior
            .iter()
            .map(|answer| u64::from(answer["experimental"] == true))
            .collect(),
    )? != 0)
}

fn consultation_content(observation: &mut serde_json::Value) {
    if let Some(members) = observation
        .get_mut("members")
        .and_then(serde_json::Value::as_array_mut)
    {
        for member in members {
            consultation_content(member);
        }
    }
    if let Some(fields) = observation.as_object_mut() {
        for exchange in [
            "question_id",
            "request_bytes",
            "response_bytes",
            "request_sha256",
            "response_sha256",
            "provider_elapsed_ms",
            "replay",
            "reuse",
        ] {
            fields.remove(exchange);
        }
    }
}

fn combined_observation(
    bytes: &[u8],
    combination: AnswerCombination,
    resolution: AnswerResolution,
) -> Result<Observation, ScanError> {
    let frame: serde_json::Value = crate::json::parse(bytes).map_err(ScanError::unresolved)?;
    let answers = frame
        .get("answers")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| ScanError::unresolved("missing answer records"))?;
    let passed = reduce(
        answers
            .iter()
            .map(|a| u64::from(a["decision"] == "pass"))
            .collect(),
    )?;
    let failed = reduce(
        answers
            .iter()
            .map(|a| u64::from(a["decision"] == "fail"))
            .collect(),
    )?;
    let unresolved = reduce(
        answers
            .iter()
            .map(|a| u64::from(a["decision"] != "pass" && a["decision"] != "fail"))
            .collect(),
    )?;
    coupling(
        reduce(vec![passed, failed, unresolved])? == answers.len() as u64,
        "answer reduction coverage disagrees",
    )?;
    let decisive = resolution == AnswerResolution::Decisive
        && match combination {
            AnswerCombination::AnyFail => failed != 0,
            AnswerCombination::AllFail => passed != 0,
            AnswerCombination::FirstResolved => false,
        };
    let first = answers
        .iter()
        .map(|a| &a["decision"])
        .find(|d| *d == "pass" || *d == "fail");
    let suggested = if combination == AnswerCombination::FirstResolved {
        match first {
            Some(d) if d == "fail" => ResultState::Fail,
            Some(_) => ResultState::Pass,
            None => ResultState::Review,
        }
    } else if answers.is_empty() || unresolved != 0 && !decisive {
        ResultState::Review
    } else if match combination {
        AnswerCombination::AnyFail => failed != 0,
        AnswerCombination::AllFail => passed == 0,
        AnswerCombination::FirstResolved => {
            return Err(ScanError::unresolved(
                "first-resolved combination reached a count-based branch",
            ));
        }
    } {
        ResultState::Fail
    } else {
        ResultState::Pass
    };
    Ok((ResultState::NotEvaluated,
        Some(json!({"type":"answers/1","fail_when":combination,"resolution":resolution,"suggested_result":suggested,
            "passed":passed,"failed":failed,"unresolved":unresolved})),
        Some("experimental combination of all declared dependency answers; not an admitted audit decision".into())))
}

/// Run a snapshot in memory. Use `scan_to_file` when a publication receipt is required.
pub fn scan(request: ScanRequest<'_>) -> Result<ScanResult, ScanError> {
    scan_bound(request, Fault::None, None, None, None)
}

fn scan_bound(
    mut request: ScanRequest<'_>,
    _fault: Fault,
    evaluators: Option<&Evaluators>,
    mut progress: Option<&mut dyn FnMut(&Record)>,
    preparation: Option<&mut dyn FnMut(&Preparation)>,
) -> Result<ScanResult, ScanError> {
    let scan_id = uuid::Uuid::new_v4().to_string();
    let baseline = request.baseline;
    let content = &baseline.content;
    if content.baseline.status == Admission::Retired
        || (content.baseline.status != Admission::Admitted && !request.experimental)
    {
        return Err(ScanError::invalid(
            "draft baselines require --experimental; retired baselines cannot scan",
        ));
    }
    let profile = content
        .profiles
        .iter()
        .find(|p| p.id == request.profile)
        .ok_or_else(|| ScanError::invalid("unknown profile"))?;
    let source = content
        .sources
        .get(request.source_alias)
        .ok_or_else(|| ScanError::invalid("unknown baseline source alias"))?;
    if evaluators.is_some_and(|e| e.live) && request.mock.is_some() {
        return Err(ScanError::invalid(
            "a mock provider cannot be combined with live evaluation",
        ));
    }
    if let Some(replay) = evaluators.and_then(|e| e.replay.as_ref()) {
        if request.mock.is_some() || evaluators.is_some_and(|e| e.live) {
            return Err(ScanError::invalid(
                "replay cannot combine with a mock or live evaluation",
            ));
        }
        replay.validate_source(&request.snapshot.identity)?;
    }
    if evaluators.is_some_and(|e| e.reuse.is_some()) && request.mock.is_some() {
        return Err(ScanError::invalid(
            "reuse cannot combine with a mock provider",
        ));
    }
    if source.adapter != request.snapshot.identity.binding {
        return Err(ScanError::invalid(
            "snapshot adapter disagrees with baseline source",
        ));
    }
    let selected = selected_indices(content, profile, &baseline.dependencies)?;
    let selected_rules = selected
        .iter()
        .map(|index| {
            content
                .rules
                .get(*index)
                .ok_or_else(|| ScanError::invalid("selected scan rule is not bound"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if (crate::scoped::media(&source.adapter).is_some()
        || selected_rules.iter().any(|rule| rule.scope.is_some()))
        && (request
            .snapshot
            .identity
            .metadata
            .get("baseline_sha256")
            .and_then(serde_json::Value::as_str)
            != Some(baseline.identity.sha256.as_str())
            || request
                .snapshot
                .identity
                .metadata
                .get("profile")
                .and_then(serde_json::Value::as_str)
                != Some(profile.id.as_str()))
    {
        return Err(ScanError::invalid(
            "scope plan belongs to a different baseline/profile",
        ));
    }
    for rule in &selected_rules {
        if rule.source != request.source_alias {
            return Err(ScanError::invalid(format!(
                "selected rule {} belongs to another source: {}",
                rule.id, rule.source
            )));
        }
        if matches!(rule.check, Check::MockModel { .. }) && !request.experimental {
            return Err(ScanError::invalid("mock requires --experimental"));
        }
        if let Some(evaluators) = evaluators
            && matches!(
                rule.check,
                Check::YesNo { .. }
                    | Check::Choice { .. }
                    | Check::Extract { .. }
                    | Check::Box { .. }
            )
        {
            let strategy = evaluators
                .strategy(evaluator::model_role(rule))
                .map_err(ScanError::invalid)?;
            if let Some(reason) = strategy.unsupported(&rule.check) {
                return Err(ScanError::invalid(format!(
                    "rule {}: the {} role cannot answer {}: {reason}",
                    rule.id, strategy.role, rule.evaluator.contract
                )));
            }
            for member in &strategy.members {
                let origin =
                    crate::evaluators::origin(&member.endpoint).map_err(ScanError::invalid)?;
                let allowed = profile.allowed_egress.contains(&origin)
                    || crate::evaluators::is_loopback(&origin)
                        && profile
                            .allowed_egress
                            .iter()
                            .any(|entry| entry == crate::evaluators::LOOPBACK);
                if evaluators.live && !allowed {
                    return Err(ScanError::invalid(format!(
                        "profile {} allowed_egress does not permit {origin} for rule {}",
                        profile.id, rule.id
                    )));
                }
            }
        }
    }
    if !Budget::new(request.limits.targets as u64)
        .try_allocate(request.snapshot.targets.len() as u64)
    {
        return Err(ScanError::unresolved(
            "complete manifest exceeds target/work ceiling; no tail was silently dropped",
        ));
    }
    let fixture_usage = baseline.verify_fixtures(&selected, &request.limits)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| ScanError::unresolved(e.to_string()))?;
    let run_at =
        u64::try_from(now.as_millis()).map_err(|_| ScanError::unresolved("timestamp overflow"))?;
    let target_registry = register(
        &request
            .snapshot
            .targets
            .iter()
            .map(|t| t.identity.id.as_str())
            .collect::<Vec<_>>(),
    )?;
    let mut manifest = Vec::new();
    let mut manifest_budget = Budget::new(request.limits.manifest_work as u64);
    for &rule_index in &selected {
        let rule = content
            .rules
            .get(rule_index)
            .ok_or_else(|| ScanError::unresolved("manifest rule is not bound"))?;
        let evidence = content
            .evidence
            .get(&rule.evidence)
            .ok_or_else(|| ScanError::invalid("manifest evidence declaration is not bound"))?;
        let evaluator = evaluator::identity(rule, evaluators);
        for (target_index, target) in request.snapshot.targets.iter().enumerate() {
            if !crate::scoped::matches_scope(rule, target) {
                continue;
            }
            if !manifest_budget.try_allocate(1) {
                return Err(ScanError::unresolved(
                    "complete manifest exceeds target/work ceiling; no tail was silently dropped",
                ));
            }
            let check_id = digest_fields(&[
                &scan_id,
                &baseline.identity.sha256,
                &profile.id,
                &rule.id,
                &rule.revision,
                &request.snapshot.identity.binding,
                &request.snapshot.identity.snapshot_id,
                &target.identity.id,
                &evidence.builder,
                &evidence.builder_revision,
                &evaluator.binding,
                &evaluator.version,
            ]);
            manifest.push(Work {
                rule: rule_index,
                target: target_index,
                check_id,
                applicable: (source.media.contains(&target.identity.kind)
                    || source.adapter == "evidence-bundle/1"
                        && matches!(
                            target.identity.kind.as_str(),
                            "application/vnd.auditoad.bundle+json"
                                | "application/vnd.checkwarden.bundle+json"
                        ))
                    && applies(rule, &target.applicability_key),
            });
        }
    }
    let work_len = manifest.len();
    coupling(
        manifest_budget.allocated() == work_len as u64,
        "work manifest budget correspondence failed",
    )?;
    let mut model_counts: BTreeMap<String, Vec<u64>> = BTreeMap::new();
    let mut call_counts = Vec::new();
    for work in &manifest {
        let rule = content
            .rules
            .get(work.rule)
            .ok_or_else(|| ScanError::unresolved("manifest call rule is not bound"))?;
        let count = if !work.applicable {
            0
        } else if matches!(
            rule.check,
            Check::YesNo { .. } | Check::Choice { .. } | Check::Extract { .. } | Check::Box { .. }
        ) {
            if let Some(evaluators) = evaluators {
                let strategy = evaluators
                    .strategy(evaluator::model_role(rule))
                    .map_err(ScanError::invalid)?;
                for member in &strategy.members {
                    model_counts.entry(member.name.clone()).or_default().push(1);
                }
                strategy.members.len() as u64
            } else {
                1
            }
        } else {
            u64::from(matches!(rule.check, Check::MockModel { .. }))
        };
        call_counts.push(count);
    }
    let calls_needed = reduce(call_counts)?;
    // CLI automatic limits are resolved against this very manifest, not a second work planner.
    if request.limits.checks == u64::MAX {
        request.limits.checks = work_len as u64;
    }
    if request.limits.provider_calls == u64::MAX {
        request.limits.provider_calls = calls_needed;
    }
    if let Some(notify) = preparation {
        notify(&Preparation {
            targets: request.snapshot.targets.len(),
            checks: work_len,
            provider_calls_at_most: calls_needed,
            models: model_counts
                .into_iter()
                .map(|(name, counts)| Ok((name, reduce(counts)?)))
                .collect::<Result<_, ScanError>>()?,
            limits: request.limits.clone(),
            evidence_sizes_depend_on_answers: selected_rules
                .iter()
                .any(|rule| rule.consult.is_some() || matches!(rule.check, Check::Answers { .. })),
        });
    }
    let manifest_bytes = serde_json::to_vec(&json!({"serializer": crate::source::SERIALIZER,
        "targets": request.snapshot.targets.iter().map(|t| &t.identity).collect::<Vec<_>>(), "work": manifest}))
        .map_err(|e| ScanError::unresolved(e.to_string()))?;
    let work_registry = register(
        &manifest
            .iter()
            .map(|w| w.check_id.as_str())
            .collect::<Vec<_>>(),
    )?;
    #[cfg(test)]
    let work_registry = {
        let mut registry = work_registry;
        if _fault == Fault::Registry {
            registry.remove(0);
        }
        registry
    };
    let mut checks = Budget::new(request.limits.checks);
    let mut model_budgets = evaluators
        .map(Evaluators::budgets)
        .transpose()?
        .unwrap_or_default();
    let pools = model_budgets
        .len()
        .checked_add(1)
        .ok_or_else(|| ScanError::unresolved("federated model pool count overflows"))?;
    let mut evidence_budget = FederatedBudget::new(request.limits.evidence_bytes, pools);
    let mut calls = FederatedBudget::new(request.limits.provider_calls, pools);
    // Source files are verified once before the first check and once before the report returns.
    let changed_at_start =
        crate::source::changed_sources(&request.snapshot.targets, &request.limits)?;
    let mut sink = AuditSink::new(work_len);
    let mut records = Vec::new();
    let mut source_reference = request.snapshot.identity.clone();
    source_reference.metadata = json!({
        "metadata_reference": "#/source/metadata",
        "metadata_sha256": sha256(&serde_json::to_vec(&request.snapshot.identity.metadata)
            .map_err(|error| ScanError::unresolved(error.to_string()))?),
    });
    // Sequential cannot construct a zero-step profile. The empty manifest has no transition.
    if work_len != 0 {
        let mut steps =
            Sequential::new(work_len, 6, 0).map_err(|e| ScanError::unresolved(e.to_string()))?;
        while !steps.is_done() {
            let ordinal = steps.completed();
            let work = manifest
                .get(ordinal)
                .ok_or_else(|| ScanError::unresolved("scan step has no manifest binding"))?;
            coupling(
                work_registry.get(ordinal as u64) == Some(ordinal as u64),
                "work registration is absent",
            )?;
            coupling(
                target_registry.get(work.target as u64) == Some(work.target as u64),
                "target registration is absent",
            )?;
            coupling(begin(&mut steps, _fault), "Sequential refused begin_step")?;
            coupling(steps.is_active(), "Sequential active-step witness absent")?;
            let rule = content
                .rules
                .get(work.rule)
                .ok_or_else(|| ScanError::unresolved("admitted scan rule is not bound"))?;
            let target = request
                .snapshot
                .targets
                .get(work.target)
                .ok_or_else(|| ScanError::unresolved("admitted scan target is not bound"))?;
            let builder = content
                .evidence
                .get(&rule.evidence)
                .ok_or_else(|| ScanError::invalid("admitted evidence declaration is not bound"))?;
            let mut record = Record {
                schema: "auditoad-result/1".into(),
                scan_id: scan_id.clone(),
                check_id: work.check_id.clone(),
                baseline: baseline.identity.clone(),
                profile: profile.id.clone(),
                rule: RuleIdentity {
                    id: rule.id.clone(),
                    revision: rule.revision.clone(),
                },
                source: source_reference.clone(),
                target: target.identity.clone(),
                evidence: None,
                evaluator: evaluator::identity(rule, evaluators),
                observation: None,
                result: ResultState::NotEvaluated,
                reason: None,
                run_at_unix_ms: run_at,
            };
            let charge_before = checks.allocated();
            let evaluated = if !work.applicable {
                Ok((
                    ResultState::Notapplicable,
                    None,
                    Some("outside declared kind/applicability".into()),
                ))
            } else if !charge(&mut checks, _fault) {
                Ok((
                    ResultState::NotEvaluated,
                    None,
                    Some("cumulative check budget exhausted".into()),
                ))
            } else {
                coupling(
                    checks.allocated().checked_sub(charge_before) == Some(1),
                    "Budget admission witness absent",
                )?;
                match read_target(target, &request.limits, &changed_at_start).and_then(|bytes| {
                    (if matches!(rule.check, Check::Answers { .. }) {
                        if rule.scope.is_some() {
                            crate::scoped::evidence(&bytes)?;
                        } else if target
                            .identity
                            .metadata
                            .get("scope_kind")
                            .and_then(serde_json::Value::as_str)
                            != Some(rule.scope_kind.as_str())
                        {
                            return Err("bundle answer scope mismatch".into());
                        }
                        answers_evidence(baseline, work, &manifest, &records, request.snapshot)
                    } else if rule.scope.is_some() {
                        crate::scoped::evidence(&bytes)
                    } else if source.adapter == "evidence-bundle/1" {
                        crate::bundle::bundle_evidence(&bytes, builder, rule)
                    } else {
                        Ok(bytes)
                    })
                    .and_then(|frame| {
                        if rule.consult.is_some() {
                            consulted_evidence(
                                frame,
                                baseline,
                                work,
                                &manifest,
                                &records,
                                request.snapshot,
                            )
                        } else {
                            Ok(frame)
                        }
                    })
                }) {
                    Err(reason) => Ok((ResultState::Error, None, Some(reason))),
                    Ok(bytes) => {
                        if !admit_pool(&mut evidence_budget, 0, bytes.len() as u64, None)? {
                            Ok((ResultState::NotEvaluated, None, Some("cumulative evidence byte budget exhausted; no truncated request issued".into())))
                        } else {
                            record.evidence = Some(EvidenceIdentity {
                                builder: builder.builder.clone(),
                                revision: builder.builder_revision.clone(),
                                sha256: sha256(&bytes),
                                bytes: bytes.clone(),
                            });
                            if let Some(gated) = consult_gate(rule, &bytes)? {
                                Ok(gated)
                            } else if let Check::Answers {
                                fail_when,
                                resolution,
                                ..
                            } = &rule.check
                            {
                                combined_observation(&bytes, *fail_when, *resolution)
                            } else if let Check::MockModel {
                                instructions,
                                pass_below,
                                fail_at_or_above,
                            } = &rule.check
                            {
                                mock_observation(
                                    &request,
                                    rule,
                                    work,
                                    &scan_id,
                                    &bytes,
                                    instructions,
                                    (*pass_below, *fail_at_or_above),
                                    &mut evidence_budget,
                                    &mut calls,
                                )
                            } else if matches!(
                                rule.check,
                                Check::YesNo { .. }
                                    | Check::Choice { .. }
                                    | Check::Extract { .. }
                                    | Check::Box { .. }
                            ) {
                                model_observation(
                                    &request,
                                    evaluators,
                                    rule,
                                    work,
                                    &scan_id,
                                    &bytes,
                                    &mut evidence_budget,
                                    &mut calls,
                                    &mut model_budgets,
                                )
                            } else {
                                Ok(
                                    match evaluator::deterministic(
                                        rule,
                                        baseline.checks.get(work.rule).ok_or_else(|| {
                                            ScanError::unresolved(
                                                "admitted compiled check is not bound",
                                            )
                                        })?,
                                        &bytes,
                                    ) {
                                        Ok((state, observation)) => {
                                            if matches!(
                                                rule.check,
                                                Check::Syntax { .. }
                                                    | Check::PythonConstantString { .. }
                                            ) && !admit_pool(
                                                &mut evidence_budget,
                                                0,
                                                serde_json::to_vec(&observation)
                                                    .map_err(|e| {
                                                        ScanError::unresolved(e.to_string())
                                                    })?
                                                    .len()
                                                    as u64,
                                                None,
                                            )? {
                                                (ResultState::NotEvaluated, None, Some(
                                                    "cumulative evidence byte budget exhausted by syntax output; no partial fields supplied".into(),
                                                ))
                                            } else {
                                                (state, Some(observation), None)
                                            }
                                        }
                                        Err((state, reason)) => (state, None, Some(reason)),
                                    },
                                )
                            }
                        }
                    }
                }
            };
            let (mut state, mut observation, mut reason) = evaluated?;
            if rule.consult.is_some()
                && record
                    .evidence
                    .as_ref()
                    .map(|evidence| experimental_inputs(&evidence.bytes))
                    .transpose()?
                    .unwrap_or(false)
                && let Some(details) = observation.as_mut()
            {
                let before = serde_json::to_vec(details)
                    .map_err(|e| ScanError::unresolved(e.to_string()))?
                    .len();
                details["experimental_inputs"] = json!(true);
                if matches!(
                    state,
                    ResultState::Pass | ResultState::Fail | ResultState::Review
                ) {
                    details["suggested_result"] = json!(state);
                    state = ResultState::NotEvaluated;
                    reason = Some(
                        "experimental consulted evidence; not an admitted audit decision".into(),
                    );
                }
                if matches!(
                    rule.check,
                    Check::Syntax { .. } | Check::PythonConstantString { .. }
                ) {
                    let after = serde_json::to_vec(details)
                        .map_err(|e| ScanError::unresolved(e.to_string()))?
                        .len();
                    if !admit_pool(
                        &mut evidence_budget,
                        0,
                        after.saturating_sub(before) as u64,
                        None,
                    )? {
                        observation = None;
                        state = ResultState::NotEvaluated;
                        reason = Some("cumulative evidence byte budget exhausted by syntax qualification metadata; no partial fields supplied".into());
                    }
                }
            }
            record.result = state;
            record.observation = observation;
            record.reason = reason;
            coupling(
                records.len() == ordinal && sink.len() == ordinal,
                "terminal account/progress correspondence failed",
            )?;
            coupling(
                append(&mut sink, ordinal as u64, _fault),
                "AuditSink refused terminal commit",
            )?;
            records.push(record);
            coupling(
                sink.record(ordinal)
                    .is_some_and(|r| r.operation == ordinal as u64),
                "terminal ordinal witness mismatch",
            )?;
            coupling(
                steps.complete_step(state.ordinal()),
                "Sequential refused complete_step",
            )?;
            if let Some(callback) = progress.as_mut() {
                callback(
                    records
                        .last()
                        .ok_or_else(|| ScanError::unresolved("callback has no committed record"))?,
                );
            }
        }
        coupling(
            steps.completed() == records.len(),
            "progress does not cover committed records",
        )?;
    }
    coupling(
        sink.validate() && sink.len() == records.len() && records.len() == manifest.len(),
        "coverage/account check failed",
    )?;
    for (ordinal, record) in records.iter().enumerate() {
        coupling(
            manifest
                .get(ordinal)
                .is_some_and(|work| record.check_id == work.check_id)
                && sink
                    .record(ordinal)
                    .is_some_and(|r| r.operation == ordinal as u64),
            "record identity/order mismatch",
        )?;
    }
    let mut counts = BTreeMap::new();
    for state in ResultState::ALL {
        let values = records
            .iter()
            .map(|r| u64::from(r.result == state))
            .collect();
        let count = reduce_bound(values, _fault)?;
        counts.insert(state, count);
    }
    coupling(
        reduce(counts.values().copied().collect())? == manifest.len() as u64,
        "reductions disagree with full coverage manifest",
    )?;
    let changed_at_end =
        crate::source::changed_sources(&request.snapshot.targets, &request.limits)?;
    if let Some(path) = changed_at_end.difference(&changed_at_start).next() {
        return Err(ScanError::unresolved(format!(
            "source changed during the scan; no report was produced: {}",
            path.display()
        )));
    }
    let count = |state| {
        counts
            .get(&state)
            .copied()
            .ok_or_else(|| ScanError::unresolved("result reduction is absent"))
    };
    let inapplicable = (count(ResultState::Notapplicable)? == manifest.len() as u64).then(|| {
        "no applicable checks; supplied evidence does not match the selected audit scope"
            .to_string()
    });
    let requirements = requirement_coverage(baseline, profile, &selected, &manifest, &records)?;
    let blocked: Vec<String> = requirements
        .iter()
        .filter(|r| r.status.blocks())
        .map(|r| format!("{} {}", r.id, r.status.name()))
        .collect();
    let blocked =
        (!blocked.is_empty()).then(|| format!("required checks blocked: {}", blocked.join(", ")));
    let outcome_reason = match (inapplicable, blocked) {
        (Some(first), Some(second)) => Some(format!("{first}; {second}")),
        (first, second) => first.or(second),
    };
    let unresolved = outcome_reason.is_some()
        || request.experimental
        || count(ResultState::Error)? > 0
        || count(ResultState::NotEvaluated)? > 0;
    let outcome = if unresolved {
        Outcome::Unresolved
    } else if count(ResultState::Fail)? > 0 || count(ResultState::Review)? > 0 {
        Outcome::Finding
    } else {
        Outcome::Clear
    };
    let blocking = profile.block_on.iter().try_fold(false, |blocked, state| {
        Ok::<_, ScanError>(blocked || count(*state)? > 0)
    })?;
    let exit_code = if unresolved {
        2
    } else if blocking {
        1
    } else {
        0
    };
    // Reused answers made no new request; they are counted apart from provider calls.
    let reused: Vec<String> = records
        .iter()
        .filter_map(|r| r.observation.as_ref())
        .flat_map(|o| {
            o["members"]
                .as_array()
                .map_or_else(|| vec![o], |m| m.iter().collect())
        })
        .filter(|m| m.get("reuse").is_some())
        .map(|m| {
            m.pointer("/evaluator/name")
                .and_then(serde_json::Value::as_str)
                .map(String::from)
                .ok_or_else(|| ScanError::unresolved("reused exchange has no evaluator identity"))
        })
        .collect::<Result<_, _>>()?;
    let (reused_exchanges, model_usage) =
        reused_usage(&reused, model_budgets, &calls, &evidence_budget, _fault)?;
    Ok(ScanResult {
        exit_code,
        report: Report {
            schema: "auditoad-report/2".into(),
            scan_id,
            baseline: baseline.identity.clone(),
            profile: profile.id.clone(),
            source: request.snapshot.identity.clone(),
            limits: request.limits,
            target_count: request.snapshot.targets.len(),
            work_count: manifest.len(),
            manifest_sha256: sha256(&manifest_bytes),
            manifest_bytes,
            records,
            excluded: request.snapshot.excluded.clone(),
            counts,
            requirements,
            outcome,
            outcome_reason,
            experimental: request.experimental,
            usage: Usage {
                checks: checks.allocated(),
                evidence_bytes: evidence_budget.master_allocated(),
                provider_calls: calls.master_allocated(),
                reused_exchanges,
            },
            fixture_usage,
            model_usage,
        },
    })
}

/// Classify each declared requirement from its admitted rule links and committed records.
fn requirement_coverage(
    baseline: &ValidatedBaseline,
    profile: &Profile,
    selected: &[usize],
    manifest: &[Work],
    records: &[Record],
) -> Result<Vec<RequirementCoverage>, ScanError> {
    let content = &baseline.content;
    let offset = content.requirements.len();
    let mut coverage = Vec::new();
    for (node, requirement) in content.requirements.iter().enumerate() {
        let linked = baseline
            .coverage
            .edges()
            .filter(|&(from, _, _)| from == node)
            .map(|(_, to, _)| {
                to.checked_sub(offset)
                    .ok_or_else(|| ScanError::unresolved("requirement edge targets a requirement"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let chosen: Vec<usize> = linked
            .iter()
            .copied()
            .filter(|index| selected.contains(index))
            .collect();
        let rules = chosen
            .iter()
            .map(|&index| {
                content
                    .rules
                    .get(index)
                    .ok_or_else(|| ScanError::unresolved("requirement rule is not bound"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut counts = BTreeMap::new();
        for state in ResultState::ALL {
            let values = manifest
                .iter()
                .zip(records)
                .map(|(work, record)| {
                    u64::from(chosen.contains(&work.rule) && record.result == state)
                })
                .collect();
            let count = reduce(values)?;
            if count > 0 {
                counts.insert(state, count);
            }
        }
        let count = |state| counts.get(&state).copied().unwrap_or(0);
        let total = reduce(counts.values().copied().collect())?;
        let required = profile
            .requirements
            .as_ref()
            .is_none_or(|ids| ids.contains(&requirement.id));
        let status = if !required {
            RequirementStatus::NotRequired
        } else if linked.is_empty() {
            RequirementStatus::Missing
        } else if chosen.is_empty() {
            RequirementStatus::Unasked
        } else if rules
            .iter()
            .any(|rule| rule.requirements.get(&requirement.id) != Some(&requirement.revision))
        {
            RequirementStatus::Stale
        } else if count(ResultState::Fail) > 0 || count(ResultState::Review) > 0 {
            RequirementStatus::Finding
        } else if count(ResultState::Error) > 0 || count(ResultState::NotEvaluated) > 0 {
            RequirementStatus::Unresolved
        } else if total == count(ResultState::Notapplicable) {
            RequirementStatus::Unsupported
        } else {
            RequirementStatus::Satisfied
        };
        coverage.push(RequirementCoverage {
            id: requirement.id.clone(),
            revision: requirement.revision.clone(),
            title: requirement.title.clone(),
            status,
            rules: rules.iter().map(|rule| rule.id.clone()).collect(),
            counts,
        });
    }
    Ok(coverage)
}

type Observation = (ResultState, Option<serde_json::Value>, Option<String>);

#[allow(clippy::too_many_arguments)]
fn model_observation(
    request: &ScanRequest<'_>,
    evaluators: Option<&Evaluators>,
    rule: &Rule,
    work: &Work,
    scan_id: &str,
    bytes: &[u8],
    evidence: &mut FederatedBudget,
    calls: &mut FederatedBudget,
    model_budgets: &mut BTreeMap<String, (usize, Budget, Budget)>,
) -> Result<Observation, ScanError> {
    // Roles, backend support and egress were checked for every selected rule before the scan.
    let role = evaluator::model_role(rule);
    let strategy = evaluators
        .map(|e| e.strategy(role))
        .transpose()
        .map_err(ScanError::invalid)?;
    let live = evaluators.is_some_and(|e| e.live);
    let replay = evaluators.and_then(|e| e.replay.as_ref());
    let reuse = evaluators.and_then(|e| e.reuse.as_ref());
    let Some(strategy) = strategy else {
        return ask_model(
            request,
            None,
            false,
            replay,
            reuse,
            rule,
            work,
            scan_id,
            bytes,
            evidence,
            calls,
            model_budgets,
        );
    };
    if strategy.off {
        return Ok((
            ResultState::NotEvaluated,
            Some(json!({"type":"model/1","role":strategy.role,"disabled":true})),
            Some("the evaluator file switches this role off; the question was not asked".into()),
        ));
    }
    let Some(combine) = strategy.combine else {
        let mut answer = ask_model(
            request,
            Some(
                *strategy
                    .members
                    .first()
                    .ok_or_else(|| ScanError::unresolved("single evaluator role has no member"))?,
            ),
            live,
            replay,
            reuse,
            rule,
            work,
            scan_id,
            bytes,
            evidence,
            calls,
            model_budgets,
        )?;
        if let Some(observation) = answer.1.as_mut() {
            crate::json::object_mut(observation)
                .map_err(ScanError::unresolved)?
                .insert("role".into(), json!(strategy.role));
        }
        return Ok(answer);
    };
    let mut members = Vec::new();
    let mut slots = Vec::new();
    let mut steps = Sequential::new(strategy.members.len(), 2, 0)
        .map_err(|e| ScanError::unresolved(e.to_string()))?;
    let mut sink = AuditSink::new(strategy.members.len());
    while !steps.is_done() {
        let ordinal = steps.completed();
        let member = *strategy
            .members
            .get(ordinal)
            .ok_or_else(|| ScanError::unresolved("role step has no evaluator member binding"))?;
        coupling(steps.begin_step(), "role sequence refused begin_step")?;
        let selected = steps.value() == 0;
        let (next_value, slot) = if selected {
            let answer = ask_model(
                request,
                Some(member),
                live,
                replay,
                reuse,
                rule,
                work,
                scan_id,
                bytes,
                evidence,
                calls,
                model_budgets,
            )?;
            let decided = answer.1.as_ref().is_some_and(|o| {
                o["suggested_result"] == "pass" || o["suggested_result"] == "fail"
            });
            let slot = json!({"ordinal":ordinal,"model":member.name,"selected":true,
                "result":answer.0,"reason":answer.2});
            members.push(answer);
            (
                u64::from(combine == Combine::FirstResolved && decided),
                slot,
            )
        } else {
            (
                steps.value(),
                json!({"ordinal":ordinal,"model":member.name,"selected":false,
                "reason":"earlier configured member resolved the first_resolved policy"}),
            )
        };
        coupling(
            sink.len() == ordinal && slots.len() == ordinal && sink.try_record(ordinal as u64),
            "role slot terminal account refused",
        )?;
        slots.push(slot);
        coupling(
            sink.record(ordinal)
                .is_some_and(|r| r.operation == ordinal as u64)
                && steps.complete_step(next_value),
            "role slot completion correspondence failed",
        )?;
    }
    coupling(
        sink.validate()
            && sink.len() == steps.completed()
            && steps.completed() == strategy.members.len()
            && slots.len() == steps.completed()
            && reduce(
                slots
                    .iter()
                    .map(|slot| u64::from(slot["selected"] == true))
                    .collect(),
            )? == members.len() as u64,
        "role sequence does not cover configured member slots",
    )?;
    let mut answer = combined_members(role, combine, members, strategy.members.len())?;
    if let Some(observation) = answer.1.as_mut() {
        observation["role_execution"] = json!({"schema":"finite-role/1","slots":slots,
            "completed":steps.completed(),"cut":steps.value() == 1});
    }
    Ok(answer)
}

/// Combines several models' suggestions to one question. Each model's complete observation is
/// retained, so any model or policy can be scored from the same run.
fn combined_members(
    role: &str,
    combine: Combine,
    members: Vec<Observation>,
    role_models: usize,
) -> Result<Observation, ScanError> {
    let suggestions: Vec<Option<ResultState>> = members
        .iter()
        .map(|(_, observation, _)| {
            observation
                .as_ref()
                .and_then(|o| o.get("suggested_result"))
                .and_then(|v| serde_json::from_value::<ResultState>(v.clone()).ok())
                .filter(|s| matches!(s, ResultState::Pass | ResultState::Fail))
        })
        .collect();
    let passed = reduce(
        suggestions
            .iter()
            .map(|s| u64::from(*s == Some(ResultState::Pass)))
            .collect(),
    )?;
    let failed = reduce(
        suggestions
            .iter()
            .map(|s| u64::from(*s == Some(ResultState::Fail)))
            .collect(),
    )?;
    let unresolved = reduce(suggestions.iter().map(|s| u64::from(s.is_none())).collect())?;
    coupling(
        reduce(vec![passed, failed, unresolved])? == members.len() as u64,
        "model-member reduction coverage disagrees",
    )?;
    let suggested = match combine {
        Combine::FirstResolved => suggestions
            .iter()
            .flatten()
            .next()
            .copied()
            .unwrap_or(ResultState::Review),
        Combine::Agreement if unresolved == 0 && (passed == 0 || failed == 0) => {
            if failed == 0 {
                ResultState::Pass
            } else {
                ResultState::Fail
            }
        }
        Combine::Agreement => ResultState::Review,
        Combine::AnyFail if failed != 0 => ResultState::Fail,
        Combine::AnyFail if unresolved == 0 => ResultState::Pass,
        Combine::AllFail if passed != 0 => ResultState::Pass,
        Combine::AllFail if unresolved == 0 => ResultState::Fail,
        Combine::AnyFail | Combine::AllFail => ResultState::Review,
    };
    let errors = reduce(
        members
            .iter()
            .map(|(state, _, _)| u64::from(*state == ResultState::Error))
            .collect(),
    )?;
    let reasons: Vec<_> = members
        .iter()
        .map(|(state, _, reason)| json!({"result":state,"reason":reason}))
        .collect();
    let observation = json!({"type":"combined-models/1","role":role,"combine":combine,
        "members":members.iter().map(|(_, observation, _)| observation).collect::<Vec<_>>(),
        "member_results":reasons,"role_models":role_models,"passed":passed,"failed":failed,"unresolved":unresolved,
        "suggested_result":suggested});
    Ok(if errors == members.len() as u64 {
        (
            ResultState::Error,
            Some(observation),
            Some("every model in the role failed".into()),
        )
    } else {
        (
            ResultState::NotEvaluated,
            Some(observation),
            Some("semantic observation only; live control admission remains open".into()),
        )
    })
}

/// Asks one model one question, or prepares the request when live evaluation is off.
#[allow(clippy::too_many_arguments)]
fn ask_model(
    request: &ScanRequest<'_>,
    backend: Option<&crate::evaluators::Evaluator>,
    live: bool,
    replay: Option<&crate::replay::Replay>,
    reuse: Option<&crate::replay::Reuse>,
    rule: &Rule,
    work: &Work,
    scan_id: &str,
    bytes: &[u8],
    evidence: &mut FederatedBudget,
    calls: &mut FederatedBudget,
    model_budgets: &mut BTreeMap<String, (usize, Budget, Budget)>,
) -> Result<Observation, ScanError> {
    let request_limit = backend.map_or(request.limits.request_bytes, |b| {
        b.request_limit(request.limits.request_bytes)
    });
    let prepared: Result<_, String> = (|| {
        // Transport identity follows the question and projected state, not this scan's UUID.
        // The mock envelope and manifest retain their unique scan/check identities below.
        let question_id = sha256(&crate::evaluators::neutral_request_bytes(
            "question",
            &rule.check,
            bytes,
            request_limit,
        )?);
        let body = match backend {
            Some(evaluator) => evaluator.request_bytes(
                &question_id,
                &rule.check,
                bytes,
                request.limits.request_bytes,
            ),
            None => crate::evaluators::neutral_request_bytes(
                &question_id,
                &rule.check,
                bytes,
                request_limit,
            ),
        }?;
        Ok((question_id, body))
    })();
    let (question_id, request_bytes) = match prepared {
        Ok(prepared) => prepared,
        Err(reason) => return Ok((ResultState::NotEvaluated, None, Some(reason))),
    };
    let request_sha = sha256(&request_bytes);
    let mut observation = json!({"mock": request.mock.is_some(),
        "evaluator": backend.map(|e| e.describe()),
        "question_id": question_id,
        "request_bytes": crate::schema::encoded_bytes(&request_bytes),
        "request_sha256": request_sha, "response_limit": crate::evaluators::RESPONSE_LIMIT});
    let fields = crate::json::object_mut(&mut observation).map_err(ScanError::unresolved)?;
    if let Some(replay) = replay {
        fields.insert("replay".into(), replay.provenance());
    }
    let mut model_budget = backend
        .map(|backend| {
            model_budgets
                .get_mut(&backend.name)
                .ok_or_else(|| ScanError::unresolved("model budget owner absent"))
        })
        .transpose()?;
    let pool = model_budget.as_ref().map_or(0, |budget| budget.0);
    if !admit_pool(
        evidence,
        pool,
        request_bytes.len() as u64,
        model_budget.as_mut().map(|budget| &mut budget.2),
    )? {
        return Ok((
            ResultState::NotEvaluated,
            None,
            Some("request/model byte ceiling refused; no provider call issued".into()),
        ));
    }
    let reused = backend
        .zip(reuse)
        .and_then(|(backend, reuse)| reuse.response(&backend.describe(), bytes, &request_bytes));
    let provider = backend.filter(|_| live || replay.is_some() || reused.is_some());
    if provider.is_none() && request.mock.is_none() {
        return Ok((
            ResultState::NotEvaluated,
            Some(observation),
            Some("request prepared; live evaluation not enabled".into()),
        ));
    }
    if let Some((_, body, _)) = &reused {
        // A reused answer issues no provider call; only its retained response bytes are admitted.
        let size = body.len() as u64;
        if !admit_pool(
            evidence,
            pool,
            size,
            model_budget.as_mut().map(|budget| &mut budget.2),
        )? {
            return Ok((
                ResultState::NotEvaluated,
                Some(observation),
                Some("response byte budget refused".into()),
            ));
        }
    } else {
        // All owners must admit the exchange before I/O. Byte usage includes conservative response
        // reservations, while call usage counts only fully admitted attempts.
        if model_budget
            .as_ref()
            .is_some_and(|budget| budget.1.available() == 0)
        {
            return Ok((
                ResultState::NotEvaluated,
                Some(observation),
                Some("model call/byte ceiling refused; no provider call issued".into()),
            ));
        }
        if !admit_pool(
            evidence,
            pool,
            crate::evaluators::RESPONSE_LIMIT,
            model_budget.as_mut().map(|budget| &mut budget.2),
        )? || !admit_pool(
            calls,
            pool,
            1,
            model_budget.as_mut().map(|budget| &mut budget.1),
        )? {
            return Ok((
                ResultState::NotEvaluated,
                Some(observation),
                Some("response/call budget refused".into()),
            ));
        }
    }
    let mut seat = ActuationPass::new(vec![None]);
    seat.allocate(0, work.target as u64)
        .map_err(|e| ScanError::unresolved(e.to_string()))?;
    coupling(
        seat.allocation(0) == Some(Some(work.target as u64)),
        "provider seat missing",
    )?;
    let instructions = match &rule.check {
        Check::YesNo { instructions, .. }
        | Check::Choice { instructions, .. }
        | Check::Extract { instructions, .. }
        | Check::Box { instructions, .. } => instructions,
        _ => {
            return Err(ScanError::invalid(
                "model invocation requires a semantic question",
            ));
        }
    };
    let target = &request
        .snapshot
        .targets
        .get(work.target)
        .ok_or_else(|| ScanError::unresolved("model invocation target is not bound"))?
        .identity
        .id;
    let started = std::time::Instant::now();
    let response = if let Some((status, body, provenance)) = reused {
        fields.insert("reuse".into(), provenance);
        Ok((status, body))
    } else if let Some(provider) = provider {
        if let Some(replay) = replay {
            replay
                .response(
                    &rule.id,
                    target,
                    &provider.describe(),
                    bytes,
                    &request_bytes,
                )
                .map(|(status, body, provenance)| {
                    fields.insert("replay".into(), provenance);
                    (status, body)
                })
        } else {
            provider.exchange(&request_bytes)
        }
    } else {
        let invocation = ProviderRequest {
            schema: "auditoad-mock-request/1",
            scan_id,
            check_id: &work.check_id,
            rule: &rule.id,
            revision: &rule.revision,
            evidence_sha256: &sha256(bytes),
            target,
            instructions,
            model: backend.map(|b| b.name.as_str()),
            state: bytes,
            evaluator: "mock-model/1",
        };
        request
            .mock
            .ok_or_else(|| {
                ScanError::unresolved("admitted model invocation has no provider binding")
            })?
            .evaluate(&invocation, &request_bytes)
            .and_then(|replies| {
                let [reply] = replies.as_slice() else {
                    return Err("mock response must contain exactly one answer".into());
                };
                if reply.scan_id != scan_id
                    || reply.check_id != work.check_id
                    || reply.request_sha256 != request_sha
                    || reply.evaluator != "mock-model/1"
                {
                    return Err("duplicate, stale or mismatched mock response".into());
                }
                let answer = match (&reply.extract_fields, &reply.choice_answer) {
                    (Some(fields), _) => json!({"type":"extract","fields":fields}),
                    (None, Some(choice)) => choice.clone(),
                    (None, None) => json!({"type":"yes-no","probability":reply.probability}),
                };
                crate::evaluators::neutral_response(&question_id, answer).map(|body| (200, body))
            })
    };
    fields.insert(
        "provider_elapsed_ms".into(),
        json!(started.elapsed().as_millis()),
    );
    seat.actuate(0)
        .map_err(|e| ScanError::unresolved(e.to_string()))?;
    seat.finish()
        .map_err(|e| ScanError::unresolved(e.to_string()))?;
    match response {
        Err(reason) => Ok((ResultState::Error, Some(observation), Some(reason))),
        Ok((status, body)) => {
            fields.insert("http_status".into(), json!(status));
            fields.insert("response_sha256".into(), json!(sha256(&body)));
            fields.insert("response_bytes".into(), crate::schema::encoded_bytes(&body));
            if matches!(rule.check, Check::Box { .. }) {
                return Ok(
                    match provider
                        .ok_or_else(|| "Box requires a configured evaluator".to_owned())
                        .and_then(|provider| provider.box_fields(status, &body, &question_id))
                    {
                        Err(reason) => (ResultState::Error, Some(observation), Some(reason)),
                        Ok(located) => {
                            fields.insert("fields".into(), located);
                            (ResultState::NotEvaluated, Some(observation),
                            Some("Box supplies normalized location fields to later checks; it makes no pass or fail suggestion".into()))
                        }
                    },
                );
            }
            if matches!(rule.check, Check::Extract { .. }) {
                let extracted = crate::evaluator::provider_state(&rule.check, bytes, request_limit)
                    .and_then(|state| match provider {
                        Some(provider) => {
                            provider.extract(status, &body, &question_id, &rule.check, &state)
                        }
                        None => crate::evaluators::mock_extract(
                            status,
                            &body,
                            &question_id,
                            &rule.check,
                            &state,
                        ),
                    });
                return Ok(match extracted {
                    Err(reason) => (ResultState::Error, Some(observation), Some(reason)),
                    Ok(extracted) => {
                        fields.insert("fields".into(), extracted);
                        (
                            ResultState::NotEvaluated,
                            Some(observation),
                            Some(
                                "extraction supplies fields to later questions; it makes no pass or fail suggestion"
                                    .into(),
                            ),
                        )
                    }
                });
            }
            let suggested = match &rule.check {
                Check::YesNo {
                    pass_below,
                    fail_at_or_above,
                    ..
                } => match provider {
                    Some(provider) => provider.probability(status, &body, &question_id),
                    None => crate::evaluators::mock_probability(status, &body, &question_id),
                }
                .map(|probability| {
                    fields.insert("probability".into(), json!(probability));
                    if probability < *pass_below {
                        ResultState::Pass
                    } else if probability >= *fail_at_or_above {
                        ResultState::Fail
                    } else {
                        ResultState::Review
                    }
                }),
                Check::Choice {
                    options,
                    min_choice_probability,
                    min_confidence,
                    ..
                } => match provider {
                    Some(provider) => provider.choice(status, &body, &question_id, options),
                    None => crate::evaluators::mock_choice(status, &body, &question_id, options),
                }
                .and_then(|answer| {
                    let selected_probability = *answer
                        .probabilities
                        .get(&answer.choice)
                        .ok_or("selected choice has no probability binding")?;
                    let result = if selected_probability < *min_choice_probability
                        || answer.confidence < *min_confidence
                    {
                        ResultState::Review
                    } else {
                        options
                            .get(&answer.choice)
                            .ok_or("selected choice is not declared")?
                            .result
                    };
                    fields.insert("choice".into(), json!(answer.choice));
                    fields.insert("confidence".into(), json!(answer.confidence));
                    fields.insert("probabilities".into(), json!(answer.probabilities));
                    Ok(result)
                }),
                _ => Err("model decision requires a yes-no or choice question".into()),
            };
            match suggested {
                Err(reason) => Ok((ResultState::Error, Some(observation), Some(reason))),
                Ok(result) => {
                    fields.insert("suggested_result".into(), json!(result));
                    Ok((
                        ResultState::NotEvaluated,
                        Some(observation),
                        Some(
                            "semantic observation only; live control admission remains open".into(),
                        ),
                    ))
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn mock_observation(
    request: &ScanRequest<'_>,
    rule: &Rule,
    work: &Work,
    scan_id: &str,
    bytes: &[u8],
    instructions: &str,
    regions: (f64, f64),
    evidence: &mut FederatedBudget,
    calls: &mut FederatedBudget,
) -> Result<Observation, ScanError> {
    let Some(mock) = request.mock else {
        return Ok((
            ResultState::NotEvaluated,
            None,
            Some("mock provider not supplied".into()),
        ));
    };
    let evidence_sha256 = sha256(bytes);
    let invocation = ProviderRequest {
        schema: "auditoad-mock-request/1",
        scan_id,
        check_id: &work.check_id,
        rule: &rule.id,
        revision: &rule.revision,
        evidence_sha256: &evidence_sha256,
        target: &request
            .snapshot
            .targets
            .get(work.target)
            .ok_or_else(|| ScanError::unresolved("mock invocation target is not bound"))?
            .identity
            .id,
        instructions,
        model: None,
        state: bytes,
        evaluator: "mock-model/1",
    };
    let request_bytes =
        serde_json::to_vec(&invocation).map_err(|e| ScanError::unresolved(e.to_string()))?;
    if !admit_pool(evidence, 0, request_bytes.len() as u64, None)?
        || !admit_pool(calls, 0, 1, None)?
    {
        return Ok((
            ResultState::NotEvaluated,
            None,
            Some("provider request/call budget refused".into()),
        ));
    }
    let mut seat = ActuationPass::new(vec![None]);
    seat.allocate(0, work.target as u64)
        .map_err(|e| ScanError::unresolved(e.to_string()))?;
    coupling(
        seat.allocation(0) == Some(Some(work.target as u64)),
        "provider seat missing before issue",
    )?;
    let response = mock.evaluate(&invocation, &request_bytes);
    seat.actuate(0)
        .map_err(|e| ScanError::unresolved(e.to_string()))?;
    seat.finish()
        .map_err(|e| ScanError::unresolved(e.to_string()))?;
    let request_digest = sha256(&request_bytes);
    match response {
        Err(reason) => Ok((
            ResultState::Error,
            Some(
                json!({"mock": true, "request_bytes": crate::schema::encoded_bytes(&request_bytes), "request_sha256": request_digest}),
            ),
            Some(reason),
        )),
        Ok(replies) => {
            let valid = match replies.as_slice() {
                [reply] => {
                    reply.scan_id == scan_id
                        && reply.check_id == work.check_id
                        && reply.request_sha256 == request_digest
                        && reply.evaluator == "mock-model/1"
                        && reply.choice_answer.is_none()
                }
                _ => false,
            };
            let suggested = replies.first().map(|reply| {
                if reply.probability < regions.0 {
                    ResultState::Pass
                } else if reply.probability >= regions.1 {
                    ResultState::Fail
                } else {
                    ResultState::Review
                }
            });
            let observation = json!({"mock": true, "request_bytes": crate::schema::encoded_bytes(&request_bytes), "request_sha256": request_digest,
                "replies": replies, "suggested_result": suggested});
            if !valid {
                return Ok((
                    ResultState::Error,
                    Some(observation),
                    Some("duplicate, stale or mismatched provider response".into()),
                ));
            }
            Ok((
                ResultState::NotEvaluated,
                Some(observation),
                Some("mock observation only; semantic rule is unadmitted".into()),
            ))
        }
    }
}

/// Scan and publish one report by atomic same-directory replacement, then return its receipt.
pub fn scan_to_file(
    request: ScanRequest<'_>,
    destination: &Path,
) -> Result<PublishedScan, ScanError> {
    publish_bound(request, destination, Fault::None, None, None, None)
}

/// Use the identical scan construction with the operator's evaluator file. Model questions are
/// prepared for the configured backends, and sent only when the file was loaded as live.
pub fn scan_to_file_with_evaluators(
    request: ScanRequest<'_>,
    destination: &Path,
    evaluators: &Evaluators,
) -> Result<PublishedScan, ScanError> {
    publish_bound(
        request,
        destination,
        Fault::None,
        Some(evaluators),
        None,
        None,
    )
}

/// Notify the caller synchronously after each committed check, before report publication.
pub fn scan_to_file_with_progress(
    request: ScanRequest<'_>,
    destination: &Path,
    evaluators: Option<&Evaluators>,
    mut progress: impl FnMut(&Record),
) -> Result<PublishedScan, ScanError> {
    publish_bound(
        request,
        destination,
        Fault::None,
        evaluators,
        Some(&mut progress),
        None,
    )
}

/// Inspect the finite manifest before any provider call, then observe committed records.
pub fn scan_to_file_with_preparation(
    request: ScanRequest<'_>,
    destination: &Path,
    evaluators: Option<&Evaluators>,
    mut preparation: impl FnMut(&Preparation),
    mut progress: impl FnMut(&Record),
) -> Result<PublishedScan, ScanError> {
    publish_bound(
        request,
        destination,
        Fault::None,
        evaluators,
        Some(&mut progress),
        Some(&mut preparation),
    )
}

pub(crate) fn protected_inputs(
    request: &ScanRequest<'_>,
    evaluators: Option<&Evaluators>,
) -> Result<Vec<std::path::PathBuf>, ScanError> {
    let mut inputs = Vec::new();
    inputs.extend(request.snapshot.input_path.iter().cloned());
    inputs.extend(request.snapshot.protected_paths.iter().cloned());
    inputs.extend(request.baseline.input_path.iter().cloned());
    if let Some(mock) = request.mock {
        inputs.extend(mock.input_path.iter().cloned());
    }
    if let Some(evaluators) = evaluators {
        inputs.extend(evaluators.input_path.iter().cloned());
        inputs.extend(evaluators.credential_paths().cloned());
        inputs.extend(
            evaluators
                .replay
                .as_ref()
                .map(|replay| replay.input_path.clone()),
        );
        inputs.extend(
            evaluators
                .reuse
                .iter()
                .flat_map(|reuse| reuse.input_paths.iter().cloned()),
        );
    }
    for rule in &request.baseline.content.rules {
        for fixture in rule.fixtures.fail.iter().chain(&rule.fixtures.pass) {
            inputs.push(
                fixture_path(&request.baseline.fixture_root, &fixture.path)
                    .map_err(ScanError::invalid)?,
            );
        }
    }
    Ok(inputs)
}

fn publish_bound(
    request: ScanRequest<'_>,
    destination: &Path,
    fault: Fault,
    evaluators: Option<&Evaluators>,
    progress: Option<&mut dyn FnMut(&Record)>,
    preparation: Option<&mut dyn FnMut(&Preparation)>,
) -> Result<PublishedScan, ScanError> {
    let destination = unlinked_path(destination).map_err(ScanError::invalid)?;
    let inputs = protected_inputs(&request, evaluators)?;
    for input in inputs {
        if same_path(&input, &destination) {
            return Err(ScanError::invalid(
                "report destination would overwrite a protected input (baseline, fixture, source, evaluator, mock or replay)",
            ));
        }
    }
    let scan = scan_bound(request, Fault::None, evaluators, progress, preparation)?;
    let bytes = serde_json::to_vec_pretty(&scan.report)
        .map_err(|e| ScanError::unresolved(e.to_string()))?;
    let receipt = publish_bytes_bound(&destination, &bytes, &scan.report.scan_id, fault)?;
    Ok(PublishedScan { scan, receipt })
}

pub(crate) fn publish_bytes(
    destination: &Path,
    bytes: &[u8],
    identity: &str,
) -> Result<PublicationReceipt, ScanError> {
    publish_bytes_bound(destination, bytes, identity, Fault::None)
}

fn publish_bytes_bound(
    destination: &Path,
    bytes: &[u8],
    identity: &str,
    fault: Fault,
) -> Result<PublicationReceipt, ScanError> {
    let destination = unlinked_path(destination).map_err(ScanError::invalid)?;
    let mut effect = ActuationPass::new(vec![None]);
    effect_allocation(&mut effect, fault)?;
    coupling(
        effect.allocation(0) == Some(Some(0)),
        "publication seat missing",
    )?;
    let parent = destination
        .parent()
        .ok_or_else(|| ScanError::invalid("report needs a parent directory"))?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)
        .map_err(|e| ScanError::unresolved(format!("report publication failed: {e}")))?;
    temporary
        .write_all(bytes)
        .and_then(|_| temporary.as_file().sync_all())
        .map_err(|e| ScanError::unresolved(format!("report write failed: {e}")))?;
    temporary
        .persist(&destination)
        .map_err(|e| ScanError::unresolved(format!("atomic report replace failed: {e}")))?;
    effect
        .actuate(0)
        .map_err(|e| ScanError::unresolved(e.to_string()))?;
    coupling(
        effect.effect(0) == Some(Some(0)),
        "publication acknowledgment missing",
    )?;
    effect
        .finish()
        .map_err(|e| ScanError::unresolved(e.to_string()))?;
    let receipt = PublicationReceipt {
        scan_id: identity.into(),
        report_sha256: sha256(bytes),
        destination: destination.to_string_lossy().into_owned(),
        acknowledgment: "atomic_replace".into(),
    };
    Ok(receipt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{bytes_baseline, directory, validate};

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "test assertions distinguish independent model and shared-capacity refusal"
    )]
    fn model_permissions_and_federation_preserve_shared_capacity_without_full_cap_reservations()
    -> Result<(), ScanError> {
        let mut owner = FederatedBudget::new(10, 3);
        let mut a = Budget::new(7);
        let mut b = Budget::new(7);
        assert!(admit_pool(&mut owner, 1, 2, Some(&mut a))?);
        assert!(admit_pool(&mut owner, 2, 7, Some(&mut b))?);
        assert_eq!(owner.master_allocated(), 9);
        assert_eq!(owner.pool_allocated(1), Some(2));
        assert_eq!(owner.pool_allocated(2), Some(7));
        // Independent model ceiling refuses even when shared capacity remains.
        assert!(!admit_pool(&mut owner, 2, 1, Some(&mut b))?);
        assert_eq!(b.allocated(), 7);
        // Shared refusal returns unused model permission; it does not undo prior consumption.
        assert!(!admit_pool(&mut owner, 1, 2, Some(&mut a))?);
        assert_eq!(a.allocated(), 2);
        assert_eq!(owner.master_allocated(), 9);
        assert!(admit_pool(&mut owner, 0, 1, None)?);
        assert!(admit_pool(&mut owner, 1, 0, Some(&mut a))?);
        assert_eq!(owner.master_allocated(), 10);
        assert!(!admit_pool(&mut owner, 0, 1, None)?);
        assert_eq!(owner.master_allocated(), 10);
        assert!(admit_pool(&mut owner, 3, 0, None).is_err());
        Ok(())
    }

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "test assertions check each independent canonical-action omission"
    )]
    fn federation_binding_refuses_bypassed_permission_delegation_or_consumption()
    -> Result<(), Box<dyn std::error::Error>> {
        // Hold the requested amount fixed; independently omit each owner action.
        for omitted in ["permission", "delegation", "consumption"] {
            let mut owner = FederatedBudget::new(10, 2);
            let mut permission = Budget::new(7);
            if omitted != "permission" {
                assert!(permission.try_allocate(2));
            }
            if omitted != "delegation" {
                assert!(owner.try_delegate(1, 2));
            }
            if omitted != "consumption" && omitted != "delegation" {
                assert!(owner.try_allocate(1, 2));
            }
            let error = admit_pool(&mut owner, 1, 1, Some(&mut permission))
                .err()
                .ok_or("omitted federation action was accepted")?;
            assert!(error.message.contains("correspondence"), "{omitted}");
        }
        Ok(())
    }

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "test assertions check exact model reuse coverage and omitted reduction refusal"
    )]
    fn reuse_reductions_preserve_model_coverage_and_refuse_bypass()
    -> Result<(), Box<dyn std::error::Error>> {
        let budgets = || {
            ["a", "b", "unused"]
                .into_iter()
                .zip(1..=3)
                .map(|(name, pool)| (name.into(), (pool, Budget::new(10), Budget::new(100))))
                .collect()
        };
        let calls = FederatedBudget::new(10, 4);
        let bytes = FederatedBudget::new(100, 4);
        let reused = vec!["a".into(), "b".into(), "a".into()];
        let (total, models) = reused_usage(&reused, budgets(), &calls, &bytes, Fault::None)?;
        assert_eq!(total, 3);
        assert_eq!(
            models.get("a").ok_or("missing model a")?.reused_exchanges,
            2
        );
        assert_eq!(
            models.get("b").ok_or("missing model b")?.reused_exchanges,
            1
        );
        assert_eq!(
            models
                .get("unused")
                .ok_or("missing unused model")?
                .reused_exchanges,
            0
        );
        assert!(reused_usage(&[], budgets(), &calls, &bytes, Fault::None).is_ok());
        for (members, fault) in [
            (vec!["undeclared".into()], Fault::None),
            (reused, Fault::Reduction),
        ] {
            let error = reused_usage(&members, budgets(), &calls, &bytes, fault)
                .err()
                .ok_or("invalid reuse reduction was accepted")?;
            assert_eq!(error.exit_code, 2);
            assert!(error.message.contains("reuse reductions"), "{error}");
        }
        Ok(())
    }

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "test assertions distinguish transport removal from retained semantic content"
    )]
    fn consulted_combined_answers_exclude_nested_transport_but_keep_answer_content()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut first = json!({"type":"combined-models/1","members":[{"probability":0.9,
            "request_bytes":"first","response_bytes":"first","provider_elapsed_ms":1,
            "fields":{"replay":"domain text must survive"}}]});
        let mut second = first.clone();
        let member = second
            .pointer_mut("/members/0")
            .ok_or("fixture has no combined member")?;
        let fields = crate::json::object_mut(member)?;
        fields.insert("request_bytes".into(), json!("different transport"));
        fields.insert("provider_elapsed_ms".into(), json!(999));
        fields.insert(
            "replay".into(),
            json!({"report_sha256":"different provenance"}),
        );
        fields.insert("reuse".into(), json!({"report_sha256":"reused provenance"}));
        consultation_content(&mut first);
        consultation_content(&mut second);
        assert_eq!(first, second);
        assert_eq!(
            first.pointer("/members/0/fields/replay"),
            Some(&json!("domain text must survive"))
        );
        *second
            .pointer_mut("/members/0/probability")
            .ok_or("member probability was removed with transport")? = json!(0.2);
        consultation_content(&mut second);
        assert_ne!(first, second);
        Ok(())
    }

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "test assertions check the complete two-answer uncertainty truth table"
    )]
    fn answer_resolution_truth_tables_preserve_uncertainty()
    -> Result<(), Box<dyn std::error::Error>> {
        for (left, right, any, all, [passed, failed, unresolved]) in [
            (Some("pass"), Some("pass"), "pass", "pass", [2, 0, 0]),
            (Some("pass"), Some("fail"), "fail", "pass", [1, 1, 0]),
            (Some("pass"), None, "review", "pass", [1, 0, 1]),
            (Some("fail"), Some("pass"), "fail", "pass", [1, 1, 0]),
            (Some("fail"), Some("fail"), "fail", "fail", [0, 2, 0]),
            (Some("fail"), None, "fail", "review", [0, 1, 1]),
            (None, Some("pass"), "review", "pass", [1, 0, 1]),
            (None, Some("fail"), "fail", "review", [0, 1, 1]),
            (None, None, "review", "review", [0, 0, 2]),
        ] {
            let bytes =
                serde_json::to_vec(&json!({"answers":[{"decision":left},{"decision":right}]}))?;
            for (combination, expected) in [
                (AnswerCombination::AnyFail, any),
                (AnswerCombination::AllFail, all),
            ] {
                for resolution in [AnswerResolution::AllAnswers, AnswerResolution::Decisive] {
                    let (terminal, observation, _) =
                        combined_observation(&bytes, combination, resolution)?;
                    let observation = observation.ok_or("combined answer has no observation")?;
                    let expected = if resolution == AnswerResolution::AllAnswers && unresolved != 0
                    {
                        "review"
                    } else {
                        expected
                    };
                    assert_eq!(terminal, ResultState::NotEvaluated);
                    assert_eq!(
                        observation
                            .get("suggested_result")
                            .and_then(serde_json::Value::as_str),
                        Some(expected),
                        "{left:?} {right:?} {combination:?} {resolution:?}"
                    );
                    assert_eq!(observation.get("passed"), Some(&json!(passed)));
                    assert_eq!(observation.get("failed"), Some(&json!(failed)));
                    assert_eq!(observation.get("unresolved"), Some(&json!(unresolved)));
                    assert_eq!(
                        observation.get("resolution"),
                        Some(&serde_json::to_value(resolution)?)
                    );
                }
            }
        }
        Ok(())
    }

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "test assertions require the named refusal and no published effect for each bypass"
    )]
    fn bypassing_each_canonical_coupling_refuses_clear_completion()
    -> Result<(), Box<dyn std::error::Error>> {
        let dir = directory();
        let baseline = validate(&bytes_baseline(dir.path()), dir.path());
        let source = Snapshot::raw_bytes(b"good".to_vec(), "input", &Limits::default())?;
        let request = || ScanRequest {
            baseline: &baseline,
            profile: "default",
            source_alias: "bytes",
            snapshot: &source,
            limits: Limits::default(),
            experimental: false,
            mock: None,
        };
        assert_eq!(scan(request())?.exit_code, 0);
        for (fault, diagnostic) in [
            (Fault::Registry, "registration"),
            (Fault::Budget, "Budget"),
            (Fault::Sequential, "Sequential"),
            (Fault::Audit, "witness"),
            (Fault::Reduction, "reductions"),
        ] {
            let error = scan_bound(request(), fault, None, None, None)
                .err()
                .ok_or("omitted canonical action was accepted")?;
            assert_eq!(error.exit_code, 2, "{fault:?}");
            assert!(error.message.contains(diagnostic), "{fault:?}: {error}");
        }
        let output = dir.path().join("report.json");
        let error = publish_bound(request(), &output, Fault::Effect, None, None, None)
            .err()
            .ok_or("publication accepted an absent effect seat")?;
        assert!(error.message.contains("publication seat"));
        assert!(!output.exists());
        Ok(())
    }
}
