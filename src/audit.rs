//! Ordinary file-based audit declarations. Each run uses the existing scanner; canonical
//! owners account for finite suite progress and terminal outcomes.
use crate::{
    Evaluators, MockModel, Preparation, PublishedScan, ScanError, ScanRequest, Snapshot,
    ValidatedBaseline, json, load_mock, scan_to_file_with_preparation,
    schema::{Admission, Limits, Record},
    source::{read_bounded, same_path, sha256, unlinked_path},
};
use automation_structures::{AuditSink, Budget, ResourceRegistry, Sequential};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
};

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunDefinition {
    pub name: String,
    pub baseline: PathBuf,
    pub input: PathBuf,
    pub report: PathBuf,
    pub profile: Option<String>,
    pub source: Option<String>,
    pub project_root: Option<PathBuf>,
    pub evaluators: Option<PathBuf>,
    pub labels: Option<PathBuf>,
    pub mock: Option<PathBuf>,
    pub replay: Option<PathBuf>,
    /// Earlier reports whose identical exchanges answer this run; overrides the audit-file default.
    /// An empty list forces fresh answers.
    #[serde(default)]
    pub reuse: Option<Vec<PathBuf>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuditFile {
    #[serde(rename = "$schema")]
    _json_schema: Option<String>,
    schema: String,
    report: PathBuf,
    evaluators: Option<PathBuf>,
    /// Default reuse sources for every run that does not declare its own.
    reuse: Option<Vec<PathBuf>>,
    runs: Vec<RunDefinition>,
}

/// Operator settings, separate from baseline and audit content. Ceilings apply per run.
#[derive(Clone)]
pub struct RunOptions {
    pub live: bool,
    pub experimental: bool,
    pub evaluators: Option<PathBuf>,
    pub timeout_seconds: Option<u64>,
    pub model_calls: Option<u64>,
    pub model_bytes: Option<u64>,
    pub limits: Limits,
    pub max_baseline_bytes: u64,
    /// Operator override of every run's reuse sources; `Some(vec![])` forces fresh answers.
    pub reuse: Option<Vec<PathBuf>>,
}

impl Default for RunOptions {
    fn default() -> Self {
        Self {
            live: false,
            experimental: false,
            evaluators: None,
            timeout_seconds: None,
            model_calls: None,
            model_bytes: None,
            max_baseline_bytes: 2 * 1024 * 1024,
            reuse: None,
            limits: Limits {
                checks: u64::MAX,
                provider_calls: u64::MAX,
                evidence_bytes: u64::MAX,
                ..Limits::default()
            },
        }
    }
}

struct Loaded {
    baseline: ValidatedBaseline,
    snapshot: Snapshot,
    profile: String,
    source: String,
    evaluators: Option<Evaluators>,
    mock: Option<MockModel>,
}

impl Loaded {
    fn request<'a>(&'a self, options: &RunOptions) -> ScanRequest<'a> {
        ScanRequest {
            baseline: &self.baseline,
            snapshot: &self.snapshot,
            profile: &self.profile,
            source_alias: &self.source,
            limits: options.limits.clone(),
            experimental: options.experimental
                || self.baseline.content.baseline.status == Admission::Draft,
            mock: self.mock.as_ref(),
        }
    }
}

fn source_alias(
    baseline: &ValidatedBaseline,
    explicit: Option<&str>,
    input: &Path,
    limit: u64,
) -> Result<String, ScanError> {
    let sources = &baseline.content.sources;
    let candidates: Vec<_> = if let Some(explicit) = explicit {
        sources
            .iter()
            .filter(|(id, source)| id.as_str() == explicit || source.adapter == explicit)
            .collect()
    } else {
        let bytes = read_bounded(input, limit).map_err(ScanError::invalid)?;
        let value = json::parse::<Value>(&bytes).ok();
        let adapter = match value
            .as_ref()
            .and_then(|v| v.get("schema"))
            .and_then(Value::as_str)
        {
            Some("auditoad-inventory/1" | "checkwarden-inventory/1") => "inventory-json/1",
            Some("auditoad-evidence-bundle/1" | "checkwarden-evidence-bundle/1") => {
                "evidence-bundle/1"
            }
            Some("auditoad-collection/1") => "collection/1",
            _ if input.extension().and_then(|e| e.to_str()).is_some_and(|e| {
                e.eq_ignore_ascii_case("jsonl") || e.eq_ignore_ascii_case("ndjson")
            }) =>
            {
                "json-lines/1"
            }
            _ if value.is_some() => "json/1",
            _ if std::str::from_utf8(&bytes).is_ok() => "text/1",
            _ => "raw-bytes/1",
        };
        let matching: Vec<_> = sources
            .iter()
            .filter(|(_, source)| source.adapter == adapter)
            .collect();
        // A sole raw-byte binding deliberately accepts any file format.
        if matching.is_empty()
            && sources.len() == 1
            && sources
                .values()
                .next()
                .is_some_and(|s| s.adapter == "raw-bytes/1")
        {
            sources.iter().collect()
        } else {
            matching
        }
    };
    match candidates.as_slice() {
        [(alias, _)] => Ok((*alias).clone()),
        _ => Err(ScanError::invalid(
            "source is absent or ambiguous for this input; choose --source with one baseline alias",
        )),
    }
}

/// Reuse sources in force for a run: the operator's override, else the run's own declaration.
fn reuse_sources<'a>(definition: &'a RunDefinition, options: &'a RunOptions) -> &'a [PathBuf] {
    options
        .reuse
        .as_deref()
        .or(definition.reuse.as_deref())
        .unwrap_or_default()
}

fn load(definition: &RunDefinition, options: &RunOptions) -> Result<Loaded, ScanError> {
    if options
        .timeout_seconds
        .is_some_and(|value| !(1..=120).contains(&value))
    {
        return Err(ScanError::invalid(
            "provider timeout must be 1..120 seconds",
        ));
    }
    let baseline =
        ValidatedBaseline::from_file_with_limit(&definition.baseline, options.max_baseline_bytes)?;
    if baseline.content.baseline.status == Admission::Retired {
        return Err(ScanError::invalid("retired baselines cannot scan"));
    }
    let profile = baseline.profile(definition.profile.as_deref())?.to_owned();
    let source = source_alias(
        &baseline,
        definition.source.as_deref(),
        &definition.input,
        options.limits.input_bytes,
    )?;
    let root = definition.project_root.as_deref().unwrap_or_else(|| {
        definition
            .input
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."))
    });
    let binding = baseline
        .content
        .sources
        .get(&source)
        .ok_or_else(|| ScanError::invalid("selected source has no baseline binding"))?;
    let snapshot = match binding.adapter.as_str() {
        "collection/1" => Snapshot::collection_file(
            &definition.input,
            Some(root),
            &baseline,
            &profile,
            &source,
            &options.limits,
        )?,
        "evidence-bundle/1" => Snapshot::scoped_bundle(
            &definition.input,
            root,
            &baseline,
            &profile,
            &source,
            &options.limits,
        )?,
        "text/1" | "json/1" | "json-lines/1" => Snapshot::scoped_file(
            &definition.input,
            &baseline,
            &profile,
            &source,
            &options.limits,
        )?,
        adapter => Snapshot::from_file(adapter, &definition.input, &options.limits)?,
    };
    let environment = std::env::var_os("AUDITOAD_EVALUATORS").map(PathBuf::from);
    let evaluator_path = options
        .evaluators
        .as_ref()
        .or(definition.evaluators.as_ref())
        .or(environment.as_ref());
    if options.live && evaluator_path.is_none() {
        return Err(ScanError::invalid(
            "--live requires an evaluator file; use --evaluators, an audit-file binding or AUDITOAD_EVALUATORS",
        ));
    }
    if options.live && definition.mock.is_some() {
        return Err(ScanError::invalid("mock and --live cannot be combined"));
    }
    if definition.replay.is_some()
        && (options.live || definition.mock.is_some() || evaluator_path.is_none())
    {
        return Err(ScanError::invalid(
            "replay requires an evaluator file and cannot combine with --live or mock",
        ));
    }
    let reuse = reuse_sources(definition, options);
    if !reuse.is_empty()
        && (definition.mock.is_some() || definition.replay.is_some() || evaluator_path.is_none())
    {
        return Err(ScanError::invalid(
            "reuse requires an evaluator file and cannot combine with mock or replay",
        ));
    }
    let mut evaluators = evaluator_path
        .map(|p| Evaluators::from_file(p, options.live, 30))
        .transpose()?;
    if let Some(evaluators) = evaluators.as_mut() {
        evaluators.override_limits(
            options.model_calls,
            options.model_bytes,
            options.timeout_seconds,
        )?;
    }
    if let Some(path) = definition.replay.as_deref() {
        evaluators = Some(
            evaluators
                .ok_or_else(|| ScanError::invalid("replay requires an evaluator file"))?
                .with_replay(path, options.limits.input_bytes)?,
        );
    }
    if !reuse.is_empty() {
        evaluators = Some(
            evaluators
                .ok_or_else(|| ScanError::invalid("reuse requires an evaluator file"))?
                .with_reuse(reuse, options.limits.input_bytes)?,
        );
    }
    let mock = definition.mock.as_deref().map(load_mock).transpose()?;
    Ok(Loaded {
        baseline,
        snapshot,
        profile,
        source,
        evaluators,
        mock,
    })
}

/// Run one ordinary scan, resolving declared defaults before entering the scanner.
pub fn run_one(
    definition: &RunDefinition,
    options: &RunOptions,
    preparation: impl FnMut(&Preparation),
    progress: impl FnMut(&Record),
) -> Result<PublishedScan, ScanError> {
    if definition.labels.is_some() {
        return Err(ScanError::invalid(
            "run_one does not score labels; use run_file or score the published scan",
        ));
    }
    let loaded = load(definition, options)?;
    scan_to_file_with_preparation(
        loaded.request(options),
        &definition.report,
        loaded.evaluators.as_ref(),
        preparation,
        progress,
    )
}

fn relative(base: &Path, path: &Path) -> Result<PathBuf, ScanError> {
    if path.as_os_str().is_empty() {
        return Err(ScanError::invalid("audit paths must be nonempty"));
    }
    unlinked_path(&base.join(path)).map_err(ScanError::invalid)
}

fn paths(definition: &mut RunDefinition, base: &Path) -> Result<(), ScanError> {
    definition.baseline = relative(base, &definition.baseline)?;
    definition.input = relative(base, &definition.input)?;
    definition.report = relative(base, &definition.report)?;
    for path in [
        &mut definition.project_root,
        &mut definition.evaluators,
        &mut definition.labels,
        &mut definition.mock,
        &mut definition.replay,
    ]
    .into_iter()
    .flatten()
    {
        *path = relative(base, path)?;
    }
    for path in definition.reuse.iter_mut().flatten() {
        *path = relative(base, path)?;
    }
    Ok(())
}

fn advance(owner: &mut Sequential, count: usize) -> Result<(), ScanError> {
    if !owner.complete_step(0) || owner.completed() != count {
        return Err(ScanError::unresolved(
            "audit run completion correspondence failed",
        ));
    }
    Ok(())
}

fn frozen_identity(
    loaded: &Loaded,
    definition: &RunDefinition,
    options: &RunOptions,
) -> Result<String, ScanError> {
    let mut identities = vec![
        loaded.baseline.identity.sha256.clone(),
        loaded.snapshot.identity.input_sha256.clone(),
        loaded.snapshot.identity.snapshot_id.clone(),
    ];
    for path in loaded
        .evaluators
        .as_ref()
        .and_then(|e| e.input_path.as_ref())
        .into_iter()
        .chain(definition.mock.as_ref())
        .chain(definition.replay.as_ref())
        .chain(reuse_sources(definition, options))
        .chain(definition.labels.as_ref())
    {
        identities.push(sha256(
            &read_bounded(path, options.limits.input_bytes).map_err(ScanError::invalid)?,
        ));
    }
    Ok(sha256(
        &serde_json::to_vec(&identities).map_err(|e| ScanError::invalid(e.to_string()))?,
    ))
}

pub struct AuditResult {
    pub report: Value,
    pub exit_code: u8,
    pub destination: PathBuf,
}

/// Preflight a finite declaration, then run it serially. Missing/failed runs are terminal records,
/// never omitted. Paths are relative to the audit file, and live consent is never read from it.
pub fn run_file(
    path: &Path,
    options: &RunOptions,
    mut preparation: impl FnMut(&str, &Preparation),
    mut progress: impl FnMut(&str, &Record),
) -> Result<AuditResult, ScanError> {
    let path = unlinked_path(path).map_err(ScanError::invalid)?;
    let bytes = read_bounded(&path, 2 * 1024 * 1024).map_err(ScanError::invalid)?;
    let mut file: AuditFile = json::parse(&bytes).map_err(ScanError::invalid)?;
    if file.schema != "auditoad-audit/1"
        || file.runs.is_empty()
        || !Budget::new(options.limits.manifest_work as u64).try_allocate(file.runs.len() as u64)
    {
        return Err(ScanError::invalid(
            "audit file requires auditoad-audit/1 and a bounded nonempty runs list",
        ));
    }
    let base = path
        .parent()
        .ok_or_else(|| ScanError::invalid("audit file has no parent directory"))?;
    let destination = relative(base, &file.report)?;
    let mut names = BTreeSet::new();
    let mut registry = ResourceRegistry::new();
    for (ordinal, definition) in file.runs.iter_mut().enumerate() {
        if definition.name.trim().is_empty() || !names.insert(definition.name.clone()) {
            return Err(ScanError::invalid(
                "audit run names must be nonempty and unique",
            ));
        }
        if definition.evaluators.is_none() {
            definition.evaluators = file.evaluators.clone();
        }
        if definition.reuse.is_none() {
            definition.reuse = file.reuse.clone();
        }
        paths(definition, base)?;
        if registry.insert(ordinal as u64, ordinal as u64).is_some()
            || registry.get(ordinal as u64) != Some(ordinal as u64)
        {
            return Err(ScanError::unresolved("audit run registration failed"));
        }
    }
    let mut outputs = vec![destination.clone()];
    outputs.extend(file.runs.iter().map(|d| d.report.clone()));
    for (index, output) in outputs.iter().enumerate() {
        if outputs
            .iter()
            .take(index)
            .any(|previous| same_path(previous, output))
        {
            return Err(ScanError::invalid(
                "audit report destinations must be distinct",
            ));
        }
        if !output.parent().is_some_and(Path::is_dir) {
            return Err(ScanError::invalid(format!(
                "report parent directory does not exist: {}",
                output.display()
            )));
        }
    }
    let mut protected = vec![path.clone()];
    let mut evidence_paths = Vec::new();
    let mut label_paths = Vec::new();
    let mut identities = Vec::new();
    let mut preflight =
        Sequential::new(file.runs.len(), 1, 0).map_err(|e| ScanError::invalid(e.to_string()))?;
    // Keep at most one scan's frozen source in memory during preflight.
    while !preflight.is_done() {
        if !preflight.begin_step() {
            return Err(ScanError::unresolved("audit preflight refused begin_step"));
        }
        let definition = file
            .runs
            .get(preflight.completed())
            .ok_or_else(|| ScanError::unresolved("preflight step has no registered run"))?;
        let loaded = load(definition, options)?;
        let inputs =
            crate::scan::protected_inputs(&loaded.request(options), loaded.evaluators.as_ref())?;
        evidence_paths.extend(loaded.snapshot.protected_paths.iter().cloned());
        evidence_paths.extend(loaded.snapshot.input_path.iter().cloned());
        if let Some(labels) = &definition.labels {
            if loaded
                .snapshot
                .protected_paths
                .iter()
                .chain(loaded.snapshot.input_path.iter())
                .any(|p| same_path(p, labels))
            {
                return Err(ScanError::invalid(
                    "labels overlap audit evidence; labels must stay outside model inputs",
                ));
            }
            crate::score::validate_labels(
                &read_bounded(labels, options.limits.input_bytes).map_err(ScanError::invalid)?,
            )?;
            protected.push(labels.clone());
            label_paths.push(labels.clone());
        }
        protected.extend(inputs);
        identities.push(frozen_identity(&loaded, definition, options)?);
        advance(&mut preflight, identities.len())?;
    }
    if outputs
        .iter()
        .any(|output| protected.iter().any(|input| same_path(input, output)))
    {
        return Err(ScanError::invalid(
            "audit report destination overlaps an input, fixture, credential or labels file",
        ));
    }
    if evidence_paths
        .iter()
        .any(|input| label_paths.iter().any(|labels| same_path(input, labels)))
    {
        return Err(ScanError::invalid(
            "suite labels overlap another run's evidence",
        ));
    }
    let mut steps =
        Sequential::new(file.runs.len(), 1, 0).map_err(|e| ScanError::invalid(e.to_string()))?;
    let mut sink = AuditSink::new(file.runs.len());
    let mut records = Vec::new();
    while !steps.is_done() {
        if !steps.begin_step() {
            return Err(ScanError::unresolved("audit suite refused begin_step"));
        }
        let ordinal = steps.completed();
        if registry.get(ordinal as u64) != Some(ordinal as u64) {
            return Err(ScanError::unresolved(
                "audit run registry correspondence failed",
            ));
        }
        let definition = file
            .runs
            .get(ordinal)
            .ok_or_else(|| ScanError::unresolved("suite step has no registered run"))?;
        let identity = identities
            .get(ordinal)
            .ok_or_else(|| ScanError::unresolved("suite run has no preflight identity"))?;
        let started = std::time::Instant::now();
        let result = (|| {
            let loaded = load(definition, options)?;
            if *identity != frozen_identity(&loaded, definition, options)? {
                return Err(ScanError::unresolved(
                    "audit inputs changed after suite preflight",
                ));
            }
            let labels = definition
                .labels
                .as_ref()
                .map(|path| {
                    read_bounded(path, options.limits.input_bytes).map_err(ScanError::invalid)
                })
                .transpose()?;
            let published = scan_to_file_with_preparation(
                loaded.request(options),
                &definition.report,
                loaded.evaluators.as_ref(),
                |plan| preparation(&definition.name, plan),
                |record| progress(&definition.name, record),
            )?;
            let scored = labels
                .as_ref()
                .map(|labels| {
                    // Score the publication encoding, and bind it to the receipt so a
                    // later standalone score identifies exactly the same report bytes.
                    let bytes = serde_json::to_vec_pretty(&published.scan.report)
                        .map_err(|e| ScanError::unresolved(e.to_string()))?;
                    if sha256(&bytes) != published.receipt.report_sha256 {
                        return Err(ScanError::unresolved(
                            "score input differs from the published report identity",
                        ));
                    }
                    crate::score::score(&bytes, labels)
                })
                .transpose();
            let (score, score_error) = match scored {
                Ok(score) => (score, None),
                Err(error) => (None, Some(error.message)),
            };
            let exit_code = if score_error.is_some() {
                3
            } else if score
                .as_ref()
                .is_some_and(|s| s.get("label_coverage_complete") == Some(&Value::Bool(false)))
            {
                2
            } else {
                published.scan.exit_code
            };
            let mut row = json!({"name":definition.name,"exit_code":exit_code,"receipt":published.receipt,"score":score,
                "outcome":published.scan.report.outcome,"usage":published.scan.report.usage,"model_usage":published.scan.report.model_usage,
                "preflight_identity":identity,
                "baseline":published.scan.report.baseline,"source":published.scan.report.source});
            if let Some(reason) = score_error {
                row.as_object_mut()
                    .ok_or_else(|| ScanError::unresolved("suite outcome is not an object"))?
                    .insert("error".into(), json!(format!("scoring failed: {reason}")));
            }
            Ok::<_, ScanError>(row)
        })();
        let mut record = match result {
            Ok(record) => record,
            Err(error) => {
                json!({"name":definition.name,"exit_code":error.exit_code,"error":error.message})
            }
        };
        record
            .as_object_mut()
            .ok_or_else(|| ScanError::unresolved("suite outcome is not an object"))?
            .insert("elapsed_ms".into(), json!(started.elapsed().as_millis()));
        if !sink.try_record(ordinal as u64) {
            return Err(ScanError::unresolved("audit outcome record refused"));
        }
        records.push(record);
        advance(&mut steps, records.len())?;
    }
    if !sink.validate() || sink.len() != records.len() || records.len() != file.runs.len() {
        return Err(ScanError::unresolved(
            "audit suite lacks complete outcome accounting",
        ));
    }
    let mut counts = Vec::new();
    for code in 0..=3 {
        counts.push(crate::scan::reduce(
            records
                .iter()
                .map(|r| u64::from(r.get("exit_code") == Some(&json!(code))))
                .collect(),
        )?);
    }
    if crate::scan::reduce(counts.clone())? != records.len() as u64 {
        return Err(ScanError::unresolved("audit suite outcome totals disagree"));
    }
    let exit_code = match counts.as_slice() {
        [_, failures, unresolved, invalid] => {
            if *invalid != 0 {
                3
            } else if *unresolved != 0 {
                2
            } else if *failures != 0 {
                1
            } else {
                0
            }
        }
        _ => {
            return Err(ScanError::unresolved(
                "audit suite exit classes are incomplete",
            ));
        }
    };
    let report = json!({"schema":"auditoad-suite-report/1","audit_sha256":sha256(&bytes),
        "live":options.live,"runs":records,"exit_code":exit_code,"exit_counts":counts,
        "scope":"Each named run uses the ordinary scan engine. Limits apply per run. Scores cover supplied labels; unlike audit domains are not pooled."});
    crate::scan::publish_bytes(
        &destination,
        &serde_json::to_vec_pretty(&report).map_err(|e| ScanError::unresolved(e.to_string()))?,
        &sha256(&bytes),
    )?;
    Ok(AuditResult {
        report,
        exit_code,
        destination,
    })
}
