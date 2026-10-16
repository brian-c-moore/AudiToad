use auditoad::{
    Preparation, ScanError, ValidatedBaseline,
    audit::{RunDefinition, RunOptions},
    schema::{Limits, Record, ResultState},
};
use clap::{Args, Parser, Subcommand};
use std::{path::PathBuf, process::ExitCode};

#[derive(Parser)]
#[command(
    version,
    about = "Run a declared audit; report findings, evidence and uncovered scope"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Baseline {
        #[command(subcommand)]
        command: BaselineCommand,
    },
    Scan(Box<ScanArguments>),
    /// Run the named scans in an auditoad-audit/1 file, with optional labels and model configurations.
    Run(Box<RunArguments>),
    /// Score retained decisions against labels, per rule, model and simulated combination policy.
    Score {
        #[arg(long)]
        report: PathBuf,
        #[arg(long)]
        labels: PathBuf,
        /// Compare this candidate report with a reference on the same source and labels.
        #[arg(long)]
        compare: Option<PathBuf>,
        /// Cumulative bytes for report, labels and optional reference; no partial score on refusal.
        #[arg(long, default_value_t = 16_777_216)]
        max_input_bytes: u64,
    },
}

#[derive(Subcommand)]
enum BaselineCommand {
    Validate {
        path: PathBuf,
    },
    /// Review the questions in a baseline or question set.
    Review(Box<ReviewArguments>),
}

#[derive(Args)]
struct ReviewArguments {
    path: PathBuf,
    /// Where to write the review report.
    #[arg(long, default_value = "review.json")]
    report: PathBuf,
    /// Permit an HTTPS origin or loopback for this review; repeat to replace the default allowlist.
    #[arg(long, value_name = "ORIGIN")]
    allowed_egress: Vec<String>,
    #[command(flatten)]
    operator: OperatorArguments,
}

#[derive(Args)]
struct ScanArguments {
    #[arg(long)]
    baseline: PathBuf,
    /// Override the baseline's default profile. A sole profile is selected automatically.
    #[arg(long)]
    profile: Option<String>,
    /// Override input-based selection with a baseline source alias or unique adapter ID.
    #[arg(long)]
    source: Option<String>,
    #[arg(long)]
    input: PathBuf,
    #[arg(long)]
    report: PathBuf,
    /// Bundle/collection file root; defaults to the input manifest's directory.
    #[arg(long)]
    project_root: Option<PathBuf>,
    /// Local mock responses; cannot be combined with --live.
    #[arg(long)]
    mock: Option<PathBuf>,
    /// Replay exact retained provider exchanges locally; requires evaluators and forbids live/mock.
    #[arg(long)]
    replay: Option<PathBuf>,
    #[command(flatten)]
    operator: OperatorArguments,
}

#[derive(Args)]
struct RunArguments {
    path: PathBuf,
    #[command(flatten)]
    operator: OperatorArguments,
}

#[derive(Args)]
struct OperatorArguments {
    /// Model configuration. Overrides an audit-file binding and AUDITOAD_EVALUATORS.
    #[arg(long)]
    evaluators: Option<PathBuf>,
    /// Explicit consent to send evidence to the configured providers. Otherwise prepare locally.
    #[arg(long)]
    live: bool,
    // Compatibility for existing commands; draft status now supplies this automatically.
    #[arg(long, hide = true)]
    experimental: bool,
    /// Override every model's timeout for this run (1..120 seconds).
    #[arg(long)]
    provider_timeout_seconds: Option<u64>,
    #[arg(long, default_value_t = 10_000)]
    max_targets: usize,
    #[arg(long, default_value_t = 100_000)]
    max_work: usize,
    /// Check ceiling; omitted allows the complete prepared manifest.
    #[arg(long)]
    max_checks: Option<u64>,
    /// Cumulative evidence/request/response-reservation ceiling, per run.
    #[arg(long)]
    max_evidence_bytes: Option<u64>,
    /// Call ceiling, per run. Omitted allows all declared role members and conditional checks.
    #[arg(long)]
    max_provider_calls: Option<u64>,
    /// Serialized request ceiling; each question/model can impose a lower endpoint limit.
    #[arg(long, default_value_t = 1_048_576)]
    max_request_bytes: u64,
    #[arg(long, default_value_t = 2_097_152)]
    max_baseline_bytes: u64,
    #[arg(long, default_value_t = 16_777_216)]
    max_input_bytes: u64,
    #[arg(long, default_value_t = 1_000)]
    max_fixture_checks: u64,
    #[arg(long, default_value_t = 16_777_216)]
    max_fixture_bytes: u64,
    /// Answer identical exchanges from this earlier report instead of asking again (repeatable).
    /// Overrides reuse declared in audit files. Unmatched questions are asked with --live.
    #[arg(long, value_name = "REPORT")]
    reuse: Vec<PathBuf>,
    /// Ask every question fresh, ignoring reuse declared in audit files.
    #[arg(long, conflicts_with = "reuse")]
    no_reuse: bool,
}

impl OperatorArguments {
    fn options(self) -> RunOptions {
        RunOptions {
            live: self.live,
            experimental: self.experimental,
            evaluators: self.evaluators,
            timeout_seconds: self.provider_timeout_seconds,
            model_calls: self.max_provider_calls,
            model_bytes: self.max_evidence_bytes,
            max_baseline_bytes: self.max_baseline_bytes,
            reuse: if self.no_reuse {
                Some(Vec::new())
            } else if self.reuse.is_empty() {
                None
            } else {
                Some(self.reuse)
            },
            limits: Limits {
                targets: self.max_targets,
                manifest_work: self.max_work,
                checks: self.max_checks.unwrap_or(u64::MAX),
                evidence_bytes: self.max_evidence_bytes.unwrap_or(u64::MAX),
                provider_calls: self.max_provider_calls.unwrap_or(u64::MAX),
                request_bytes: self.max_request_bytes,
                input_bytes: self.max_input_bytes,
                fixture_checks: self.max_fixture_checks,
                fixture_bytes: self.max_fixture_bytes,
            },
        }
    }
}

fn preparation(name: &str, plan: &Preparation) {
    println!(
        "Prepared {name}: {} targets, {} checks; at most {} model calls if enabled.",
        plan.targets, plan.checks, plan.provider_calls_at_most
    );
    if !plan.models.is_empty() {
        println!("  Calls by model: {}", serde_json::json!(&plan.models));
    }
    println!(
        "  Ceilings: {} checks, {} calls, {} bytes per request.",
        plan.limits.checks, plan.limits.provider_calls, plan.limits.request_bytes
    );
    if plan.limits.evidence_bytes == u64::MAX {
        println!("  No operator cumulative byte ceiling; use --max-evidence-bytes to set one.");
    } else {
        println!("  Cumulative byte ceiling: {}", plan.limits.evidence_bytes);
    }
    if plan.evidence_sizes_depend_on_answers {
        println!(
            "  Later evidence/request sizes depend on prerequisite answers; exact total is not known yet."
        );
    }
}

fn progress(name: &str, record: &Record) {
    if matches!(
        record.evaluator.contract.as_str(),
        "choice/1" | "yes-no/1" | "extract/1" | "box/1"
    ) {
        let observation = record.observation.as_ref();
        println!(
            "{name}: {} [{}]: suggested={}, terminal={:?}",
            record.rule.id,
            record.target.id,
            observation
                .and_then(|o| o.get("suggested_result"))
                .and_then(serde_json::Value::as_str)
                .unwrap_or("none"),
            record.result
        );
    }
}

fn execute(cli: Cli) -> Result<u8, ScanError> {
    match cli.command {
        Command::Baseline {
            command: BaselineCommand::Validate { path },
        } => {
            let baseline = ValidatedBaseline::from_file(&path)?;
            println!(
                "Valid {} {} ({:?}); {} controls. Schema/bindings checked; fixture admission is checked at scan time.",
                baseline.baseline().baseline.id,
                baseline.baseline().baseline.version,
                baseline.baseline().baseline.status,
                baseline.baseline().rules.len()
            );
            Ok(0)
        }
        Command::Baseline {
            command: BaselineCommand::Review(arguments),
        } => {
            let published = auditoad::question_review::run_file(
                &arguments.path,
                &arguments.report,
                &arguments.operator.options(),
                (!arguments.allowed_egress.is_empty())
                    .then_some(arguments.allowed_egress.as_slice()),
                |plan| preparation("question review", plan),
                |record| progress("question review", record),
            )?;
            println!("Review outcome: {:?}", published.scan.report.outcome);
            println!(
                "Counts: {}",
                serde_json::to_string(&published.scan.report.counts)
                    .map_err(|error| ScanError::unresolved(error.to_string()))?
            );
            println!("Report: {}", published.receipt.destination);
            Ok(published.scan.exit_code)
        }
        Command::Score {
            report,
            labels,
            compare,
            max_input_bytes,
        } => {
            let summary =
                auditoad::score_files(&report, &labels, compare.as_deref(), max_input_bytes)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&summary)
                    .map_err(|error| ScanError::unresolved(error.to_string()))?
            );
            Ok(
                if summary
                    .get("label_coverage_complete")
                    .and_then(serde_json::Value::as_bool)
                    .ok_or_else(|| {
                        ScanError::unresolved("score coverage field is absent or invalid")
                    })?
                {
                    0
                } else {
                    2
                },
            )
        }
        Command::Run(arguments) => {
            let result = auditoad::audit::run_file(
                &arguments.path,
                &arguments.operator.options(),
                preparation,
                progress,
            )?;
            for run in result
                .report
                .get("runs")
                .and_then(serde_json::Value::as_array)
                .ok_or_else(|| ScanError::unresolved("suite runs are absent or invalid"))?
            {
                let name = run
                    .get("name")
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| ScanError::unresolved("suite run name is absent or invalid"))?;
                let exit_code = run
                    .get("exit_code")
                    .and_then(serde_json::Value::as_u64)
                    .ok_or_else(|| {
                        ScanError::unresolved("suite run exit code is absent or invalid")
                    })?;
                let error = run
                    .get("error")
                    .map(|error| {
                        error
                            .as_str()
                            .ok_or_else(|| ScanError::unresolved("suite run error is not a string"))
                    })
                    .transpose()?;
                println!(
                    "{name}: exit={exit_code}{}",
                    error.map_or(String::new(), |reason| format!("; {reason}"))
                );
                if let Some(receipt) = run.get("receipt") {
                    let path = receipt
                        .get("destination")
                        .and_then(serde_json::Value::as_str)
                        .ok_or_else(|| {
                            ScanError::unresolved("suite receipt destination is absent or invalid")
                        })?;
                    println!("  Report: {path}");
                }
                if let Some(score) = run.get("score").filter(|score| !score.is_null()) {
                    println!(
                        "  Score: {}",
                        score.get("overall").ok_or_else(|| ScanError::unresolved(
                            "suite score overall field is absent"
                        ))?
                    );
                }
            }
            println!("Suite report: {}", result.destination.display());
            Ok(result.exit_code)
        }
        Command::Scan(arguments) => {
            let definition = RunDefinition {
                name: "scan".into(),
                baseline: arguments.baseline,
                input: arguments.input,
                report: arguments.report,
                profile: arguments.profile,
                source: arguments.source,
                project_root: arguments.project_root,
                mock: arguments.mock,
                replay: arguments.replay,
                reuse: None,
                labels: None,
                evaluators: None,
            };
            let published = auditoad::audit::run_one(
                &definition,
                &arguments.operator.options(),
                |plan| preparation("scan", plan),
                |record| progress("scan", record),
            )?;
            let report = &published.scan.report;
            println!(
                "{:?}: {} targets, {} checks{}",
                report.outcome,
                report.target_count,
                report.work_count,
                if report.experimental {
                    " (experimental: cannot clear an audit)"
                } else {
                    ""
                }
            );
            if let Some(reason) = &report.outcome_reason {
                println!("  {reason}");
            }
            for record in report
                .records
                .iter()
                .filter(|r| r.result != ResultState::Pass && r.result != ResultState::Notapplicable)
                .take(8)
            {
                println!(
                    "  {:?} {} [{}]: {}",
                    record.result,
                    record.rule.id,
                    record.target.id,
                    record
                        .reason
                        .as_deref()
                        .unwrap_or("inspect retained evidence and observation")
                );
            }
            println!(
                "Counts: {}",
                serde_json::to_string(&report.counts).unwrap_or_default()
            );
            if !report.requirements.is_empty() {
                let statuses: Vec<_> = report
                    .requirements
                    .iter()
                    .map(|r| format!("{} {}", r.id, r.status.name()))
                    .collect();
                println!("Requirements: {}", statuses.join(", "));
            }
            println!("Report: {}", published.receipt.destination);
            println!(
                "Receipt: {}",
                serde_json::to_string(&published.receipt).unwrap_or_default()
            );
            Ok(published.scan.exit_code)
        }
    }
}

fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => {
            let code = if error.use_stderr() { 3 } else { 0 };
            let _ = error.print();
            return ExitCode::from(code);
        }
    };
    match execute(cli) {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            eprintln!("AudiToad: {}", error.message);
            ExitCode::from(error.exit_code)
        }
    }
}
