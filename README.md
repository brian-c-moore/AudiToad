# AudiToad 🐸

AudiToad is a general-purpose, AI-backed tool for audits and compliance checks. It combines
exact local checks with focused questions to models.

Define the requirements and questions in a **baseline**, supply the evidence, and run the audit
again as your work changes. AudiToad records findings, unanswered questions and coverage with
the evidence behind each result. The baseline defines the audit, so the same engine can serve
many kinds of work:

- Review [formal methods claims](examples/formal-claims/README.md) against supplied artifacts
  and evidence.
- Check [configuration and inventory policy](examples/disk-encryption/README.md),
  [scanner findings](examples/scanner-policy/README.md) and [security events](examples/windows-memory/README.md).
- Review code against [requirements](examples/python-review/README.md) or
  [security rules](examples/web-security/README.md).
- Enforce [writing standards](examples/no-slop/README.md), or ask focused questions about
  an article, a report or chapters of a novel.

Call the CLI or Rust library from your own tools, a CI/CD pipeline or a SOAR workflow. JSON
reports and exit codes let the calling system route findings and unresolved checks. Start with
the [user guide](docs/user-guide.md) or a [self-contained example](examples/README.md).

## Built with Automation Structures

AudiToad's audit engine is built by composing the reusable
[Automation Structures](https://github.com/brian-c-moore/automation-structures) in the published
Rust crate. The same engine runs research, compliance, security and writing baselines.

The [case study](docs/automation-structures.md) walks through how it is built and how the parts
work together. The [research](https://github.com/brian-c-moore/automation-structures-research)
explains the underlying method.

## See a result

For example, the disk-encryption audit produces these selected fields in its JSON report:

```json
{
  "outcome": "unresolved",
  "counts": {
    "pass": 1,
    "fail": 1,
    "review": 0,
    "notapplicable": 0,
    "not_evaluated": 1,
    "error": 0
  }
}
```

One supplied disk record declares encryption, one declares no encryption, and one omits the
fact. The command exits 2 so the missing fact stays visible. The [example guide](examples/disk-encryption/README.md)
connects this check to a NIST control and explains the additional evidence an assessment needs.

## Local checks and model judgments

Local JSON, inventory, YARA and text predicates evaluate supplied evidence directly. Admitted
checks can report `pass` or `fail`; missing evidence and refused work remain explicit.
Syntax helpers select source text for later checks and retain its identity and byte offsets.

Model-assisted audits work today. AudiToad sends live requests when enabled, decodes answers,
applies the baseline's thresholds, connects helper results to later questions, and retains
the evidence and model suggestions. Retained exchanges can be replayed, and suggestions can
be scored against labels.

The final status is a separate policy. This release retains model judgments and external
helper results as suggestions and does not promote them to accepted final audit decisions.
A successful model evaluation can therefore have a `suggested_result` of `pass`, `fail` or
`review` while its terminal result remains `not_evaluated`. That status alone does not mean
the model was never called; inspect the retained answer and reason. Dependent checks retain
the experimental status, and scans with these results exit 2.

The [web-security example](examples/web-security/README.md#results-on-the-owasp-benchmark-for-python)
already includes labelled Jev benchmark measurements, with failures and reviews. Those results
belong to the recorded baseline revisions and do not establish current or general model accuracy.
The [roadmap](ROADMAP.md) separates baseline qualification from the implemented model workflow.

That roadmap includes broader baselines for indicators of compromise (IoCs), OWASP and
MITRE ATT&CK, and screenshot-assisted review of selected manual STIG checks. Experimental
PNG/JPEG support already exists, including native image requests to TypeSafe's Jev model;
screenshot-based compliance baselines remain planned work. See the
[image example](examples/jev-images/README.md) for the current binding.

## Install

From a source checkout, with Rust 1.99.1 and a native build toolchain:

```console
cargo install --path . --locked
auditoad --help
```

## Run a scan

Check an inventory against a rule requiring disk encryption:

```console
auditoad baseline validate examples/disk-encryption/baseline.json
auditoad scan --baseline examples/disk-encryption/baseline.json --input examples/disk-encryption/inventory.json --report report.json
```

The supplied inventory has an encrypted disk, an unencrypted disk and a disk with no encryption
fact. The report contains a pass, a failure and an unresolved result. The command exits with
code 2 because the missing fact leaves the audit incomplete. Open `report.json` to inspect each
record. This example checks supplied inventory data and makes no network requests.

A baseline specifies what to check, which evidence to use and how to evaluate each result.
Profiles select groups of checks and determine which results block a scan. See
[Writing baselines](BASELINES.md) for the format, examples and guidance on choosing questions.

| Exit code | Meaning |
|---|---|
| 0 | Scan completed without a blocking result |
| 1 | Scan completed with a blocking finding |
| 2 | Unresolved or experimental results, an incomplete scan, or a report-write failure |
| 3 | Invalid inputs or baseline |

## Model questions

The shipping-policy example checks a Python function against a written rule: orders of at least
5,000 cents receive free shipping. Prepare its question and evidence locally:

```console
auditoad scan --baseline examples/shipping-policy/baseline.json --input examples/shipping-policy/bundle.json --report prepared.json
```

Preparation makes no provider request. To send the question to a model, add
`--evaluators <file> --live` with an evaluator file that names your backend. The examples include
one for [TypeSafe's Jev](https://typesafe.ai/), a model that answers focused questions with typed
values and probabilities (`examples/evaluators.json`, which reads `TYPESAFE_API_KEY`), and one
for a local OpenAI-compatible server (`examples/evaluators.local.json`).

Baselines never name a model. An evaluator file maps each question role to TypeSafe's question
API, a compatible-chat server such as llama.cpp, Ollama or vLLM, or AudiToad's neutral service
protocol for models and conventional helpers. Swap implementations by editing that file;
see [Choose the models](docs/user-guide.md#choose-the-models).

The [examples guide](examples/README.md) explains the files, commands, expected results and how
to supply your own inputs. The [Jev image example](examples/jev-images/README.md) demonstrates
experimental native PNG requests and Box location helpers.

## Audit files

For recurring audits or comparisons, put named runs in an audit file:

```console
auditoad run examples/audit.json
```

This example combines inventory, code, writing and event checks. It prepares model requests
locally; add an evaluator configuration and `--live` to enable them. Each run keeps its report,
and the suite includes scores wherever you supplied labels. See [Audit files and suites](docs/user-guide.md#run-an-audit-file-or-suite).

## Rust library

Add `auditoad` to your dependencies. The main entry points are `ValidatedBaseline`, `Snapshot`,
`scan` and `scan_to_file`; see the [API documentation](https://docs.rs/auditoad) for a usage example.

## Where it started

I started AudiToad because I needed a better way to audit my own work, especially formal
methods research. The idea grew as I explored other uses across my interests, including
security, compliance and writing. That practical need and the Automation Structures research
both shape the project.

## Development

The [documentation index](docs/README.md) links the build, architecture, developer and user guides.
The [Automation Structures case study](docs/automation-structures.md) explains how the scanner
uses the crate's actual owners and actions. The repository also includes a
[self-audit baseline](audit/README.md) for selected implementation requirements.

See [Contributing](CONTRIBUTING.md) for contribution and release steps. Implementation and compatibility changes are documented in the
[changelog](CHANGELOG.md).

## License

Available under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.
