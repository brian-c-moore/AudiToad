# AudiToad 🐸

AudiToad is a general-purpose, AI-backed audit tool. Define an audit once, run it as your project
changes, and trace each result back to its evidence.

Your work has rules worth checking: writing must follow a style guide, a function must meet its
requirements, or an inventory must satisfy a security policy. Put those checks in a **baseline**,
along with the evidence each check needs and how to evaluate the result. Combine focused
questions to the models you choose with local YARA rules and inventory checks to build an audit around your
project's requirements.

AudiToad works through the checks and records the results, evidence and coverage in a report
you can inspect, share or process with other tools. Reuse the baseline for the next revision,
or write a new one for a different project or kind of audit.

Use AudiToad from the command line or integrate its Rust library into your own tools. Its scan
engine uses the published Automation Structures 0.4.0 crate.

Start with the [user guide](docs/user-guide.md) or choose a [self-contained example](examples/README.md).
AudiToad accepts supplied text, byte inputs and inventory records; the subject does not have to
be a code project. Python and other tools can invoke the CLI and read its JSON reports.

Model questions and external helper results remain experimental; use their suggestions and labelled scores alongside the retained evidence.
The [roadmap](ROADMAP.md) defines release gates, model-specific baseline research and the path
to production. The [helper contract](docs/user-guide.md#neutral-evaluator-protocol) supports
compatible models and conventional services. Baselines can declare the requirements an audit
must cover, and reports show any requirement left unchecked or undecided. Image
evidence is experimental; the [Jev image example](examples/jev-images/README.md)
shows explicit PNG/JPEG requests and Box location helpers.

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
one for TypeSafe's Jev (`examples/evaluators.json`, which reads `TYPESAFE_API_KEY`) and one for a
local OpenAI-compatible server (`examples/evaluators.local.json`).

Baselines never name a model. An evaluator file maps each question role to TypeSafe's question
API, a compatible-chat server such as llama.cpp, Ollama or vLLM, or AudiToad's neutral service
protocol for models and conventional helpers. Swap implementations by editing that file;
see [Choose the models](docs/user-guide.md#choose-the-models).

Model questions currently produce experimental observations and suggested decisions. Their terminal
result is `not_evaluated`, and the scan exits with code 2. The [examples guide](examples/README.md)
explains the files, commands, expected results and how to supply your own inputs.

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

## Development

The [documentation index](docs/README.md) links the build, architecture, developer and user guides.
The [Automation Structures case study](docs/automation-structures.md) explains how the scanner
uses the crate's actual owners and actions. The repository also includes a
[self-audit baseline](audit/README.md) for selected implementation requirements.

See [Contributing](CONTRIBUTING.md) for contribution and release steps. Version changes and input compatibility are documented in the
[changelog](CHANGELOG.md).

## License

Available under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.
