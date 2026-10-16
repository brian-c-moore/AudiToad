# Developer guide

Begin with the [architecture](architecture.md) and [construction walkthrough](automation-structures.md).
The public CLI, library and example baselines are the user interfaces. Keep normal audit workflows
usable through those interfaces.

## Find the implementation

| File | Owns |
|---|---|
| `src/main.rs` | CLI arguments, input dispatch and user-visible status |
| `src/audit.rs` | Audit declarations, default resolution, cross-run custody and canonical suite progression |
| `src/lib.rs` | Public Rust entry points and errors |
| `src/schema.rs`, `src/json.rs` | Typed documents and strict JSON decoding |
| `src/baseline.rs` | Baseline validation, selection and known-answer rule checks |
| `src/source.rs` | File confinement, bounded reads, snapshots and identities |
| `src/bundle.rs` | Pinned file reads and text/PNG evidence with explicit spans/regions |
| `src/scoped.rs`, `src/collection.rs` | Complete unit enumeration, declared context and correspondence between inputs |
| `src/evaluator.rs` | Deterministic evaluators, declared model state selection and scripted test responses |
| `src/markdown.rs` | CommonMark vocabulary, list and paragraph predicates with Unicode word boundaries |
| `src/command_line.rs` | Command-line token and option interpretation without executing the subject |
| `src/syntax.rs`, `src/tlaplus.rs` | Bounded source-faithful syntax captures and narrow written TLA+ relationships |
| `src/evaluators.rs` | Evaluator files, backend request formats, bounded HTTPS and response validation |
| `src/scan.rs` | Canonical scan composition, record commitment and report publication |
| `src/score.rs` | Label correspondence, canonical result reductions, bounded score inputs and paired comparisons |
| `src/replay.rs` | Original-exchange custody, replay and canonical preparation of bounded reuse inputs |
| `tests/` | Public API, CLI, refusal and canonical-contract tests |
| `examples/`, `docs/` | Runnable audit baselines and user/developer documentation |

## Make a change

Describe the required behavior before selecting an implementation. Identify its state,
transitions, success conditions and refusal paths. For governed behavior, find the existing
canonical owner or composition and show which actions decide the outcome.

Reuse that implementation. Domain questions, data formats, scoring criteria and physical I/O
bindings belong in the application. A second scheduler, budget, registry, lifecycle or aggregate
owner does not become domain content because it has a different name. If the required action
cannot be expressed through the published API, record the exact gap before substituting code.

Trace a new binding through validation, snapshot identity, evidence selection, admission,
evaluation, commitment and reporting. A parser or HTTP client must not create an independent
execution path that bypasses scan ownership. Keep effect identity and refusal behavior visible.

Use checked conversions and arithmetic at identity and size boundaries. Reject unknown fields
and unsupported combinations. Return an explicit unresolved or invalid result when evidence is
missing; do not invent a passing default. Keep dependencies locked and unsafe code denied.
The only unsafe-code exceptions are the foreign declaration and static language-function
construction in `src/verus.rs`, which bind the bundled upstream Verus grammar. Keep those
exceptions confined to that binding; scanner, evaluator and test code retain the denial.

## Test behavior and refusal

Use the [build commands](build.md#verify-a-change). Tests should distinguish the intended
behavior from a plausible failure: changed input after snapshotting, missing context, exhausted
budget, a wrong response identity, or a report path that overlaps an input.

`tests/support/` owns temporary test-directory setup under Cargo's target directory, allowing
source checkouts to remain read-only. `tests/fixtures/` holds fixed local
evaluator inputs. Product tests must be self-contained in the package and must not depend on
private baselines, credentials or development reports. Keep model answers scripted or local
unless a live experiment is explicitly intended.

Mock replies normally match a rule, revision, instruction hash and evidence hash. An optional
`target` restricts a reply to one exact target ID, allowing distinct recorded answers when two
targets have identical evidence. Generic and target-specific replies cannot overlap for the
same rule and hashes. A replay remains a mock observation and does not measure fresh inference.

`src/scan.rs` has fault controls for canonical coupling. These exercise refusal when a required
owner action is bypassed. Passing tests establish their checked behavior; they do not prove
every possible adapter, interleaving or platform behavior.

## Change a baseline or example

Keep the example's audit subject separate from its expected results. Put explanations and
observations in its guide, and select only the required subject and policy in the bundle.
Do not put answers in source comments or send an answer table as evidence.

When bytes change, update the bundle hashes and rerun preparation. When a question changes,
revise its identity and preserve the earlier observation as belonging to the earlier inputs.
Show incorrect and unresolved answers alongside correct ones. Run example commands through the
installed CLI; a private test harness is not the public usage path.

## Review and document

Explain what changed, why, how it was tested and what remains outside the result. Keep architecture
and API claims tied to the implementation. Public documentation should explain behavior and use;
private audit histories and consumer-specific policy do not belong in the package.

For an interface change, update help, examples, authoring guidance and compatibility notes
together. See [Contributing](../CONTRIBUTING.md) for contribution and release commands.
