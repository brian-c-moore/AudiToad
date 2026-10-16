# Contributing to AudiToad

Start with the [developer guide](docs/development.md). The [build guide](docs/build.md) covers
prerequisites and releases; the [architecture](docs/architecture.md) explains the scan.

Use the pinned Rust toolchain and lockfile. A checkout of this repository contains the source,
tests and test inputs needed for development; no model credential is needed for the default checks.

```console
cargo fmt --all -- --check
cargo test --locked -- --test-threads=1
cargo clippy --locked --all-targets -- -D warnings
cargo doc --locked --no-deps
cargo package --locked
```

Run Cargo from the repository root. The checked-in configuration limits builds to two jobs and
uses `target/`. The package
check builds the distributable source; it does not upload it. CI runs these commands on Windows
and Linux with a 30-minute limit per job. Registry publication is a maintainer action.

`Cargo.toml` declares the compiler and Clippy policy for this standalone crate. Run Clippy
explicitly: ordinary `cargo build` does not execute it. Source and test setup must not use
`unwrap` or `expect`. Preserve typed failure outcomes and checked access, arithmetic and
conversions. A scoped lint exception needs a specific reason and contract review.

Keep scan mechanics separate from baseline content and physical bindings. Reuse the published
Automation Structures and existing compositions. For a mechanism change, describe its required
behavior, actual canonical owners and actions, coupling, refusal paths and any missing API before
implementing it. Do not add a second budget, scheduler, registry, lifecycle or audit authority.

`src/scan.rs` connects `ResourceRegistry` for identity slots, `Sequential` for scan order,
`Budget` for scoped limits, `FederatedBudget` for shared scan/model capacity and permissions,
`ActuationPass` for effects, `AuditSink` for ordinal continuity
and `Reduction` for result totals. Baseline content and evaluator bindings use this construction.

## Source layout

| Files | Purpose |
|---|---|
| `src/lib.rs`, `src/main.rs` | Library entry points and CLI |
| `src/schema.rs`, `src/json.rs`, `src/baseline.rs` | Input/output types and baseline validation |
| `src/source.rs`, `src/bundle.rs`, `src/scoped.rs`, `src/collection.rs` | Input snapshots, evidence bundles, unit enumeration and related evidence |
| `src/evaluator.rs`, `src/evaluators.rs` | Local evaluators, mock responses and model backends |
| `src/scan.rs` | Scan composition and report publication |
| `tests/` | Behavior, canonical API and fault controls; shared fixture setup in `support/` |
| `examples/` | Isolated inventory, Python and writing audits with their own guides |
| `tests/fixtures/` | Fixed inputs for deterministic and mock evaluator tests |
| `docs/`, `audit/` | User/developer guides, construction case study and public self-audit baseline |
| `Cargo.toml`, `Cargo.lock`, `rust-toolchain.toml`, `.cargo/` | Dependencies and build configuration |
| `build.rs`, `src/verus.rs`, `vendor/tree-sitter-verus/` | Bundled upstream Verus grammar, license, provenance and native binding |
| `.gitignore`, `.gitattributes`, `.github/` | Repository exclusions, fixture byte preservation and CI |
| `README.md`, `BASELINES.md`, `CONTRIBUTING.md`, `CHANGELOG.md`, `LICENSE-*` | Usage, authoring, development, releases and licenses |

## Tests and evidence

Changes to evidence or predicates need positive, negative and unresolved controls. Preserve the
input bytes and expected results used to reproduce a reported discrepancy.
Keep expected labels outside provider requests. Record the question, evidence and retained
observation when reporting a model discrepancy. Experimental scores are not admitted findings.

Reports retain submitted evidence. Review their contents before sharing them in an issue.
Keep credentials in the environment or a key file outside the repository. Never include them
in fixtures, baselines, reports or pull requests.

## Releasing

The maintainer publishes the repository at `brian-c-moore/auditoad` and the crate at crates.io.
Keep the crate version and changelog aligned, run the checks above, and review `cargo package --list`
before publication. Commit the source and lockfile, let both CI platforms pass, then use
`cargo publish --locked --dry-run` followed by `cargo publish --locked`. Create the matching
`v<version>` Git tag and GitHub release from that source revision. The CI workflow does not
publish packages, create releases or call a model.
