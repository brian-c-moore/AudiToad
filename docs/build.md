# Build and release

The repository is an independent Rust crate. It uses Rust 1.99.1, edition 2024, its checked-in
lockfile and the published `automation-structures` 0.4.0 crate from crates.io.

## Prerequisites

Install Rust with the pinned toolchain and a native compiler/linker for your platform. Windows
MSVC builds require the Visual Studio C++ build tools and Windows SDK. Linux builds require a
native C/C++ toolchain. The CI configuration lists the tested commands for Windows and Linux;
a configured CI job is not evidence that a particular revision passed it.

The Verus grammar is bundled under `vendor/tree-sitter-verus/` with its upstream license,
revision and file hashes. Cargo compiles those sources during ordinary source and package
builds; a separate Git dependency or grammar-generation command is not needed.

```console
rustup toolchain install 1.99.1 --profile minimal --component rustfmt --component clippy
cargo build --locked
cargo install --path . --locked
```

Run these commands from the repository root. Cargo downloads the locked dependencies when
needed. Once cached, add `--offline` for an offline build. The configuration limits compilation
to two jobs and uses the single `target/` directory.

## Verify a change

```console
cargo fmt --all -- --check
cargo test --locked -- --test-threads=1
cargo clippy --locked --all-targets -- -D warnings
cargo doc --locked --no-deps
```

Also run `cargo package --locked` before release.

Tests use local deterministic evaluators and scripted or loopback provider responses. They do
not need a model credential. The package check builds the distributable archive and does not
publish it. Run the documented example commands as well when changing a baseline or its input.
Before release, run those commands from the unpacked `.crate` archive too. This checks that
the package includes the input files required by each example.

The source layout and testing expectations are in the [developer guide](development.md).
Live model observations require a separate, explicitly enabled run and do not replace tests.

## Prepare a release

Update the crate version and changelog together. Inspect `cargo package --list` and confirm
that the source, distributable tests, example baselines, documentation and licenses are present.
Private reports, credentials, local build output and unrelated consumer baselines do not belong
in the public repository or archive.

Commit the intended source and lockfile, then let the supported CI platforms pass. The
maintainer can run `cargo publish --locked --dry-run` before publishing with
`cargo publish --locked`. Tag the same source revision with `v<version>` and create its release.
CI does not publish packages or run live model audits.
