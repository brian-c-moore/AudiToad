# Changelog

## 0.0.1-beta.1

- Add explicit TypeSafe native PNG/JPEG image assets for state, instructions and criteria, retaining original-byte custody and unchanged default text requests.
- Add experimental `box/1` location helpers with strict normalized-coordinate decoding and committed fields for later checks. They require fixed Jev 1.14 and the image preview opt-in; they make no policy verdict.
- Add inclusive local `json-number-range/1` checks for declared numeric and geometry tolerances.
- Collection inputs can select nested JSON values with `json_pointer`, retaining complete-file custody while scoping checks to individual rows. Distinct projections of the same file share its confined read and strict parse.
- Collection baselines can expose computed file identities to local checks, allowing direct receipt-to-file hash comparisons without a preprocessing script.
- Collection manifests can pin complete input files and source dependencies before any model question is dispatched.
- Add explicit `verus` syntax helpers through an immutable upstream grammar. Verus operators and contracts retain their original bytes and capture offsets; incomplete parses still withhold fields.

- Baselines can declare the `requirements` an audit must cover; rules name the requirement
  revisions they check, and profiles can narrow which requirements they must cover. Reports
  give each requirement a status. Missing, unasked, stale, unsupported and unresolved
  requirements block the audit (exit 2) and are named in `outcome_reason`. Baselines without
  requirements scan as before.

- Native image and Box observations remain experimental and do not admit an audit.

- Use automation-structures 0.4.0 from crates.io.

- Evidence bundles retain complete pinned text files and reject `start_line` and `end_line`.
  Syntax helpers select named functions locally; quotation helpers and explicit projections
  supply selected code to model questions. Source hashes and byte bounds remain in evidence.

- The helper evaluator example configures a local Qwen2.5-Coder text model through
  llama.cpp, with separate Jev judgments and bounded requests.

- OpenAI-compatible extraction uses strict JSON Schema for the declared field names and
  types, with separate validation that quotations occur verbatim in the supplied evidence.

- Model checks can require a non-null value from each `state_required_any` group of projected
  fields. Python helpers and policy questions refuse dispatch when their selected function
  is absent, even if an import or optional helper context remains. Named capture projections
  select unique source text by query label and refuse ambiguous or malformed selections.

- Reuse can select fresh live replies from reports that also contain reused answers, while
  retaining the requirement to name each answer's original live source.

- Enforce strict compiler and Clippy rules for checked access, arithmetic and conversions, typed error handling, resource cleanup and guards across await points.

- Shared scan/model capacity uses canonical `FederatedBudget` pools and permission ceilings.
  Admissions and refusals follow its owner actions, including rollback after refused delegation.

- Scoring and multi-model result totals use the scanner's shared canonical `Reduction` binding,
  including missing/unresolved coverage and policy simulations. Suite totals reuse that binding.

- Configured model slots advance through canonical `Sequential` and `AuditSink`. First-resolved
  fallback retains selected/skipped slots under `role_execution` without issuing skipped calls.

- Inventory freezing, source verification, reuse-report preparation and score-file loading use
  canonical finite progress. Inventory frames and combined reuse/score inputs have canonical
  byte allowances. `auditoad score --max-input-bytes` sets the combined score-input limit.

- Empty inventories and wholly inapplicable selections retain their reports, exit unresolved
  and explain that no applicable checks ran. They cannot produce a clear audit disposition.

- A local scanner-export example checks declared completion, coverage and findings separately,
  with labelled development data and missing-evidence behavior. Fixture digest refusals show
  both expected and computed identities to support reviewed baseline authoring.

- Compatible-chat responses require the expected model identifier for every task. Operators
  can declare the exact returned identifier for a request alias with `response_model`; that
  policy is retained in report identity and invalidates incompatible replay/reuse.

- `auditoad-compatible` connects models or conventional helper services through a versioned
  neutral protocol. Explicit task capabilities participate in evaluator/reuse identity.
  Replies must match implementation, question identity and declared fields; the existing
  synchronous effect, budgets, egress and publication boundaries govern each exchange.

- Evidence bundles retain pinned PNG bytes, header dimensions and declared regions for
  compatible image helpers. Original images remain intact; text-only bindings refuse visual
  payloads, and automatic text scope refuses image subjects. Pixel decoding/OCR quality are
  helper responsibilities with separate qualification.

- Repair experimental evidence admission: local checks and closed consultation gates cannot
  turn unqualified model/helper fields into terminal clearance. Experimental status propagates
  through derived observations; suggested decisions remain available for labelled scoring.

- Public roadmap defines alpha, beta and production gates, baseline research priorities,
  interchangeable tool/model helpers, image evidence and a repeatable authoring workflow.

- Answer reuse: `--reuse REPORT` (repeatable) and audit-file `reuse` lists answer each exchange
  whose evaluator identity, complete evidence and exact request bytes equal a retained original
  live exchange, without a new request; every other exchange is asked with `--live` or prepared
  without it. A run's own `reuse` overrides the file default, an empty list and `--no-reuse`
  force fresh answers, and nothing is reused unless a source is named. Reused answers carry
  provenance naming the source report and response hash, are counted as `reused_exchanges`
  apart from `provider_calls`, and are never themselves a replay or reuse source.

- Reuse usage totals follow canonical reductions over committed observations. Global and
  per-model totals must agree before a report can be published.

- Self-audit source selections and hashes were reviewed after reuse. Accounting evidence now
  includes manifest construction and owner bindings; historical model results remain qualified
  to their original source.

- `json-pointer-contains/1` checks exact membership of one evidence value in an evidence array.
  It preserves typed equality, checks every position and leaves missing or non-array inputs
  unresolved. This supports selected-property and policy-list checks without model calls.

- The formal-claims example reads the original claim against an explicit proposition using
  asserted/not-asserted/insufficient choices. Four pinned local status checks replace a model
  question about the declared synthetic proof-support record. The original 36 cases and 108
  expectations are preserved, with 16 additional status labels. Preparation scores 20 correct,
  zero wrong and 104 unresolved observations without model calls; a live run needs at most 68.
  One Jev 1.13.0 development run scored 100 correct, zero wrong and 24 unresolved across all
  labels, including 24 correct and 12 unresolved parent judgments. These remain experimental.

- `tlaplus-relation/1` checks a direct alias, positive written conjunct or exact weak-fairness
  form locally, using typed operand pointers and the existing bounded parse. Missing or
  ambiguous definitions remain unresolved. Reports retain definition and witness spans.

- TLA+ and TLAPS syntax helpers use the pinned `tree-sitter-tlaplus 1.5.0` grammar through
  the existing bounded `syntax/1` binding. Captures preserve source definitions and proof
  leaves; they do not resolve selected formulas or establish proof-checker success.

- `json-pointer-compare/1` compares two values from the same frozen JSON evidence frame locally.
  Missing operands remain unresolved; reports preserve both pointers and values. This supports
  exact evidence-identity comparisons without model calls or case-specific expected constants.

- Formal claim questions separate assertion reading from artifact judgment. The example retains
  original prose, external labels and strict parent resolution; confidence does not qualify
  semantic accuracy or grant compliance clearance.

- Formal claim examples cover TLA+, TLAPS and Verus with 36 authored sound, obvious-overclaim,
  subtle-overclaim and disclosed-limitation cases. Separate claim/artifact questions and strict
  combinations retain uncertainty; external development labels and reviewer witnesses explain
  the expected distinctions. Synthetic status records are not proof-checker receipts.

- `scan --replay` and audit-file `replay` reuse original retained response bytes through the
  installed backend decoders without credentials or HTTP. Exact source, evidence, evaluator
  and request identities must match; missing or changed exchanges remain unresolved. Reports
  retain explicit replay provenance, and replay inputs are protected from output overwrites.
- Consulted combined-model answers exclude nested transport metadata, keeping later questions
  independent of scan timing and response bookkeeping while preserving the original records.

- Label files can declare dataset identity, revision and development/calibration/holdout split.
  Scores retain that declaration and show resolved accuracy beside decision coverage; unanswered
  cases cannot look like perfect coverage. Split labels do not certify independence.

- Draft baselines can use local `syntax/1` helpers for Bash, Zsh, PowerShell, Python and Rust.
  Pinned Tree-sitter grammars supply exact source captures and diagnostics to consulted questions.
  Errors and resource refusals cannot become complete empty results or policy decisions.

- Scores include every labelled case, including errors and missing records. `score --compare`
  pairs a candidate and reference on the same frozen source snapshot, retaining regressions,
  unresolved answers and recorded request/evidence identities without new model calls.

- Preparation excludes rule/target pairs known to be inapplicable from its model-call bound.
  Execution reuses that same manifest decision and still records every skipped pair.

- `auditoad run audit.json` runs named audits serially with separate reports, optional labels
  and evaluator configurations. Suite custody checks reject cross-run input/output overlap;
  every run retains an outcome even after an earlier finding or unresolved result.
- Scans resolve a declared `default_profile` or sole profile, infer an unambiguous source from
  the input, default bundle roots to their manifest directory, and derive experimental status
  from draft baselines. The old experimental flag remains hidden for compatibility.
- Evaluators can be selected in audit files or through `AUDITOAD_EVALUATORS`; CLI overrides
  take precedence. Live consent remains an explicit `--live` invocation.
- Preparation prints finite target/check counts and an upper bound on model calls. Automatic
  CLI check/call ceilings follow that manifest. Per-model call/byte ceilings and timeouts are
  configurable, and model budget usage is retained in reports.
- Labels can identify a bundle packet or an input and JSON Lines line number, as well as exact
  target IDs. Ambiguous/duplicate selectors are refused and missing targets remain unresolved.

- Scans accept `--max-baseline-bytes` for larger explicit question graphs. The default
  remains 2 MiB; increasing it preserves schema, dependency and execution-budget checks.
- Collection targets share their immutable file-dependency list, avoiding a full copy
  per target while preserving verification before and after scanning.
- Scope matching rejects a different named input before serializing the full scope,
  reducing preparation overhead for large collections without changing selection.
- Scoring keeps missing labelled records in the denominator as unresolved and exits with
  code 2 for incomplete label coverage. Duplicate report pairs and empty label sets are refused;
  an error record cannot be scored as a successful suggested answer.
- Invalid Choice probability sums report the actual total and required tolerance.
- Operators can explicitly allow rounded TypeSafe Choice distributions with
  `choice_probability_sum_tolerance` (maximum 0.01). The default remains 0.000001;
  raw values are preserved and a nondefault policy changes evaluator identity.
- Model-independent baselines. Model questions are `yes-no/1` and `choice/1` with evaluator kind
  `model` and an optional `role`; they no longer name a model. An operator evaluator file
  (`auditoad-evaluators/1`) maps roles to `typesafe-jev` or `openai-compatible` backends.
  `--evaluators <file>` and `--live` replace `--jev` and `--jev-key-file`.
- `allowed_egress` accepts any HTTPS origin and `loopback`; every live endpoint must be permitted.
- `consult` adds earlier rules' answers and observations to a rule's evidence, and can ask a model
  only when a local check reports a candidate.
- `command-line/1` interprets command lines with named `command_grammars`: Windows argument
  rules, declared options and abbreviations, cmd.exe `/C` quoting and launchers.
- Reports are `auditoad-report/2`: retained bytes are UTF-8 text, or hex when not UTF-8, instead
  of integer arrays.
- Source files are verified once before the first check and again before the report returns; a
  change during the scan refuses the report. Bundle packets depend only on the files they select.
- The local test double is `mock-model/1`; scripts use `auditoad-mock-model/1`. The earlier mock
  schema names `auditoad-mock-jev/1` and `checkwarden-mock-jev/1` are refused.
- Model requests are backend-neutral until a backend translates them: a yes-no question has type
  `yes-no`, and mocks answer in AudiToad's own response form. No backend's request-size limit is
  built in: a request is bounded by `--max-request-bytes` (default 1 MiB), the question's own
  `max_request_bytes` and an optional per-role `max_request_bytes` in the evaluator file. The
  question limit no longer has a 120,000-byte maximum.
- `openai-compatible` backends answer `choice/1` questions of up to 26 options from the first
  token's log-probabilities over option letters.
- Evaluator files name models and may declare `roles`: a role uses one model, asks several and
  combines their answers (`first_resolved`, `agreement`, `any_fail`, `all_fail`), or is switched
  `off`. Combined records keep every model's observation.
- `extract/1` helper tasks: a generative model returns declared fields (strings, booleans,
  numbers, lists and verbatim quotes checked against the evidence) for later questions to
  consult. `state_projection` fields may be `optional`.
- `consult` accepts `run_when` values `any_pass`, `any_unresolved` and `all_resolved`, and
  `answers/1` accepts `fail_when: "first_resolved"`.
- `auditoad score` scores a report against an `auditoad-labels/1` file per rule, per model and
  per simulated combination policy.
- A mock script can answer for named models, and `--mock` works with a non-live evaluator file,
  so role strategies can be replayed offline.
- Consulted evidence (`prior`) no longer carries provider request and response hashes, which
  included per-scan check IDs and made evidence hashes differ between scans.
- Removed the `project-files/1` source, the `rust-context/1` and `rust-site-context/1` evidence
  builders and their `include` parts, and pinned-corpus manifests with expected labels. Reports
  no longer carry `corpus` or per-record `expected` fields. Source code is audited through
  `evidence-bundle/1`. The CLI no longer reserves an enlarged stack.
- Web security example for the OWASP Top 10:2025. Version 2 answers each injection weakness as
  the combination of three questions (the operation occurs, request data reaches it, nothing
  neutralizes it), with a `helper` extraction that traces the data for them.
- Example baselines revised so each model question asks one focused judgment:
  - no-slop version 2 asks per-sentence and per-paragraph questions where the rule concerns one
    sentence or paragraph, and uses a helper for the first requested instruction.
  - windows-memory version 2 decides channels, event IDs, `.dmp` names, LSASS targets and
    memory-read access masks with local checks, and asks a model only whether a process-creation
    command requests a memory dump.
  - python-review and shipping-policy version 2 give the questions the language rules they
    depend on.
- The example evaluator files declare roles: `evaluators.json` switches the `helper` role off,
  because Jev does not answer extraction tasks.

## Initial alpha implementation

Initial AudiToad release, formerly developed as CheckWarden.

- Rust library and CLI for declarative, versioned baseline scans.
- Deterministic YARA-X byte checks and JSON inventory predicates.
- Exact JSON predicates and selected-string YARA checks over scoped and bundled evidence.
- Local CommonMark vocabulary, list-length, bold-in-prose and paragraph sentence-length checks with explicit Unicode boundaries and counting rules.
- Declared project and evidence-bundle inputs with source hashes and confined paths.
- Automatic document, paragraph, sentence and record scopes, related input collections and explicit answer dependencies.
- Explicit dependency resolution policy for decisive answers, preserving unresolved children and full scan coverage.
- Canonical Automation Structures for scan order, budgets, effect seats, identity slots,
  audit continuity and result totals.
- JSON reports containing coverage, terminal results, evidence and provider observations.
- Local Jev mock, prepared requests and opt-in serial HTTPS evaluation.
- Jev yes/no and closed-choice questions with explicit uncertainty and answer mappings.
- Optional named field selection for Jev requests, with full local evidence retained.
- Baseline authoring guide with isolated inventory, Python and writing examples.
- User, build, architecture and developer documentation, with an Automation Structures case study.
- Public self-audit baseline and recorded experimental observations.

The crate, executable and Rust import are `auditoad`. New JSON output schemas use the
`auditoad-` prefix. Version-one `checkwarden-` baseline, project, evidence-bundle, inventory
and mock inputs remain readable, including the old bundle media type. There is no old executable
alias. Renamed input files have new byte identities; existing reports are not rewritten.

Semantic controls remain experimental and return `not_evaluated` with suggested decisions.
This release does not provide recursive source discovery, a Git-diff selector, automatic retry,
parallel provider calls, crash recovery or an aggregate architecture judgment.

Licensed under MIT OR Apache-2.0.
