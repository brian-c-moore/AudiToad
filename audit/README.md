# Audit AudiToad

This baseline asks 24 implementation questions about AudiToad itself. It covers provider
opt-in and TypeSafe response validation, work accounting, experimental results, publication and JSON
decoding. It is a public baseline for this repository, separate from the runnable examples.

The [results note](RESULTS.md) records current source selection and development observations
for the earlier compound and atomic questions. The current source selection includes the updated
semantic-result path for closed-choice answers; the separate Choice decoder is outside these
24 checks.
Version 7 pins complete source files and selects the named owners with local syntax queries. Provider
checks include dispatch and opt-in/origin guards; accounting checks include the manifest,
budget/commit bindings and complete terminal records; publication includes protected inputs
and credential paths, including their configuration-time declaration. These packets still cover only the declared 24 questions. Neutral protocol
decoding, compatible-chat model identity, PNG ingestion and propagation through experimental local consumers have separate
product controls; this baseline does not claim to cover those complete implementations.
The response packet selects the TypeSafe probability decoder and its finite/range
helper. Provider packets select the model dispatch, opt-in and egress guards and
the existing budget binding; accounting selects the manifest and complete
terminal-commit loop; publication selects entry points, protected inputs,
credential paths, the error-returning coupling helper and the write/persist/acknowledgment path.
Eight syntax queries select complete named functions and response declarations, plus the two exact declarations
that compute `unresolved` and assign the overall outcome. The current local development scan
reused five validated Qwen helper responses offline with zero errors against version 4. The 24
judgment questions were switched off. That historical quotation check is not a Jev policy
measurement. Version 5 supplies the previously omitted publication refusal helper and credential
declaration caller, and distinguishes fresh provider HTTP from local preparation, mocks, replay
and reuse. Version 6 kept those questions unchanged and refreshed the scan source pin;
its selected accounting function includes the local Python constant-string predicate's
cumulative output-budget match. Version 7 updates the strict JSON parser source and selects
the duplicate-key visitor, typed parser and new value parser together. Report loading now uses
the already validated JSON value directly; the same visitor and trailing-input refusal remain
in that path. The performance effect has not been measured. Versions 6 and 7 have no fresh Jev measurement. One historical version-5
Jev development run made 24 calls, with nine correct pass
suggestions, zero wrong suggestions and fifteen reviews on the 24 negative controls.
The [version-5 decision score](v5.score.json) binds those observations to that exact prior
source snapshot; it does not measure versions 6 or 7. All judgments remain unadmitted.
It also does not cover scoring, suite execution, reuse preparation or every module's construction.
The new `python_value` implementation is outside these 24 questions and has not been audited
by this baseline.
Its historical model observations cannot qualify those paths. Mechanically decidable owner
coupling and refusal checks belong in deterministic source controls and product tests.

From the repository root, with `auditoad` installed:

```console
auditoad baseline validate audit/baseline.json
auditoad scan --baseline audit/baseline.json --profile all --source evidence --input audit/bundle.json --project-root . --report prepared.json
```

`bundle.json` identifies the source revision through file hashes. The baseline's local
`syntax/1` queries capture complete named functions, the TypeSafe response declarations with
their validation attributes and the two experimental-outcome declarations. `policy.md` states
the requirements. The report records
37 applicable checks: eight local syntax observations, five quote-helper records and the
24 implementation questions. Other rule/target pairs are `notapplicable`.
Preparation calls no provider and exits 2. With the default evaluator file, helpers are off and
a live run can make at most 24 Jev judgment calls. An explicitly configured helper arrangement
can add five quotation calls.

To submit the selected source and policy, run the command below.
[`evaluators.json`](../examples/evaluators.json) sends questions to Jev using `TYPESAFE_API_KEY`
and switches optional helpers off. It submits source code about credential-path handling,
without reading or supplying an actual credential file as audit evidence:

```console
auditoad scan --baseline audit/baseline.json --profile all --source evidence --input audit/bundle.json --project-root . --evaluators examples/evaluators.json --live --max-provider-calls 24 --provider-timeout-seconds 10 --report report.json
auditoad score --report report.json --labels audit/labels.json
```

The 24 labels are author-reviewed "no violation" expectations for the selected current paths.
They measure false alarms on these controls, not detection of defects. Syntax observations and
helper quotations are excluded from that policy denominator.

Whole files are parsed locally. Provider state contains selected capture text strings, policy
and optional helper quotes. The five helpers supply advisory verbatim excerpts and make no
compliance decision. The draft judgments receive the two outcome declarations directly from
the syntax parser. Judges retain the complete selected owners even when a helper is switched
off. The declared request ceiling is 120,000 bytes so complete accounting functions are not
truncated.

The terminal results remain `not_evaluated`. Read the suggestions alongside the source and
the product tests. These questions do not replace testing, dependency review or a complete
security audit. Response identity, probability range and token usage have separate checks;
opt-in and allowed origin are also separate guards. The
[authoring guide](../BASELINES.md) describes how to decompose these requirements.

After a source change, inspect whether the selected functions and callers still supply the
necessary evidence. Update selector names and hashes deliberately. A hash mismatch should cause refusal
until that review is done; replacing the hash alone does not establish that the new evidence
still answers the question.
