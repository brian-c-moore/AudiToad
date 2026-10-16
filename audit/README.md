# Audit AudiToad

This baseline asks 24 implementation questions about AudiToad itself. It covers provider
opt-in and TypeSafe response validation, work accounting, experimental results, publication and JSON
decoding. It is a public baseline for this repository, separate from the runnable examples.

The [results note](RESULTS.md) records the current local development observations and the
earlier compound and atomic questions. The current source selection includes the updated
semantic-result path for closed-choice answers; the separate Choice decoder is outside these
24 checks.
Version 4 pins complete source files and selects the named owners with local syntax queries. Provider
checks include dispatch and opt-in/origin guards; accounting checks include the manifest,
budget/commit bindings and complete terminal records; publication includes protected inputs
and credential paths. These packets still cover only the declared 24 questions. Neutral protocol
decoding, compatible-chat model identity, PNG ingestion and propagation through experimental local consumers have separate
product controls; this baseline does not claim to cover those complete implementations.
The response packet selects the TypeSafe probability decoder and its finite/range
helper. Provider packets select the model dispatch, opt-in and egress guards and
the existing budget binding; accounting selects the manifest and complete
terminal-commit loop; publication selects entry points, protected inputs,
credential paths and the write/persist/acknowledgment path. Eight syntax queries produce
46 captures: complete named functions and response declarations, plus the two exact declarations
that compute `unresolved` and assign the overall outcome. The current local development scan
reused five validated Qwen helper responses offline with zero errors. The 24 judgment questions
were switched off. Current Jev measurements await approval; all judgments remain unadmitted.
It also does not cover scoring, suite execution, reuse preparation or every module's construction.
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
Preparation calls no provider and exits 2. A combined live run can make at most 29 calls:
five helper calls and 24 judgment calls.

To submit the selected source and policy, run the command below.
[`evaluators.helpers.json`](../examples/evaluators.helpers.json) uses a configured local text
helper for source excerpts and sends questions to Jev using `TYPESAFE_API_KEY`; pass
[`evaluators.local.json`](../examples/evaluators.local.json) to check only the local helper with
judgment questions switched off, or supply your own evaluator file:

```console
auditoad scan --baseline audit/baseline.json --profile all --source evidence --input audit/bundle.json --project-root . --evaluators examples/evaluators.helpers.json --live --max-provider-calls 29 --provider-timeout-seconds 60 --report report.json
```

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
