# Check a Python shipping function

This is a single-rule baseline. The requirement says orders of at least 5,000 cents receive
free shipping. The audit pairs the function with that written policy and asks whether its
returned fee can disagree.

| File | Why it is here |
|---|---|
| `shipping.py` | The function being audited |
| `policy.md` | Its required behavior |
| `baseline.json` | The question, evidence roles and response thresholds |
| `bundle.json` | The two files and their SHA-256 identities |

Run from this directory with `auditoad` installed:

```console
auditoad baseline validate baseline.json
auditoad scan --baseline baseline.json --profile experiment --source project --input bundle.json --project-root . --report prepared.json
```

Preparation calls no provider. It records one question with the source and policy, then exits
2 because the question has no answer yet. To submit it, run the command below. [`evaluators.json`](../evaluators.json) sends questions to
Jev and reads `TYPESAFE_API_KEY`; pass [`evaluators.local.json`](../evaluators.local.json) or your
own evaluator file to use another model:

```console
auditoad scan --baseline baseline.json --profile experiment --source project --input bundle.json --project-root . --evaluators ../evaluators.json --live --max-provider-calls 1 --provider-timeout-seconds 10 --report report.json
```

The function charges 500 cents at exactly 5,000 cents because it uses `>` instead of `>=`.
That violates the policy. This explanation is outside the provider evidence; the source has no
comment revealing the issue. A model response can suggest pass, fail or review. The terminal
result remains `not_evaluated`, and live execution exits 2.

Live runs returned 0.42 on 2026-09-28 and 0.73 on 2026-09-29, both review suggestions under the
declared thresholds.
Neither resolved this defect. The first run's scan ID was `58b2a867-4c03-471f-8c79-dfac7bc03d24` and its
raw report SHA-256 was `e5ec9476bdc76458d76db00535a0e3e13616bfeff6ab9f097e3dd7bcc0bc7f74`.

This question asks for numeric behavior over all order totals. Jev's source-reading score does
not establish that behavior. The example retains the unsuccessful question so its limitation
can be inspected; use execution or analysis evidence to qualify the full shipping requirement.
Hardcoding this function's operator into the question would narrow the requirement to one
implementation pattern. See [check design](../../BASELINES.md#design-the-check-before-writing-the-question).

In the baseline, `required_roles` selects both the function and policy. `criteria_true` defines
a disagreement; `criteria_false` defines agreement. The `draft` status automatically keeps
the semantic result unresolved. Change the question and policy together for a different
requirement, then update the bundle's hashes when input bytes change.

The [Python review example](../python-review/README.md) adds multiple independent checks and
comparison functions. Each example can be run on its own.
