# Check a Python shipping function

This is a single-rule baseline. The requirement says orders of at least 5,000 cents receive
free shipping. The audit pairs the function with that written policy and asks whether its
free-shipping condition excludes an order exactly at the threshold.

| File | Why it is here |
|---|---|
| `shipping.py` | The function being audited |
| `policy.md` | Its required behavior |
| `baseline.json` | The question, evidence roles and response thresholds |
| `bundle.json` | The two files and their SHA-256 identities |
| `labels.json` | The known boundary defect, recorded as one development expectation |

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

The version 2 boundary question returned 0.95 on 2026-09-30, a correct fail suggestion under
the fixed 0.1/0.9 thresholds. This is one already inspected development example, not an
accuracy estimate or semantic acceptance. Its scan ID was `263e2f75-3117-4b83-9a3d-5ec1241f8b3c`.

Earlier broad questions returned 0.42 on 2026-09-28 and 0.73 on 2026-09-29, both review
suggestions. The first run's scan ID was `58b2a867-4c03-471f-8c79-dfac7bc03d24` and its
raw report SHA-256 was `e5ec9476bdc76458d76db00535a0e3e13616bfeff6ab9f097e3dd7bcc0bc7f74`.

The current question isolates the threshold boundary and gives the meanings of Python's
comparison operators. It does not establish numeric behavior over all order totals; use
execution or analysis evidence to qualify that full requirement. See
[check design](../../BASELINES.md#design-the-check-before-writing-the-question).

```console
auditoad score --report report.json --labels labels.json
```

In the baseline, `required_roles` selects both the function and policy. `criteria_true` defines
exclusion at the threshold; `criteria_false` defines qualification there. The `draft` status automatically keeps
the semantic result unresolved. Change the question and policy together for a different
requirement, then update the bundle's hashes when input bytes change.

The [Python review example](../python-review/README.md) adds multiple independent checks and
comparison functions. Each example can be run on its own.
