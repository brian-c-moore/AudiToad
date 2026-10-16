# Python audit observations

## Current development measurement

Version 6 on 2026-10-16 specifies two successive completed calls of the unchanged selected
function, using distinct strings, retaining both returned lists and excluding caller mutation
between calls. Only the two list questions changed. Source functions, expected answers,
shipping question and fixed 0.1/0.9 thresholds remain unchanged.

The Jev-only development run made four new calls and reused 12 unchanged exchanges under their
complete identities. It matched **12 of 14 final policy labels, with zero wrong and two
unresolved**, and reported no transport or decoding errors. `shipping_fee` remains unresolved
at 0.58. The `add_message` list parent remains unresolved because its identity and content
premises returned 0.49 and 0.25. The separate four list diagnostics matched two answers and
left two unresolved, with zero wrong; they are not additional policy cases.

The [version-6 policy score](v6.score.json) SHA-256 is
`8aaae06b26e686284e07ed975fb1b05cc1913a7de72d40d2deb014ae192eef8c`.
Its original report SHA-256 is
`f279017506819ebb245181c8519c614629b2c4752016c494e597ae29679e186d`.
The version-6 baseline SHA-256 is
`8dbfc3ae915eb79ab91ef8efdbddbb821e59ee3f26cb141c1f5f2026d75aa84d`.
The bundle and both label sets retain the identities recorded below. This is one further
development run on the same authored examples, with no improvement in policy coverage.
All semantic terminal outcomes remain `not_evaluated`; source reading does not establish
numeric execution or complete Python object-lifetime analysis.

## Recorded version-4 and version-5 measurements

On 2026-10-16 the version 4 Jev-only run made 16 calls with no transport or
decoding errors. It matched 10 of 14 final policy labels, with zero wrong and
four unresolved. Version 5 clarified four question families before one further
development run: shipping equality, lowercase normalization and the two separate
list-lifetime premises. Source functions, expected answers and 0.1/0.9 thresholds
stayed fixed. Eight unchanged exchanges were reused under their complete identities;
eight revised questions were sent to `jev-1.13.0`.

| Measure | Version 4 | Version 5 |
|---|---:|---:|
| Final policy labels | 14 | 14 |
| Correct suggestions | 10 | 12 |
| Wrong suggestions | 0 | 0 |
| Unresolved suggestions | 4 | 2 |
| New provider calls | 16 | 8 |
| Reused exchanges | 0 | 8 |
| Transport/decoding errors | 0 | 0 |

Direct product scoring against the current 14-label `labels.json` reproduces these totals
for both retained reports. The paired comparison identifies two policy changes from review
to correct pass: `PY-EMAIL-CASE` on `contact_email` changed from 0.19 to 0.06, and
`PY-SHIPPING` on `express_shipping_fee` changed from 0.13 to 0.07. Both retain the same
source evidence and have revised requests.

The defective shipping function remains unresolved (0.58), and the fresh-list
comparison remains unresolved because its identity and content premises returned
0.25 and 0.33. Those are retained reviews. In each version, the separate four list prerequisite
labels matched two answers and left two unresolved, with zero wrong; they are not added to the
policy denominator. Use `labels.json` for final policy scoring and
`diagnostic.labels.json` for those prerequisites.

The version 4 report SHA-256 is
`e8ea2c5588271584c7f72267111612f8c4085d1fd6495b40741f79ec45c51674`.
The version 5 report SHA-256 is
`ba397511f0cfb7b316d9950485e79fe541aa8fc021740da6df23fe5b0c99b34b`.

The current 14-policy labels SHA-256 is
`6edadc0a76a8653b292f24913d3a7fede5c3cc07e57d47f779fb3da9685de99d`;
the separate four-diagnostic labels SHA-256 is
`45cc0a980fdaf5b1c2dd3aa142900fd12330c2da66e3077fb531496510afb467`.
Earlier scores that combined all 18 labels retain that historical denominator. The current
policy scores and comparison use only the 14 final policy expectations:

| Retained product artifact | SHA-256 |
|---|---|
| [Version 4 policy score](v4.score.json) | `7e047c9d3d607b337d71a6401dbde434d1aea0a5b4057e7ad81b8d66c1d2c6cc` |
| [Version 5 policy score](v5.score.json) | `52e04328656f036ec83ac6ad525888fcbcab1b83e014c9f07ca4aab914b74f66` |
| Version 4 diagnostic score | `1abc4c60adc694caf1543b1973805cddeeb5600ac84ff247f4d394a60f97c89c` |
| Version 5 diagnostic score | `cd7f18eb3e5cfb5bf6b1cfa631cce5140606d53047bf59351a21f541c4a49f3d` |
| Version 5 versus 4 policy comparison | `aa07018bd6123e8e83d58dcc92e3eedd1fb6d7413cecd8216c3ea22be05f5568` |

Both reports use bundle SHA-256
`e640f2a9ed39eab5321c19fbdef4c66d90649638c7e326cdd93e118043780c7f`.
The version 4 baseline SHA-256 is
`a5203522ded191592510d9c745dcf978a14c539fd94eb32dae83295a0584cc70`;
the version 5 baseline SHA-256 is
`55f0213c4e557c206a73bb3291caac3d40832713b64a24a679b0642b31741efb`.
This comparison uses the same authored development cases. It does not establish
accuracy on unfamiliar code. All semantic terminal outcomes remain `not_evaluated`.

## Earlier observations and design

This note separates current design from retained development observations and historical
measurements. Version 2 added Python truthiness context. Version 3 replaced hand-selected
lines with local function-name queries and source-quote helpers and fixed decision thresholds
at 0.1/0.9. Version 4 introduced a mandatory selected-function prerequisite to each helper and policy
question: either `code_a` or `code_b` must be non-null before dispatch. Imports and optional
helper context cannot substitute for a missing function. That revision kept version 3's
questions, thresholds, queries and source; its Jev development measurement is reported above.
Versions 5 and 6 retain these dispatch prerequisites and source selection, with their
question clarifications described above. Semantic admission remains open.
Projections select unique `function` and `imports` capture labels, independent of their
positions. Several imports cannot satisfy function presence; ambiguous matching labels and
malformed selected text refuse dispatch. Multiple imports or duplicate named functions need
a reviewed selection update. Selection still does not establish dependency completeness.
An offline version 4 check reused all ten original Qwen helper exchanges, made zero provider
calls and reported zero errors across 38 applicable checks. Exact evidence, request and model
identity checks remained enabled. This confirms the revised projection accepts those pinned
inputs and retained quotations; it does not add fresh model measurements or policy accuracy.
The old probabilities and calibrated thresholds below retain their original scope; they do not
qualify the current selection, helper or question design.

The retained version 3 helper-only development run used Qwen2.5-Coder-7B-Instruct Q4_K_M through the
existing llama.cpp b11146 server. All ten helpers returned correctly typed, verbatim source
quotations, with ten calls and zero errors. The shipping excerpt included the fallback charge;
`decode_return` quoted its actual decoding call without inventing a handler. Judgment questions
were switched off. These observations establish response and quotation compatibility on the
pinned example, not extraction completeness or policy accuracy. The version 4/5 Jev observations
above are separate measurements; semantic admission remains open.

An earlier development run on 2026-10-13 used Foundation-Sec-1.1-8B-Instruct Q4_K_M with
llama.cpp b11146 for both roles. The first JSON-object request produced ten refused helper
responses. After the provider binding requested strict JSON Schema, nine helpers returned
fields with valid verbatim quotations; `decode_return` still invented an exception handler
and was refused. The corrected run made 25 calls and reused one unchanged exchange.
Valid quotations do not establish completeness: the shipping helper omitted the fallback
charge, and the local judge wrongly suggested pass for `shipping_fee` at the free-shipping
threshold. All semantic results remained unadmitted. This does not qualify the local model,
the optional helper design or the current Jev arrangement for policy decisions.

Version 1 was evaluated on 2026-09-29 using `jev-1.13.0`, selected by
[`evaluators.json`](../evaluators.json). 13 of 14 policy results matched the expected labels,
with one review and no wrong suggestions. `PY-EMAIL-CASE` for `contact_email` returned exactly
0.10; `pass_below` is exclusive, so that answer is a review. An earlier run of the same questions
returned 0.09 and matched all 14. Four model answers are prerequisites of the two list results
and are excluded from the policy denominator. All terminal results remained `not_evaluated`.

| Rule | Function | Expected violation | Probability | Suggestion |
|---|---|---|---|---|
| `PY-SHIPPING` | `shipping_fee` | Yes | 0.82 | fail |
| `PY-SHIPPING` | `express_shipping_fee` | No | 0.17 | pass |
| `PY-MEMBER` | `discount_rate` | Yes | 0.92 | fail |
| `PY-MEMBER` | `renewal_discount` | No | 0.07 | pass |
| `PY-DECODE` | `decode_order` | Yes | 0.97 | fail |
| `PY-DECODE` | `decode_return` | No | 0.06 | pass |
| `PY-EMAIL` | `contact_email` | Yes | 0.94 | fail |
| `PY-EMAIL` | `billing_email` | No | 0.03 | pass |
| `PY-EMAIL-END` | `contact_email` | Yes | 0.95 | fail |
| `PY-EMAIL-END` | `billing_email` | No | 0.04 | pass |
| `PY-EMAIL-CASE` | `contact_email` | No | 0.10 | review |
| `PY-EMAIL-CASE` | `billing_email` | No | 0.04 | pass |
| `PY-LIST-IDENTITY` | `add_note` | Yes | 0.96 | fail |
| `PY-LIST-IDENTITY` | `add_message` | No | 0.53 | pass |
| `PY-LIST-CONTENT` | `add_note` | Yes | 0.97 | fail |
| `PY-LIST-CONTENT` | `add_message` | No | 0.29 | pass |
| `PY-LIST` | `add_note` | Yes | Combined locally | fail |
| `PY-LIST` | `add_message` | No | Combined locally | pass |

Before version 1, an earlier baseline matched 12/14 policy results, with shipping and shared-list
behavior unresolved. Version 1 separated returned identity from retained contents and included
the relevant language semantics. See Python's [default-argument rules](https://docs.python.org/3/tutorial/controlflow.html#default-argument-values)
and [mutable sequence operations](https://docs.python.org/3/library/stdtypes.html#mutable-sequence-types).

Thresholds were selected on a separate development set before the fresh test below. A score
below the pass limit suggests pass; a score at or above the fail limit suggests fail;
intermediate scores require review. These are empirical decision boundaries, not guarantees
that the scores are calibrated probabilities of correctness.

| Question | Pass below | Fail at or above |
|---|---:|---:|
| Shipping at the cutoff | 0.30 | 0.50 |
| Returned list identity | 0.70 | 0.80 |
| Contents from earlier calls | 0.70 | 0.85 |
| Other questions | 0.10 | 0.90 |

The remaining questions distinguished their authored defective and comparison functions in
this run. This does not establish detection rates for other code, policies or question wording.
Function ranges were selected in the bundle before execution; they were not discovered by Jev.
The explanatory table was not submitted as evidence.

Repeat the run with the command in [README.md](README.md).
New calls can return different probabilities. An initial run without network access produced
transport errors; it supplied no model answers and is not counted as an accuracy observation.

## Transfer to other Python forms

With the historical questions and calibrated thresholds frozen, 24 new authored functions tested equivalent
comparisons, intermediate variables, copying, clearing, slice assignment and returned aliases.
Expected labels were recorded before inference. This is author-reviewed validation, not an
independently annotated corpus or a test of arbitrary Python programs. This historical transfer
run does not measure the current version 5 questions or fixed 0.1/0.9 thresholds.

| Result | Correct | Wrong | Review |
|---|---:|---:|---:|
| Shipping boundary, 8 functions | 7 | 1 | 0 |
| List identity, 16 functions | 12 | 1 | 3 |
| List contents, 16 functions | 15 | 0 | 1 |
| Combined list requirement, 16 functions | 14 | 0 | 2 |

The policy-level result is **21/24 correct (87.5%), one wrong and two unresolved**.
The 40 individual model answers are **34/40 correct (85%), two wrong and four unresolved**.
Do not add the parent answers to the leaf answers to claim more independent validation cases.

The shipping false positive treats `total_cents > 4_999` as charging an order at 5,000 cents.
The identity false positive occurs when a shared list is updated through a slice and a copy is
returned. That function does retain prior contents, so its combined violation is correct despite
the wrong identity explanation. List unpacking and replacement through slice assignment leave
two combined results unresolved. These failures remain open; the public example's 100% does
not establish reliable numeric reasoning or complete Python object-lifetime analysis.

An earlier revision also missed leading whitespace retained by `rstrip().lower()`. The current
baseline retains separate leading-whitespace, trailing-whitespace and case-conversion questions.

## Compare a local model on the same questions

The same 40 atomic questions were also submitted to Cisco's
[Foundation-Sec-1.1-8B-Instruct](https://huggingface.co/fdtn-ai/Foundation-Sec-1.1-8B-Instruct),
using its official Q4_K_M checkpoint through llama.cpp. The local model received the same
question, criteria and selected evidence as Jev. It received neither the expected labels nor
Jev's answers. The model and combination policies were fixed before this local run.

| Decision policy | Correct / all 40 | Wrong | Review |
|---|---:|---:|---:|
| Jev | 34 (85%) | 2 | 4 |
| Foundation-Sec | 20 (50%) | 20 | 0 |
| Jev, then Foundation-Sec for reviews | 36 (90%) | 4 | 0 |
| Accept only agreement | 17 (42.5%) | 1 | 22 |

The fallback resolves two of Jev's reviews correctly and two incorrectly. It adds a missed
list-identity violation and a false contents violation. Both models incorrectly flag the
returned identity in the slice-copy case. Agreement therefore leaves one wrong answer despite
requiring review for more than half of the questions. Reversing the fallback equals local-only
because the local model never abstained.

Foundation-Sec answered every shipping question as nonviolating and every contents question
as violating. Those two balanced groups each scored 50%; the identity group also scored 50%.
These observations concern this checkpoint, prompt and single-word output mode. They do not
establish its best achievable performance with other inference settings. No comparison here
establishes mixed-model accuracy for the locally combined list findings.

The 40 local calls took 185.5 seconds, including loading the model for every call, versus 10.7
seconds of recorded Jev provider time. This does not compare persistent-server throughput.
All local calls completed without malformed output or timeout. AudiToad's public semantic
backend for that historical comparison was Jev; the current optional local helper configuration
does not enable automatic verdict fallback.
