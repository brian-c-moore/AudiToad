# Self-audit observations

The current version 4 baseline retains 24 atomic implementation questions on six source packets,
with eight local syntax selectors producing 46 captures and five source-quote helpers. There are
37 applicable records and at most 29 combined live calls. Its frozen baseline SHA-256 is
`33d60149623f502386c45e5eb99bba0885151ad2efc5fcc3efd418e7128e34e2`.

The current local development observation on 2026-10-13 reused five retained responses from
`qwen2.5-coder-7b-instruct-q4_k_m` through the ordinary CLI offline. All five helper responses
passed declared-field, type and verbatim-quotation validation. The scan made zero provider calls,
reused five exchanges and recorded zero errors. All 37 applicable results remained
`not_evaluated`, with an unresolved overall outcome; the 24 judgment questions were switched
off. The report SHA-256 is
`2aeab0bc4c729bace3a37dddc6132b53c7c4e4d1403d55695cb775ccacd61774`.
This is a bounded integration observation. It does not qualify helper accuracy, source
correctness or the judgment questions. Current Jev measurements await approval, and all
judgments remain unadmitted.

The experimental-outcome context is now selected mechanically: one syntax query captures the
complete `unresolved` declaration and the following `outcome` declaration inside `scan_bound`.
Both draft judgments retain all four complete function captures and require these two statement
captures. An earlier Qwen DRAFT helper returned a valid quotation of the Retired/Admission guard
instead of the requested outcome statements. Passing quotation validation did not establish
task accuracy; that response remains a development observation of the earlier design.

Earlier development attempts remain separate. A six-helper Qwen design produced three valid
helper responses, quotation refusals for EGRESS and COVERAGE, and a DRAFT timeout. The earlier
Foundation-Sec-1.1-8B-Instruct Q4_K_M run through llama.cpp b11146 used both model roles, strict
JSON Schema output, 4,096 output tokens and a 60-second request deadline. It made 30 provider
calls: one of six helpers returned valid verbatim quotations, four returned invalid quotations
and were refused, and the coverage helper timed out. All 37 applicable results remained
unadmitted or errors. Those outcomes retain their original source and task scopes; they do not
qualify the final design or establish a dependable helper. The historical Jev observations below
also retain their original source and question scopes.

The earlier baseline had 24 atomic checks on six source packets. The source they selected has since changed
(evaluator roles, extraction tasks and scoring were added), so the packets now select the new
named functions, reviewed again after checked-binding repairs on 2026-10-06, and have not yet
been rerun with Jev on the current source. A live run with `jev-1.13.0` on
2026-09-29, bound to the source hashes of that day, suggested pass for 16 checks and left eight
in review. None suggested fail. Every expected label is "no violation", so this run measures
false alarms on correct code, not detection of defects.

| Suggestion | Rules | Probabilities |
|---|---|---|
| Review | `SELF-EVIDENCE-BUDGET` | 0.10 (the pass limit is exclusive) |
| Review | `SELF-ORIGIN`, `SELF-DRAFT`, `SELF-INPUTS`, `SELF-KEY-INPUT`, `SELF-KNOWN-ANSWERS` | 0.13 to 0.22 |
| Review | `SELF-EGRESS`, `SELF-MOCK-INPUT` | 0.34 and 0.56 |
| Pass | The remaining 16 rules | 0.03 to 0.09 |

The egress and credential questions concern the evaluator-file design introduced the same day,
and their packets were re-selected to include the complete request path and the credential-path
source. Earlier runs against the previous provider code passed 18 and 19 of 24; several answers
sit near the 0.1 limit and vary between runs.

The earlier six-question baseline ran once with `jev-1.13.0` on 2026-09-28. Two checks suggested pass and four
remained in review. None suggested fail. All six terminal results were `not_evaluated`, so
this report does not clear AudiToad's implementation.

| Rule | Expected violation | Probability | Suggestion |
|---|---|---|---|
| `SELF-EGRESS` | No | 0.17 | review |
| `SELF-RESPONSE` | No | 0.12 | review |
| `SELF-COVERAGE` | No | 0.07 | pass |
| `SELF-DRAFT` | No | 0.11 | review |
| `SELF-PUBLISH` | No | 0.16 | review |
| `SELF-JSON` | No | 0.03 | pass |

The expected labels come from source review and the product's behavioral tests. They were not
sent to Jev. A review suggestion is unresolved evidence; it does not establish a defect or
establish that the implementation is correct. Source review and tests remain necessary for
the opt-in, response, draft-result and publication obligations.

The six-question table is historical evidence, not a measurement of the current questions or source.
The [README](README.md) explains how to repeat the audit after reviewing
the selected named owners and hashes. Other requirements and unselected source remain outside its scope.
