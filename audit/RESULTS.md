# Self-audit observations

## Current version 7 source selection

Version 7 retains the 24 implementation questions and pins the current scan source at
`be7797df4c20108351d7a2186fc80e49bd7e96859106f9fe496a19e76e8d91f9` and strict JSON source at
`38592f18ee0ee51a05197b352d63056ed0a9420723373c9a5101689c73b9792c`.
The JSON packet now selects the duplicate-key visitor, typed parser and strict value parser
together. Replay and reuse report loading use the already validated JSON value directly,
retaining duplicate-member and trailing-input refusal; their complete exchange-validation
paths remain outside this baseline's 24-question scope. The performance effect has not been
measured. No fresh Jev measurement exists for version 7.

The version-7 baseline SHA-256 is
`6e82756f1f6a58e0bd25fc633ee090ed283461ac5b8b836e64892b7216ffb151`;
the version-7 bundle SHA-256 is
`a732574dddd04fb75ffe5a2194f0d75a346ca25ed44bc9179679f0989efa8cfc`.

## Earlier version 6 source selection

Version 6 retained the same 24 implementation questions and refreshed the `src/scan.rs` pin to
`0382e0c9e0bf79843a8a6a883c92958a945344a6589263e5ee0581509dd63683`.
The other three source/policy pins were unchanged. Its selected complete accounting function
included the cumulative output-budget match for the local Python constant-string
predicate. No fresh Jev measurement exists for this version. The `python_value` module
was outside its 24-question scope; selecting its caller does not audit that module.

The version-6 baseline SHA-256 is
`d94fdf38e400ef225ecc89f82346daa6beebea099703b2fb08e09bf33e5c02a5`;
its bundle SHA-256 was
`072e5034f121d3a299e66277e98d8e0947d0821cd0f7557d98451f7bade6ce50`.

The version-5 results below belong to their exact earlier source snapshot and remain historical.
They do not establish current-source accuracy or clear the local predicate or parser changes.

## Historical version 5

Version 5 retained 24 implementation questions on six source packets. Its source pins
were reviewed against the selected owners and callers at that revision. Publication included
the error-returning `coupling` helper; credential evidence includes configuration-time path
declaration as well as enumeration. All nine publication functions and both credential
functions are required projected fields. The opt-in question concerns fresh outbound HTTP,
excluding local preparation, mocks, replay and reused replies. The origin question concerns
the shown guard over the computed origin, with URL parsing outside that proposition.

Eight syntax selectors supplied 48 captures. The version-5 measurement arrangement disabled
the five optional quotation helpers and permits at most 24 Jev calls. The 24 externally stored
policy labels are all negative controls, fixed before those calls; they measure false alarms
on the named paths.

On 2026-10-16 one development run sent 24 questions to `jev-1.13.0`, with no execution
errors and no helper calls. It returned **nine correct pass suggestions, zero wrong
suggestions and fifteen reviews**:

| Suggestion on the 24 negative controls | Count |
|---|---:|
| Correct pass | 9 |
| Incorrect fail | 0 |
| Review | 15 |

No violating implementations were included. These observations do not measure defect
detection or establish accuracy, and the fifteen reviews remain unresolved evidence.
The eight syntax observations and five disabled helper records are excluded from the
24-policy denominator. Every semantic terminal result remains `not_evaluated`; this run
does not clear AudiToad's implementation.

The shipped [version-5 decision score](v5.score.json) retains probabilities, decisions and
frozen identities without source text or raw provider payloads. Its SHA-256 is
`bb478417811d2ebcfd04fb59567a407b4af08a9c0ef2283302a86770c3cc5cea`.
The full report SHA-256 is
`9f86ded7ab2559b09397e7a9fac7dc0f052381255910aeb13a8e144b43e454f3`.
The observation binds baseline SHA-256
`61abc9a0584cf8a4c622261b59e55d05a36b9a56ee97eb1e1e5cc5a9fb289a6d`,
bundle SHA-256
`b18af0518daf1481e7f4ef51cbb40f116cb36586c9e4b71ea2aa2339837d3e82`
and labels SHA-256
`fe9e6b837dd2f15700eed9de1574e187c5f60e02fbbdd51e458c7757a797b7a6`.
The full provider report remains private. Historical helper-only observations below retain
their original scope.

## Historical version 4

The version 4 baseline retained 24 atomic implementation questions on six source packets,
with eight local syntax selectors producing 46 captures and five source-quote helpers. There are
37 applicable records and at most 29 combined live calls. Its frozen baseline SHA-256 is
`33d60149623f502386c45e5eb99bba0885151ad2efc5fcc3efd418e7128e34e2`.

The local development observation on 2026-10-13 reused five retained responses from
`qwen2.5-coder-7b-instruct-q4_k_m` through the ordinary CLI offline. All five helper responses
passed declared-field, type and verbatim-quotation validation. The scan made zero provider calls,
reused five exchanges and recorded zero errors. All 37 applicable results remained
`not_evaluated`, with an unresolved overall outcome; the 24 judgment questions were switched
off. The report SHA-256 is
`2aeab0bc4c729bace3a37dddc6132b53c7c4e4d1403d55695cb775ccacd61774`.
This is a bounded historical integration observation. It does not qualify helper accuracy, source
correctness or the judgment questions. Version 4 had no current-source Jev policy measurement, and all
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

The earlier baseline had 24 atomic checks on six source packets. The selected source later changed
(evaluator roles, extraction tasks and scoring were added), so the packets selected the new
named functions, reviewed again after checked-binding repairs on 2026-10-06. At that earlier
checkpoint they had not been rerun with Jev on the revised source. A live run with `jev-1.13.0` on
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
