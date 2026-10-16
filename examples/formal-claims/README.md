# Audit formal claims

This example asks whether a stated assurance matches its supplied formal artifact. It covers
TLA+, TLAPS and Verus with 37 authored cases: nine families each retain a sound
correspondence, an obvious overclaim, a subtle overclaim and an accurately disclosed limitation.
A fifth fairness case starts with `done = TRUE` and tests exclusion by the initial condition.

These are development controls. The source snippets are excerpts, not executed proof projects.
The obligation-status lists are explicitly synthetic, not authentic TLAPS receipts. A matching
claim is only correct for the named question; it does not certify the entire specification,
proof or program. For example, the selection family asks whether a check is enabled, not whether
that check succeeds. Independent examples and real source-bound tool results are needed before
claiming useful accuracy on a research repository.

## Run it

From this directory, prepare the complete finite question set without model calls:

```sh
auditoad baseline validate baseline.json
auditoad scan --baseline baseline.json --input inputs.json \
  --evaluators ../evaluators.json --report prepared.json
```

Set `TYPESAFE_API_KEY`, inspect the prepared requests, and add `--live` to obtain fresh answers:

```sh
auditoad scan --baseline baseline.json --input inputs.json \
  --evaluators ../evaluators.json --live --report report.json
auditoad score --report report.json --labels labels.json
```

You can substitute another evaluator configuration. The included profile permits TypeSafe's
HTTPS origin and loopback; review `allowed_egress` before choosing another endpoint. A full
run asks at most 80 model questions and produces 142 applicable observations: 37 claim readings,
43 artifact premises, 16 local status checks, four status combinations, five fairness-gap
combinations and 37 parent observations. The existing 127 labels are unchanged; the 15 new
fairness premises are diagnostics outside that denominator. Exit 2 is expected: semantic
results and combinations remain experimental. Preparation makes no calls.

## Revised gap boundaries

Version 5 changed only the negative criteria of `FAIR-GAP` and `QUANT-GAP`.
The first includes any reason the selected specification excludes the permanently
pending behavior, including `Init`; exclusion need not come from fairness. The second
assesses the selected conclusion together with its supplied assumptions. Both still ask
one proposition, use only the complete supplied artifact, and retain the fixed 0.1/0.9
thresholds. Claim readings, their 0.9/0.9 limits, and all 124 original label values are unchanged.

Version 6 made the constant-FALSE behavior explicit, including its initial state, and supplied
the neutral TLA+ contract for weak fairness. It asks whether that one behavior satisfies the
selected specification. The quantifier question and its two criteria now state the same
countermodel proposition and its exact negation. Source artifacts, controls, labels,
thresholds, claim readings and profiles remain unchanged.

Version 7 separates permission by the initial condition, the next-state constraint and selected
fairness into three questions. `FAIR-GAP` combines their answers locally: all three permissions
are needed to admit the constant-FALSE behavior; one exclusion rules it out. The original
five fairness-gap labels are unchanged.

The new fairness line 5 asserts completion and supplies `Init == done = TRUE`, with no
fairness conjunct. The constant `done = FALSE` behavior violates that initial condition.
Its fixed labels are claim asserted, no permanently pending behavior, and no claim mismatch.
This is an authored negative control, not an executed formal proof.

The current `gap-development` profile selects five fairness-gap combinations, their 15
premises and four quantifier questions. It asks at most 19 model questions and does not
select claim readings or mismatch judgments. Its nine gap labels are frozen in
[gap-development.labels.json](gap-development.labels.json).

The `fairness-development` profile selects only the five fairness-gap combinations and
their 15 premises. It asks at most 15 model questions across 12 unique request payloads.
Fairness lines 3/4 share one artifact, as do quantifier lines 3/4; each pair preserves an overclaim
and an accurately disclosed limitation for the separate claim and parent controls. The
artifact-only questions therefore repeat within each pair. These paired development observations are not an
acceptance repetition. Retained-answer reuse requires the same complete evidence frame,
exact request and evaluator identity. The pairs have different claim text in their complete
frames, so the existing reuse contract does not share answers between them.

```sh
auditoad scan --baseline baseline.json --input inputs.json \
  --profile gap-development --evaluators ../evaluators.json \
  --max-provider-calls 19 --report gap-prepared.json
```

Inspect those prepared requests, then add `--live` and choose `gap-report.json` for the
single development run of this design. Score it with:

```sh
auditoad score --report gap-report.json --labels gap-development.labels.json
```

## Current version-7 focused development run

The version-7 development run on 2026-10-16 made 15 new calls to `jev-1.13.0` for the
decomposed fairness premises and reused four unchanged quantifier exchanges. It reported
no execution errors and scored **five correct, zero wrong and four unresolved** against the
nine gap labels. All four quantifier observations remain correct. Fairness line 5 now
resolves correctly because its initial condition excludes the constant-FALSE initial state.
The other four fairness-gap observations remain unresolved.

The five initial-condition premises resolved correctly. All five next-state premises remain
unresolved. Two selected-fairness premises resolved correctly and three remain unresolved.
These diagnostic premises are not additional gap cases. The run does not establish
accuracy on formal projects or measure the complete 127-label set. All semantic and
dependent terminal results remain `not_evaluated`.

The [version-7 gap score](v7-gaps.score.json) SHA-256 is
`37aacdf75c71676ff7fc3e353d3e224443caff95b8d4a74364332b78a994d248`.
Its original report SHA-256 is
`75c0929ef80227f5e60e247d82d0b098c17b8ca4c082473cf6fe28475a0f7486`.
The version-7 baseline SHA-256 is
`23c34aef24a90464a99d7f6c6ebedc282080289e3509d9be83b88c09e1356594`.
The gap labels retain the SHA-256 recorded below.

## Historical version-6 focused development run

The version-6 focused run on 2026-10-16 made nine calls to `jev-1.13.0`, covering seven
unique payloads, with no execution errors. It scored **four correct, zero wrong and five
unresolved** against the same nine frozen gap labels. All four quantifier observations
resolved correctly, including the universal negative control at 0.07. All five fairness
observations remain unresolved, at 0.26, 0.53, 0.63, 0.73 and 0.15 in source order.

The [version-6 gap score](v6-gaps.score.json) SHA-256 is
`6ffd2f42f6fcf1e583302e06e519abee5261b73e6dab02e34e1d3bbf72b0a99e`.
Its original report SHA-256 is
`765bc3d2467b0b7b0e6bfa21c16240ef2040e2daa2be5b8823d60dc9e2db60da`.
The version-6 baseline SHA-256 is
`ce332bf04b92027fbc633df21844937d27891e3536ad8260c2249bd552463950`.
The gap labels retain SHA-256
`aff974861bb2bd01a981cd1bf7d754340314dc82ad635a85c8ccdf45adce5b4b`.
This focused development result does not measure all 127 labels or establish accuracy on
formal projects. All nine semantic terminal results remain `not_evaluated`.

## Recorded version-5 focused development run

The version-5 focused development run on 2026-10-16 made nine calls to `jev-1.13.0`,
covering the seven unique payloads described above, with no execution errors. It scored
**three correct, zero wrong and six unresolved** across the nine frozen gap labels:

| Revised artifact family | Correct | Wrong | Unresolved |
|---|---:|---:|---:|
| Fairness, five records | 0 | 0 | 5 |
| Quantifiers, four records | 3 | 0 | 1 |

The new initial-true fairness control returned 0.15 and remains in review. The sound
quantifier control returned 0.33 and also remains unresolved. The three resolved answers
are positive quantifier-gap observations; no negative control resolved in this focused run.
The 0.1/0.9 limits stayed fixed. This is development evidence on two revised question
families; it does not measure all 127 labels or establish accuracy on formal projects.
All nine semantic terminal results remain `not_evaluated`.

The shipped [version-5 gap score](v5-gaps.score.json) retains the decisions, probabilities
and source/report identities, without raw provider payloads. Its SHA-256 is
`fc6221162a50a0535b29b622dc60224448096bc591d071d748ae314967366d65`.
The original report SHA-256 is
`f8a1cddcaf8caedb15bec919fec71de61f7d282a64cc3302d0a7a5309e76ec85`,
and its gap labels SHA-256 is
`aff974861bb2bd01a981cd1bf7d754340314dc82ad635a85c8ccdf45adce5b4b`.
The original development run below retains its version-4 scope.

## Recorded version-4 development run

The revision-4 development run on 2026-10-03 used Jev `jev-1.13.0`, without helpers, at the
fixed 0.1/0.9 and 0.9/0.9 thresholds. Across its 124 labels it scored **100 correct, zero wrong and 24
unresolved**, with 68 fresh calls. The 36 parent judgments scored **24 correct and 12
unresolved**. Parent coverage by family was fairness 1/4, vacuity 4/4, property selection 2/4,
proof support 2/4, assumptions 1/4, quantifiers 3/4, preconditions 4/4, trust 3/4 and contract
strength 4/4; every resolved parent matched its label. Unresolved atoms remain unresolved in
their parents. This is one authored development run, not independent acceptance, and another
backend or service revision must be measured separately. Semantic terminal results remain
`not_evaluated` even when their suggested decisions match a label.

## The question graph

Every family separates the claim from its artifact. `*-CLAIM` classifies the author's
position on an explicit proposition: asserted, not asserted or insufficient evidence.
It receives only the original claim and that proposition. An asserted promise maps to `fail`
for this premise; not asserted maps to `pass`, and insufficient evidence maps to `review`.
Both choice probability and confidence must reach 0.9 before a pass/fail suggestion is used.
`*-GAP` examines whether the supplied artifact has the corresponding assurance gap. The
external-body question uses three categories: the gap is present, it is absent, or the evidence
is insufficient, with probability and confidence thresholds of 0.9. Nine artifact questions
use yes/no answers, including the three fairness premises. Each receives only the artifact
and its complete small context. `FAIR-GAP` combines its three same-artifact premises with
`all_fail` and `decisive` resolution.

Proof-support status is mechanical: `LEAF-STATUS-0` through `LEAF-STATUS-3` compare each of
four required synthetic status rows with `proved`. `LEAF-GAP` combines their answers using
`any_fail` and `all_answers`. A missing status stays unresolved. This example declares those
four rows to be its complete required context; it does not discover supporting dependencies,
authenticate a checker log or establish completeness of an arbitrary TLAPS proof chain.
The fixture files pin local positive and negative cases. The four combination suggestions
remain experimental even though their premises are local.

`*-MISMATCH` combines the claim and gap propositions with `answers/1` and `all_fail`.
The strict `all_answers` policy keeps the parent unresolved if either premise is unresolved.

Classifying a claim is separate from checking its truth. An endorsed quotation can make a
promise; a withdrawn quotation or future acceptance condition does not establish a current
claim. Preserve the original prose when using an extraction helper and test that extraction
separately. The category question remains experimental: its confidence and a yes/no probability
are different outputs, and neither establishes model accuracy on a new collection.

Neither example type, expected answer nor reviewer explanation enters model state. Labels
remain outside the evidence. An atomic label's `violation: true` means that its named proposition
is true; an affirmative claim-reading answer is not itself an audit defect. The `*-MISMATCH`
rows are the assurance discrepancies. Inspect both atomic and parent scores when measuring
errors and coverage. A model's confidence is not a proof.

## Expected distinctions and witnesses

The first four records of each linked JSON Lines file follow the order shown below. Line 4 uses the same
limited artifact as line 3 but honestly describes its limitation; it must not be accused of
that overclaim. For every family the expected parent outcomes are **pass, fail, fail, pass**.
These are expected experimental suggestions, not admitted compliance results.

| Family and input | Line 1: sound correspondence | Line 2: obvious overclaim | Line 3: subtle overclaim; line 4 discloses this limit |
|---|---|---|---|
| [TLA+ fairness](tla-fairness.jsonl) | Selected `Spec` includes `WF_done(Finish)`, excluding permanent pending stutter. | Selected `Spec` has no fairness; repeating `done = FALSE` forever is allowed. | `Fairness` and `CompleteSpec` are defined, but the configuration selects the weaker `Spec`. The same infinite stutter is a counterexample to the completion promise. |
| [TLA+ vacuity](tla-vacuity.jsonl) | `Ready` holds in the initial state, providing a concrete antecedent witness. | `Ready` starts false and `Next` preserves it. | `Enter` would make `Ready` true, but `Next` selects only `Maintenance`; every reachable state stays idle. `Ready => ack` therefore supplies no evidence of handling ready work. |
| [TLA+ property selection](tla-selection.jsonl) | The configured `AuditInvariant` expands to `NeverNegative`. | Only `TypeOK` is enabled. | The impressive alias `AuditInvariant` expands to `TypeOK`, not `NeverNegative`; integer membership permits `balance = -1`. Defining a stronger invariant does not select it. |
| [TLAPS proof support](tlaps-obligations.jsonl) | All four required synthetic status rows are marked proved. | The supplied row for a `Safety` leaf is omitted despite its proved QED. | The supplied row for cited lemma `Support` is omitted although `Safety`'s rows are proved. The declared four-row context remains incomplete. |
| [TLAPS assumptions](tlaps-assumptions.jsonl) | The theorem context admits all `Int` values. | Local `NEW n in Nat` excludes `n = -1`. | An enclosing module assumption narrows `n` to `Nat`. That the square bound also happens to be true for negative integers does not widen this theorem's context. |
| [TLAPS quantifiers](tlaps-quantifiers.jsonl) | The conclusion universally quantifies over `Items`. | The conclusion is existential. | `AllAccepted` expands through `Covered` to an existential. `Items = {1,2}` and `Accepted = {1}` satisfy it while leaving item 2 unaccepted. |
| [Verus preconditions](verus-domain.jsonl) | No `requires` clause restricts the `u8` domain. | `requires false` admits no input. | `admitted(x)` means `x < 128`; `x = 200` is a concrete input outside the verified domain. |
| [Verus trust](verus-trust.jsonl) | The selected function has no trusted dependency; an unrelated external body is a false-positive control. | The selected function itself is `external_body`. | `preserve` calls `bridge`, which calls `foreign_identity`; the foreign body is trusted. Checking a wrapper against that contract does not check the foreign implementation. |
| [Verus contract strength](verus-contract.jsonl) | `same(x,r)` expands to equality. | `ensures true` imposes no equality requirement. | `preserves(x,r)` expands only to `r <= x`; `x = 1, r = 0` satisfies the contract while violating exact identity. |

For the original four records in all nine families, the atomic claim labels are true, true,
true, false; the gap labels are false, true, true, true. Fairness line 5 adds claim=true,
gap=false and mismatch=false. These truth tables explain the parent labels in [labels.json](labels.json).
The baseline supplies relevant language rules but does not supply these case classifications.
The 16 additional labels name individual status rows. The same author selected questions and expected answers, so this collection is not an independent
holdout or an industry benchmark. The controlled indirections are subtle relative to the direct
cases, not a claim that they represent the hardest formal-audit problems.

## Semantic references

TLA+ selects the behavior formula separately from enabled invariant/property checks; fairness
must occur in that selected formula. See the [Toolbox model overview](https://tla.msr-inria.inria.fr/tlatoolbox/doc/model/overview-page.html)
and [Lamport's liveness tutorial](https://lamport.azurewebsites.net/tla/tutorial/session9.html).
The TLAPS [hierarchical proof tutorial](https://proofs.tlapl.us/doc/web/content/Documentation/Tutorial/Hierarchical_proofs.html)
explains why a proved QED can coexist with omitted supporting steps and how context limits a goal.
Verus documents [preconditions and postconditions](https://verus-lang.github.io/verus/guide/requires_ensures.html)
and [assumptions and trusted components](https://verus-lang.github.io/verus/guide/tcb.html).
These references support the examples' semantics, not a measured model-accuracy claim.
