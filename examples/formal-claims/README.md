# Audit formal claims

This example asks whether a stated assurance matches its supplied formal artifact. It covers
TLA+, TLAPS and Verus with 36 authored cases: nine families, each containing a sound
correspondence, an obvious overclaim, a subtle overclaim and an accurately disclosed limitation.

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
run asks at most 68 model questions and covers 124 labelled observations: 36 claim readings,
32 artifact questions, 16 local status checks, four status combinations and 36 parent
observations. Exit 2 is expected: semantic results and combinations remain experimental.
Preparation makes no calls. Labelled scoring resolves 20 observations correctly from the
local checks and their four suggested combinations, with zero wrong and 104 unresolved.
Those counts describe this development collection and do not measure model accuracy.

The revision-4 development run on 2026-10-03 used Jev `jev-1.13.0`, without helpers, at the
fixed thresholds above. Across all 124 labels it scored **100 correct, zero wrong and 24
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
is insufficient, with probability and confidence thresholds of 0.9. Seven artifact questions
retain yes/no answers. Each receives only the artifact and its complete small context.

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

Each linked JSON Lines file has four records in the order shown below. Line 4 uses the same
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

For all nine families, the atomic claim labels are true, true, true, false; the gap labels are
false, true, true, true. This truth table explains every parent label in [labels.json](labels.json).
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
