# Writing audit observations

## Current version 3

The five-family revision addresses demonstrated evidence and evaluator-selection problems.
The emphasis question now receives the brief and is gated by exact paired-phrase presence.
The closing-expression question is gated by exact phrase presence and receives the complete
article alongside its selected sentence.
The preview question explicitly excludes bare headings. Exact role and filler phrase detection
uses local predicates with pinned positive and near-miss controls.

All current yes/no thresholds are fixed at 0.1/0.9 before new calls. The legacy calibrated
limits below remain attached to historical observations. Changing only a decision limit does
not justify repeating a model request.

On 2026-10-16 one development run of `revision-3` made 31 calls to `jev-1.13.0`, with no
execution errors. It matched **10 of 10 final policy expectations, with zero wrong and zero
unresolved**, across five revised families and two authored articles:

| Final policy family | Correct | Wrong | Unresolved |
|---|---:|---:|---:|
| Paired emphasis (`FRAME-01`) | 2 | 0 | 0 |
| Closing expression (`FRAME-13`) | 2 | 0 | 0 |
| Role phrase (`FRAME-14`) | 2 | 0 | 0 |
| Filler transition (`WORDS-03`) | 2 | 0 | 0 |
| Announcing a topic (`GROUND-02`) | 2 | 0 | 0 |

The run recorded 381 checks, including local predicates, gates, unit observations and
document combinations. Those are not 381 independent policy cases. Its 31 provider calls
comprised one gated emphasis question, one gated closing-expression question and 29
paragraph-preview questions. The role and filler predicates ran locally. Final policy
labels came from `revision-3.labels.json`, fixed before these calls; unit judgments and helper
responses are excluded from that ten-case denominator.

This is a focused development observation on already inspected writing. It does not measure
the complete 94-policy set or establish independent accuracy. Semantic terminal results
remain `not_evaluated`, and the overall scan remains unresolved.

| Retained artifact | SHA-256 |
|---|---|
| Version 3 baseline | `98b9d3608deaaa7a3d72bec24e20a8d7444b797db540bdfcf8a66c093a27dee2` |
| Article/brief bundle | `e66ee34b61a2cf440a0f2298336e64e52f953754c2b812bcb4e35990de25a7dc` |
| Ten-policy labels | `d18eaa16d72b314ca5c4952fe9518259c16969d5380c3e5300e6ad5339b8a563` |
| Development report | `5a41e6a9125fbf717c65d3d383d8ae196cfe84c77c688e08041685a51cf72198` |
| [Public product score](v3-focused.score.json) | `14a4b3f99705539e2ccf56315b1cd0515e255fabb2d11e81fbdb0a7e3fc224c7` |

## Historical version 2

The retained Jev 1.13.0 helper-off development run on 2026-09-30 matched 71 of 94 final policy
labels, with zero wrong and 23 unresolved. It made 1,286 provider calls with zero execution
errors. The helper-on run matched 73 of 94, with zero wrong and 21 unresolved; both helper
responses were refused as invalid quotations. Those small differences do not establish helper
benefit. Version 2 used the original calibrated decision limits and different evidence from
version 3. These are authored development controls, not independent acceptance measurements.

## Historical version 1

The following detailed tables record version 1. They do not measure the current questions or
evidence. The complete historical raw reports are not part of this example's distributed files.
The local `punctuation.baseline.json` implements `FORMAT-05` exactly and can be run using the
[README commands](README.md). Its deterministic results are separate from the Jev scores below.

One live run on 2026-09-29 resolved 77 of the 94 document-level policy answers correctly
(81.9%), with 17 reviews and no wrong suggestions. This denominator includes fourteen local checks
and eight document answers combined from sentence or paragraph observations. It excludes the
additional 114 sentence answers and 58 paragraph answers, which would otherwise inflate the
result with many easy negatives.
Semantic terminal results remain `not_evaluated`; local checks return `pass` or `fail`.
The combined scan remains experimental and unresolved.

The expected labels were recorded before the run: each rule was expected to find a violation
in article A and none in article B. The table below separates the provider's numeric output
from the human explanation of the source. Line numbers refer to [article-a.md](article-a.md).
Most requests contain the complete article, with the brief included for questions that use it.
The two sentence questions receive each automatically selected sentence; they need no wider
context for their declared grammatical pattern. The two paragraph questions receive each
complete nonblank block separated by blank lines, including heading and list blocks. They
check naming and repeated sentence meanings within that block. Jev receives neither this
table nor the labels.

The recap and preview questions receive the complete article as a named text field. The
request-restatement question also receives the brief. This revision resolved article A's
recap and repeated-request examples, previously left in review. Article B remains unresolved
for all three questions. Fresh validation of this revision has not yet run.

The baseline maps each probability using the question's declared thresholds:

| Question | Pass below | Fail at or above |
|---|---|---|
| Opening range (`FRAME-03-SENTENCE`) | 0.20 | 0.90 |
| Trailing clause (`FRAME-06-SENTENCE`) | 0.20 | 0.60 |
| Synonymous names (`WORDS-07-PARAGRAPH`) | 0.20 | 0.80 |
| Repeated meaning (`TONE-04-PARAGRAPH`) | 0.30 | 0.80 |
| Personification (`WORDS-05`) | 0.50 | 0.90 |
| Generic sympathy (`TONE-06`) | 0.40 | 0.90 |
| Other semantic questions | 0.10 | 0.90 |

Values between those boundaries are `review`, including the pass boundary itself. The four
scoped questions and two language questions use decision policies tested on new passages after
development. The language questions receive the complete article without the brief.
These decision policies do not establish a calibrated error rate for arbitrary writing.
`WORDS-01`, `WORDS-02`, `WORDS-04`, `FORMAT-01`, `FORMAT-04`, `FORMAT-05` and `FORMAT-07`
use local predicates and have no model probability.
`FRAME-03`, `FRAME-06`, `WORDS-07` and `TONE-04` show dependency-combined decisions, also without
a model probability.

Sentence scope enumerated 53 units in article A and four in article B, including headings and
list entries under the documented Unicode text convention. The opening-range question matched
57/57 sentence labels. The trailing "-ing" question matched 55/57, with two reviews and no wrong
answers. Each family has only one positive sentence in these articles. Their document summaries
matched three of four labels; the trailing-clause result for article B remains in review.
Paragraph scope enumerated 27 units in article A and two in article B. The synonym question
matched 24/29 paragraph labels, leaving its positive and four negatives in review. The repetition
question matched 27/29, with two negative reviews. Its positive witness resolves article A's
document answer despite those reviews. Both repetition summaries resolve. The synonym summary
remains in review for both articles. Each family has only one positive
paragraph in these articles.
Across all 244 Jev calls, 221 matched and 23 remained unresolved, with no wrong suggestions.
The report preserves unresolved unit counts even when a positive witness settles its document summary.

The vocabulary checks also passed 231 rule/input comparisons across 77 additional inputs through
the public baseline. These cover all 61 configured terms, case and apostrophe variants, rendered
markup, word-boundary near misses, excluded code and misleading text in the brief. Each input
is checked against all three vocabulary rules. These are local predicate tests, not model calls
or an estimate of Jev's accuracy. The report retains matched wording and its source block.

## Rhetorical frames

| Rule | Example in article A | Line | A: score, suggestion | B: score, suggestion |
|---|---|---|---|---|
| `FRAME-01` | Not-only/but-also description of the inventory | 7 | 0.98 fail | 0.03 pass |
| `FRAME-02` | Not-just recasting of a record as a journey | 7 | 0.96 fail | 0.02 pass |
| `FRAME-03` | Beginner-to-expert range opener | 7 | fail | pass |
| `FRAME-04` | Whether-you-are audience framing | 7 | 0.97 fail | 0.04 pass |
| `FRAME-05` | Generic contemporary landscape | 7 | 0.94 fail | 0.03 pass |
| `FRAME-06` | Trailing clause about revealing opportunities | 9 | fail | review |
| `FRAME-07` | Rhetorical question before operational instructions | 1 | 0.91 fail | 0.06 pass |
| `FRAME-08` | Closing recap of topics | 58 | 0.92 fail | 0.60 review |
| `FRAME-09` | Promise of what the article will cover | 5 | 0.94 fail | 0.10 review |
| `FRAME-10` | Repetition of the question in the brief | 5 | 0.93 fail | 0.19 review |
| `FRAME-11` | Hands-on claim without a named activity | 11 | 0.83 review | 0.03 pass |
| `FRAME-12` | Real-world modifier without a stated domain | 11 | 0.95 fail | 0.03 pass |
| `FRAME-13` | Stock completion phrase at the end | 58 | 0.99 fail | 0.03 pass |
| `FRAME-14` | Importance expressed through a vital role | 9 | 0.98 fail | 0.06 pass |
| `FRAME-15` | Contrast between destination and confidence | 58 | 0.93 fail | 0.04 pass |
| `FRAME-16` | Repeated fragments about file, process and future | 9 | 0.88 review | 0.06 pass |
| `FRAME-17` | Paired negations about friction and delay | 9 | 0.92 fail | 0.07 pass |
| `FRAME-18` | Three promotional adjectives | 11 | 0.97 fail | 0.02 pass |

## Word choice

| Rule | Example in article A | Line | A: score, suggestion | B: score, suggestion |
|---|---|---|---|---|
| `WORDS-01` | Listed stock vocabulary in the opening and descriptions | 1, 7, 9, 11 | fail (local) | pass (local) |
| `WORDS-02` | Buffer announcing that a fact is important | 13 | fail (local) | pass (local) |
| `WORDS-03` | Stock end-of-the-day transition | 13 | 0.96 fail | 0.05 pass |
| `WORDS-04` | Listed adverbs | 13 | fail (local) | pass (local) |
| `WORDS-05` | A platform assigned thoughts and wants | 13 | 0.91 fail | 0.09 pass |
| `WORDS-06` | A gateway description substituted for a direct statement | 15 | 0.76 review | 0.03 pass |
| `WORDS-07` | Developers, engineers and programmers name the same readers | 15 | review | pass |
| `WORDS-08` | Unnamed experts support a cost claim | 15 | 0.96 fail | 0.04 pass |
| `WORDS-09` | An instruction to do unspecified relevant things | 54 | 0.94 fail | 0.20 review |

## Grounding and organization

| Rule | Example in article A | Line | A: score, suggestion | B: score, suggestion |
|---|---|---|---|---|
| `GROUND-01` | A 73 percent cost reduction absent from the brief | 15 | 0.96 fail | 0.18 review |
| `GROUND-02` | A paragraph announcing later discussion | 19 | 0.95 fail | 0.23 review |
| `GROUND-03` | An opening about the response itself | 1 | 0.93 fail | 0.05 pass |
| `GROUND-04` | The requested action arrives after background and benefits | 3-54 | 0.96 fail | 0.22 review |

## Formatting

| Rule | Example in article A | Line | A: score, suggestion | B: score, suggestion |
|---|---|---|---|---|
| `FORMAT-01` | A list with three items | 27-29 | fail (local) | pass (local) |
| `FORMAT-02` | Connected narrative separated into bullets | 33-36 | 0.67 review | 0.07 pass |
| `FORMAT-03` | Bold label and colon at each bullet's start | 27-29 | 0.96 fail | 0.07 pass |
| `FORMAT-04` | A bold phrase inside prose | 25 | fail (local) | pass (local) |
| `FORMAT-05` | Two em dashes in one sentence | 54 | fail (local) | pass (local) |
| `FORMAT-06` | Headings dividing short passages | 38-58 | 0.89 review | 0.07 pass |
| `FORMAT-07` | Single-sentence paragraphs lacking the required length range | 40-46 | fail (local) | pass (local) |

## Tone and editing

| Rule | Example in article A | Line | A: score, suggestion | B: score, suggestion |
|---|---|---|---|---|
| `TONE-01` | Repeated expanded forms in conversational instructions | 33-36 | 0.93 fail | 0.09 pass |
| `TONE-02` | Promotional enthusiasm across unrelated passages | 1-50 | 0.96 fail | 0.03 pass |
| `TONE-03` | Basic explanations the audience already knows | 21 | 0.97 fail | 0.08 pass |
| `TONE-04` | Repeated statements that an inventory contains records | 25 | fail | pass |
| `TONE-05` | Unsupported importance claim about inventory export | 50 | 0.90 fail | 0.23 review |
| `TONE-06` | Generic sympathy and reassurance | 50 | 0.92 fail | 0.02 pass |
| `TONE-07` | Canned assistant greeting | 1 | 0.91 fail | 0.03 pass |
| `RHYTHM-01` | Four paragraphs with the same sentence shape | 40-46 | 0.96 fail | 0.12 review |
| `EDIT-01` | Topic announcements and repeated instructions add no facts | 19, 33-46 | 0.98 fail | 0.70 review |

## What the run shows

Several literal rhetorical frames and the invented cost claim received failure suggestions
for article A and passing suggestions for article B. Other distinctions stayed unresolved.
Before the evaluator change, the em-dash question returned 0.17 and 0.13 despite the articles'
different character counts. The local check now distinguishes them exactly.
Sentence scope found the trailing-participle example in article A, but could not establish
its absence throughout article B at the configured thresholds.

Those outcomes matter when choosing an evaluator. Exact character counts are better checked
with an exact predicate than inferred from a semantic probability. Questions about useful
headings, repetition or tone also need an audience and purpose; even with the brief, many
comparison-article observations remained in review.

The observed matches are development evidence for these articles and questions. They are not
an accuracy estimate for arbitrary writing, an authorship detector, or proof of stylistic quality.
This run does not show every rule successfully finding its intended example.

Repeated calls can change decisions near a threshold. Compared with the preceding 76/94 run,
the unchanged heading and contraction questions crossed into correct decisions at 0.90 and 0.09.
One synonym observation crossed to 0.20 and left article B's summary unresolved. This explains
the net increase to 77/94; replacing vocabulary questions does not establish a semantic-model
improvement. No threshold was changed to absorb that variation.

The [README](README.md) gives the ordinary CLI commands for a new run. Submitted evidence consists
only of the selected article and brief, or the selected sentence or paragraph for a scoped
question. The explanations above are human review; scoped byte ranges come from automatic preparation.
