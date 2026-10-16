# Audit writing with no-slop rules

This example adapts [Dan Lovejoy's writing standards](https://github.com/danhlovejoy/no-slop/blob/main/noslop.md)
into focused questions about prose. It covers rhetorical frames, word choice, factual grounding,
formatting and tone. The source was reviewed on 2026-09-28. These are style preferences selected
by a baseline author, not a test of who wrote a document.

The two articles answer the same operational request. One contains examples of the targeted
writing patterns; the other is a shorter comparison. Neither article contains comments or
labels identifying the answers. The brief provides the audience, requested task and known facts.

[The results note](RESULTS.md) maps every rule to its example passage and records the results of
version 1 of this baseline, which matched 77 of 94 document-level expected answers (81.9%), with
17 reviews and no wrong answers. Version 2 breaks the whole-article questions that were really
about individual sentences or paragraphs into per-sentence or per-paragraph questions, and gives
finding the first requested instruction to a helper. It has not yet been measured.

| File | Why it is here |
|---|---|
| `article-a.md`, `article-b.md` | The prose being audited |
| `brief.md` | Audience, task and evidence available to the writer |
| `baseline.json` | 40 semantic questions, one helper task, 26 document summaries and seven exact local checks |
| `bundle.json` | Pairs each article with the brief and pins their hashes |
| `punctuation.baseline.json` | Exact local implementation of the em-dash limit |
| `local-checks-pass.json`, `local-checks-fail.json` | Small known-answer inputs for vocabulary, list, bold, sentence-length and em-dash checks |

## Run it

Run from this directory with `auditoad` installed:

```console
auditoad baseline validate punctuation.baseline.json
auditoad scan --baseline punctuation.baseline.json --profile all --source document --input article-a.md --report punctuation-a.json
auditoad scan --baseline punctuation.baseline.json --profile all --source document --input article-b.md --report punctuation-b.json
```

These checks use no provider. Article A fails with exit 1 because it contains two UTF-8 em
dashes; article B passes with exit 0 because it contains none. The baseline permits at most
one em dash in the complete input, including quoted or code text. It uses the YARA-X occurrence
count of the bytes for U+2014. An en dash, two hyphens and the literal text `\u2014` do not count.

The main baseline combines semantic questions, document summaries and local checks. Prepare it with:

```console
auditoad baseline validate baseline.json
auditoad scan --baseline baseline.json --profile all --source evidence --input bundle.json --project-root . --report prepared.json
```

Preparation writes the questions and evidence without contacting a model. For a live run with
[`evaluators.json`](../evaluators.json), which sends questions to Jev and reads `TYPESAFE_API_KEY`,
run the command below. Pass [`evaluators.local.json`](../evaluators.local.json) or your own
evaluator file to use another model.

```console
auditoad scan --baseline baseline.json --profile all --source evidence --input bundle.json --project-root . --evaluators ../evaluators.json --live --max-provider-calls 1288 --provider-timeout-seconds 10 --report report.json
```

Both commands exit 2 because semantic checks remain experimental. The live report keeps each
probability and suggested result. The seven local checks record a pass or failure,
including during preparation. Their two known-answer files are sanity checks; the articles are
the documents being audited. A review or error remains unresolved. You can run one group
with `--profile grammar`, `paragraphs`, `language`, `structure`, `vocabulary`, `frames`, `words`, `grounding`, `format`, `tone` or `editing` to inspect fewer rules.
The supplied articles require 1,288 provider calls: one per sentence or paragraph for each
scoped question, one per article for each whole-article question, and one helper extraction per
article. With the helper role switched off, as in `evaluators.json`, they require 1,286. Longer articles may require a higher explicit
call allowance; exhausted allowances remain unresolved.

## How the rules become checks

The baseline turns a preference into a question with explicit true and false conditions.
The `vocabulary` profile checks the source's stock words, buffer phrases and banned adverbs
locally. It matches complete words and phrases in visible Markdown, including headings, lists
and quoted prose. Code, image alternative text, link destinations and the brief are excluded.
Capitalization and whitespace may vary; curly apostrophes are accepted. Other punctuation is
literal, and the check does not infer word meaning or match stems. Its report includes the
matched wording and the containing source block. Run it without a provider:

```console
auditoad scan --baseline baseline.json --profile vocabulary --source evidence --input bundle.json --project-root . --report vocabulary.json
```

The `structure` profile checks whether the article ends with a recap, previews later content,
or repeats the reader's request before answering it. Each question receives the complete
article, because position and earlier content affect the answer. Only the request-restatement
question also receives the brief. The baseline selects those named text fields from the
evidence bundle; article identifiers and expected answers are not part of the model's input.

Questions about a pattern within one sentence are asked of every sentence. For example,
`FRAME-03-SENTENCE` and `FRAME-06-SENTENCE` ask each sentence about an opening range and a
trailing "-ing" clause. Their `scope` enumerates every sentence automatically, without supplied
answer locations. Each request contains only that complete sentence. `FRAME-03` and `FRAME-06`
combine those answers for their article: one positive witness establishes presence; absence
requires every sentence to resolve negatively. Unresolved child answers remain in the report.
Sixteen further question families work the same way, among them the rhetorical frames, filler
and inflated wording, unnamed authorities, vague instructions and written-out contractions.
`GROUND-01` and `EDIT-01` also receive the brief with each sentence, because whether a fact is
supported or a sentence is needed depends on it. The `grammar` profile runs just the first two
families and their document summaries.

Questions about a paragraph are asked of every paragraph. `WORDS-07-PARAGRAPH` asks whether
different synonymous nouns name the same subject. `TONE-04-PARAGRAPH` asks whether a sentence
repeats an earlier sentence's meaning without adding information. Slogan contrasts, dramatic
fragments, announced topics, promotional tone and unexplained importance are also asked per
paragraph; `TONE-03` receives the brief as well. The others inspect the paragraph alone, with no
brief or neighboring paragraph in the request. Here a paragraph is a nonblank block separated by blank lines;
headings and list blocks are included. This is a text boundary, distinct from the Markdown
parser used by the local formatting checks. Their document summaries use the same rule:
one positive paragraph establishes presence; absence requires all paragraphs to resolve
negatively. The `paragraphs` profile runs these two families. It does not check repetition
across paragraphs or redundancy within a single sentence.

The `language` profile checks personification and generic sympathy. `WORDS-05` covers mental
attributes assigned to software, models, algorithms or mathematics, including understanding,
intentions and preferences. `TONE-06` checks generic sympathy or reassurance about the reader's
difficulties; practical advice elsewhere does not exempt it. This interprets a pattern in the
wording and does not determine whether the writer is sincere. Both questions receive the
complete article as one named field, without the brief. Keeping the full article preserves
antecedents, quotations, denials and any practical instructions.

`GROUND-01` compares each sentence with the brief; it checks support within the brief, not truth.
`GROUND-04` asks whether unrequested background delays the first requested instruction. A
`helper` task first copies that instruction from the article, and the question consults it; with
the helper role off, the question receives the article and brief alone. `FORMAT-01` parses Markdown and counts each list's
direct items, including nested lists separately. `FORMAT-04` finds bold text inside prose
paragraphs. It excludes headings, lists, code blocks and image alternative text; quoted prose
and bold link labels count. `FORMAT-07` requires each prose paragraph
to contain both a sentence under seven words and one over thirty. It excludes headings,
code blocks and list items, and uses the documented [Unicode counting convention](../../BASELINES.md#choose-an-evaluator).
Raw HTML and a missing prose scope remain unresolved. `FORMAT-05` selects the article's
text and counts em dashes with YARA-X in this same scan. The standalone punctuation baseline
also demonstrates that predicate without experimental semantic checks.

Expected answers and the discussion of results remain outside the bundle. The model sees the
article and brief, plus the selected question. It does not see this README or the results table.

The adaptation groups each original vocabulary list into a question and gives separate IDs to
the rhetorical and formatting rules. Some judgments depend on audience and context; the brief
makes those dependencies explicit. Several original rules combine a visible form with an
interpretation of its purpose; version 2 asks those of the smallest unit that contains both. Preserve the policy's meaning across different wording and structure;
do not encode the answer from one article into a question. [Writing baselines](../../BASELINES.md)
describes evaluator choice, neutral questions and qualification on unfamiliar cases.

## Scope of the observations

Most semantic questions ask whether a named pattern occurs in one sentence or paragraph; the
rest ask about the whole article. Scoped questions record the checked sentence or paragraph's
source byte range; none generates a rationale.
Sentence scope uses Unicode text boundaries, including nonblank headings and list entries.
It does not parse Markdown structure or infer how a reader would resolve an abbreviation. The local Markdown
checks return source byte ranges and counts. The results guide identifies passages by human
review and keeps that explanation separate from the provider's probability.

This is an authored demonstration with a comparison article. It is not an independent accuracy
study, and the rules do not establish that a passage was generated by AI. To audit your writing,
replace the article and brief, update the bundle hashes, and revise the policy questions you want
to enforce. No Python or Rust code project is required.
