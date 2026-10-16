# Writing baselines

A baseline is a JSON document describing your audit: the rules, their evidence, how each
rule is evaluated, and which results block the scan. Start with the
[example baselines](examples/README.md). They cover a local inventory check and a Python
function checked against a written policy. The [writing example](examples/no-slop/README.md)
applies the same format to prose, and the [Python review](examples/python-review/README.md)
shows several independent rules and comparison cases.

## Start with a rule you can check

An optional top-level `"default_profile": "all"` selects an existing profile for ordinary
runs. `--profile` overrides it; a baseline with only one profile needs no default field.
Models, credentials, operator ceilings and live consent stay outside the baseline. An audit
file binds baseline, inputs, optional labels and evaluator configuration for recurring runs.

Write the requirement first. For example: "Each disk record must declare encryption" or
"Orders of at least 5,000 cents receive free shipping." Then identify the evidence needed
to check it. The disk rule needs an inventory fact. The shipping rule needs both the
function and the policy.

Use a local evaluator when the rule is an exact data comparison or byte pattern. Use a
model question when you need a semantic comparison between supplied evidence and a written
requirement. Each question should ask about one condition. A combined check can depend on
smaller checks and apply an explicit logical rule to their answers.

## Design the check before writing the question

A semantic model suits one bounded observation about supplied text. Ask for one focused judgment
per question, and check what the model that will answer it is known to do poorly; counting,
arithmetic and indirect reasoning are common weaknesses.
An accepted request establishes that the input format is valid, not that the model can reliably
perform the requested task.

For each check, write down the proposition, its subject, the evidence needed to decide it, and
what its answer would establish. Then choose the evaluator:

| Required decision | Appropriate construction |
|---|---|
| A literal byte pattern occurs, or exceeds a count | A local YARA predicate with exact encoding and scope |
| An inventory fact equals a required value | A local JSON comparison |
| A passage attributes a belief to a software product | One semantic question with that passage and the subject's identity |
| A sentence repeats another sentence's meaning | A relational question with both sentences and their paragraph context |
| A Python function behaves correctly for all inputs | Execution or analysis evidence; a source-reading probability does not establish this |
| Markdown contains listed terms, a forbidden list length, bold prose or paragraphs outside sentence-length requirements | Local `markdown/1` with a declared predicate |
| A program always rejects unauthorized effects | Individual guards, callers and refusal paths, followed by an explicit policy judgment |

A narrow question should describe a reusable observation. For example, "Does this exception
handler return an ordinary value?" can be asked of different implementations and can receive
either answer. Naming the defective function, its expected answer, or the exact repair is not
question decomposition. Keep policy constants in the supplied policy unless a rule explicitly
governs a fixed value. Do not replace a behavior requirement with a particular spelling such as
one method name and then claim the original requirement was checked.

Split independent premises. Email normalization has separate requirements for leading
whitespace, trailing whitespace and letter case. Provider response validation has separate
requirements for model identity, answer identity and probability range. Each premise needs its
own complete evidence. A positive observation about one premise says nothing about the others.

A question is too large when answering it requires finding something, following it, and then
judging it. "Can request data change which file this code opens?" asks the model to find where
request data enters, trace it through assignments and conditions, find every file operation and
decide whether a guard makes it safe. Answer the large question as the combination of its
premises instead: declare each premise as its own rule and combine them with
[`answers/1`](#combine-smaller-answers), so the dependency map states how the premises answer
the larger question. Give each premise to the evaluator suited to it:

| Premise | Evaluator |
|---|---|
| An exact pattern, count or field value | A local check |
| Something to find, copy, list or compute from the evidence | A helper model's [`extract/1`](#let-evaluators-work-together) task |
| A judgment about supplied, already located evidence | One `yes-no/1` or `choice/1` question |

Phrase each premise so that its true answer supports the violation. The combination can then
use `all_fail` for "every premise holds" and `any_fail` for "any premise holds".

Check the implication as carefully as the questions. Separate answers that some input passes
each guard do not establish that one input passes all guards together. Supply a shared witness
and check its individual constraints, or limit the result to the local observations actually
made. `answers/1` evaluates the declared combination; it does not establish that the chosen
premises are sufficient for the larger claim.

Use the smallest **complete** context. A shorter excerpt can remove the decisive type, caller,
reference or failure branch. The question should identify the subject and supporting roles by
name; it must not rely on the question ID, which a backend need not show the model.
Inspect the prepared request to confirm those roles were actually selected. A listed file or a
valid hash does not prove the model received the relevant passage.

An absence judgment covers only the supplied scope. Finding no problem in one function does
not clear its callers, and finding no example in one paragraph does not clear the document.
Automatic scopes enumerate every declared unit of the supplied input. Dependency checks combine
answers according to the declared resolution policy. `all_answers` retains any uncertainty;
`decisive` can resolve only when the known answers settle the combination regardless of the
unknown answers. Neither operation establishes that the declared questions cover an unstated
requirement.

## Separate the claim from its support

When auditing an assurance claim, separate **what the author claims** from **what the evidence
supports**. Give the claim-reading question the original prose and one explicit proposition.
Give the artifact question the relevant source, selected configuration, assumptions and tool
evidence. Combine the answers only after checking that those premises describe the same claim
and artifact. A proved leaf does not establish a complete supporting proof; a checked finite
model does not by itself establish an unbounded result.

For claim interpretation, compare a focused yes/no question with a `choice/1` question whose
categories distinguish assertion, denial, no claim and insufficient evidence. A quotation,
retraction, conditional goal and current assertion can contain the same words but make different
commitments. Keep uncertain readings unresolved. Test each arrangement with frozen examples and
external labels; its probability and confidence limits need their own validation. The
[formal-claims example](examples/formal-claims/README.md) shows this separation. Locating the
right proposition and establishing complete artifact coverage remain separate obligations.

Use a local `json-pointer-compare/1` check for exact relations between supplied values. For example,
compare the bundle-computed hashes of a current configuration and the configuration retained with
a verification run:

```json
"evaluator": {"kind":"json-pointer-compare","contract":"json-pointer-compare/1"},
"check": {"kind":"json-pointer-compare/1",
  "left":"/parts/2/source_sha256", "right":"/parts/3/source_sha256",
  "fail_when":"unequal"}
```

The two pointers address the same complete evidence frame. Both values must exist; a missing
operand is `not_evaluated`, even if both are missing. Present JSON nulls compare equal, so an
equality check alone does not establish that an arbitrary supplied field contains a valid hash.
Comparison uses typed JSON value equality: strings are not coerced to numbers, integer and
floating-point representations remain distinct, object key order does not matter, and array
order does. `fail_when` can be `equal` or `unequal`. The observation retains both pointers and
values. Like other deterministic checks, it requires pinned passing and failing fixtures.

Bundle hashes identify the bytes actually supplied to AudiToad. Their equality establishes
consistency of those files, not that an external tool ran, that a receipt is authentic, or that
its proof covers the stated claim. Keep those evidence and semantic obligations separate.

For exact membership in a supplied list, use `json-pointer-contains/1`. Both operands come
from the same frozen evidence frame. This can check whether an advertised property appears in
a parsed configuration, or whether a supplied value belongs to a policy list:

```json
"evaluator": {"kind":"json-pointer-contains","contract":"json-pointer-contains/1"},
"check": {"kind":"json-pointer-contains/1",
  "array_pointer":"/subject/configuration/properties",
  "value_pointer":"/subject/advertised_property",
  "fail_when":false}
```

Here, absence is a failure. Set `fail_when` to `true` when membership is a failure. The array
must be present and actually be an array; the queried value must also be present. Missing or
wrongly typed operands remain `not_evaluated`. An empty array establishes absence; an explicit
null can match a null member. Matching uses the typed equality described above, over every
array element. It does not coerce numbers, match substrings or require a fixed element position.
The observation retains both pointers, the queried value and the membership result. Pinned
passing and failing fixtures are required. Membership alone does not establish the meaning of
a selected property or authenticate the supplied list.

## Declare scope instead of selecting known locations

For ordinary UTF-8 text, use the `text/1` source with `text/plain` media. For JSON, use `json/1`
with `application/json` media. Both use the `scoped-input/1` evidence builder, revision `r1`.
For event logs containing one JSON value per nonblank line, use `json-lines/1` with
`application/x-ndjson` media. It supports record and document scopes and retains original line
numbers. One malformed line refuses the input; a record cannot be silently dropped.
Give each question a scope:

```json
"scope_kind": "site",
"scope": { "unit": "paragraph", "context": "document" }
```

This asks the question about **every paragraph**, with the complete document available as
context. No line numbers or known issue locations are needed. A paragraph is a run of nonblank
lines separated by one or more blank lines; Markdown headings and lists receive no special
interpretation. In JSON, `record` selects every element of a root array. `document` selects the
complete input and uses `scope_kind: "whole"`. A document scope uses `context: "none"` because
its subject already contains the complete input. For smaller units, `context: "none"` supplies
only that unit; `document` supplies the complete input as supporting context.

The question addresses `subject`; `context`, when present, supports that subject. All units are
selected before answers exist. Applicability must be `{"include":["*"],"exclude":[]}` for these
sources. Invalid input shapes refuse before evaluation. Empty unit selections remain unresolved.
If the complete context exceeds a limit, AudiToad refuses it instead of cutting it down.

The operator chooses the input file. The baseline author chooses a repeatable unit and the
context needed to decide the question. AudiToad performs that selection and records source
locations and hashes. It does not infer missing external facts or recursively discover files.
Code functions, inferred event relationships and time windows need explicit format contracts;
paragraph splitting is not a code parser or an event correlator.

Use `"unit": "sentence"` for questions about individual sentences. AudiToad enumerates
every nonblank segment produced by the pinned `unicode-segmentation` 1.13.3 implementation
of Unicode sentence boundaries. It trims surrounding whitespace and records exact UTF-8 byte
ranges. This is a text convention: Markdown headings, list markers and code remain text;
abbreviations and punctuation can produce boundaries that differ from a reader's interpretation.
An empty input stays unresolved. The complete document can accompany each sentence as context.

An `evidence-bundle/1` baseline can also declare sentence, paragraph or document scope when
each applicable packet contains one complete `subject` file. AudiToad keeps the ordinary
packet for existing checks and enumerates the scoped units automatically. Scoped checks use
`scoped-input/1`; unscoped checks keep `declared-parts/1`. Other declared parts accompany scoped
units under `supporting`. A partial subject or multiple subjects refuses preparation. Packet
applicability chooses the documents; it cannot omit individual units within them. A document
dependency check combines only that packet's child answers. The CLI prepares these scopes
automatically; library callers use `Snapshot::scoped_bundle`.

## Connect evidence from different inputs

Use `collection/1` with `application/vnd.auditoad.collection+json` media when a question needs
several files. The [collection manifest schema](docs/collection.schema.json) names complete
inputs and their formats. Paths are relative to the manifest's directory, or `--project-root`
when supplied. A missing source can be declared with `unavailable` and a reason instead of a
path. The [related-events example](examples/related-events/README.md) runs this directly.

An input with a `path` may also declare `sha256`, a lowercase SHA-256 pin for that
complete file. AudiToad checks every declared pin before preparing the questions,
including files supplied only as source dependencies. An unavailable input cannot
declare a pin. All declared files remain protected against changes during the scan.

An available `json/1` input can also declare `json_pointer` to select a nested
JSON value before ordinary scope enumeration:

```json
"reviews": {"adapter":"json/1", "path":"review.json",
            "json_pointer":"/reviews"}
```

Record scope enumerates every element of the selected array; document scope
supplies the selected value. Document context also refers to that selected value.
The empty pointer selects the root. Pointer escapes `~0` and `~1` select literal
`~` and `/` in member names. Malformed or missing pointers refuse preparation,
including on unused declared inputs; non-array record selections refuse, and
empty selected arrays remain unresolved. Other adapters and unavailable inputs
cannot declare this option. Strict JSON validation still covers the complete file.

Distinct named inputs may select different explicit pointers from the same exact
path. AudiToad reads, hashes and parses that file once; every alias pin must match
its complete bytes. Duplicate views, shared unprojected paths and case-variant
path collisions refuse. Source locations retain pointers into the original file,
and provenance retains the complete file hash. Omitting `json_pointer` preserves
existing evidence frames. These selections establish evidence scope, not the truth
of supplied review or execution claims.

The baseline maps those inputs to each question:

```json
"scope": {
  "input": "dns", "unit": "record", "context": "none",
  "related": [{
    "role": "process", "input": "processes", "unit": "record",
    "on": [
      {"subject": "/host", "related": "/host"},
      {"subject": "/process_instance", "related": "/instance"}
    ],
    "allow_empty": false
  }]
}
```

AudiToad enumerates every DNS record and supplies every process record with matching host and
process instance. JSON Pointer values must be non-null scalars of the same type and value;
there is no case folding or string-to-number conversion. All declared keys must match.
An empty `on` list supplies every unit of the related input, which is useful for a complete
reference document. Text can be related this way without being converted to event records.

The request contains `subject`, optional `context`, and arrays under `related.<role>`.
Source locations and hashes accompany the report. The baseline author chooses what makes two
records related; AudiToad enforces that declaration before asking a model. Use stable identities:
a reused operating-system process ID alone does not establish the same process instance.

`allow_empty: true` permits an available input with no matching records, as needed when checking
membership in an allowlist. It never permits an absent input or a missing correspondence key.
Those are named evidence errors, and dependent questions remain unresolved. A declared path
that cannot be read refuses preparation; either supply the file or declare why it is unavailable.
There is no inferred time window, causal link or external reputation lookup.

To compare a receipt's recorded file hash with the bytes AudiToad actually reads, set
`"include_provenance": true` in the baseline's `collection/1` source declaration.
The evidence frame then includes `/provenance/subject/input_sha256` and
`/provenance/related/<role>/<index>/input_sha256`. These are computed from complete
input files, including when the question selects a single record. Related identities
follow the same selection and order as `related.<role>`; each retains its input name
and location. A missing input has no computed hash and keeps its evidence error.
Use `json-pointer-compare/1` to compare a supplied receipt field with the corresponding
computed hash. This establishes byte correspondence, not that the receipt's claimed
execution occurred. The option is valid only for collections. Omitting it preserves
the existing evidence frame and does not change the evidence sent to models.

## Combine smaller answers

A combined check uses the `answers/1` evidence builder and evaluator. For example:

```json
"evaluator": { "kind": "answers", "contract": "answers/1" },
"check": {
  "kind": "answers/1",
  "rules": ["PROCESS-START", "ENCODED-COMMAND"],
  "fail_when": "all_fail",
  "coverage": "Flag a record only when it shows both process startup and an encoded command."
}
```

Both child questions must define the observations they report as failures. A parent with
`scope.unit: "record"` combines answers about **the same record**. A parent with
`scope.unit: "document"` combines every instance of its referenced rules. In a collection,
unit-level children must name the same subject input as the parent; their related evidence can
come from different inputs. Document-level parents may summarize explicitly referenced rules
across inputs. Equal row numbers in different inputs never establish a unit-level relationship.
Use a record-level `all_fail` followed by a document-level `any_fail` to ask whether any one
record has both properties. Combining the children directly at document scope would ask a
different question. Paragraphs follow the same rule. Combined checks use `context: "none"`;
their evidence consists of the referenced answer records.

`any_fail` suggests failure when at least one child fails. `all_fail` suggests failure when
every child fails. The optional `resolution` field determines how unresolved children affect
that answer. Its default, `all_answers`, requires every prerequisite to resolve.

Use `resolution: "decisive"` when one answer can establish the larger claim. For example,
one recorded file creation answers "Was any dump file created?" even if another event remains
unclassified. Every child still runs and remains in the report; this policy changes only the
combination's suggestion.

| Child decisions | `any_fail`, decisive | `all_fail`, decisive |
|---|---|---|
| All pass | Pass | Pass |
| All fail | Fail | Fail |
| Both a pass and a failure | Fail | Pass |
| Failures and unresolved answers, no passes | Fail | Review |
| Passes and unresolved answers, no failures | Review | Pass |
| Only unresolved answers, or no units | Review | Review |

`fail_when: "first_resolved"` takes the first prerequisite, in the order listed in `rules`, that
has a pass or fail decision; with none, it suggests review. Use it when later rules are
fallbacks that run only if an earlier one stays unresolved (see `run_when` below). The
`resolution` field does not apply to it.

More directly: with `any_fail`, one failure is enough, but a pass requires every child to pass.
With `all_fail`, one pass is enough, but a failure requires every child to fail. Errors, missing
evidence and budget refusals count as unresolved, never as a negative answer. The report retains
the direct child counts in `passed`, `failed` and `unresolved`, plus the selected resolution
policy. A resolved suggestion does not mean that every child was resolved. Empty scope remains
unresolved under either policy. Probabilities are not summed or multiplied.

Write down the parent question before choosing its resolution. "Does any event satisfy all
four conditions?" can be settled by one event whose four premises are established. "Have all
events been classified?" still needs every event to resolve. A known false premise also refutes
a conjunction for that one event while other premises remain unknown. Preserve those unknown
children in both cases. To compare these policies, replay the same child answers and score the
parents separately; new model answers would confound the policy comparison. A better parent
score alone does not justify changing a baseline's promised completeness.

Place prerequisites before dependent checks in `rules`. Selecting a parent automatically selects
its transitive prerequisites. Validation rejects unknown, duplicate, forward, cyclic and
cross-source dependencies. A unit-level parent cannot depend on a different unit type.
Reports retain each prerequisite's check ID, target, result and evidence hash. Combined checks
make no additional model request and remain experimental, including when their suggestion is clear.

For an `evidence-bundle/1` source, you can also omit `scope` on the parent and its children.
The parent then combines answers about the **same named packet**, such as two requirements
for one selected Python function. All prerequisites must use the same `scope_kind` as the parent.
Packet and automatic scopes cannot be mixed in a dependency. This does not expand selected
spans or establish that a function's dependencies were supplied; the bundle still controls them.

The `coverage` explanation states why the logical expression answers the larger question.
AudiToad validates the references and scope correspondence. Human review and counterexamples
must establish the implication itself: checking two convenient symptoms does not establish a
general claim that a system is secure.

## Let evaluators work together

A baseline decides which questions are asked and how their answers depend on each other. The
operator's evaluator file decides which models answer each role and how several models share
one question (see [Choose the models](docs/user-guide.md#choose-the-models)). Keep the two
apart: the same baseline can then be run with one model, two models in agreement, or a helper
feeding a judge, and the runs can be compared with `auditoad score`.

### Feed one rule's answer to another

Add `consult` to any evaluated rule:

```json
"consult": {"rules": ["POWERSHELL-CODE"], "run_when": "any_fail"}
```

The consulted rules' decisions and observations are added to this rule's evidence frame as
`prior`, in declaration order. A model question can then select them with `state_projection`, for
example `"parsed_commands": "/prior/0/observation/commands"`. Consulted rules follow the same
ordering, source and scope requirements as `answers/1` prerequisites. The evidence builder
must be `scoped-input/1` or `declared-parts/1`. `prior` omits provider request and response
bytes and their hashes, per-scan check IDs and timing, so the same input produces the same
evidence hash in every scan.

`run_when` controls whether the rule is evaluated at all:

| `run_when` | Evaluated when | Otherwise |
|---|---|---|
| `always` (default) | Always, with `prior` as supporting evidence | |
| `any_fail` | At least one consulted rule fails | All pass: suggests pass (a local check records pass); else suggests review |
| `any_pass` | At least one consulted rule passes | Not asked, no suggestion |
| `any_unresolved` | At least one consulted rule has no pass or fail decision | Not asked, no suggestion |
| `all_resolved` | Every consulted rule has a pass or fail decision | Not asked, no suggestion |

Use `any_fail` so a local selector decides which units need a model question. In the
[related-events example](examples/related-events/README.md), an exact command-line check finds
PowerShell invocations that carry `-Command` code; the model is asked about that code only for those
events. Use `any_unresolved` for a second question that runs only when the first stays
unresolved, and combine the two with `fail_when: "first_resolved"`. A skipped question makes no
provider call, and its record says why.

### Ask a helper to find or copy something

A judgment model is best at one focused decision about evidence it is given. Finding,
listing, copying and computing are a different job. Give that job to a helper with an
`extract/1` task, and let the judgment question consult it:

```json
{
  "id": "OPENED-NAME",
  "evaluator": {"kind": "model", "contract": "extract/1", "role": "helper"},
  "check": {
    "kind": "extract/1",
    "instructions": "Quote the expression that names the file this code opens.",
    "fields": {
      "name": {"type": "quote", "description": "The file-name expression, copied exactly."},
      "from_request": {"type": "boolean", "description": "Whether that expression reads request data."}
    },
    "max_request_bytes": null
  }
}
```

The helper returns exactly the declared fields. Field types are `string`, `boolean`, `number`,
`string_list`, `quote` and `quote_list`. A quote must occur verbatim in the evidence sent to the
helper; an invented quote refuses the answer with an error instead of passing it on. An
extraction makes no pass or fail suggestion, so `answers/1` cannot combine it; consult it instead:

```json
"consult": {"rules": ["OPENED-NAME"]},
"check": {"kind": "yes-no/1", "state_projection": {
  "code": "/parts/0/text",
  "name": {"pointer": "/prior/0/observation/fields/name", "optional": true}}, ...}
```

A projected field marked `optional` is sent as `null` when it is absent, for example when the
operator switches the helper role off. The same judgment can then be run with and without
the helper. `openai-compatible` requires strict JSON Schema response support for `extract/1`;
`auditoad-compatible` accepts its typed extraction response. `typesafe-jev` does not answer
extraction tasks. The neutral protocol also accepts typed fields from a conventional
helper service. Declare its supported tasks in the evaluator file and retain its exact
implementation revision. See the [neutral evaluator protocol](docs/user-guide.md#neutral-evaluator-protocol).

The author still has to show that the consulted evidence is enough for the question. `prior`
contains what the consulted evaluator reported, not a guarantee that it found everything.

## Interpret command lines

Use `command-line/1` when a rule depends on how a program parses its arguments. It tokenizes
each selected string with the Microsoft C runtime argument rules, identifies the invoked
program by the final component of its name, and binds declared options. It never executes or
decodes a command.

Declare the programs once under the baseline's top-level `command_grammars`, then reference
the grammar by name:

```json
"check": {"kind": "command-line/1", "json_array_pointer": "/related/process",
  "item_string_pointer": "/command", "grammar": "windows",
  "predicate": {"kind": "option", "programs": ["pwsh"], "option": "EncodedCommand"}}
```

Select either one string with `json_string_pointer`, or every item of an array with
`json_array_pointer` and `item_string_pointer`. An empty array passes; a missing pointer or a
non-string command is `not_evaluated`. The `invokes` predicate fails when any command runs a
listed program. The `option` predicate fails when an invocation binds the option, with a value
if the option takes one.

A program declares its `executables` (lowercase names), single-character `option_prefixes`,
whether a doubled prefix such as `--` is accepted, and an ordered `options` list. The first
matching option wins. An argument matches an option word when it is a case-insensitive prefix
of the word at least as long as `shortest`, which is how PowerShell matches `-enc` to
`-EncodedCommand`. Each option, and the `unmatched` and `positional` fallbacks, has a value
kind:

| Value | Meaning |
|---|---|
| `none` | A switch, or an ignored argument |
| `value` | The next argument is the option's value |
| `rest` | This and every later argument belong to a script or code; parsing stops |
| `launch` | This argument and the rest of the line are another command line |
| `cmd_command` | cmd.exe `/C` or `/K`: the rest of the raw line is a cmd command |
| `cmd_strip_quotes` | cmd.exe `/S` |

`cmd_command` applies the quote rule documented by `cmd /?`, splits the command on unquoted
`&` and `|` (honoring `^` escapes), and interprets each part. Whether a quoted name is an
existing executable cannot be checked, so an executable file extension stands in for it.
`title_argument` marks `start`, whose first quoted argument is a window title. Nesting deeper
than eight levels is `not_evaluated`.

The observation lists every invocation with its program, options, values and remainder, so a
consulting rule can inspect the parsed structure. Code passed to a program, such as the text
after PowerShell's `-Command`, is reported but not interpreted; ask a separate question about it.

## Qualify a question on different cases

Before the first live run, fix the requirement, question, evidence selection, model, thresholds
and expected answers. Include compliant and violating cases, nearby nonviolations, renamed
identifiers and equivalent forms. For text, include quoted examples and literal uses of language
that might otherwise look rhetorical. For code, include alternate control flow and the types or
contracts needed to understand it. Keep all expected answers outside provider evidence.

Use some cases to develop the question, then evaluate the frozen candidate on fresh cases.
Once a fresh case influences a revision, it becomes development data. Repeat unchanged inputs
to check stability, and record mistakes, reviews, errors and label corrections separately.
Report both correctness among decisive answers and the fraction of all checks resolved correctly.
A run that abstains on everything has found no wrong answers and has completed no decisions.

Choose thresholds for the question and the cost of a false answer. The examples retain a review
region, and the writing baseline uses different thresholds for its two grammar questions.
Thresholds are a decision policy, not a measured guarantee. Do not tune them on the examples
and report the result as new accuracy. A near-complete baseline
needs evidence for each rule family on unfamiliar inputs, including missed violations and false
alarms. The current semantic examples are development studies, not qualified universal checks.

The [writing example's local punctuation baseline](examples/no-slop/punctuation.baseline.json)
shows an exact rule using the installed evaluator. Its retained model study also shows why that
counting question should not be delegated to a semantic model.

When comparing evaluators, give each the same question, criteria and complete evidence. Use
each model's published input format. Keep expected answers and other evaluators' answers out
of the request. Report results for each question family: frequent negative cases can hide
missed violations in an overall percentage.

When testing decomposition, label the smaller observations as well as the final condition.
For an existential text question, compare judging the complete document with judging every
sentence and combining those answers. Keep necessary document context available to each
sentence, and test meanings that cross sentence boundaries. Use the same documents and final
labels for both designs; run both through an [audit file](docs/user-guide.md#run-an-audit-file-or-suite).
Inspect the prepared requests before enabling live calls. Labels belong outside every input.

Report sentence judgments and document combinations separately. Do not pool children and
parents into an accuracy percentage or count a local combination as another model call. If
comparing `all_answers` and `decisive`, two parent rules can consume the same children without
asking the model again. More individual questions can introduce more uncertain answers, and
an absence claim still needs every relevant unit to resolve. Decomposition is a hypothesis to
measure, not a guarantee of better results. Freeze a stop condition, retain failed candidates,
and check unchanged controls in other task families before adopting a change.

Choose combination rules before measuring them. Requiring agreement can leave more questions
unresolved, and two models can agree on a wrong answer. Letting a second model answer reviews
can increase coverage while introducing mistakes. Count both effects, and retain which errors
the models share. Select routing or thresholds using development cases, then test the complete
decision policy on new inputs. A model's stated confidence is not a calibrated error rate.

`auditoad score` compares runs. Write the expected answers in a labels file, kept outside every
input the scan reads:

```json
{"schema": "auditoad-labels/1", "labels": [
  {"rule": "WEB-PATH", "target": "handler-3", "violation": true}
]}
```

```console
auditoad score --report report.json --labels labels.json
auditoad score --report candidate.json --compare reference.json --labels labels.json
```

Scores expose every labelled case and its decision, comparison and refusal reason. Paired
scoring matches those labels across one frozen source snapshot, retaining changed decisions,
missing records and recorded request/evidence hashes. It accepts fresh child IDs in parent
evidence without treating those derived bytes as identical. Review differences in baseline
meaning separately; matching sources alone cannot establish equivalent questions. See the
[scoring workflow](docs/user-guide.md#labels-beside-your-inputs) for identity and exit rules.

Overall and per-rule totals include every supplied label. Missing report records count as
unresolved, appear in `labels_without_records`, and set `label_coverage_complete` to false;
the command prints the score and exits with code 2. Complete label coverage exits with code 0,
even when decisions are wrong or unresolved. Duplicate report pairs and empty label sets are
refused. Per-model totals cover recorded model observations only. Label coverage concerns
the supplied labels; it does not establish coverage of an entire project or document set.

The summary counts true and false positives and negatives and unresolved answers for the whole
report, each rule and each model. A role that asks several models and combines them with
`agreement`, `any_fail` or `all_fail` asks every model, so one such run also scores each model
alone and simulates every combination policy. Run the same labels against reports from
different evaluator files or question designs to compare them. An unresolved answer counts as
not reported in the rates, as the OWASP Benchmark scorecard counts it.

## Read a baseline

The schema is `auditoad-baseline/1`. The [JSON Schema](docs/baseline.schema.json) supports editor
validation; `auditoad baseline validate` also checks references and installed contracts.
These fields describe the audit:

| Field | What you put in it |
|---|---|
| `baseline` | An ID, version, title, publisher and status (`draft`, `admitted` or `retired`) |
| `sources` | Names for input adapters and the types of data they accept |
| `evidence` | How to select the content a rule will inspect |
| `groups` | Names for related rules |
| `requirements` | Optional: the requirements the audit must cover, with revisions |
| `rules` | Each rule's question or predicate, evaluator, applicability and known-answer checks |
| `profiles` | Which rules to run, which results block the scan and where model requests may go |

The CLI's `--source` selects an alias from `sources`; `--profile` selects a profile.
Rules run in baseline order, with targets in source order. Profiles select all rules with
`*`, one rule by ID, or a group with `GROUP/*`.

Each rule has an `id` and `revision`. Give it a title that names the requirement. Its
`source`, `group` and `evidence` refer to declarations elsewhere in the baseline.
`risk` is `low`, `medium`, `high` or `critical`. `falsifier` describes the counterexample
the rule should detect. Change the rule revision when its meaning or evidence changes,
and change the baseline version when you revise the document.

`applicability.include` accepts `*` or exact filenames or target kinds; `exclude` removes
exact matches. These are not glob patterns. Every selected rule/target pair receives a
record, including pairs classified as `notapplicable`.

## Declare the requirements

A scan records every rule it ran, but it cannot know about a requirement nobody wrote a rule
for. List the requirements the audit must cover, and link each rule to the ones it checks:

```json
"requirements": [
  {"id": "ENC-1", "revision": "2", "title": "Disks are encrypted", "reference": "Policy 4.1"}
],
"rules": [
  {"id": "DISK-ENCRYPTED", "requirements": {"ENC-1": "2"}, "...": "..."}
]
```

The value in a rule's `requirements` is the requirement revision the rule was written
against. When you change a requirement, raise its `revision`; every rule still naming the
old revision reports the requirement as `stale` until you review the rule and update it.

The report lists each requirement with the selected rules that check it and their result
counts. Its `status` is one of:

| Status | Meaning | Blocks the audit |
|---|---|---|
| `satisfied` | Every applicable linked result passed | No |
| `finding` | A linked result failed or needs review | No; it is a finding |
| `missing` | No rule checks this requirement | Yes |
| `unasked` | Rules check it, but the profile selected none of them | Yes |
| `stale` | A selected rule names another revision of the requirement | Yes |
| `unsupported` | No selected linked rule applied to the supplied evidence | Yes |
| `unresolved` | A linked result is an error or was not evaluated | Yes |
| `not_required` | The profile does not require this requirement | No |

Any blocking status makes the outcome `unresolved` (exit 2), and `outcome_reason` names each
blocked requirement. A profile's optional `requirements` list names the requirements it must
cover; omit it to require all of them. Baselines without `requirements` scan as before.
Coverage is checked only for requirements the baseline declares.

## Choose an evaluator

| What you are auditing | Input adapter | Evidence builder | Evaluator |
|---|---|---|---|
| Bytes in a supplied file | `raw-bytes/1` | `bytes/1` | `yara-x/1.20.0` |
| Vocabulary, emphasis, lists or paragraph counts in Markdown | `raw-bytes/1` | `bytes/1` | `markdown/1` |
| Facts in inventory records | `inventory-json/1` | `item-json/1` | `json-pointer-equals/1` |
| Every sentence, paragraph or a complete text input | `text/1` | `scoped-input/1` | `yes-no/1` |
| Every record in a JSON array or a complete JSON value | `json/1` | `scoped-input/1` | `yes-no/1` |
| Every record in a JSON Lines event log | `json-lines/1` | `scoped-input/1` | `yes-no/1` |
| Related records or documents from several inputs | `collection/1` | `scoped-input/1` | `yes-no/1` |
| How command lines invoke programs and bind options | Any source with a JSON evidence frame | That source's builder | `command-line/1` |
| A declared combination of earlier answers | The same scoped source | `answers/1` | `answers/1` |
| Python, other source code, documents or configuration with supporting evidence | `evidence-bundle/1` | `declared-parts/1` | `yes-no/1` |

The evaluator declaration's `kind` is `yara-x`, `markdown`, `json-pointer-equals`,
`json-pointer-compare`, `json-pointer-contains`, `syntax`, `tlaplus-relation`, `command-line`,
`model`, `mock-model` or `answers`.
Its `contract` and the check's `kind` use the versioned names in the table. Unknown bindings,
unknown JSON fields, duplicate keys and unresolved references fail validation.

For inventory checks, `pointer` is a JSON Pointer such as `/facts/encrypted`. Set
`expected` to the required value and `fail_when` to `unequal` to reject a different value.
A missing fact produces `not_evaluated`. AudiToad evaluates the supplied records; inventory
collection belongs to the system that produced them.

The same `json-pointer-equals/1` check works on scoped, bundle and Rust evidence frames.
For example, `/subject/type` selects a field from a scoped record, and
`/related/allowlist` selects the complete matched allowlist. Compare that array with `[]`
to check whether it is empty. Missing related input still refuses evidence construction;
it cannot become an empty array or a passing check. Equality is exact and does not coerce
strings, numbers or letter case. Local answers can be prerequisites of `answers/1` rules.

For YARA checks, `source` contains the YARA rule, `rule_name` selects its compiled rule,
and `fail_when` is `match` or `no_match`. YARA-X compiles and evaluates that rule locally.

To scan one string in a JSON evidence frame, add `json_string_pointer`. With scoped text,
`/subject` selects the paragraph or document. With a scoped JSON record, `/subject/message`
selects its message field. In a bundle whose evidence requires only the single `subject`
role, `/parts/0/text` selects that subject's text. Check the prepared evidence before choosing
a pointer. Only the decoded string's UTF-8 bytes are scanned; surrounding context, field names
and JSON escapes are excluded. An absent or non-string value is `not_evaluated`, while an
empty string is a valid input. The report retains the complete frame and the selected string's
hash and byte length. Omit the pointer only for the original raw-byte binding.

For `markdown/1`, set the evaluator to `{"kind":"markdown","contract":"markdown/1"}`.
Choose one predicate:

```json
{"kind":"markdown/1","json_string_pointer":"/subject","predicate":{"kind":"list_length","forbidden_length":3}}
```

```json
{"kind":"markdown/1","json_string_pointer":"/subject","predicate":{"kind":"paragraph_sentence_lengths","shorter_than":7,"longer_than":30}}
```

```json
{"kind":"markdown/1","json_string_pointer":"/subject","predicate":{"kind":"prose_bold"}}
```

```json
{"kind":"markdown/1","json_string_pointer":"/subject","predicate":{"kind":"forbidden_terms","terms":["very","keep in mind","cutting-edge"]}}
```

The pointer selects a decoded string just as it does for YARA; omit it for raw UTF-8 input.
The first predicate fails if any CommonMark list has exactly the forbidden number of direct
items. Nested lists are counted separately. The second fails if any prose paragraph lacks
either a sentence shorter than `shorter_than` or one longer than `longer_than`. Those limits
are exclusive: seven words is not shorter than seven. Thresholds must be positive, with
`2 <= shorter_than <= longer_than`.

`forbidden_terms` fails when a listed word or phrase occurs in visible Markdown text. It checks
paragraphs, headings, list items and block quotes, including link labels. Inline and fenced code,
image alternative text and link destinations do not count. Terms cannot span separate blocks or
excluded code or images. Formatting and entities are decoded, so `v&#101;ry` and `v**er**y`
both match `very`.

Terms use complete Unicode word boundaries: `very` does not match `delivery` or `veryé`.
Matching compares Unicode lowercase spellings and treats a curly apostrophe (U+2019) as `'`.
Whitespace inside phrases may vary; other punctuation must match, so `cutting-edge` and
`cutting edge` differ. There is no stemming, Unicode composition normalization or full case
folding. Use separate terms for those variants when the policy requires them. The list must
contain at least one term; each term must start and end with a word and contain no non-whitespace
control character. An empty document passes this absence check.

Each `term_matches` entry identifies the configured term, a decoded `matched_text` witness and
the containing Markdown block's `source_block_bytes` range. That range selects the whole block,
because markup and entities can make the decoded witness differ from the source spelling.

`prose_bold` fails when visible text inside a prose paragraph has strong emphasis (`**text**`
or `__text__`). Bold link labels and quoted prose count. Headings, lists, code blocks, escaped
delimiters, image alternative text and image-only spans do not. A document without bold prose
passes. The report's `bold_spans` gives each matching source range, including its delimiters.

The binding uses CommonMark without extensions, parsed by `pulldown-cmark` 0.13.4. For the
bold and sentence-length predicates, prose means paragraphs outside lists, including block
quotes; headings and code blocks are excluded. For sentence-length counts, inline code, link
labels and image alternative text contribute words, but destinations and markup do not.
Entities are decoded and Markdown line breaks become spaces. Sentence and word
boundaries use [unicode-segmentation 1.13.3's UAX #29 convention](https://docs.rs/unicode-segmentation/1.13.3/unicode_segmentation/trait.UnicodeSegmentation.html). This is reproducible, but not
language-specific linguistic analysis: for example, `Mr. Fox jumped.` becomes sentences of
one and two words, while `Short sentence. lowercase continuation.` stays one sentence.
Review that convention before selecting it for your policy.

Raw HTML produces `not_evaluated`, since this binding does not interpret its lists or prose.
No prose paragraphs also produces `not_evaluated` for the sentence predicate. No lists is a
valid pass for the forbidden-list-length predicate. Reports include selected-text hashes,
list sizes, sentence word counts and source byte ranges within the selected string. They are
zero-based ranges whose end is excluded; they do not refer to the surrounding JSON frame.

Model questions name no model. The operator's evaluator file decides which model answers each
rule, through the optional `role` in the rule's evaluator declaration; see
[Choose the models](docs/user-guide.md#choose-the-models).

For `yes-no/1` checks, set the evaluator to `{"kind":"model","contract":"yes-no/1"}`, supply a
complete question in `instructions` and describe the two answers in `criteria_true` and
`criteria_false`. With `pass_below: 0.1` and `fail_at_or_above: 0.9`, a probability below 0.1
suggests pass, one at least 0.9 suggests fail, and values between them suggest review. These
thresholds specify how to interpret a response; they do not establish accuracy, and a threshold
validated for one model need not suit another.

Use `choice/1` when a question has several named answers. It accepts the same inputs and
evidence builders as `yes-no/1`. Set the evaluator to
`{"kind":"model","contract":"choice/1"}`. The check declares `instructions`, `options`,
`min_choice_probability` and `min_confidence`. `typesafe-jev` answers it through TypeSafe's
choice protocol; `openai-compatible` answers choices of up to 26 options from the first token's
log-probabilities over option letters. For example, an option can be
`"missing":{"description":"The required approval is absent.","result":"fail"}`.
Each option has a description and a `pass`, `fail` or `review` mapping. Include an option
for evidence that cannot resolve the question, mapped to `review`. There must be 2 to 255
options; make their meanings distinct and cover the possible answers.

The model receives the question and option descriptions. AudiToad retains the selected label,
all option probabilities and the separate confidence value. Both decision limits must be
met before applying the selected option's mapping; otherwise the suggestion is `review`.
The response must name exactly the declared options, contain finite probabilities in [0,1],
and select a highest-probability option. By default the probability sum must be within
`0.000001` of one. TypeSafe operators can explicitly allow rounding with
`choice_probability_sum_tolerance`, bounded from zero through `0.01`; a nondefault value
changes evaluator identity. A rejected sum reports its actual value and the required tolerance.
Values are not silently renormalized. Invalid responses are errors. Choice confidence
and yes-no probability describe different outputs, and each backend defines its own confidence;
thresholds need validation for the question type and the backend that answers it.

Semantic baselines must remain `draft`; ordinary CLI runs derive experimental status from it. Their terminal result
is `not_evaluated`, even when the response suggests pass or fail. Provider failures remain
errors. The local `mock-model/1` adapter is available for testing response handling.

## Choose which fields the model receives

By default, the model receives the complete prepared evidence frame. Model questions and extraction tasks accept
an optional `state_projection` mapping from readable field names to JSON Pointers in that
frame. For a scoped record, this check field selects its message and related process records:

```json
"state_projection": {
  "message": "/subject/message",
  "processes": "/related/process"
}
```

The question can then refer directly to `message` and `processes`. The baseline author controls
this mapping. AudiToad applies it to every applicable target; it does not search for a passage
that supports a particular answer. Inspect a prepared report to find the correct pointers.
Array values are preserved in full, and no text is truncated or summarized.

The map must contain at least one field, and field names cannot be blank. A missing pointer
leaves the check unresolved before a provider call. An existing null, empty string or empty
array remains that value. Projection cannot restore evidence that the scope or evidence builder
omitted; select all the context required by the question first. The normal request-size ceiling
still applies.

When several optional fields are alternatives for required evidence, declare
`state_required_any` alongside the projection:

```json
"state_projection": {
  "code_a": {"pointer": "/prior/0/observation/fields/captures", "capture": "function", "optional": true},
  "code_b": {"pointer": "/prior/1/observation/fields/captures", "capture": "function", "optional": true},
  "context": {"pointer": "/prior/2/observation/fields/context", "optional": true}
},
"state_required_any": [["code_a", "code_b"]]
```

Every group must be nonempty and name fields declared in `state_projection`. At least one
field in each group must have a non-null projected value; otherwise AudiToad records
`not_evaluated`, retains the evidence and refuses provider dispatch. Missing optional fields
and explicit nulls do not satisfy a group. Other values, including false, empty strings and
empty arrays, remain present values; this condition does not validate their type or meaning.
In this example, missing helper context is allowed, but missing both selected functions is
refused. A `yes-no/1`, `choice/1` or `extract/1` check without groups keeps its existing behavior.

The optional `capture` declaration selects source text by the label written in the syntax
query, such as `@function`, rather than a capture's position in the array. Its pointer must
name the capture array. Exactly one matching label must have nonempty string `text`.
No matching label follows the field's ordinary optional/required behavior; multiple matching
labels, a non-array value or malformed selected text refuse the request even for an optional
field. Capture names cannot be blank. Unknown field settings, misspelled settings and a null
`capture` are rejected when loading the baseline. Ordinary pointer fields and declarations
without `capture` keep their existing selection and serialization.

Reports retain the complete evidence in `evidence.bytes` and the actual provider request in
`observation.request_bytes`. Compare them during preparation to verify exactly what would leave
the machine. Selection changes the information available to the model, so validate the question
again after changing its mapping. A smaller request alone does not establish better accuracy.

## Known-answer checks (`fixtures`)

A fixture is a saved input with a known expected result. Deterministic rules require at
least one passing input and one failing input. Before scanning your input, AudiToad checks
their hashes and evaluates them to confirm that the rule still produces those results.

In the disk-encryption example, `encrypted.json` and `unencrypted.json` are these checks.
`inventory.json` is the data being audited. The baseline's `fixtures.pass` and
`fixtures.fail` arrays name the two checks and record their `corpus_revision`,
`source_sha256` and `evidence_sha256`. Paths are relative to the baseline's directory and
must stay beneath it. Preserve exact file bytes, including line endings.

`source_sha256` identifies the input file. `evidence_sha256` identifies the bytes the
evaluator sees. For byte checks they are identical. Inventory checks serialize a single
record into compact JSON, so its evidence hash can differ from its file hash.

For a local check over a scoped or bundle frame, the known-answer file contains the JSON
frame to evaluate. Its source and evidence hashes identify that complete frame; a YARA or Markdown
string pointer is applied during evaluation exactly as it is for the audit input. The
writing example's `local-checks-pass.json` and `local-checks-fail.json` check its seven local
predicates before the articles are audited.

Model questions use empty fixture arrays. The scanner does not admit semantic rules by
running them against known answers. Evaluate a proposed question separately before relying
on its suggestions, including examples that satisfy the policy and examples that violate it.

## Supply Python or other file evidence

An evidence bundle names the files and the parts each question needs. See
[the shipping-policy bundle](examples/shipping-policy/bundle.json) for a complete example.
It pairs the Python function with its policy. The bundle's paths are relative to
`--project-root`, which can be your project's directory.

Every file has a lowercase SHA-256 hash in `files`. Update that hash when you intentionally
change the file. A changed hash, missing file, non-UTF-8 file, parent traversal or symbolic
link is refused for text declarations. AudiToad reads Python as text; this adapter does not
import or execute it. PNG declarations use the explicit image form below.

Each packet has an `id`, a `kind`, a `scope_kind` and a list of `parts`. Parts name a
`role` and `path` and retain the complete pinned file. A packet's `kind` is a name you choose, such as
`python-function`, and rules can use that name in their applicability settings.

To select a function, use a local `syntax/1` helper with a query naming that function.
A later question can consult its captures and project only their text. For selection that
depends on behavior, use an `extract/1` helper to quote the relevant code, then project that
checked quotation into the question. Keep supporting policy and caller context explicit.
The bundle format rejects `start_line` and `end_line`; moving code does not require editing
line selectors. File hashes still change when the source changes.

The scope describes the supplied subject:

| Scope | Required parts |
|---|---|
| `site` | One `subject`, such as a function, with any supporting evidence |
| `relation` | One `subject` and a distinct `peer` file, plus supporting evidence |
| `whole` | Complete files for all subject parts |

The baseline's evidence declaration lists `required_roles`, including `subject`. Only
parts with those roles enter the request. Naming a policy file in the bundle is not enough:
the evidence declaration must select its role too. Missing required roles produce an error
before a provider call. Review the selected files, helper captures and projected request for
the question you are asking.

To calculate a file's hash with Python:

```console
python -c "import hashlib, pathlib; print(hashlib.sha256(pathlib.Path('examples/shipping-policy/shipping.py').read_bytes()).hexdigest())"
```

## Supply screenshot evidence

Screenshot and image-model evidence is experimental. Native TypeSafe image questions and
Box location helpers are explicit preview bindings; their observations do not admit an audit.

The same evidence bundle can declare a PNG or JPEG and a region:

```json
{
  "schema": "auditoad-evidence-bundle/1",
  "files": {
    "screen.png": {"sha256": "<lowercase SHA-256 of the original file>", "media": "image/png"}
  },
  "packets": [{
    "id": "settings-screen", "kind": "screenshot", "scope_kind": "site",
    "parts": [{"role": "subject", "path": "screen.png",
      "region": {"x": 20, "y": 40, "width": 300, "height": 80}}]
  }]
}
```

Coordinates start at zero at the top left; width and height are positive pixel counts.
Omit `region` to select the full image. A `region` is valid only for an image part.
Use `"media": "image/jpeg"` for a JPEG file. The original image bytes, hash, header dimensions and region remain in evidence. The full image
is retained and sent when that part is selected; a region does not crop or redact the bytes.
Supply a separately cropped, pinned file when only that content may enter a provider request.

AudiToad reads the PNG signature/IHDR or JPEG start/frame header. It does not decode pixels,
check complete image structure or certify capture origin, freshness, complete format validity
or visible content. Reports identify this as `png-header-only/1` or `jpeg-header-only/1`.
The provider must decode the original bytes and report failure when they are invalid.
Other image formats and automatic text scope on an image are unsupported. Region bounds use
the supplied header; they do not establish pixel validity.

Configure a neutral helper with `"backend": "auditoad-compatible"` and
`"capabilities": ["extract/1", "image/png"]`. Its `extract/1` task can select the image part
through `state_projection`, return declared `string` fields for OCR text, and make no policy
decision. The helper receives lossless hex under the part's `bytes` field, the original file
hash and region. A later rule consults that committed helper and selects its fields, retaining
the original image and derivation in its evidence. Required missing or mistyped fields refuse.
`quote` is for existing text; new OCR text uses `string` and needs separate extraction testing.

The native TypeSafe image binding accepts whole-image parts and refuses partial regions;
it sends the original image bytes and does not crop or confine the provider to a region.
Text-only bindings refuse native image payloads. They can process an explicit projection of
derived text after the image helper. AudiToad ships the binding contract and controls; supply
a compatible OCR/vision service and measure it against labelled images before relying on it.
Transport/protocol tests do not establish accurate OCR.

### Native Jev images and Box locations

Select original image parts with a question's optional `image_assets` map. Each value is a
JSON Pointer into the complete retained evidence frame; each key is an opaque image reference.
References use 16–1024 ASCII letters, digits, hyphens or underscores, must not overlap, and
must appear in the projected state, instructions or criteria. Each selected pointer has one
reference. The total reference length is
at most 65,536 bytes. An exact image part in projected state becomes its reference; references
in instruction and criterion strings remain in place. Object keys are never image references.
Select the complete image part, including its source hash, media, dimensions and lossless bytes.

```json
{
  "kind": "box/1",
  "instructions": "The red rectangle in `photo`.",
  "state_projection": {"photo": "/parts/0"},
  "image_assets": {"auditoad-image-controlled-001": "/parts/0"}
}
```

The rule uses `{"kind":"model","contract":"box/1","role":"vision"}`. Its baseline stays
`draft` and its scan uses `--experimental`. Configure that role with the fixed model:

```json
{
  "backend": "typesafe-jev",
  "model": "jev-1.14.0",
  "endpoint": "https://api.typesafe.ai/v1/systemone",
  "key": {"env": "TYPESAFE_API_KEY"},
  "allow_images": true,
  "capabilities": ["yes-no/1", "choice/1", "box/1", "image/png", "image/jpeg"]
}
```

The explicit opt-in sends `TypeSafe-Danger-Zone-Images: true`. It is recorded in evaluator and
reuse identity. Omitted `allow_images` and `image_assets` preserve existing text bindings and
request bytes, including existing Jev 1.13 questions. Native PNG/JPEG bytes become top-level
TypeSafe `assets` with standard padded base64. This binding uses JSON uploads; it does not
rewrite, resize, crop or transcribe the image. One image reference can occur in state,
instructions or a yes/no/choice criterion. Every declared asset must actually be referenced.
The neutral compatible protocol retains original image descriptors under its optional assets.

Before a native TypeSafe request, AudiToad checks the original-byte hash, image header
dimensions, 16 MiB file limit, 256–1568 pixels per dimension, 78,400–2,458,624 total pixels,
and the 32 MiB wire-body limit in addition to the scan/question/model byte ceilings. The
provider's decoded/processed-image and expanded-context limits remain server checks. An HTTP
refusal remains an error with the original response retained; it is never retried automatically.
These TypeSafe limits do not change the neutral helper's existing image policy.

Box needs exactly one evaluator and, for TypeSafe, fixed `jev-1.14.0` with the opt-in. It accepts
no criteria. A successful response commits `fields.box.{left,right,top,bottom}` and
`fields.confidence` in the observation. Coordinates are finite fractions of the full image:
0 through 1, with left strictly below right and top strictly below bottom. Model, question,
answer set, response type and token usage must match. The helper remains `not_evaluated` and
makes no pass/fail suggestion. Later rules can consult those committed fields; experimental
provenance propagates to their results.

Use a local `json-number-range/1` check for a known geometry or confidence threshold:

```json
{
  "kind": "json-number-range/1",
  "pointer": "/prior/0/observation/fields/box/left",
  "minimum": 0.23,
  "maximum": 0.27,
  "fail_when_outside": true
}
```

Its evaluator is `{"kind":"json-number-range","contract":"json-number-range/1"}`.
Bounds are finite and inclusive; missing or mistyped values are unresolved. Declare local
pass/fail fixtures. Four separate edge checks and a confidence check can be combined using
the existing `answers/1` rule. A passing synthetic-image geometry test establishes that case
and tolerance only; protocol validity, source custody and visual accuracy remain distinct.
See the [TypeSafe image protocol](https://docs.typesafe.ai/images) and
[Box protocol](https://docs.typesafe.ai/primitives/box) for the preview API.

## Admission and derived evidence

For this release, `admitted` baselines support installed mechanical checks with known-answer
fixtures. Semantic questions and external extraction remain `draft`; setting their baseline
to `admitted` is refused. `retired` baselines cannot scan. A status label is not independently
authenticated qualification, and mechanical admission does not prove a supplied record is true.

Experimental status follows consulted model/helper output through later local checks, helpers
and conditional gates. These consumers retain `experimental_inputs: true`; pass/fail decisions
become `suggested_result` with terminal `not_evaluated`, available to scoring. A deterministic
comparison cannot turn an unqualified OCR or model result into an admitted clearance. Local
checks over supplied evidence and local syntax captures retain their own mechanical scope.

Qualification and reuse are bound to the baseline/evidence/evaluator arrangement. Changed
questions, evidence, source pins, implementation revisions, endpoints or capability/decoding
policy invalidate matching reuse. Preserved hashes check consistency, not independent provider
attestation. No automatic semantic admission or model accuracy percentage is a beta gate.

## Use syntax helpers

Use `syntax/1` when a question needs exact source spans selected by syntax. It runs locally
with a pinned Tree-sitter grammar; it does not execute the supplied code. Supported `language`
values are `bash`, `zsh`, `powershell`, `python`, `rust`, `verus` and `tlaplus`. For example:

```json
{
  "kind": "syntax/1",
  "language": "python",
  "json_string_pointer": "/subject",
  "query": "(call function: (identifier) @callee) @call",
  "limits": {"input_bytes":1048576,"nodes":100000,"captures":1000,"output_bytes":1048576,"timeout_ms":2000,"match_limit":256}
}
```

Declare `"evaluator":{"kind":"syntax","contract":"syntax/1"}` and a draft baseline with
empty pass/fail fixture lists. A helper produces evidence, not a policy decision; its record
remains `not_evaluated`, even with a complete query. `answers/1` cannot use it as a decision.
Omit the pointer only for raw UTF-8 bytes; otherwise select one string from a scoped, bundle or
inventory frame. Offsets refer to that selected string, not its enclosing JSON encoding or the
whole original file when only a source slice was supplied.

Use `verus` for Rust files containing Verus contracts or `verus!` blocks. It uses the
upstream Verus grammar pinned to commit `0c939ef2ec0a188c3cf24518474fb8082db02ec4`,
including its named function, contract and expression nodes. The helper parses the original
bytes and preserves their source hashes and capture offsets; it does not normalize source,
expand macros or check proofs. Whole-source parse errors still withhold capture fields.

Queries use the selected grammar's node/field names. Named captures and Tree-sitter's built-in
text predicates are supported. Custom predicates, property predicates and directives are refused
at validation rather than silently ignored. The [public example](examples/language-helpers/README.md)
shows queries for six languages and questions using `consult`.

Each observation retains source/query SHA-256, grammar/runtime version, parser ABI, limits,
diagnostics and `complete`. Successful `fields.captures` entries retain exact source text,
half-open UTF-8 byte spans, capture name, node kind and pattern/match grouping. A syntax error
or missing token leaves `complete: false` and supplies no fields. Missing source and resource
refusals retain a reason and no observation. Require the fields in a question's `state_projection`
to prevent dispatch when the helper is incomplete, or explicitly declare them optional.

Limits shown above are defaults; omitted members retain defaults. All must be positive;
`match_limit` is at most 65536. Input, node traversal, capture count, serialized output and query
match limits refuse partial results. The cooperative timeout covers parsing/traversal/query work;
it is not an OS-enforced deadline or a process memory limit. Syntax output also consumes the
scan's cumulative evidence allowance. A dependent question's evidence is charged separately.

| Language | Pinned grammar | Coverage boundary |
|---|---|---|
| Bash | `tree-sitter-bash 0.25.1` | Shell syntax; expansions, aliases and sourced code are not executed |
| Zsh | `tree-sitter-zsh 0.63.4` | Distinct Zsh grammar; arbitrary delimiters in some glob qualifiers remain unsupported upstream |
| PowerShell | `tree-sitter-powershell 0.26.4` | Syntax; no command binding, alias resolution or PowerShell runtime validation |
| Python | `tree-sitter-python 0.25.0` | Syntax; no import/name resolution, type checking or execution |
| Rust | `tree-sitter-rust 0.24.2` | Syntax; no crate resolution, cfg evaluation, macro expansion or borrow checking |
| TLA+ / TLAPS | `tree-sitter-tlaplus 1.5.0` | Module and proof syntax; no TLC configuration parsing, operator/instance resolution, proof discharge or temporal checking |

The shared runtime is `tree-sitter 0.27.0`. These grammar versions are not language-version or
edition guarantees. A recovered tree does not prove valid syntax under a particular compiler;
an error-free tree establishes only this grammar's interpretation. `complete: true` means the
declared query completed on the supplied syntax. It does not establish full project coverage or
that an empty capture list proves a behavior absent. Keep semantic questions and their required
context explicit, and compare the helper's usefulness on frozen labels before adopting a baseline.

For TLA+ definitions, `(operator_definition name: (identifier) @name definition: (_) @body)`
preserves the written name and expression. `(fairness) @fairness` captures actual fairness
syntax rather than a matching string or comment. A definition containing fairness may be unused;
these captures do not establish that the configuration selects it. For TLAPS,
`(theorem name: (identifier) @name proof: (terminal_proof) @leaf)` retains direct proof leaves,
including `OMITTED`. Nested proofs need their own query, and a captured `BY` step does not
establish that all its dependencies were proved. Use SANY and the relevant proof checker for
their authoritative language and verification results.

## Check written TLA+ relationships

`tlaplus-relation/1` uses the same pinned TLA+ parse to decide one written relationship
without a model. The source and operand names come from JSON pointers in the frozen frame:

```json
{
  "kind":"tlaplus-relation/1",
  "json_string_pointer":"/subject/source",
  "operator_pointer":"/subject/operator",
  "predicate":{"kind":"positive_conjunct","reference_pointer":"/subject/dependency"},
  "fail_when":true
}
```

Use evaluator kind `tlaplus-relation`, contract `tlaplus-relation/1`, and both pass and fail
fixtures. The predicate is true when the named reference is a written positive conjunct
after flattening only conjunctions and parentheses. Negation, implication, disjunction,
strings and comments do not supply it. `direct_alias` uses the same `reference_pointer`
but requires the whole body to be that reference, allowing parentheses. `weak_fairness`
instead requires `action_pointer` and `subscript_pointer`; the whole body must be the
corresponding `WF_` expression. `SF_` does not match that exact syntactic predicate.
`fail_when` maps the observed boolean to the baseline's failure condition.

The binding selects one zero-argument definition directly in one outer module. Names must
be simple ASCII identifiers. Missing, duplicate, nested-only or parameterized definitions,
missing/wrongly typed operands, syntax errors and exhausted limits remain unresolved.
The optional `limits` use the syntax-helper limits above, with relation traversal charged
to the same node budget. Reports retain the selected definition, actual operand names and
any positive witness as exact source spans under `fields.relation`. A false predicate retains
the complete selected definition so its scope is inspectable.

These are local syntax predicates. They do not expand aliases, resolve imported names,
select a TLC configuration or prove a theorem. For example, `A == B /\\ TRUE` is logically
equivalent to `B` but is not a direct written alias. Keep evidence support and claim meaning
as separate questions. The [formal relationships example](examples/formal-relations/README.md)
runs all three predicates locally with external labels.

## Validate and run

From the repository root:

```console
auditoad baseline validate examples/shipping-policy/baseline.json
auditoad scan --baseline examples/shipping-policy/baseline.json --input examples/shipping-policy/bundle.json --report prepared.json
```

Preparation writes evidence and `request_bytes` to the report without calling a model. To send
the request, add `--evaluators <file> --live` with an evaluator file naming your backend.
The profile's `allowed_egress` must permit every endpoint the evaluator file uses:
the backend's HTTPS origin, such as `["https://api.example.com"]`, `["loopback"]` for a model on this machine, and an empty
list for local-only profiles. Reports contain the submitted evidence, so check their contents
before sharing them.

Use `auditoad scan --help` for input, evidence, check and provider-call limits and the
provider timeout. Oversized requests refuse without truncation. Each live call also reserves
65,536 bytes of the cumulative evidence allowance for its response. The scan request limit
defaults to 1 MiB; a check's or evaluator's `max_request_bytes` can impose a smaller limit.
See the [limits guidance](docs/user-guide.md#limits-and-common-failures) for budgeting a prepared
scan and the explicit TypeSafe Choice rounding policy.

Profiles must block `error` and `not_evaluated`; audits that require findings to block should
also include `fail` and `review`. A complete scan without a blocking result exits 0. A blocking
finding exits 1. Unresolved, incomplete or experimental work exits 2, which takes precedence
over 1. Invalid inputs exit 3. See the [examples guide](examples/README.md) for expected reports.
