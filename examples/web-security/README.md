# Review Python web handlers against the OWASP Top 10

This example checks each handler in `handlers.py`, a small Flask application, for one weakness
from the [OWASP Top 10:2025](https://top10.owasp.org/2025), identified by its CWE. The code
contains no comments that reveal which handlers are vulnerable.

| Question | OWASP Top 10:2025 | CWE |
|---|---|---|
| `WEB-PATH` | A01 Broken Access Control | 22, path traversal |
| `WEB-REDIRECT` | A01 Broken Access Control | 601, open redirect |
| `WEB-COOKIE` | A02 Security Misconfiguration | 614, cookie without Secure |
| `WEB-XXE` | A02 Security Misconfiguration | 611, XML external entities |
| `WEB-HASH` | A04 Cryptographic Failures | 328, weak hash |
| `WEB-RANDOM` | A04 Cryptographic Failures | 330, weak random values |
| `WEB-SQL` | A05 Injection | 89, SQL injection |
| `WEB-COMMAND` | A05 Injection | 78, OS command injection |
| `WEB-CODE` | A05 Injection | 94, code injection |
| `WEB-LDAP` | A05 Injection | 90, LDAP injection |
| `WEB-XPATH` | A05 Injection | 643, XPath injection |
| `WEB-XSS` | A05 Injection | 79, cross-site scripting |
| `WEB-TRUST` | A06 Insecure Design | 501, trust boundary violation |
| `WEB-DESERIALIZE` | A08 Software or Data Integrity Failures | 502, unsafe deserialization |

An injection weakness is not one question. It holds only when three premises hold together, so
each `WEB-` rule for an injection is an `answers/1` combination of three focused questions:

| Premise | Example for `WEB-PATH` | Asked of |
|---|---|---|
| The dangerous operation occurs | `PATH-CALL`: does the code open, read, write or delete a file? | The default role |
| Request data reaches it | `PATH-REACH`: can request data become part of that file path? | The default role |
| Nothing neutralizes it | `PATH-OPEN`: after the checks before the call, can the path still leave the directory? | The default role |

The combination fails only when all three premises hold, and any premise that does not hold
clears the handler. `PATH-FLOW` asks a `helper` model to quote each file operation and the
request reads, assignments, conditions and checks relevant to its path. Every helper field,
including the excerpts named `reaching_value`, is a list of verbatim source quotations.
`PATH-REACH` and `PATH-OPEN` read the complete selected handler, its module and those advisory excerpts;
the helper does not establish a data-flow conclusion. With the helper switched off, the same
questions read the handler and module directly. An invented quotation is refused. Unsafe deserialization and XML external
entities have two premises: the object-constructing format or entity-resolving parser, and
request data reaching it. Weak hashes, weak random values and cookies without `Secure` are single
facts and remain single questions.

Each packet in `bundle.json` pins the complete source file and has a `kind` naming its weakness.
A local `syntax/1` query selects the complete handler by its exact function name and its complete
module before any provider request. Both named captures are required and must be unique;
missing or duplicate captures refuse dispatch. The module supplies imports, globals and local
helper definitions. Each question concerns only the selected handler and its reachable callees;
the other handlers in the module are context. Version 4 introduced questions about whether a hazardous value can
survive all transformations and conditions at the same operation, rather than treating the
presence of a check as sufficient protection. The categories match the
[OWASP Benchmark for Python](https://github.com/OWASP-Benchmark/BenchmarkPython).
Version 5 distinguishes client-supplied content from fixed server content selected by a request.
Its handler frame uses normal invocation under the route declared in the module and standard
Flask response conversion: strings become HTML bodies unless the content type is overridden,
and response headers remain separate from the body. The SQL questions distinguish statement
text from separately bound parameters.
The separate benchmark assets below select BenchmarkPython's `init` functions and pin their
required imported helpers.

## Run

From this directory, with `auditoad` installed:

```console
auditoad baseline validate baseline.json
auditoad scan --baseline baseline.json --profile all --source evidence --input bundle.json --project-root . --evaluators ../evaluators.json --max-provider-calls 0 --report prepared.json
```

Preparation has 70 applicable records: 14 local syntax observations, 11 extraction tasks,
34 policy questions and 11 local combinations. No network request is made.
The syntax queries retain the complete named function and module; they do not establish name
resolution, data flow or policy compliance.

[`evaluators.helpers.json`](../evaluators.helpers.json) uses a configured local text helper for
the extraction tasks and Jev for policy questions. Both receive the selected function and
complete module; the file is parsed locally first. Helper quotations remain advisory and are
checked against the supplied source. To run this configuration:

```console
auditoad scan --baseline baseline.json --profile all --source evidence --input bundle.json --project-root . --evaluators ../evaluators.helpers.json --live --max-provider-calls 45 --provider-timeout-seconds 60 --report report.json
```

[`evaluators.json`](../evaluators.json) sends the questions to Jev
and reads `TYPESAFE_API_KEY`; Jev does not answer extraction tasks, so that file switches the
`helper` role off. [`evaluators.local.json`](../evaluators.local.json) checks only the local helper
on this machine, with judgment questions switched off. An evaluator file can also give each role a different model, for example Jev
for the questions and a local model as the helper.
The Jev configuration requires at most 34 calls; the combined helper configuration requires
at most 45. Semantic suggestions remain experimental and cannot clear an audit.

## Expected observations

| Handler | Combined rule | Vulnerable |
|---|---|---|
| `read_report` | `WEB-PATH` | Yes |
| `ping_host` | `WEB-COMMAND` | No |
| `calculate` | `WEB-CODE` | Yes |
| `restore_cart` | `WEB-DESERIALIZE` | Yes |
| `fingerprint` | `WEB-HASH` | No |
| `find_user` | `WEB-LDAP` | No |
| `continue_to` | `WEB-REDIRECT` | Yes |
| `remember_theme` | `WEB-COOKIE` | Yes |
| `list_orders` | `WEB-SQL` | No |
| `login_hint` | `WEB-TRUST` | Yes |
| `reset_token` | `WEB-RANDOM` | No |
| `catalog_lookup` | `WEB-XPATH` | Yes |
| `greet` | `WEB-XSS` | Yes |
| `import_feed` | `WEB-XXE` | No |

Expected judgments are also supplied in [`labels.json`](labels.json) for `auditoad score`.
Several safe handlers resemble vulnerable ones: `ping_host` adds request data to a list and
removes it again before running the command. `find_user` keeps only letters and digits and calls
the supplied `ldap_search` stub, which returns a dictionary and performs no LDAP operation.
One handler per weakness establishes expected behavior, not accuracy.

Version 4 was prepared with both evaluator configurations: 34 Jev requests with helpers off,
or 34 judgment requests and 11 helper requests. Both preparations made zero provider calls
and reported zero errors. The selected handler and complete module reached every prepared
request. Version 5 preparation has 34 Jev requests, zero provider calls and zero errors;
20 serialized requests changed and 14 remain identical to version 4.

One version-5 development run on 2026-10-16 used `jev-1.13.0` with helpers off and made
34 calls with zero errors. It matched **10 of 14 final labels**, with zero wrong and four
unresolved: `ping_host`, `find_user`, `read_report` and `login_hint`. The ten correct
suggestions comprise six vulnerabilities and four safe handlers. These authored controls
do not establish accuracy on unfamiliar code; all semantic terminal results remain
`not_evaluated`. The [public version-5 score](v5.score.json) retains all fourteen decisions
and their evidence identities, without source text or raw provider payloads.

| Small-example identity | SHA-256 |
|---|---|
| Version-5 baseline | `21fd95ba6d1ae24827a329acd5aca36beb166896eb23a8d4620679b92c23fd5a` |
| Source bundle | `1aad908c29de441a652b1a3086bcae815f499158bb02f075164b8c1a1562f237` |
| Source `handlers.py` | `89dd1c5351599dcc3bd12aa52408f16eee6aa8d3f796a51dcdec41228de999b5` |
| Fourteen final labels | `c530deba134dc29531a3c16a64073338603f2dfaf552f8ef06a2bc5c4299e06a` |
| Original version-5 report | `dcac5422fbfc63babf91d366ef03d7d5bc3b372b4e4a1683fc5770cffe17bc11` |
| [Version-5 score](v5.score.json) | `bcc969c9a64405feb3874010f258b2cd91b8bf7ac92f051ada2ef2c465e90523` |

Before version 4, a helper-only development check used Qwen2.5-Coder-7B-Instruct Q4_K_M through
llama.cpp b11146. All eleven helpers returned correctly typed, verbatim source quotations,
with eleven calls and zero errors. Judgment questions were switched off. This establishes
response and quotation compatibility on the pinned handlers, not complete data-flow extraction
or vulnerability accuracy. It does not qualify the changed version 4 or 5 requests.

An earlier development check on 2026-10-13 used Foundation-Sec-1.1-8B-Instruct Q4_K_M
through llama.cpp b11146 for both roles. After every helper field was restricted to source
quotation lists, all eleven helpers returned valid verbatim quotations and the 70 applicable
records contained no errors. The check made 31 calls and reused 14 unchanged exchanges.
These are response-format and quotation observations; they do not establish complete data-flow
extraction or correct vulnerability judgments. All semantic results remained unadmitted.

## Results on the OWASP Benchmark for Python

These published results concern all 1,230 cases in BenchmarkPython v0.1: 452 labelled
vulnerabilities and 778 safe cases. Recall is the fraction of vulnerabilities reported;
FPR is the fraction of safe cases reported as vulnerable.

| Published configuration | Recall | FPR |
|---|---|---|
| [VyQL](https://github.com/vyprai/vyql/blob/main/benchmarks/RESULTS.md) | 452/452 (100%) | 99/778 (12.7%) |
| [Kolega, three runs](https://kolega.ai/blog/kolega-dev-owasp-benchmark-results) | 98.2–100% | 7.3–10.4% |
| [Cyfendo](https://cyfendo.com/benchmarks) | 407/452 (90.04%) | 27/778 (3.47%) |

These are author-reported evaluations with separate configurations and methods, checked
2026-10-16. They provide same-corpus context, not matched tests, a current ranking or an industry cutoff.

### Current version 11 development measurement

On 2026-10-16 the maintained benchmark baseline ran with `jev-1.13.0` and helpers off.
Version 11 retains the same pinned source, 1,230 labels and fixed 0.1/0.9 thresholds as the
earlier development versions. Its focused XPath and XSS run made 275 new provider calls
with zero errors. The complete version-11 report then reused all 2,622 original exchanges
under their exact identities, with zero new calls and zero errors. Unchanged answers were
not measured again. These are development results after question revisions, not an independent
acceptance test or a measurement on unfamiliar code.

| Final testcase judgment | Version 4 | Version 5 | Version 8 | Version 10 | Version 11 |
|---|---:|---:|---:|---:|---:|
| Vulnerabilities reported (recall) | 282/452 (62.4%) | 295/452 (65.3%) | 316/452 (69.9%) | 333/452 (73.7%) | 351/452 (77.7%) |
| Safe cases reported as vulnerable (FPR) | 20/778 (2.6%) | 14/778 (1.8%) | 16/778 (2.1%) | 30/778 (3.9%) | 19/778 (2.4%) |
| Safe cases correctly cleared | 281 | 293 | 293 | 292 | 292 |
| Vulnerable cases unresolved and unreported | 170 | 157 | 136 | 119 | 101 |
| Safe cases unresolved | 477 | 471 | 469 | 456 | 467 |
| Correct / wrong / unresolved | 563 / 20 / 647 | 588 / 14 / 628 | 609 / 16 / 605 | 625 / 30 / 575 | 643 / 19 / 568 |

Following the OWASP scorecard convention, reviews count as unreported. Version 11 leaves
101 labelled vulnerabilities unreported and 467 safe cases unresolved. All final suggestions
remain unadmitted. Compared with version 8, it reported 35 more vulnerabilities and three more
false alarms. Compared with the earlier version-1 runs below, recall fell from 93.4% to 77.7%
while FPR also fell.

Versions 9–11 separated neutralization from operation and origin, selected the actual XPath
and response-body insertion sites, and supplied the XPath string-literal contract with source
guards and replacements. The questions remain single propositions. These changes did not
resolve every data-flow judgment, and version 10 exposed 30 false alarms before version 11
reduced that count to 19. The intermediate measurements remain available in the
[version-9 score](benchmark-v9.score.json) and [version-10 score](benchmark-v10.score.json).

Version 6 broadened the operation questions to include filesystem metadata queries and made
response-body production explicit. It matched 609 labels, with 17 wrong and 604 unresolved.
All 17 false alarms shared a list mutation followed by selection of a fixed server string.
Version 7 added a bounded local Python calculation and supplementary origin questions; its
56 proved intermediate values did not remove those 17 model mistakes, and the final totals
were unchanged. Version 8 supplies the exact calculated literals and permits the original
origin answer only when the local calculation is unresolved. One false alarm became
unresolved; 16 remained in that version. A local expression proof is not a whole-sink data-flow proof: later
assignments and the actual sink still need to be bound to that expression. The missing
complete Python data-flow binding remains a limit on these model judgments.

The public [version-11 score](benchmark-v11.score.json) retains all 1,230 final decisions,
evidence identities and the complete report hash. The [version-4 score](benchmark-v4.score.json),
[version-5 score](benchmark-v5.score.json) and [version-8 score](benchmark-v8.score.json)
retain their historical observations.
Full source-bearing provider reports remain private. The current baseline and pinned
bundle/labels below reproduce the version-11 question set.
The [paired version-5 versus version-4 comparison](benchmark-v5-versus-v4.comparison.json)
lists all 1,230 labelled decisions on the same pinned source and labels.

| Full-benchmark identity | SHA-256 |
|---|---|
| Historical version-4 baseline | `7cfac663fad097c88557bf728ab9a48be35465a330f52bef23c0e7a5f523878c` |
| Historical version-5 baseline | `4e8645a8465d580d4d396f0c147a6a61bf539652f7c5a6844d3af95ccd405b8f` |
| Historical version-8 baseline | `849a06eeefb1d7e2218eb5a0181dd6cf25389e0ae43c75ebc144a8b181e919e9` |
| Current version-11 baseline | `c084990045db44aff40f3d3267708adecbdfb6bf21ad1bcefb562e84793eb888` |
| Source bundle, all versions | `dd29ca139251fbaa422af00b857f5643f4125eda4d96ccecf56723b05acb84e4` |
| Final labels, all versions | `22013f2e96a1d5ababf3a12f65559bd21613d8b251973bd88898937d1d6501fa` |
| Original version-4 report | `60f716b5b117933fcb6640f174bbf382f33a2fb3869340c8a749490238e1a42e` |
| Original version-5 report | `5f7149e192991c6f67579918d69bfe65269e7e4ee34637fb2cbd6c9e21ed077e` |
| Focused version-8 live report, 37 new exchanges | `8bb00c7904d6b947f2a2e89a350a2cca1e2af9bbb88983e4b191bd5e8bf00370` |
| Complete version-8 report, 2,613 reused exchanges | `98d84c4f2bd8837361180ad5fa7d7cbb7000ad87ecc136748452be5aa3f93d67` |
| Focused version-11 live report, 275 new exchanges | `360d83e05ebdefe2aa2838da4f1de8686443300079d315ca83853640da1002a1` |
| Complete version-11 report, 2,622 reused exchanges | `687e3c5b8772d1c61136a3342e989c02b2250557375b7b8e9d47665952e1ada3` |
| [Version-4 score](benchmark-v4.score.json) | `8c6d8d2f0952cfdc279202112dd3462f90c989b27ba080fde2cda0d8a48a4639` |
| [Version-5 score](benchmark-v5.score.json) | `f7329bbd9466edf2cb5334714ab8d8d80bc2c6e696d5fdbd5eeada56a789c58b` |
| [Version-8 score](benchmark-v8.score.json) | `d35de6f07403ca22a5d03e4fe3bb8a67765d68e681df01737d85173285754b4c` |
| [Version-11 score](benchmark-v11.score.json) | `25fe4c5d5e487c35681bb6b24580448062c4e2d8d559f55cbef65e3c01e5c6f3` |
| [Version-5 versus version-4 comparison](benchmark-v5-versus-v4.comparison.json) | `305eea77d433f317c988d89e4455243441701dfd0f7acf424b09e7d069fc4712` |

### Earlier version 1 measurements

The results below were measured with version 1 of this baseline, which asked one question per
weakness. Version 2 split those questions into the premises above. Version 3 added function-name
selection. Version 4 includes complete module/helper context and the revised survival questions.
The small-example selectors name these handlers; the separate benchmark baseline below
selects the upstream test cases.
Version 1 was run with Jev on all 1,230 BenchmarkPython v0.1 test cases.
Following the OWASP scorecard convention, a review counts as not reported.

| Measure | First run | Second run |
|---|---|---|
| Real vulnerabilities reported (TPR) | 422 of 452 (93.4%) | 422 of 452 (93.4%) |
| Safe cases reported as vulnerable (FPR) | 179 of 778 (23.0%) | 178 of 778 (22.9%) |
| Safe cases left for review | 281 | 293 |
| Mean category score (TPR - FPR) | 0.715 | 0.709 |

Each run left 30 labelled vulnerabilities unreported. Weak hashes, cookies without `Secure` and SQL injection
scored 1.0 in both. The data-flow categories scored lowest: path traversal 0.44 and 0.43, XPath
0.45 in both, and LDAP 0.46 and 0.31. Their safe cases pass request data through list
operations or constant conditions that leave only a fixed value at the sink, and Jev seldom
recognized that. Those questions asked Jev to follow the data itself. Later versions provide optional
helper quotations while keeping the dataflow judgment with the policy question. Version 1
questions were written without reference to the benchmark's cases.

## Reproduce the full BenchmarkPython study

The maintained [`benchmark.baseline.json`](benchmark.baseline.json),
[`benchmark.bundle.json`](benchmark.bundle.json) and [`benchmark.labels.json`](benchmark.labels.json)
cover all 1,230 cases. The version-11 baseline has 82 rules: three local syntax selectors,
one local Python expression check, 34 atomic question designs, 11 gated origin questions,
11 final combinations and 22 local answer-selection rules. It selects each complete `init`
function and sends the complete testcase module, imports and pinned helper files that testcase
uses. Helpers are switched off. This pinned corpus selects 2,622 Jev requests, including
37 supplementary questions gated by a proved intermediate
string. Unsupported calculations stay unresolved; they do not clear a handler.

The pinned upstream source is
[`OWASP-Benchmark/BenchmarkPython` at `f1291485808b66e20ddb6b01b10dc71b3df8c8ba`](https://github.com/OWASP-Benchmark/BenchmarkPython/tree/f1291485808b66e20ddb6b01b10dc71b3df8c8ba).
Its `expectedresults-0.1.csv` has SHA-256
`6396f37c97cfd0c018db3d8750095ce6c678a083f83620cfb3e88fe27a46bb0c`.
The source corpus is GPL version 3 and is obtained from upstream; these assets contain paths,
content hashes, question declarations and external labels, with no copied corpus or raw provider reports.

The benchmark question frame uses normal invocation of each registered POST handler, respecting
the route constraints retained in its complete `init` function. The pinned upstream
[`app.py`](https://github.com/OWASP-Benchmark/BenchmarkPython/blob/f1291485808b66e20ddb6b01b10dc71b3df8c8ba/app.py)
constructs a Flask application and registers the testcase modules through `init(app)`;
[`requirements.txt`](https://github.com/OWASP-Benchmark/BenchmarkPython/blob/f1291485808b66e20ddb6b01b10dc71b3df8c8ba/requirements.txt)
pins Flask 3.1.0. Their SHA-256 hashes are
`1e66534772ea54e7fa0c5ed395fba345c281f697bae2277ad637af779a17aeb7` and
`d071df9f5084dcb89af43d5e2dd5138460ad010bda4d1ae4b363b60e61876177`, respectively.

The XSS questions declare Flask's verified response rules: a returned string becomes the body,
the default response MIME type is `text/html`, and `(body, headers)` keeps header values separate
from body content. These rules are recorded in the tagged Flask 3.1.0
[`make_response` implementation](https://github.com/pallets/flask/blob/3.1.0/src/flask/app.py)
and [response class](https://github.com/pallets/flask/blob/3.1.0/src/flask/wrappers.py).
The SQL questions distinguish the SQL string from separately bound values according to the
[SQLite cursor contract](https://docs.python.org/3.13/library/sqlite3.html#sqlite3.Cursor.execute).
The pinned [database helper](https://github.com/OWASP-Benchmark/BenchmarkPython/blob/f1291485808b66e20ddb6b01b10dc71b3df8c8ba/helpers/db_sqlite.py)
returns a `sqlite3` connection. These API premises fix the question frame; content propagation
and surviving syntax remain separate judgments.

From the AudiToad repository root, clone the corpus alongside the repository and prepare without
network calls to a model:

```console
git -c core.autocrlf=false -c core.eol=lf clone --no-checkout https://github.com/OWASP-Benchmark/BenchmarkPython.git ../BenchmarkPython
git -C ../BenchmarkPython -c core.autocrlf=false -c core.eol=lf checkout --detach f1291485808b66e20ddb6b01b10dc71b3df8c8ba
auditoad baseline validate examples/web-security/benchmark.baseline.json
auditoad scan --baseline examples/web-security/benchmark.baseline.json --profile all --source evidence --input examples/web-security/benchmark.bundle.json --project-root ../BenchmarkPython --evaluators examples/evaluators.json --max-provider-calls 0 --max-work 100860 --max-evidence-bytes 536870912 --report ../auditoad-benchmark-prepared.json
```

Review the prepared requests, then set `TYPESAFE_API_KEY` and run:

```console
auditoad scan --baseline examples/web-security/benchmark.baseline.json --profile all --source evidence --input examples/web-security/benchmark.bundle.json --project-root ../BenchmarkPython --evaluators examples/evaluators.json --live --max-provider-calls 2622 --provider-timeout-seconds 60 --max-work 100860 --max-evidence-bytes 536870912 --report ../auditoad-benchmark-report.json
auditoad score --report ../auditoad-benchmark-report.json --labels examples/web-security/benchmark.labels.json --max-input-bytes 536870912 > ../auditoad-benchmark-score.json
```

The scan covers 100,860 rule/target records, of which 8,353 are applicable. Score the 1,230
labelled final judgments separately from their children; local calculations and combinations
add no model calls.

For a focused development run, `constant-origin-development` selects only the complete-source
selector, the local calculation and the eleven supplementary origin-question designs. On this
pinned corpus only 37 questions pass the local gate. Prepare and inspect those requests first:

```console
auditoad scan --baseline examples/web-security/benchmark.baseline.json --profile constant-origin-development --source evidence --input examples/web-security/benchmark.bundle.json --project-root ../BenchmarkPython --evaluators examples/evaluators.json --max-provider-calls 0 --max-evidence-bytes 536870912 --report ../auditoad-benchmark-origin-prepared.json
auditoad scan --baseline examples/web-security/benchmark.baseline.json --profile constant-origin-development --source evidence --input examples/web-security/benchmark.bundle.json --project-root ../BenchmarkPython --evaluators examples/evaluators.json --live --max-provider-calls 37 --provider-timeout-seconds 60 --max-evidence-bytes 536870912 --report ../auditoad-benchmark-origin-report.json
```

The `insertion-development` profile selects the current XPath and XSS questions with their
syntax dependencies. It prepares 275 requests on this corpus:

```console
auditoad scan --baseline examples/web-security/benchmark.baseline.json --profile insertion-development --source evidence --input examples/web-security/benchmark.bundle.json --project-root ../BenchmarkPython --evaluators examples/evaluators.json --max-provider-calls 0 --max-evidence-bytes 536870912 --report ../auditoad-benchmark-insertion-prepared.json
auditoad scan --baseline examples/web-security/benchmark.baseline.json --profile insertion-development --source evidence --input examples/web-security/benchmark.bundle.json --project-root ../BenchmarkPython --evaluators examples/evaluators.json --live --max-provider-calls 275 --provider-timeout-seconds 60 --max-evidence-bytes 536870912 --report ../auditoad-benchmark-insertion-report.json
```

Reuse unchanged exchanges with `--reuse` rather than issuing them again. The measured complete
version-11 run combined the focused live report and earlier original-question reports under
strict reuse, with `--max-provider-calls 0`. The focused profile alone does not produce the
1,230 final testcase judgments and must not be scored as the full benchmark.
