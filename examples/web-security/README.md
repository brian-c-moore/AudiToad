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
`PATH-REACH` and `PATH-OPEN` read the complete selected code and those advisory excerpts;
the helper does not establish a data-flow conclusion. With the helper switched off, the same
questions read the selected code alone. An invented quotation is refused. Unsafe deserialization and XML external
entities have two premises: the object-constructing format or entity-resolving parser, and
request data reaching it. Weak hashes, weak random values and cookies without `Secure` are single
facts and remain single questions.

Each packet in `bundle.json` pins the complete source file and has a `kind` naming its weakness.
A local `syntax/1` query selects the complete handler by its exact function name before any
provider request. Each handler receives only the selected code and
the questions for its own weakness. The categories match the
[OWASP Benchmark for Python](https://github.com/OWASP-Benchmark/BenchmarkPython).
Using the current baseline on that benchmark also requires reviewing and adapting the named
selectors to its source.

## Run

From this directory, with `auditoad` installed:

```console
auditoad baseline validate baseline.json
auditoad scan --baseline baseline.json --profile all --source evidence --input bundle.json --project-root . --report prepared.json
```

Preparation has 70 applicable records: 14 local syntax observations, 11 extraction tasks,
34 policy questions and 11 local combinations. No network request is made.
The syntax queries report one complete function capture each; they do not establish name
resolution, data flow or policy compliance.

[`evaluators.helpers.json`](../evaluators.helpers.json) uses a configured local text helper for
the extraction tasks and Jev for policy questions. Both receive only the selected function;
the file is parsed locally first. The helper's semantic trace remains advisory and source quotes
are checked against that code. To run this configuration:

```console
auditoad scan --baseline baseline.json --profile all --source evidence --input bundle.json --project-root . --evaluators ../evaluators.helpers.json --live --max-provider-calls 45 --provider-timeout-seconds 60 --report report.json
```

[`evaluators.json`](../evaluators.json) sends the questions to Jev
and reads `TYPESAFE_API_KEY`; Jev does not answer extraction tasks, so that file switches the
`helper` role off. [`evaluators.local.json`](../evaluators.local.json) checks only the local helper
on this machine, with judgment questions switched off. An evaluator file can also give each role a different model, for example Jev
for the questions and a local model as the helper.
Semantic results remain experimental, and the command exits 2.

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

Several safe handlers resemble vulnerable ones: `ping_host` adds request data to a list and
removes it again before running the command, and `find_user` keeps only letters and digits.
One handler per question establishes expected behavior, not accuracy.

The current helper-only development check used Qwen2.5-Coder-7B-Instruct Q4_K_M through
llama.cpp b11146. All eleven helpers returned correctly typed, verbatim source quotations,
with eleven calls and zero errors. Judgment questions were switched off. This establishes
response and quotation compatibility on the pinned handlers, not complete data-flow extraction
or vulnerability accuracy. Current Jev judgments and semantic admission remain pending.

An earlier development check on 2026-10-13 used Foundation-Sec-1.1-8B-Instruct Q4_K_M
through llama.cpp b11146 for both roles. After every helper field was restricted to source
quotation lists, all eleven helpers returned valid verbatim quotations and the 70 applicable
records contained no errors. The check made 31 calls and reused 14 unchanged exchanges.
These are response-format and quotation observations; they do not establish complete data-flow
extraction or correct vulnerability judgments. All semantic results remained unadmitted.

## Results on the OWASP Benchmark for Python

The results below were measured with version 1 of this baseline, which asked one question per
weakness. Version 2 split those questions into the premises above. Current version 3 adds
function-name selection and projects only selected source text to those questions and helpers.
Versions 2 and 3 have no current Jev benchmark measurements here. The public version 3 selectors name these example
handlers; applying them to other source requires reviewing and adapting those names.
Version 1 was run with Jev on all 1,230 BenchmarkPython v0.1 test cases.
Following the OWASP scorecard convention, a review counts as not reported.

| Measure | First run | Second run |
|---|---|---|
| Real vulnerabilities reported (TPR) | 422 of 452 (93.4%) | 422 of 452 (93.4%) |
| Safe cases reported as vulnerable (FPR) | 179 of 778 (23.0%) | 178 of 778 (22.9%) |
| Safe cases left for review | 281 | 293 |
| Mean category score (TPR - FPR) | 0.715 | 0.709 |

Neither run reported a false negative. Weak hashes, cookies without `Secure` and SQL injection
scored 1.0 in both. The data-flow categories scored lowest: path traversal 0.44 and 0.43, XPath
0.45 in both, and LDAP 0.46 and 0.31. Their safe cases pass request data through list
operations or constant conditions that leave only a fixed value at the sink, and Jev seldom
recognized that. Those questions asked Jev to follow the data itself, which is the computation version 2 hands
to the helper. They were written without reference to the benchmark's cases.
