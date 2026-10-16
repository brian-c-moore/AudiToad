# AudiToad roadmap

AudiToad's goal is to make repeatable audits possible across domains: define the requirements,
supply the evidence, choose suitable tools and models, and receive findings that can be traced
back to what was actually examined. Evidence may come from a system inventory, a security
scanner, source code, operational records, documents or screenshots.

The product should provide a stable audit engine and a research workflow for building good
baselines. Most domain knowledge belongs in baselines and helper bindings. A security audit
may benefit from a security specialist; a Python audit may use a parser or analyzer; a screenshot
may need OCR or visual analysis. A helper can be a conventional tool or a model.

This roadmap describes intended work and release gates. The [user guide](docs/user-guide.md)
describes installed capabilities; [Writing baselines](BASELINES.md) describes today's format.
Future capabilities below are proposals until implemented and qualified.

## Where we are

The CLI and library scan supplied text, byte and structured inventory evidence with local
checks, configurable model roles and helpers, audit suites, labelled scoring, matched
comparison and exchange reuse. Baselines can declare requirements, and reports block on any
requirement left missing, unasked, stale, unsupported or unresolved. Model answers remain
experimental suggestions with terminal `not_evaluated`.

The neutral helper protocol, experimental PNG/JPEG evidence, native Jev image/Box bindings and
experimental-evidence propagation exist with development controls. The
[image example](examples/jev-images/README.md) records the current scope. Qualification of
screenshot-assisted audits and broader visual interpretation remains planned work.

| Stage | Definition for AudiToad | Work that should dominate |
|---|---|---|
| Alpha | The intended initial scope, engine contracts and correctness still need substantive work. | Finish the machinery, resolve design gaps and establish repeatable testing. |
| Beta | The main capabilities are built and basically work end to end. Polish, accuracy and breadth are refined through testing. | Research and tune baselines, evaluate helper arrangements, expand independent testing and fix robustness or usability defects. |
| Production | The supported engine, workflows and admitted baseline arrangements have enough evidence and operational maturity for routine use within their declared scope. | Maintain compatibility, monitor regressions and evolve supported content deliberately. |

Beta should not be a long engine construction phase. A newly discovered fundamental defect may
require a substantial repair, but that is a release blocker to surface, rather than normal
baseline tuning. New domain packs should ordinarily fit the established extension contracts.

Engine maturity and baseline maturity are separate. A production engine can run an experimental
baseline. A good baseline result cannot qualify a faulty engine. Qualification attaches to a
specific baseline, evidence contract and evaluator/helper arrangement, rather than every model
or every possible audit.

The initial beta has no fixed semantic accuracy percentage. Prioritize a substantially settled
engine and a usable research workflow, then make the starter baselines as reliable as reasonable
with the available models, helpers and evidence. Report what they achieve and where they fail.
Further formal-methods research, question tuning and model/helper comparisons are central beta
work. No release promise depends on Jev or another model reaching an assumed accuracy ceiling.

Model backends should be easy to configure and exchange through stable capability contracts.
Baseline tuning is specific to the tested model and arrangement; replacing a backend must not
require rebuilding the engine, and must not inherit another model's accuracy qualification.
AudiToad should make that process efficient: inspect requests, retain and reuse unchanged
exchanges during development, compare matched runs, expose costs/limits and preserve evidence
and unresolved work through one flexible CLI/library workflow.

### First demanding use: our own formal-methods research

AudiToad was built to help audit Automation Structures and the associated formal-methods
research. It remains the first deep baseline research target after the engine foundations.
The tool should
help identify unsupported claims, missing obligations, incorrect evidence correspondence and
other defects so the audited work can be reviewed and repaired.

Pursue depth here while building a general-purpose engine. Formal-methods requirements and
checker bindings belong in domain packs; they do not define the engine's domain boundary.
The broader portfolio should demonstrate transfer to other audits without displacing this
founding use case. Research findings must identify their exact subject, evidence and residuals;
each finding should make the defect and its proposed repair clear.

## Current foundation and gaps

| Area | Current foundation | Remaining product work |
|---|---|---|
| Supplied evidence | Text, bytes, structured records and explicit bundles with identities and evidence selection. | Broader import contracts, explicit collection completeness and richer provenance. |
| Exact checks | Local byte, inventory and structured-value checks. | Reusable policy examples and independent positive, negative and refusal controls. |
| Semantic questions | Configurable roles, combinations, extraction and consultation. Experimental derivation propagates through local consumers and gates. | Stronger research coverage and later exact-arrangement semantic admission. Current semantic results remain experimental `not_evaluated` observations. |
| Helpers | Model extraction, local syntax and a versioned neutral protocol for conventional/model services with declared capabilities. | Qualify concrete helper implementations and broaden tested protocols through this boundary. |
| Baseline experiments | Validation, preparation, named runs, external labels, scoring, matched comparisons, replay and exact exchange reuse. | Broader independent research and acceptance evidence; preserve custody/freshness controls. |
| Images | Pinned PNG/JPEG bytes, dimension headers and region metadata retained through helper derivation; native Jev image and Box bindings with development controls. | Qualify screenshot audit workflows, OCR/vision services and extraction quality, then additional formats. No bundled OCR or complete image decoder is shipped. |
| Collection | Operators supply the material to examine. | Reviewed discovery and collection bindings if needed; active machine or fleet scanning remains future work. |

## Milestone A: finish alpha and release the initial beta

The intended checkpoint is a **0.0.1 beta**: a usable public product whose core should need
relatively few changes during baseline research.

### A1. Freeze and complete the initial product scope

The first-beta scope is supplied text and structured evidence, including documents, code,
structured inventory and scanner records. Provide local checks, configurable helper/evaluator
roles, declared requirement coverage and the normal baseline-testing flow. Experimental native
image and helper bindings are available for development; qualified screenshot assessments remain
later work, including selected manual STIG checks.
Active collectors, scheduled fleet scans and remediation are also later capabilities.

Before freezing the engine, demonstrate that the same contracts support:

- An inventory checked against an explicit configuration policy.
- An imported scanner finding checked against an audit policy, preserving the scanner's result.
- A document or code requirement using exact checks and a bounded semantic question.
- Declared requirements whose unchecked or undecided coverage blocks the audit.
- A conventional helper and a model helper supplying evidence through the same declared boundary.

### A2. Resolve correctness and evidence defects

Canonical Automation Structures must govern the engineering throughout AudiToad before beta.
This is a hard release gate. Review every product module and public workflow for competing
progress, resource, relationship, aggregate, lifecycle and effect owners. Replace handwritten
automation with the published canonical structures and existing compositions; document the
actual actions and correspondence that make their refusal decisive. A few imports or passing
behavioral tests do not satisfy this gate. Parsing, predicates and physical bindings remain
domain content with explicit boundaries. Any unreconstructable obligation needs an owner
decision before a substitute can be written.

Use AudiToad to retain source-bound findings and the results after repair. Qualify the changed
candidate again, and keep residuals visible. AudiToad is intended to demonstrate this
construction method in serious software as well as audit it in other projects.

- Preserve the completed reuse and scoring construction. Bind reused responses to complete evidence,
  exact requests and evaluator identities; distinguish original inference, reuse, replay and mocks.
- Resolve known question, label and evidence defects. An asserted count, checker selection,
  attempted proof or capture duration must not silently stand for a stronger proposition.
- Keep missing, malformed, unsupported, contradictory and out-of-scope evidence visible.
  Refusal and abstention must remain distinguishable from a finding and from a passing result.
- Check source identity, prerequisite correspondence, coverage, budgets, helper effects,
  aggregation and report publication through the actual Automation Structures owners.
- Define and test the initial admission, derivation and invalidation boundary before beta.
  Local mechanical checks use their fixture contract; semantic/external arrangements remain
  draft-only, and experimental derivations cannot grant clearance. Later semantic admission
  must bind exact baseline/evidence/evaluator identity through the same scan boundary.

**Exit evidence:** focused regression and fault controls reproduce each repaired defect;
integration checks show that failed required operations cannot produce complete passing reports.
Source changes invalidate earlier source-specific qualification.

### A3. Put baseline research on the normal product path

Implement any missing pieces of the [authoring workflow below](#baseline-research-and-authoring)
through the existing CLI, audit declarations and reports. A new author should be able to define
requirements, validate a baseline, inspect requests, run a labelled development set, compare
arrangements and prepare acceptance evidence without writing an experiment runner.

Ship a small starter portfolio with readable inputs, expected outcomes, independent labels,
research notes and commands. Give each pack an explicit purpose, applicability, tested
arrangements, measured limitations and admission status. Experimental packs can be useful beta
material when their suggested decisions and unresolved terminal results are plainly explained.

Use the formal-methods pack to demonstrate the research workflow and improve it as far as
reasonably supported before beta. Correct known question, checker-evidence and label defects
before presenting measurements as valid. Publish its tested scope, actual correctness and
coverage, known failures and experimental status. Neither 99% performance nor completion of
the whole Automation Structures/research audits is a prerequisite for the initial beta.
Continue that deeper qualification and those inventory-bound audits during beta; focused
snippets or a successful benchmark score cannot stand for whole-subject audit completion.

**Exit evidence:** an outside user can install AudiToad, run the examples, adapt a baseline,
reproduce a labelled comparison and understand incomplete results using only public material.

### A4. Qualify the public release itself

- Run the build, test, lint, documentation, example and package checks described in the
  [build guide](docs/build.md) against the exact release candidate.
- Exercise the repository and extracted package independently of private workspace inputs.
  Check supported-platform CI and installation, including failure messages and exit codes.
- Inspect the public tree and archive for required files, credentials, private data, licensing
  and stale claims. Refresh example results against the baseline revisions actually shipped.
- Publish a release note with supported scope, experimental areas, measured results and known
  limitations. Keep release qualification distinct from baseline accuracy.

**Beta gate:** A1–A4 are complete for the declared scope. No unresolved defect can conceal
missing work, misattribute evidence, bypass limits or turn an unqualified suggestion into a
compliance clearance. The engine is ready for broad testing; domain validation remains ongoing.
The gate tests engine behavior and the usability/honesty of the baseline workflow, rather than
requiring a model-dependent accuracy target. Starter packs may remain experimental with
measured limitations; knowingly invalid labels cannot support their advertised accuracy.

## Milestone B: beta baseline research and field testing

The main beta deliverable is a better-supported collection of baselines and helper arrangements,
backed by representative data. Engine changes should mostly address discovered defects,
observability, compatibility and usability.

### B1. Build the starter portfolio in priority order

These are recommended research priorities. They are not claims of present standards support or
already-qualified packs. Choose small, useful control subsets with defensible labels first.

| Priority | Baseline family | Why it belongs | Evidence and research needed |
|---|---|---|---|
| Immediate qualification | Formal-methods and research claim correspondence | The founding use case and first demanding test of audit accuracy. | Claims, exact artifacts and checker receipts with independently justified witnesses; complete declared subject coverage. Keep proof scope and implementation correspondence explicit. |
| First | Evidence quality and audit coverage | Every audit depends on identity, scope, freshness and required evidence. | Supplied manifests and records; missing, stale, duplicate, conflicting and incomplete inputs. Check supplied declarations separately from independently verified provenance. |
| First | Configuration and inventory policy | Useful across organizations and provides strong mechanical reference cases. | Exported settings, assets, accounts and policy parameters; encryption, required ownership, logging or approval checks with exact expected results. |
| First | Scanner-result policy and triage | Directly supports auditing existing system and security scan outputs. | Results plus scanner version, target scope, execution status and coverage. Test severity policy, exception handling and missing scans; an empty findings array alone cannot establish a clean system. |
| First | Policy, writing and process records | Demonstrates audits of prose and records, including long-form writing and novels. | Declared writing standards or focused text questions; requirements and supporting approvals, reviews or retention evidence. Separate what a text says from whether a corresponding practice occurred. |
| Next | Threat indicators and ATT&CK-related evidence | Extends the YARA and event examples into security baselines. | Versioned indicators of compromise (IoCs), supplied artifacts or event windows, and selected MITRE ATT&CK techniques. Distinguish an indicator match, observed behavior and an attribution claim; independently label each evaluated proposition. |
| Next | Software requirements and OWASP security findings | Builds on existing code examples while supporting multiple languages and analyzers. | Source, selected OWASP Top 10 risk categories, versioned references, analyzer outputs and executable or independently reviewed witnesses. Syntax, comments and model agreement cannot establish full program behavior. |
| Next | Visual evidence, document forms and manual STIG checks | Makes screenshot-assisted reviews useful across compliance and other audits. | The selected STIG revision and check procedure, captured system/setting identity, capture context, region annotations and independently labelled observations; blurry, cropped, misleading and inaccessible evidence. |
| Next | Supply-chain artifact policy | A natural extension of inventory and imported findings. | SBOMs, component identities, provenance and vulnerability-context records. Test incomplete inventories, mismatched artifacts and unsupported exploitability claims. |
| Later | Event and operational process controls | Supports relationships, ordering and repeated audit evidence. | Complete declared event windows, source/time identities and records of actions. Include partial logs, clock uncertainty and missing events. |

The initial public portfolio should show inventory, scanner-result and document/process audits
alongside code and formal-methods examples. Formal-methods qualification remains the immediate
depth priority. Reuse sound existing examples; broader coverage should add reviewed domain
content through the same engine.

Security pack references include [OWASP](https://owasp.org/projects/top-ten),
[MITRE ATT&CK](https://attack.mitre.org/) and [DISA STIGs](https://www.cyber.mil/stigs/).
The existing web-security and event examples are starting points for this research; each
published pack must name its evaluated subset and evidence requirements.

### B2. Evaluate interoperability by task

Prefer established evidence formats where they fit. Research the following mappings before
committing to adapters or claiming conformance:

- **SARIF:** a candidate input/output mapping for static-analysis findings. Preserve rule,
  artifact, location and run identities. It specifies static-analysis results rather than a
  general compliance verdict. [OASIS SARIF specification](https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html)
- **SCAP, including XCCDF and OVAL:** candidates for consuming security configuration assessment
  content and results. Begin with a declared import subset and test its semantics; parsing
  exported JSON is not full SCAP implementation or validation.
  [NIST SCAP project](https://csrc.nist.gov/projects/security-content-automation-protocol)
- **OSCAL:** a candidate for linking controls, selected profiles, system context and assessment
  evidence. Preserve that context when mapping findings, including controls AudiToad did not
  evaluate. [NIST OSCAL layers and models](https://pages.nist.gov/OSCAL/learn/concepts/layer/)
- **CycloneDX/SBOM and VEX:** candidates for component-policy and vulnerability-context packs.
  VEX expresses exploitability in a product context; accepting a statement does not independently
  establish it. [CycloneDX VEX](https://cyclonedx.org/capabilities/vex/)

Framework coverage must identify the edition, applicable controls, evaluated subset and residual
human assessment. A mapping between requirements is not proof that they are equivalent.
Check content redistribution rights before including external control catalogs or benchmarks.

### B3. Measure helpers and models rather than assume benefit

Compare no helper, conventional helper, specialist model and selected combinations on the same
frozen cases. Measure helper extraction quality separately from final audit decisions. A helper
can improve evidence, add errors or consume budget without improving outcomes.

Report correct, wrong, false clearance, false alarm, unresolved, missing and error outcomes;
decision coverage; per-control and domain results; variability; latency; calls; and known cost.
Keep unresolved cases in the all-case denominator. Report resolved accuracy separately.

Release a compatibility matrix describing tested capabilities and arrangements. Backend protocol
compatibility alone does not guarantee support for probabilities, structured extraction or images.
Equivalent model families may fit the same binding, but each admitted arrangement needs evidence.

### B4. Test with independent users and representative evidence

Use varied real-world sources where permission and privacy allow, alongside controlled cases.
Track baseline-authoring friction, misleading reports, ambiguous requirements, unsupported inputs,
resource refusals and operational failures. Expand data by source and domain, rather than just
adding more variants of one template. Feedback that changes a question makes its inspected
cases development material.

**Beta exit evidence:** repeatable results on independently labelled holdouts for the initial
production packs; documented limitations and invalidation rules; representative end-to-end
use; and no remaining engine defect that defeats the stated audit contract.

## Shared evidence and helper contract

This contract must be designed and exercised during alpha, then remain stable enough for beta
baseline work. Implement missing parts through reviewed bindings of the existing scan engine.

- Declare a capability, supported input media/schema, output schema, implementation/model
  identity, version, configuration and applicable limits. Reject unsupported capabilities early.
- Distinguish extraction, normalization, triage and final evaluation. A helper's output becomes
  attributable evidence; it does not gain decision authority merely by having high confidence.
- Retain input/output identities and transformation provenance. Derived evidence points to the
  original artifact and relevant text span, record or image region. Transformation failures,
  uncertain readings and omitted regions stay visible.
- Let baseline authors request capabilities while operators choose compatible providers.
  Keep secrets, endpoint selection, egress consent and budgets in operator configuration.
- Apply the same custody, progress, effect and resource contracts to local tools and remote
  models. Bound execution time, input/output size and any expanded image/decompression costs.
  No helper may hide retries, execute subject instructions or start a competing work engine.
- Treat audit content, including instructions embedded in text or images, as untrusted evidence.
  Test prompt injection, response substitution, source mixing and outbound-data boundaries.

The existing construction uses `ResourceRegistry` for identities, `RelationshipGraph` for
prerequisites, `Sequential` for progress, `Budget` for scoped admission, `FederatedBudget` for
shared capacity and model permissions, `ActuationPass` for effects,
`AuditSink` for records and `Reduction` for totals. New bindings reuse these owners and their
reviewed coupling. Identify a missing canonical API or composition before implementing a new
mechanism. See the [construction walkthrough](docs/automation-structures.md).

### Images and screenshots

An intended use is screenshot-assisted review of selected manual checks in DISA STIG
compliance baselines. Bind each question to the exact STIG revision and check procedure,
the assessed system and the capture context. Establish the visible setting or condition
separately from judging whether it satisfies the requirement. Missing context or an unreadable
setting stays unresolved. The current image binding is a development foundation for this
workflow; assessment baselines and their visual observations still need qualification.

Preserve the original image identity, dimensions, capture context and declared scope. Retain
OCR text and region coordinates, image transformations and the tool/model that produced them.
Support direct visual observations when OCR cannot express the required fact.

Separate three questions: was the evidence captured for the right subject, was the relevant
content read correctly, and does that content satisfy the stated requirement? A screenshot of
a setting may show its displayed value at capture time; proving continuing system behavior may
require telemetry or additional records. Poor quality, occlusion or missing context remains
unresolved when it prevents a necessary observation.

For an accessibility pack, screenshots may support selected visual checks, while structure,
keyboard behavior and other requirements need additional evidence. W3C explicitly requires
knowledgeable human evaluation for accessibility conformance; qualify the particular automated
checks rather than promise complete conformance from images.
[W3C accessibility evaluation guidance](https://www.w3.org/WAI/test-evaluate/)

## Baseline research and authoring

Baseline creation is a product workflow. Research, fixtures, labels and acceptance evidence must
be reproducible through AudiToad's own user-facing tooling. Extend the existing
`baseline validate`, `scan`, `run` and `score` surfaces as needed.

1. **Define the audit.** Record the purpose, intended users, authoritative requirements and
   edition, applicability, required evidence, permitted inferences and consequential failure
   modes. Explain exactly what a pass would establish and what remains outside scope.
2. **Research and decompose.** Map each requirement to explicit propositions, decisive evidence
   and a suitable exact check or semantic question. Use parsers and exact comparisons for
   mechanical facts. Separate claim reading from evidence judgment. Split compound questions
   and combine their answers under an explicit policy.
3. **Construct an independent oracle.** Explain each label through an executable witness,
   authoritative record or independent review. Model consensus is not ground truth. Record
   ambiguity and disagreements; keep labels separate from the subject and provider requests.
4. **Build the data plan.** Include compliant and noncompliant cases, legitimate near misses,
   missing or contradictory evidence, unsupported forms and adversarial cases. Freeze development,
   calibration and holdout splits by independent source where possible. Record identity,
   provenance, licensing and possible training-data overlap. Synthetic variants are controls,
   not automatically independent samples.
5. **Validate locally and inspect requests.** Check schemas, references, fixture admission,
   evidence completeness and exact prepared requests before live work. Each semantic question
   asks one explicit proposition and includes the smallest complete relevant context. Claim
   reading uses `choice/1`, the claim and explicit proposition, and the established asserted /
   not asserted / insufficient categories with .9/.9 thresholds. Yes/no questions use the
   established .1/.9 thresholds. Category meanings and thresholds stay fixed before observing
   outcomes; no open-ended residual question.
6. **Run development and compare.** Use one live development run per design, with explicit reuse
   of unchanged valid exchanges. Use paired scoring and replay to diagnose differences. Preserve
   old labels and results when correcting defects; justify the revision independently. Never
   relabel a disagreement merely to improve the score.
7. **Freeze acceptance.** Select the final arrangement and predeclare per-control and family
   gates, adversarial controls, severe-error rules and sufficient sample sizes. Run three fresh
   repetitions on untouched acceptance data. Reuse, replay and mocks cannot count as fresh
   inference. Report uncertainty and source dependence alongside point estimates.
8. **Admit or retain as experimental.** Publish the scope, dataset identity, tested arrangement,
   measured results, known failures and reviewer disposition. Failure of a family cannot be
   hidden by an aggregate score. An experimental pack retains unresolved terminal status.
9. **Maintain.** Version the baseline and requirement mappings. Define which changes invalidate
   admission, run relevant regression/acceptance checks, and preserve earlier reports with their
   original identities. Model, helper, prompt, evidence or threshold changes need an explicit
   assessment of qualification impact.

For the existing high-accuracy formal audit research, retain the aspirational goal of at least
99% correct over all labelled cases and at least 99% decision coverage in each family and each
of three fresh repetitions, with zero known severe false clearances. This is not a beta-release
requirement or a guarantee about any model. Research should establish what is reasonably
achievable, preserve failures and tune throughout beta. Any claimed admission must still meet
its explicitly declared, risk-appropriate gate; lower coverage or a different threshold cannot
silently inherit an earlier admission. Engine reliability remains a separate release obligation.

### What a published pack should contain

Provide a readable purpose and scope, requirement references, baseline and profile versions,
example subjects, commands, independent labels and their rationale, compatible helper/evaluator
arrangements, research and acceptance summaries, known limitations, licenses and maintenance
policy. Small redistributable fixtures ship with the pack. Larger corpora can be referenced by
pinned identity and access instructions when their permissions require it.

Choose external data by task fit. [NIST SARD](https://samate.nist.gov/SARD/) supplies programs
with documented weaknesses and is a candidate for selected software-security controls.
[DocLayNet](https://github.com/DS4SD/DocLayNet) supplies document-layout annotations and is a
candidate for testing layout helpers. Neither supplies general compliance ground truth.
Pair such data with independently labelled audit cases and domain-specific evidence; verify
licenses and freeze selected revisions before use.

### Dogfooding and the authoring rails

Develop and qualify every shipped pack through this same workflow. Use normal audit files for
experiments, retained reports for inspection and `score --compare` for matched comparisons.
The authoring experience should guide users through missing requirements, absent witnesses,
leaking labels, incompatible helpers, weak coverage and premature admission claims.

Extend AudiToad's self-audit to exercise both detection and refusal: changed identities, missing
evidence, wrong assertions, incomplete coverage and invalid reuse must have independently known
outcomes. A self-audit containing only expected-clean cases tests false alarms, not detection.
Keep ordinary implementation tests and independent review alongside dogfooding; the product
cannot establish its own correctness solely by agreeing with its own reports.

## Milestone C: production readiness

Production means supported routine use within a documented scope. It does not require a pack
for every industry, a universally accurate model or fully automated legal certification.

| Gate | Required evidence |
|---|---|
| Engine correctness | Required work and coverage accounted for; evidence identity and limits enforced; failed operations remain visible; independent review and meaningful fault controls for critical boundaries. |
| Baseline admission | Each production pack and supported arrangement meets its frozen family/control gates on independent acceptance data, including severe false-clearance controls and uncertainty reporting. |
| Usability | Users can install, author, validate, prepare, run, compare and interpret audits through documented CLI/library workflows. Reports show actionably distinct findings, uncertainty and operational errors. |
| Operational reliability | Tested large and malformed inputs, bounded helper/provider failures, interruption and publication behavior, predictable resource use and supported-platform qualification. |
| Data handling | Explicit outbound-data consent, credential hygiene, inspectable evidence selection, documented retention/redaction behavior and tested treatment of untrusted content. |
| Compatibility | Versioned baseline, evaluator, helper and report contracts; documented migrations and tested compatibility policy. Model-serving changes and unavailable identities have a defined admission response. |
| Release and maintenance | Exact-source repository/package/CI qualification, reproducible examples, license review, issue and security reporting paths, regression fixtures and a policy for updating or retiring packs. |

Use a release candidate to rehearse installation and the supported workflows on representative
evidence. Resolve blockers, freeze the release identities and publish the results and residuals.
The production release should be supported by those records, not by a version number alone.

## After the first production release

Expand control coverage and helper bindings through the established contracts. Consider reviewed
collection/discovery, scheduled audits, larger inventories and dedicated workflow connectors
when field use demonstrates the need. Each capability needs its own declared scope, canonical
construction, resource limits, failure behavior and acceptance evidence.

The CLI and Rust library can already be called from CI/CD pipelines, SOAR workflows or other
tools. JSON reports and exit status let the caller route results under its own policy.
Dedicated supported connectors and automated remediation are separate work.

Remediation introduces authority to change audited systems and needs a separate design and
authorization model. Keep evidence evaluation useful on its own while that work is considered.

The sustained product direction is a stable engine, well-researched baselines and interchangeable,
measured helpers, with each audit report making its evidence and coverage easy to inspect.
