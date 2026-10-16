# Examples

Each example is self-contained. Open its directory, read its README, and run the commands
there with `auditoad` installed. The baseline and its audit inputs are in the same directory.

Run several examples together with `auditoad run examples/audit.json` from the repository root.
The [audit file](audit.json) covers inventory, code, writing format and related events. It makes
no model calls unless you add `--live`; individual reports and `suite-report.json` are written
under `examples/`. [Audit files](../docs/user-guide.md#run-an-audit-file-or-suite) also let you
compare evaluator configurations against the same inputs and external labels.

| Example | What it teaches |
|---|---|
| [Disk encryption](disk-encryption/README.md) | An exact local rule, known-answer checks and missing inventory facts |
| [Scanner policy](scanner-policy/README.md) | Check imported findings alongside declared completion and coverage; empty findings cannot clear an incomplete scan |
| [Shipping policy](shipping-policy/README.md) | One Python function, one written requirement and one model question |
| [Python review](python-review/README.md) | Five requirements applied to defective and comparison functions |
| [Writing audit](no-slop/README.md) | A no-slop style baseline applied to articles and an audience brief |
| [Related events](related-events/README.md) | Connect DNS activity, process commands and an allowlist, then combine the answers |
| [Windows memory activity](windows-memory/README.md) | Decide exact event facts locally and ask a model only about the records that need it |
| [Web security](web-security/README.md) | Break each OWASP Top 10 weakness into premises, with a helper tracing data for the questions |
| [Language helpers](language-helpers/README.md) | Extract exact syntax spans in six languages, including TLA+, and consult them in focused questions |
| [Native Jev images](jev-images/README.md) | Send a pinned PNG in state, instructions and criteria; consume a Box helper with local numeric checks |
| [Formal relationships](formal-relations/README.md) | Check 28 written TLA+ relationships locally, with exact witnesses and external labels |
| [Formal claims](formal-claims/README.md) | Distinguish sound, obvious and subtle overclaims, and disclosed limitations in TLA+, TLAPS and Verus |

The [self-audit baseline](../audit/README.md) checks selected requirements in AudiToad's own
implementation. It uses this repository as its audit target.

Examples that ask model questions can first prepare their requests locally. Live evaluation
needs an evaluator file and explicit `--live`. [`evaluators.json`](evaluators.json) sends
questions to TypeSafe's Jev, reads its key from `TYPESAFE_API_KEY` and switches the `helper` role
off, because Jev does not answer extraction tasks. [`evaluators.local.json`](evaluators.local.json)
checks the local Qwen text helper with judgment questions switched off. The
[`evaluators.helpers.json`](evaluators.helpers.json) configuration uses that local model only
for text extraction and Jev for judgments. See [server setup](../docs/user-guide.md#choose-the-models).
Reports retain the observed probabilities; semantic results remain experimental. Expected
answers and explanations are kept outside the evidence sent to a model.
