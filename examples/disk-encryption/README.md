# Audit disk-encryption records

This baseline checks an asset inventory for disks that do not declare encryption. It runs
locally and shows how an exact compliance rule handles a failure and missing information.

Run from this directory with `auditoad` installed:

```console
auditoad baseline validate baseline.json
auditoad scan --baseline baseline.json --profile inventory --source inventory --input inventory.json --report report.json
```

The command exits 2. `disk/boot` passes, `disk/backup` fails, and `disk/unknown` is
`not_evaluated` because its encryption fact is missing. AudiToad checks the supplied records;
it does not inspect your disks.

| File | Why it is here |
|---|---|
| `baseline.json` | Defines the encryption rule and blocking-result policy |
| `inventory.json` | The records being audited |
| `encrypted.json` | Known passing input used to verify the rule before the audit |
| `unencrypted.json` | Known failing input used to verify the rule before the audit |

Read `rules[0].check` in the baseline. It selects `/facts/encrypted`, compares it with `true`,
and fails on `unequal`. The `fixtures` field names the two known-answer checks; the actual
audit input is selected by `--input`. `profiles[0]` makes failures, review and unresolved
results block the scan.

To use your own inventory, preserve the inventory schema and supply its path through `--input`.
To check a different fact, change the pointer, expected value, rule identity and known-answer
records together. [Writing baselines](../../BASELINES.md) explains the hashes and other fields.

## Relate the check to a security control

[NIST SP 800-53 Rev. 5, SC-28(1), Cryptographic Protection](https://csrc.nist.gov/CSRC/media/Projects/risk-management/800-53%20Downloads/800-53r5/SP_800-53_v5_1-derived-OSCAL.pdf#page=326)
calls for cryptographic protection against unauthorized disclosure and modification of selected
information at rest on organization-defined components or media.

This example checks one supplied declaration relevant to that assessment: whether each disk
record says encryption is enabled.

| Supplied fact | Result | Assessment use |
|---|---|---|
| `encrypted: true` | `pass` | The record declares encryption |
| `encrypted: false` | `fail` | The record declares an encryption gap |
| Fact absent | `not_evaluated` | Evidence is missing; the audit stays unresolved |

A full assessment also needs the defined information and component scope, trustworthy and
current collection evidence, and evidence that the selected mechanisms provide the required
confidentiality and integrity protections. A `pass` here establishes only the supplied
declaration. Keep those additional obligations explicit in the assessment baseline.
