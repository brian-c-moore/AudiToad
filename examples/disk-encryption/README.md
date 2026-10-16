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
