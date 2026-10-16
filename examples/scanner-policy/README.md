# Audit a supplied scanner export

This example applies a small policy to supplied scanner records: the scan must declare
completion, declare complete target coverage, and return no findings. It evaluates the export;
it does not run the scanner or independently verify its declarations. This is a generic example
format, not a SARIF, SCAP or vendor-specific importer.

The four records deliberately distinguish a clear scan, a finding, an incomplete scan with no
findings, and a completed scan whose findings field is missing. Completion and coverage are
separate requirements. An empty list alone cannot clear the scan.

With `auditoad` installed, run these commands from this directory:

```console
auditoad baseline validate baseline.json
auditoad scan --baseline baseline.json --input inventory.json --report report.json
auditoad score --report report.json --labels labels.json
```

No model or network access is needed. The scan exits 2: its twelve records contain eight
passes, three failures and one `not_evaluated` result for missing findings. The incomplete
record passes only the literal empty-list check; its completion and coverage requirements fail.

The baseline declares the policy's three requirements and links each rule to the one it
checks. The report's `requirements` section shows all three as `finding`, with each one's
result counts. Add a requirement that no rule links to and the scan names it `missing`.

Two scope controls also exit 2 and retain a report explaining why nothing applicable ran:

```console
auditoad scan --baseline baseline.json --input empty-inventory.json --report empty-report.json
auditoad scan --baseline baseline.json --input wrong-scope-inventory.json --report wrong-scope-report.json
```

The first has no records; the second has three `notapplicable` records for a disk item.
Neither clears the scanner policy, and both report every requirement as `unsupported`.

The development labels describe eleven supplied facts under this written policy. The missing
findings field has no independently justified boolean label, remains unresolved and appears
as one unlabelled report record. These tiny, already inspected examples establish the local
workflow; they are not a representative security benchmark or a holdout. `clear.json` and
`not-clear.json` are pinned positive/negative fixtures for each exact check.
Their source hashes identify file bytes; evidence hashes identify the serialized inventory item,
whose fact keys are sorted and whose bytes omit the file's trailing newline. Inspect both
identities when updating a fixture; a computed hash alone does not justify its expected label.

For your scanner, supply its version, target and capture identity with the records, map its
completion and coverage semantics deliberately, and define the actual policy for findings and
exceptions. Missing declarations remain unresolved. A supplied declaration is evidence of what
the scanner reported, not independent proof of a clean system. Use a separately configured
helper if a finding needs specialized interpretation, and research that arrangement with
independent labels before relying on its suggestions.
