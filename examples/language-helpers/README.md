# Language helpers

This example extracts command/call syntax from Bash, Zsh, PowerShell, Python and Rust,
and operator definitions from TLA+.
It parses the supplied files without executing them. From this directory:

```console
auditoad baseline validate baseline.json
auditoad scan --baseline baseline.json --input inputs.json --report syntax-report.json
```

The default profile runs six local helpers and makes no model calls. Exit 2 is expected:
helpers supply evidence and remain `not_evaluated`. In each applicable record, inspect
`observation.complete`, `diagnostics`, grammar/version identity, and `fields.captures`.
Each capture contains its name, node kind, query pattern/match, original text and half-open
UTF-8 byte range within the selected source string. Offsets do not count Unicode characters.

The queries capture direct command/call syntax and callee spelling. They do not resolve
aliases, imports, dynamic calls, types or runtime reachability. Rust macros remain unexpanded;
the selected Rust query does not match method or macro invocations. A complete query can
legitimately return no matches without proving that the program has no relevant behavior.

To prepare the Python question using its helper:

```console
auditoad scan --baseline baseline.json --profile review --input inputs.json --report prepared.json
```

The question receives the full Python source and exact captures. It asks only whether the
displayed argument is the enclosing parameter. It does not establish exploitability or which
runtime function `open` names. With an evaluator configured, add `--evaluators ../evaluators.json
--live` to ask it. The evaluator and model are operator choices; this is an authoring example,
not a measured accuracy claim.

`consult` adds a helper's committed observation under `prior`. This question requires the
capture field, so malformed syntax or helper refusal prevents the model call. Other baselines
can declare optional helper fields and keep missing evidence explicit.

The `formal` profile prepares one question about whether the displayed `Spec` definition
directly refers to `Progress`. Its TLA+ helper supplies the exact operator names and bodies:

```console
auditoad scan --baseline baseline.json --profile formal --input inputs.json --report formal-prepared.json
```

This is one source relationship, not a liveness check. The helper does not read TLC
configurations, resolve module instances or prove TLAPS obligations. An unused fairness
definition cannot establish fairness of the selected specification. The Rust helper also
does not parse the contents of `verus!` into a Verus proof tree.

See [syntax helper authoring](../../BASELINES.md#use-syntax-helpers) for limits and coverage.
