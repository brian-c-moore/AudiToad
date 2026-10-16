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

The optional `review` profile compares two source identifiers locally:

```console
auditoad scan --baseline baseline.json --profile review --input inputs.json --report review-report.json
```

Its dedicated syntax query selects a function with one plain identifier parameter and a
direct top-level return of `open(identifier, ...)` or a method call on that expression.
It captures the parameter, callee and first argument in source order and requires the callee
spelling `open`. Each candidate parameter/call pair retains three captures, so the limit
refuses multiple plain parameters or matching calls. Missing, malformed or
unsupported shapes supply no comparison operands and remain `not_evaluated`.
`PY-PATH` uses `json-pointer-compare/1` to compare the parameter and argument spellings.
Equal spellings produce `fail` and different spellings produce `pass`: the positive predicate
is being demonstrated, not a vulnerability finding. This proves neither unchanged parameter
value nor runtime name binding. A parameter may have been reassigned, and `open` may name
something other than the built-in function. The default Python helper remains unchanged.

`consult` adds the dedicated helper's committed observation under `prior`. The pinned
`python-identifiers-*.json` fixtures check the comparison consumer's equal and unequal cases;
they are declared observations, not independently parsed source receipts.

The `formal` profile checks one narrower written TLA+ relationship locally: whether the
declared reference is a positive conjunct of the declared zero-argument top-level definition:

```console
auditoad scan --baseline baseline.json --profile formal --input inputs.json --report formal-report.json
```

`tlaplus-operands.json` supplies the singleton operand object, currently `Spec` and `Progress`.
The collection relates that complete JSON document to the unchanged TLA+ source. An array,
missing peer, missing name or malformed name cannot supply the required operands and refuses
evaluation. An unavailable peer is an evidence-preparation `error`; a supplied object with
missing or malformed names remains `not_evaluated`. The parser also refuses duplicate
selected definitions and parameterized operators.
The pinned positive and negative fixtures distinguish `/\` from `\/`. The current source
matches and produces `fail` because the check declares `fail_when: true` for this relationship.

This is written syntax, not a general direct-reference or liveness check. It does not expand
aliases, resolve module instances, read TLC configurations or prove TLAPS obligations. An
unused fairness definition cannot establish fairness of a selected specification. The Rust
helper does not parse the contents of `verus!` into a Verus proof tree.

All three profiles make zero provider calls and permit no egress. They exit 2 because this
baseline is a draft. The supplied `formal` demonstration has one deterministic `fail` and
no syntax-only prerequisite; `review` also retains its syntax helper's `not_evaluated`
alongside the local comparison's `fail`. Neither profile makes a model-accuracy claim.

See [syntax helper authoring](../../BASELINES.md#use-syntax-helpers) for limits and coverage.
