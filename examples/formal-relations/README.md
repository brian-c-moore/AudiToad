# Check written TLA+ relationships

This example runs 28 local checks using the TLA+ parser: direct aliases, positive written
conjuncts and exact weak-fairness forms. No model or proof checker runs.

From this directory:

```console
auditoad baseline validate baseline.json
auditoad scan --baseline baseline.json --input inputs.json --report report.json
auditoad score --report report.json --labels labels.json
```

The example deliberately maps a present relationship to `fail` and an absent one to `pass`,
so its ordinary scan exits 1. Those names encode boolean premises here; a present alias or
fairness clause is not itself an audit defect. The external labels explain that convention.
All 28 examples are authored development controls, not an independent accuracy benchmark.

Operand names come from each input record. The source and names are preserved in the frozen
evidence. A relation observation retains the exact definition, actual operands and positive
witness spans. Missing/ambiguous definitions, malformed source and exhausted limits are
unresolved, not absent relationships.

The controls distinguish parentheses and whitespace from comments, strings, negation,
disjunction, implication and indirect references. Some definitions deliberately have the
same truth value: logical equivalence does not satisfy a question about written syntax.
Strong fairness does not match the exact weak-fairness predicate even where it implies a
related semantic property.

The supported scope is one zero-argument definition directly in one outer module, using
simple ASCII operand names. These checks do not resolve imported names or aliases, parse
TLC configurations, check TLAPS obligations or establish liveness. Supply those separately
when using syntax facts to evaluate a broader claim.

See [baseline authoring](../../BASELINES.md#check-written-tla-relationships) for the contract.
