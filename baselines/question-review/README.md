# Question review

Review an AudiToad baseline or a standalone question set:

```console
auditoad baseline review questions.json --report review.json
```

This prepares locally. Add `--evaluators <file> --live` for model suggestions.
See [Writing baselines](../../BASELINES.md#review-the-questions) for the input format,
network permissions, limits and exact answer reuse.

Version 4 checks atomic judgments, identified subjects, answer-neutral wording,
unrelated commentary, mechanical facts and declared evidence omissions.

The [development controls](validation.questions.json), scored against
[separate labels](validation.labels.json), produced **10 correct, 0 wrong and
2 unresolved answers out of 12** with Jev 1.14.0. The
[retained score](validation-v4.score.json) records the source identities and thresholds.
These authored controls do not establish accuracy on unfamiliar questions.

Reviewing the ten current model baselines and the reviewer's own questions produced
1,224 observations: **418 pass suggestions, 0 defect suggestions, 805 unresolved
reviews and 1 provider-format error**. The rejected response's choice probabilities
summed to 0.99 instead of 1. These observations have no correctness labels and do
not establish that the baselines contain no defects. Reviews concern declarations;
they do not verify actual runtime evidence or answer the original audit questions.
