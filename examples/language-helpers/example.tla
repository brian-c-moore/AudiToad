-------------------------- MODULE example --------------------------
VARIABLE done
\* A comment mentioning WF_done(Idle) is not an operator definition.
Finish == done' = TRUE
Progress == WF_done(Finish)
Spec == [][Finish]_done /\ Progress
====================================================================
