# Documentation

AudiToad checks supplied evidence against a baseline you choose. The subject can be writing,
source code, configuration, an inventory, or a policy and the records used to check it.

| You want to... | Read |
|---|---|
| Install and run an audit | [User guide](user-guide.md) |
| Repeat audits or compare model arrangements | [Audit files and suites](user-guide.md#run-an-audit-file-or-suite), [audit schema](audit.schema.json), [label schema](labels.schema.json) |
| Understand an example baseline | [Examples](../examples/README.md) |
| Write compliance checks | [Writing baselines](../BASELINES.md) |
| Understand release goals and baseline research priorities | [Roadmap](../ROADMAP.md) |
| Build from source or prepare a release | [Build guide](build.md) |
| Understand the scan and its boundaries | [Architecture](architecture.md) |
| Change the implementation | [Developer guide](development.md) |
| See how the scanner uses `automation-structures` | [Construction walkthrough](automation-structures.md) |

The CLI accepts local input files. It does not discover a machine's state or import a Python
project to run it. Export the evidence you want checked and name it in the baseline or bundle.
The user guide lists the installed adapters and explains how to use them for different subjects.
