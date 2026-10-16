//! Closed baseline validation and immutable evaluator installation.
use crate::{
    ScanError, json,
    schema::*,
    source::{InventoryItem, fixture_path, read_bounded, sha256},
};
use automation_structures::RelationshipGraph;
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
};

pub(crate) enum CompiledCheck {
    Yara(Box<yara_x::Rules>),
    Json,
    Markdown,
    Syntax(crate::syntax::CompiledSyntax),
    PythonConstantString(crate::syntax::CompiledSyntax),
    TlaplusRelation(crate::syntax::CompiledSyntax),
    CommandLine(std::collections::BTreeMap<String, CommandProgram>),
    Mock,
    Model,
    Answers,
}

pub struct ValidatedBaseline {
    pub(crate) content: Baseline,
    pub(crate) identity: BaselineIdentity,
    pub(crate) checks: Vec<CompiledCheck>,
    pub(crate) fixture_root: PathBuf,
    pub(crate) input_path: Option<PathBuf>,
    pub(crate) dependencies: RelationshipGraph,
    /// Edges from requirement node `r` to rule node `requirements.len() + rule`.
    pub(crate) coverage: RelationshipGraph,
}

fn require(condition: bool, message: impl Into<String>) -> Result<(), ScanError> {
    if condition {
        Ok(())
    } else {
        Err(ScanError::invalid(message))
    }
}

fn unique<'a>(items: impl Iterator<Item = &'a str>, label: &str) -> Result<(), ScanError> {
    let mut ids = BTreeSet::new();
    for id in items {
        require(
            !id.is_empty() && ids.insert(id),
            format!("empty/duplicate {label}: {id}"),
        )?;
    }
    Ok(())
}

fn nonempty(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::String(v) => !v.is_empty(),
        serde_json::Value::Array(v) => v.iter().all(nonempty),
        serde_json::Value::Object(v) => v.iter().all(|(k, v)| !k.is_empty() && nonempty(v)),
        _ => true,
    }
}

fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

fn json_evidence_binding(source: &str, evidence: &str) -> bool {
    source == "inventory-json/1" && evidence == "item-json/1"
        || source == "evidence-bundle/1"
            && matches!(evidence, "declared-parts/1" | "scoped-input/1")
        || crate::scoped::media(source).is_some() && evidence == "scoped-input/1"
}

pub(crate) fn pointer_valid(pointer: &str) -> bool {
    if !pointer.starts_with('/') {
        return false;
    }
    let mut chars = pointer.chars();
    while let Some(ch) = chars.next() {
        if ch == '~' && !matches!(chars.next(), Some('0' | '1')) {
            return false;
        }
    }
    true
}

impl ValidatedBaseline {
    /// Validate schema and installed bindings without evaluating fixtures or targets.
    pub fn from_bytes(bytes: &[u8], fixture_root: &Path) -> Result<Self, ScanError> {
        Self::from_bytes_with_limit(bytes, fixture_root, 2 * 1024 * 1024)
    }

    /// Validate with an explicit baseline byte ceiling; all semantic checks still apply.
    pub fn from_bytes_with_limit(
        bytes: &[u8],
        fixture_root: &Path,
        max_bytes: u64,
    ) -> Result<Self, ScanError> {
        require(
            automation_structures::Budget::new(max_bytes).try_allocate(bytes.len() as u64),
            format!("baseline exceeds {max_bytes} byte input limit"),
        )?;
        let content: Baseline = json::parse(bytes).map_err(ScanError::invalid)?;
        require(
            nonempty(
                &serde_json::to_value(&content).map_err(|e| ScanError::invalid(e.to_string()))?,
            ),
            "baseline has an empty string",
        )?;
        require(
            matches!(
                content.schema.as_str(),
                "auditoad-baseline/1" | "checkwarden-baseline/1"
            ),
            "unknown baseline schema",
        )?;
        require(
            !content.rules.is_empty() && !content.profiles.is_empty(),
            "baseline requires rules and profiles",
        )?;
        unique(content.groups.iter().map(|v| v.id.as_str()), "group")?;
        unique(content.rules.iter().map(|v| v.id.as_str()), "rule")?;
        unique(content.profiles.iter().map(|v| v.id.as_str()), "profile")?;
        require(
            content
                .default_profile
                .as_ref()
                .is_none_or(|id| content.profiles.iter().any(|p| &p.id == id)),
            "default_profile must name an existing profile",
        )?;
        let dependencies = dependency_graph(&content)?;
        let coverage = coverage_graph(&content)?;
        for source in content.sources.values() {
            require(
                matches!(
                    source.adapter.as_str(),
                    "raw-bytes/1"
                        | "inventory-json/1"
                        | "evidence-bundle/1"
                        | "text/1"
                        | "json/1"
                        | "json-lines/1"
                        | "collection/1"
                ),
                format!("source not installed: {}", source.adapter),
            )?;
            require(!source.media.is_empty(), "source media/kinds are empty")?;
            require(
                !source.include_provenance || source.adapter == "collection/1",
                "include_provenance requires collection/1",
            )?;
            unique(source.media.iter().map(String::as_str), "source kind")?;
            if let Some(media) = crate::scoped::media(&source.adapter) {
                require(
                    source.media == [media],
                    "scoped text/json source has an incompatible media type",
                )?;
            }
            if source.adapter == "raw-bytes/1" {
                require(
                    source.media == ["application/octet-stream"],
                    "raw-bytes/1 accepts application/octet-stream",
                )?;
            }
            if source.adapter == "evidence-bundle/1" {
                require(
                    source.media == ["application/vnd.auditoad.bundle+json"]
                        || source.media == ["application/vnd.checkwarden.bundle+json"],
                    "evidence-bundle/1 accepts application/vnd.auditoad.bundle+json",
                )?;
            }
        }
        for evidence in content.evidence.values() {
            require(
                matches!(
                    evidence.builder.as_str(),
                    "bytes/1" | "item-json/1" | "declared-parts/1" | "scoped-input/1" | "answers/1"
                ) && evidence.builder_revision == "r1",
                "unknown evidence builder/revision",
            )?;
            if evidence.builder == "declared-parts/1" {
                let roles = evidence.required_roles.as_ref().ok_or_else(|| {
                    ScanError::invalid("declared-parts/1 requires explicit roles")
                })?;
                require(!roles.is_empty(), "bundle roles are empty")?;
                unique(roles.iter().map(String::as_str), "bundle role")?;
            } else {
                require(
                    evidence.required_roles.is_none(),
                    "roles require declared-parts/1",
                )?;
            }
        }
        let mut checks = Vec::new();
        for rule in &content.rules {
            let source = content
                .sources
                .get(&rule.source)
                .ok_or_else(|| ScanError::invalid(format!("unknown source for {}", rule.id)))?;
            let evidence = content
                .evidence
                .get(&rule.evidence)
                .ok_or_else(|| ScanError::invalid(format!("unknown evidence for {}", rule.id)))?;
            require(
                content.groups.iter().any(|g| g.id == rule.group),
                format!("unknown group for {}", rule.id),
            )?;
            require(
                if crate::scoped::media(&source.adapter).is_some()
                    || source.adapter == "evidence-bundle/1" && rule.scope.is_some()
                {
                    let scope = rule
                        .scope
                        .as_ref()
                        .ok_or_else(|| ScanError::invalid("scoped sources require scope"))?;
                    matches!(evidence.builder.as_str(), "scoped-input/1" | "answers/1")
                        && rule.scope_kind
                            == if scope.unit == ScopeUnit::Document {
                                "whole"
                            } else {
                                "site"
                            }
                        && (!matches!(scope.unit, ScopeUnit::Paragraph | ScopeUnit::Sentence)
                            || matches!(
                                source.adapter.as_str(),
                                "text/1" | "collection/1" | "evidence-bundle/1"
                            ))
                        && (scope.unit != ScopeUnit::Record
                            || !matches!(source.adapter.as_str(), "text/1" | "evidence-bundle/1"))
                        && (scope.unit != ScopeUnit::Document
                            || scope.context == ScopeContext::None)
                } else if source.adapter == "evidence-bundle/1" {
                    (evidence.builder == "declared-parts/1"
                        || evidence.builder == "answers/1"
                            && matches!(rule.check, Check::Answers { .. }))
                        && matches!(rule.scope_kind.as_str(), "site" | "relation" | "whole")
                } else {
                    rule.scope_kind == "site"
                },
                "scope/source mismatch",
            )?;
            require(
                rule.scope.is_none()
                    || crate::scoped::media(&source.adapter).is_some()
                    || source.adapter == "evidence-bundle/1",
                "automatic scope requires a scoped source adapter",
            )?;
            if let Some(scope) = &rule.scope {
                require(
                    if source.adapter == "collection/1" {
                        scope.input.is_some()
                    } else {
                        scope.input.is_none() && scope.related.is_empty()
                    },
                    "named inputs and related evidence require collection/1; collection scopes must name their input",
                )?;
                unique(
                    scope.related.iter().map(|link| link.role.as_str()),
                    "related evidence role",
                )?;
                for link in &scope.related {
                    require(
                        !matches!(link.role.as_str(), "subject" | "context"),
                        "related evidence role is reserved",
                    )?;
                    require(
                        link.on
                            .iter()
                            .all(|key| pointer_valid(&key.subject) && pointer_valid(&key.related)),
                        "related evidence keys require nonempty JSON Pointers",
                    )?;
                    require(
                        link.on.iter().collect::<BTreeSet<_>>().len() == link.on.len(),
                        "duplicate correspondence key",
                    )?;
                }
                require(
                    source.adapter == "evidence-bundle/1"
                        || rule.applicability.include == ["*"]
                            && rule.applicability.exclude.is_empty(),
                    "automatic scope checks every unit; applicability must include * with no exclusions",
                )?;
            }
            if evidence.builder == "declared-parts/1" {
                let roles = evidence
                    .required_roles
                    .as_ref()
                    .ok_or_else(|| ScanError::invalid("missing roles"))?;
                require(
                    roles.iter().any(|r| r == "subject"),
                    "bundle requires subject role",
                )?;
                require(
                    rule.scope_kind != "relation" || roles.iter().any(|r| r == "peer"),
                    "relation requires peer role",
                )?;
            }
            require(
                !rule.applicability.include.is_empty(),
                "applicability include is empty",
            )?;
            for patterns in [&rule.applicability.include, &rule.applicability.exclude] {
                unique(
                    patterns.iter().map(String::as_str),
                    "applicability selector",
                )?;
                for pattern in patterns {
                    require(
                        pattern == "*"
                            || !pattern.contains(['*', '?', '[', ']', '{', '}', '\\'])
                                && !pattern.starts_with('/'),
                        "applicability supports * or exact filename/kind only; directory globs need a directory adapter",
                    )?;
                }
            }
            let check = match &rule.check {
                Check::Answers { .. } => {
                    require(
                        rule.scope
                            .as_ref()
                            .map_or(source.adapter == "evidence-bundle/1", |s| {
                                s.context == ScopeContext::None && s.related.is_empty()
                            })
                            && evidence.builder == "answers/1"
                            && rule.evaluator.kind == "answers"
                            && rule.evaluator.contract == "answers/1",
                        "answer combination requires a bundle packet or an automatic scope without source context and answers/1 binding",
                    )?;
                    require(
                        content.baseline.status == Admission::Draft,
                        "answer combinations remain experimental until composition admission",
                    )?;
                    require(
                        rule.fixtures.fail.is_empty() && rule.fixtures.pass.is_empty(),
                        "answer combinations use dependency records, not standalone fixtures",
                    )?;
                    CompiledCheck::Answers
                }
                Check::Yara {
                    source: text,
                    rule_name,
                    json_string_pointer,
                    ..
                } => {
                    require(
                        (if let Some(pointer) = json_string_pointer {
                            pointer_valid(pointer)
                                && json_evidence_binding(&source.adapter, &evidence.builder)
                        } else {
                            source.adapter == "raw-bytes/1" && evidence.builder == "bytes/1"
                        }) && rule.evaluator.kind == "yara-x"
                            && rule.evaluator.contract == "yara-x/1.20.0",
                        "YARA source/evidence/evaluator contract mismatch",
                    )?;
                    let mut compiler = yara_x::Compiler::new();
                    compiler.enable_includes(false);
                    compiler
                        .add_source(text.as_str())
                        .map_err(|e| ScanError::invalid(format!("{}: {e}", rule.id)))?;
                    let compiled = compiler.build();
                    require(
                        compiled.iter().any(|r| r.identifier() == rule_name),
                        "named YARA rule is absent",
                    )?;
                    require(
                        compiled.imports().next().is_none(),
                        "this YARA binding has no imported modules",
                    )?;
                    CompiledCheck::Yara(Box::new(compiled))
                }
                Check::Json { pointer, .. } => {
                    require(
                        json_evidence_binding(&source.adapter, &evidence.builder)
                            && rule.evaluator.kind == "json-pointer-equals"
                            && rule.evaluator.contract == "json-pointer-equals/1",
                        "JSON source/evidence/evaluator contract mismatch",
                    )?;
                    require(pointer_valid(pointer), "malformed or empty JSON Pointer")?;
                    CompiledCheck::Json
                }
                Check::JsonCompare { left, right, .. } => {
                    require(
                        json_evidence_binding(&source.adapter, &evidence.builder)
                            && rule.evaluator.kind == "json-pointer-compare"
                            && rule.evaluator.contract == "json-pointer-compare/1",
                        "JSON comparison source/evidence/evaluator contract mismatch",
                    )?;
                    require(
                        pointer_valid(left) && pointer_valid(right),
                        "malformed or empty JSON comparison pointer",
                    )?;
                    CompiledCheck::Json
                }
                Check::JsonContains {
                    array_pointer,
                    value_pointer,
                    ..
                } => {
                    require(
                        json_evidence_binding(&source.adapter, &evidence.builder)
                            && rule.evaluator.kind == "json-pointer-contains"
                            && rule.evaluator.contract == "json-pointer-contains/1",
                        "JSON membership source/evidence/evaluator contract mismatch",
                    )?;
                    require(
                        pointer_valid(array_pointer) && pointer_valid(value_pointer),
                        "malformed or empty JSON membership pointer",
                    )?;
                    CompiledCheck::Json
                }
                Check::JsonNumberRange {
                    pointer,
                    minimum,
                    maximum,
                    ..
                } => {
                    require(
                        json_evidence_binding(&source.adapter, &evidence.builder)
                            && rule.evaluator.kind == "json-number-range"
                            && rule.evaluator.contract == "json-number-range/1",
                        "JSON range source/evidence/evaluator contract mismatch",
                    )?;
                    require(
                        pointer_valid(pointer)
                            && minimum.is_finite()
                            && maximum.is_finite()
                            && minimum <= maximum,
                        "JSON range requires a pointer and finite ordered bounds",
                    )?;
                    CompiledCheck::Json
                }
                Check::TlaplusRelation {
                    json_string_pointer,
                    operator_pointer,
                    predicate,
                    limits,
                    ..
                } => {
                    require(
                        json_evidence_binding(&source.adapter, &evidence.builder)
                            && rule.evaluator.kind == "tlaplus-relation"
                            && rule.evaluator.contract == "tlaplus-relation/1",
                        "TLA+ relation source/evidence/evaluator contract mismatch",
                    )?;
                    let mut pointers = vec![json_string_pointer, operator_pointer];
                    match predicate {
                        TlaplusPredicate::DirectAlias { reference_pointer }
                        | TlaplusPredicate::PositiveConjunct { reference_pointer } => {
                            pointers.push(reference_pointer)
                        }
                        TlaplusPredicate::WeakFairness {
                            action_pointer,
                            subscript_pointer,
                        } => {
                            pointers.extend([action_pointer, subscript_pointer]);
                        }
                    }
                    require(
                        pointers.into_iter().all(|p| pointer_valid(p)),
                        "malformed or empty TLA+ relation pointer",
                    )?;
                    CompiledCheck::TlaplusRelation(
                        crate::syntax::CompiledSyntax::new(
                            SyntaxLanguage::Tlaplus,
                            "(module name: (identifier) @module)",
                            limits,
                        )
                        .map_err(ScanError::invalid)?,
                    )
                }
                Check::Markdown {
                    json_string_pointer,
                    predicate,
                } => {
                    require(
                        (if let Some(pointer) = json_string_pointer {
                            pointer_valid(pointer)
                                && json_evidence_binding(&source.adapter, &evidence.builder)
                        } else {
                            source.adapter == "raw-bytes/1" && evidence.builder == "bytes/1"
                        }) && rule.evaluator.kind == "markdown"
                            && rule.evaluator.contract == "markdown/1",
                        "Markdown source/evidence/evaluator contract mismatch",
                    )?;
                    require(
                        match predicate {
                            MarkdownPredicate::ForbiddenTerms { terms } => {
                                !terms.is_empty()
                                    && terms.iter().all(|term| crate::markdown::valid_term(term))
                            }
                            MarkdownPredicate::ProseBold => true,
                            MarkdownPredicate::ListLength { forbidden_length } => {
                                *forbidden_length > 0
                            }
                            MarkdownPredicate::ParagraphSentenceLengths {
                                shorter_than,
                                longer_than,
                            } => *shorter_than > 1 && shorter_than <= longer_than,
                        },
                        "Markdown terms must start and end with words; thresholds must allow positive sentence/item counts and an ordered length range",
                    )?;
                    CompiledCheck::Markdown
                }
                Check::Syntax {
                    language,
                    json_string_pointer,
                    query,
                    limits,
                } => {
                    require(
                        (if let Some(pointer) = json_string_pointer {
                            pointer_valid(pointer)
                                && json_evidence_binding(&source.adapter, &evidence.builder)
                        } else {
                            source.adapter == "raw-bytes/1" && evidence.builder == "bytes/1"
                        }) && rule.evaluator.kind == "syntax"
                            && rule.evaluator.contract == "syntax/1",
                        "syntax source/evidence/evaluator contract mismatch",
                    )?;
                    require(
                        content.baseline.status == Admission::Draft,
                        "syntax helpers supply evidence only and require a draft baseline",
                    )?;
                    require(
                        rule.fixtures.fail.is_empty() && rule.fixtures.pass.is_empty(),
                        "syntax helpers make no pass/fail decision; use labelled audit cases",
                    )?;
                    CompiledCheck::Syntax(
                        crate::syntax::CompiledSyntax::new(*language, query, limits)
                            .map_err(ScanError::invalid)?,
                    )
                }
                Check::PythonConstantString {
                    json_string_pointer,
                    query,
                    limits,
                } => {
                    require(
                        (if let Some(pointer) = json_string_pointer {
                            pointer_valid(pointer)
                                && json_evidence_binding(&source.adapter, &evidence.builder)
                        } else {
                            source.adapter == "raw-bytes/1" && evidence.builder == "bytes/1"
                        }) && rule.evaluator.kind == "syntax"
                            && rule.evaluator.contract == "python-constant-string/1",
                        "Python constant-string source/evidence/evaluator contract mismatch",
                    )?;
                    require(
                        content.baseline.status == Admission::Draft,
                        "Python constant-string checks require a draft baseline",
                    )?;
                    require(
                        rule.fixtures.fail.is_empty() && rule.fixtures.pass.is_empty(),
                        "Python constant-string checks prove only passes; use labelled audit cases",
                    )?;
                    CompiledCheck::PythonConstantString(
                        crate::syntax::CompiledSyntax::python_constant_string(query, limits)
                            .map_err(ScanError::invalid)?,
                    )
                }
                Check::CommandLine {
                    json_string_pointer,
                    json_array_pointer,
                    item_string_pointer,
                    grammar,
                    predicate,
                } => {
                    let programs = content.command_grammars.get(grammar).ok_or_else(|| {
                        ScanError::invalid(format!("unknown command grammar: {grammar}"))
                    })?;
                    require(
                        json_evidence_binding(&source.adapter, &evidence.builder)
                            && rule.evaluator.kind == "command-line"
                            && rule.evaluator.contract == "command-line/1",
                        "command-line source/evidence/evaluator contract mismatch",
                    )?;
                    require(
                        match (json_string_pointer, json_array_pointer, item_string_pointer) {
                            (Some(pointer), None, None) => pointer_valid(pointer),
                            (None, Some(items), Some(field)) => {
                                pointer_valid(items) && pointer_valid(field)
                            }
                            _ => false,
                        },
                        "command-line checks select one string pointer, or an array pointer with an item string pointer",
                    )?;
                    let lowercase_ascii = |word: &str| {
                        !word.is_empty()
                            && word
                                .bytes()
                                .all(|b| b.is_ascii_graphic() && !b.is_ascii_uppercase())
                    };
                    require(
                        !programs.is_empty()
                            && programs.values().all(|program| {
                                !program.executables.is_empty()
                                    && program.executables.iter().all(|e| {
                                        !e.contains(['\\', '/'])
                                            && e.to_lowercase() == *e
                                            && !e.trim().is_empty()
                                    })
                                    && !program.option_prefixes.is_empty()
                                    && program
                                        .option_prefixes
                                        .iter()
                                        .all(|p| p.chars().count() == 1)
                                    && !matches!(
                                        program.unmatched,
                                        CommandValue::CmdCommand | CommandValue::CmdStripQuotes
                                    )
                                    && !matches!(
                                        program.positional,
                                        CommandValue::CmdCommand | CommandValue::CmdStripQuotes
                                    )
                                    && program.options.iter().all(|option| {
                                        !option.name.trim().is_empty()
                                            && !option.matches.is_empty()
                                            && option.matches.iter().all(|m| {
                                                lowercase_ascii(&m.word)
                                                    && lowercase_ascii(&m.shortest)
                                                    && m.word.starts_with(&m.shortest)
                                            })
                                    })
                            }),
                        "command programs need lowercase executable names, one-character option prefixes and lowercase ASCII option words that start with their shortest match",
                    )?;
                    for program in programs.values() {
                        unique(
                            program.options.iter().map(|o| o.name.as_str()),
                            "command option name",
                        )?;
                    }
                    require(
                        match predicate {
                            CommandPredicate::Invokes { programs: selected } => {
                                !selected.is_empty()
                                    && selected.iter().all(|p| programs.contains_key(p))
                            }
                            CommandPredicate::Option {
                                programs: selected,
                                option,
                            } => {
                                !selected.is_empty()
                                    && selected.iter().all(|p| {
                                        programs.get(p).is_some_and(|p| {
                                            p.options.iter().any(|o| o.name == *option)
                                        })
                                    })
                            }
                        },
                        "command predicate names an undeclared program or option",
                    )?;
                    CompiledCheck::CommandLine(programs.clone())
                }
                Check::MockModel {
                    pass_below,
                    fail_at_or_above,
                    ..
                } => {
                    require(
                        (source.adapter == "raw-bytes/1" && evidence.builder == "bytes/1"
                            || crate::scoped::media(&source.adapter).is_some()
                                && evidence.builder == "scoped-input/1")
                            && rule.evaluator.kind == "mock-model"
                            && rule.evaluator.contract == "yes-no/1",
                        "mock source/evidence/evaluator contract mismatch",
                    )?;
                    require(
                        pass_below.is_finite()
                            && fail_at_or_above.is_finite()
                            && 0.0 <= *pass_below
                            && pass_below < fail_at_or_above
                            && *fail_at_or_above <= 1.0,
                        "invalid mock decision regions",
                    )?;
                    require(
                        content.baseline.status == Admission::Draft,
                        "mock rules cannot be admitted",
                    )?;
                    CompiledCheck::Mock
                }
                Check::YesNo {
                    max_request_bytes,
                    state_projection,
                    state_required_any,
                    ..
                }
                | Check::Choice {
                    max_request_bytes,
                    state_projection,
                    state_required_any,
                    ..
                }
                | Check::Extract {
                    max_request_bytes,
                    state_projection,
                    state_required_any,
                    ..
                }
                | Check::Box {
                    max_request_bytes,
                    state_projection,
                    state_required_any,
                    ..
                } => {
                    require(
                        json_evidence_binding(&source.adapter, &evidence.builder)
                            && rule.evaluator.kind == "model"
                            && rule.evaluator.contract
                                == match rule.check {
                                    Check::YesNo { .. } => "yes-no/1",
                                    Check::Choice { .. } => "choice/1",
                                    Check::Box { .. } => "box/1",
                                    _ => "extract/1",
                                },
                        "model question source/evidence/evaluator contract mismatch",
                    )?;
                    require(
                        rule.evaluator
                            .role
                            .as_ref()
                            .is_none_or(|role| !role.trim().is_empty()),
                        "an evaluator role must be nonempty",
                    )?;
                    require(
                        state_projection.as_ref().is_none_or(|fields| {
                            !fields.is_empty()
                                && fields.iter().all(|(name, field)| {
                                    !name.trim().is_empty()
                                        && pointer_valid(field.pointer())
                                        && field
                                            .capture_name()
                                            .is_none_or(|capture| !capture.trim().is_empty())
                                })
                        }),
                        "state projection requires nonempty field and capture names and valid JSON Pointers",
                    )?;
                    require(
                        state_required_any.iter().all(|group| {
                            !group.is_empty()
                                && state_projection.as_ref().is_some_and(|fields| {
                                    group.iter().all(|name| fields.contains_key(name))
                                })
                        }),
                        "state_required_any groups must be nonempty and name declared projected fields",
                    )?;
                    require(
                        max_request_bytes.is_none_or(|limit| limit >= 1),
                        "question request limit must be at least 1 byte",
                    )?;
                    if let Some(assets) = rule.check.image_assets() {
                        require(
                            !assets.is_empty()
                                && assets.iter().all(|(reference, pointer)| {
                                    (16..=1024).contains(&reference.len())
                                        && reference.bytes().all(|byte| {
                                            byte.is_ascii_alphanumeric()
                                                || matches!(byte, b'-' | b'_')
                                        })
                                        && pointer_valid(pointer)
                                        && assets.keys().all(|other| {
                                            other == reference || !other.contains(reference)
                                        })
                                })
                                && assets.keys().map(String::len).sum::<usize>() <= 65_536
                                && assets.values().collect::<BTreeSet<_>>().len() == assets.len(),
                            "image assets require nonoverlapping ASCII references of 16..1024 bytes and valid evidence pointers",
                        )?;
                    }
                    match &rule.check {
                        Check::YesNo {
                            pass_below,
                            fail_at_or_above,
                            ..
                        } => require(
                            pass_below.is_finite()
                                && fail_at_or_above.is_finite()
                                && 0.0 <= *pass_below
                                && pass_below < fail_at_or_above
                                && *fail_at_or_above <= 1.0,
                            "invalid yes-no decision regions",
                        )?,
                        Check::Choice {
                            options,
                            min_choice_probability,
                            min_confidence,
                            ..
                        } => {
                            require(
                                (2..=255).contains(&options.len()),
                                "Choice requires 2 to 255 options",
                            )?;
                            require(
                                options.values().all(|option| {
                                    matches!(
                                        option.result,
                                        ResultState::Pass | ResultState::Fail | ResultState::Review
                                    )
                                }) && options
                                    .values()
                                    .any(|option| option.result == ResultState::Review),
                                "Choice options require pass/fail/review mappings and an explicit review option",
                            )?;
                            require(
                                [min_choice_probability, min_confidence]
                                    .iter()
                                    .all(|value| value.is_finite() && (0.0..=1.0).contains(*value)),
                                "invalid Choice decision limits",
                            )?;
                        }
                        Check::Extract { fields, .. } => require(
                            !fields.is_empty()
                                && fields.iter().all(|(name, field)| {
                                    !name.trim().is_empty() && !field.description.trim().is_empty()
                                }),
                            "extraction declares nonempty field names and descriptions",
                        )?,
                        Check::Box { .. } => require(
                            rule.check.image_assets().is_some(),
                            "Box requires declared image assets",
                        )?,
                        _ => {
                            return Err(ScanError::invalid(
                                "model evaluator has a non-model check",
                            ));
                        }
                    }
                    require(
                        content.baseline.status == Admission::Draft,
                        "semantic rules remain experimental until live admission",
                    )?;
                    CompiledCheck::Model
                }
            };
            if !matches!(
                check,
                CompiledCheck::Mock
                    | CompiledCheck::Model
                    | CompiledCheck::Answers
                    | CompiledCheck::Syntax(_)
                    | CompiledCheck::PythonConstantString(_)
            ) {
                require(
                    !rule.fixtures.fail.is_empty() && !rule.fixtures.pass.is_empty(),
                    "deterministic rules require pass and fail fixtures",
                )?;
            }
            for fixture in rule.fixtures.fail.iter().chain(&rule.fixtures.pass) {
                require(
                    digest(&fixture.source_sha256) && digest(&fixture.evidence_sha256),
                    "fixture digest must be full lowercase SHA-256",
                )?;
                fixture_path(fixture_root, &fixture.path).map_err(ScanError::invalid)?;
            }
            checks.push(check);
        }
        for profile in &content.profiles {
            unique(
                profile.select.iter().map(String::as_str),
                "profile selector",
            )?;
            require(
                !profile.block_on.contains(&ResultState::Pass)
                    && !profile.block_on.contains(&ResultState::Notapplicable),
                "pass/notapplicable cannot be blocking states",
            )?;
            require(
                profile.block_on.contains(&ResultState::Error)
                    && profile.block_on.contains(&ResultState::NotEvaluated),
                "profiles must block error and not_evaluated",
            )?;
            require(
                profile.block_on.iter().collect::<BTreeSet<_>>().len() == profile.block_on.len(),
                "duplicate block_on state",
            )?;
            unique(
                profile.allowed_egress.iter().map(String::as_str),
                "allowed_egress entry",
            )?;
            require(
                profile.allowed_egress.iter().all(|entry| {
                    entry == crate::evaluators::LOOPBACK
                        || crate::evaluators::origin(entry)
                            .is_ok_and(|origin| origin == *entry && entry.starts_with("https://"))
                }),
                "allowed_egress entries are https origins without a path, or loopback",
            )?;
            if let Some(required) = &profile.requirements {
                require(
                    !required.is_empty(),
                    "profile requirements must name at least one requirement; omit it to require all",
                )?;
                unique(required.iter().map(String::as_str), "profile requirement")?;
                for id in required {
                    require(
                        content.requirements.iter().any(|r| r.id == *id),
                        format!("profile {} names unknown requirement: {id}", profile.id),
                    )?;
                }
            }
            selected_indices(&content, profile, &dependencies)?;
        }
        let identity = BaselineIdentity {
            id: content.baseline.id.clone(),
            version: content.baseline.version.clone(),
            sha256: sha256(bytes),
        };
        Ok(Self {
            content,
            identity,
            checks,
            fixture_root: fixture_root.into(),
            input_path: None,
            dependencies,
            coverage,
        })
    }

    pub fn from_file(path: &Path) -> Result<Self, ScanError> {
        Self::from_file_with_limit(path, 2 * 1024 * 1024)
    }

    /// Read and validate a baseline under the same explicit byte ceiling.
    pub fn from_file_with_limit(path: &Path, max_bytes: u64) -> Result<Self, ScanError> {
        let bytes = read_bounded(path, max_bytes).map_err(ScanError::invalid)?;
        let mut baseline = Self::from_bytes_with_limit(
            &bytes,
            path.parent().unwrap_or(Path::new(".")),
            max_bytes,
        )?;
        baseline.input_path = Some(crate::source::unlinked_path(path).map_err(ScanError::invalid)?);
        Ok(baseline)
    }

    pub fn baseline(&self) -> &Baseline {
        &self.content
    }

    /// Resolve an operator override, a declared default, or the only profile.
    pub fn profile(&self, explicit: Option<&str>) -> Result<&str, ScanError> {
        let id = explicit.or(self.content.default_profile.as_deref())
            .or(match self.content.profiles.as_slice() { [profile] => Some(profile.id.as_str()), _ => None })
            .ok_or_else(|| ScanError::invalid("choose --profile or declare default_profile; this baseline has several profiles"))?;
        self.content
            .profiles
            .iter()
            .find(|p| p.id == id)
            .map(|p| p.id.as_str())
            .ok_or_else(|| ScanError::invalid(format!("unknown profile: {id}")))
    }

    pub(crate) fn verify_fixtures(
        &self,
        indices: &[usize],
        limits: &Limits,
    ) -> Result<Usage, ScanError> {
        use automation_structures::{Budget, Sequential};
        // Admission controls have a separate, declared scope and cumulative ceilings.
        // Pure predicate evaluation still requires actual canonical admission/progress.
        let selected = indices
            .iter()
            .map(|&index| {
                self.content
                    .rules
                    .get(index)
                    .map(|rule| (index, rule))
                    .ok_or_else(|| {
                        ScanError::unresolved("fixture selection has an unknown rule index")
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let manifest: Vec<_> = selected
            .iter()
            .filter(|(_, rule)| {
                !matches!(
                    rule.check,
                    Check::MockModel { .. }
                        | Check::YesNo { .. }
                        | Check::Choice { .. }
                        | Check::Extract { .. }
                        | Check::Box { .. }
                        | Check::Answers { .. }
                )
            })
            .flat_map(|&(index, rule)| {
                rule.fixtures
                    .fail
                    .iter()
                    .map(move |f| (index, rule, ResultState::Fail, f))
                    .chain(
                        rule.fixtures
                            .pass
                            .iter()
                            .map(move |f| (index, rule, ResultState::Pass, f)),
                    )
            })
            .collect();
        let mut checks = Budget::new(limits.fixture_checks);
        let mut evidence = Budget::new(limits.fixture_bytes);
        if !manifest.is_empty() {
            let mut steps = Sequential::new(manifest.len(), 1, 0)
                .map_err(|e| ScanError::invalid(e.to_string()))?;
            while !steps.is_done() {
                let &(index, rule, expected, fixture) = manifest
                    .get(steps.completed())
                    .ok_or_else(|| ScanError::unresolved("fixture step has no manifest entry"))?;
                let source =
                    self.content.sources.get(&rule.source).ok_or_else(|| {
                        ScanError::unresolved("fixture rule has no source binding")
                    })?;
                let evidence_binding =
                    self.content.evidence.get(&rule.evidence).ok_or_else(|| {
                        ScanError::unresolved("fixture rule has no evidence binding")
                    })?;
                let check = self
                    .checks
                    .get(index)
                    .ok_or_else(|| ScanError::unresolved("fixture rule has no compiled check"))?;
                require(
                    steps.begin_step() && checks.try_allocate(1),
                    "fixture check admission refused",
                )?;
                let path =
                    fixture_path(&self.fixture_root, &fixture.path).map_err(ScanError::invalid)?;
                let bytes = read_bounded(&path, limits.input_bytes).map_err(ScanError::invalid)?;
                let source_digest = sha256(&bytes);
                require(
                    source_digest == fixture.source_sha256,
                    format!(
                        "fixture source digest mismatch: {}; expected {}, computed {}",
                        fixture.path, fixture.source_sha256, source_digest
                    ),
                )?;
                let frame = if source.adapter == "inventory-json/1" {
                    let item: InventoryItem = json::parse(&bytes).map_err(ScanError::invalid)?;
                    require(
                        !item.id.is_empty() && !item.kind.is_empty(),
                        "fixture has empty item identity/kind",
                    )?;
                    serde_json::to_vec(&item).map_err(|e| ScanError::invalid(e.to_string()))?
                } else if evidence_binding.builder == "scoped-input/1" {
                    crate::scoped::evidence(&bytes).map_err(ScanError::invalid)?
                } else {
                    bytes
                };
                let evidence_digest = sha256(&frame);
                require(
                    evidence_digest == fixture.evidence_sha256,
                    format!(
                        "fixture evidence digest mismatch: {}; expected {}, computed {}",
                        fixture.path, fixture.evidence_sha256, evidence_digest
                    ),
                )?;
                require(
                    evidence.try_allocate(frame.len() as u64),
                    "fixture evidence budget refused",
                )?;
                let actual = crate::evaluator::deterministic(rule, check, &frame);
                require(
                    matches!(actual, Ok((state, _)) if state == expected),
                    format!(
                        "{} fixture contradicts declared {:?}: {}",
                        rule.id, expected, fixture.path
                    ),
                )?;
                require(steps.complete_step(0), "fixture progress refused")?;
            }
        }
        Ok(Usage {
            checks: checks.allocated(),
            evidence_bytes: evidence.allocated(),
            reused_exchanges: 0,
            provider_calls: 0,
        })
    }
}

pub(crate) fn selected_indices(
    content: &Baseline,
    profile: &Profile,
    dependencies: &RelationshipGraph,
) -> Result<Vec<usize>, ScanError> {
    for selector in &profile.select {
        let known = selector == "*"
            || content.rules.iter().any(|r| r.id == *selector)
            || selector
                .strip_suffix("/*")
                .is_some_and(|id| content.groups.iter().any(|g| g.id == id));
        require(known, format!("unknown rule/group selector: {selector}"))?;
    }
    let mut indices: BTreeSet<_> = content
        .rules
        .iter()
        .enumerate()
        .filter_map(|(index, rule)| {
            profile
                .select
                .iter()
                .any(|s| {
                    s == "*" || *s == rule.id || s.strip_suffix("/*") == Some(rule.group.as_str())
                })
                .then_some(index)
        })
        .collect();
    require(!indices.is_empty(), "profile expands to no rules")?;
    // Dependencies must precede dependents, so one reverse pass closes the finite selection.
    for index in (0..content.rules.len()).rev() {
        if indices.contains(&index) {
            for (dependency, dependent, _) in dependencies.edges() {
                if dependent == index {
                    indices.insert(dependency);
                }
            }
        }
    }
    Ok(indices.into_iter().collect())
}

fn coverage_graph(content: &Baseline) -> Result<RelationshipGraph, ScanError> {
    unique(
        content.requirements.iter().map(|r| r.id.as_str()),
        "requirement",
    )?;
    let offset = content.requirements.len();
    let nodes = offset
        .checked_add(content.rules.len())
        .ok_or_else(|| ScanError::invalid("requirement and rule node count overflows"))?;
    let mut graph = RelationshipGraph::new(nodes, 1);
    for (index, rule) in content.rules.iter().enumerate() {
        for id in rule.requirements.keys() {
            let requirement = content
                .requirements
                .iter()
                .position(|r| r.id == *id)
                .ok_or_else(|| {
                    ScanError::invalid(format!("rule {} names unknown requirement: {id}", rule.id))
                })?;
            let node = offset
                .checked_add(index)
                .ok_or_else(|| ScanError::invalid("rule node index overflows"))?;
            graph
                .add_edge(requirement, node, 1)
                .map_err(|e| ScanError::invalid(e.to_string()))?;
            require(
                graph.contains(requirement, node),
                "requirement edge witness absent",
            )?;
        }
    }
    Ok(graph)
}

fn dependency_graph(content: &Baseline) -> Result<RelationshipGraph, ScanError> {
    let mut graph = RelationshipGraph::new(content.rules.len(), 1);
    for (index, rule) in content.rules.iter().enumerate() {
        let mut declared = Vec::new();
        if let Check::Answers {
            rules,
            fail_when,
            resolution,
            ..
        } = &rule.check
        {
            require(
                *fail_when != AnswerCombination::FirstResolved
                    || *resolution == AnswerResolution::AllAnswers,
                "first_resolved takes the first decision in order; resolution does not apply",
            )?;
            require(
                rules.iter().all(|id| {
                    content.rules.iter().find(|r| r.id == *id).is_none_or(|r| {
                        !matches!(
                            r.check,
                            Check::Extract { .. } | Check::Box { .. } | Check::Syntax { .. }
                        )
                    })
                }),
                "answer combinations combine decisions; an extraction or syntax helper makes none",
            )?;
            declared.push(rules);
        }
        if let Some(consult) = &rule.consult {
            require(
                content
                    .evidence
                    .get(&rule.evidence)
                    .is_some_and(|evidence| {
                        matches!(
                            evidence.builder.as_str(),
                            "scoped-input/1" | "declared-parts/1"
                        ) || evidence.builder == "answers/1"
                            && matches!(rule.check, Check::Answers { .. })
                    }),
                "consult requires scoped-input/1, declared-parts/1 or an answers/1 combination frame",
            )?;
            declared.push(&consult.rules);
        }
        for rules in declared {
            require(
                !rules.is_empty(),
                "answer combination and consult require dependencies",
            )?;
            unique(rules.iter().map(String::as_str), "answer dependency")?;
            for id in rules {
                let dependency =
                    content
                        .rules
                        .iter()
                        .position(|r| r.id == *id)
                        .ok_or_else(|| {
                            ScanError::invalid(format!("unknown answer dependency: {id}"))
                        })?;
                require(
                    dependency < index,
                    format!(
                        "dependency {id} must occur before {}; forward references and cycles are refused",
                        rule.id
                    ),
                )?;
                let child = content
                    .rules
                    .get(dependency)
                    .ok_or_else(|| ScanError::unresolved("answer dependency index is not bound"))?;
                require(
                    child.source == rule.source,
                    "answer dependencies must share the same source",
                )?;
                require(
                    match (&rule.scope, &child.scope) {
                        (Some(parent), Some(child)) => {
                            parent.unit == ScopeUnit::Document
                                || parent.unit == child.unit && parent.input == child.input
                        }
                        (None, None) => {
                            content
                                .sources
                                .get(&rule.source)
                                .ok_or_else(|| {
                                    ScanError::unresolved("answer rule has no source binding")
                                })?
                                .adapter
                                == "evidence-bundle/1"
                                && rule.scope_kind == child.scope_kind
                        }
                        _ => false,
                    },
                    "answer dependencies require compatible automatic units or the same bundle packet scope kind; scope modes cannot be mixed",
                )?;
                if !graph.contains(dependency, index) {
                    graph
                        .add_edge(dependency, index, 1)
                        .map_err(|e| ScanError::invalid(e.to_string()))?;
                }
                require(
                    graph.contains(dependency, index),
                    "dependency edge witness absent",
                )?;
            }
        }
    }
    Ok(graph)
}
