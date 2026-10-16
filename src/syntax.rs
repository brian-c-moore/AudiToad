//! Source-faithful syntax evidence. Grammars interpret content; the scan owns execution.
use crate::{
    json,
    schema::{ResultState, SyntaxLanguage, SyntaxLimits},
    source::sha256,
};
use automation_structures::Budget;
use serde_json::{Value, json};
use std::{
    ops::ControlFlow,
    time::{Duration, Instant},
};
use tree_sitter::{
    Language, Node, ParseOptions, Parser, Query, QueryCursor, QueryCursorOptions, StreamingIterator,
};

const RUNTIME: &str = "tree-sitter/0.27.0";

fn grammar(language: SyntaxLanguage) -> (Language, &'static str) {
    match language {
        SyntaxLanguage::Bash => (tree_sitter_bash::LANGUAGE.into(), "tree-sitter-bash/0.25.1"),
        SyntaxLanguage::Zsh => (tree_sitter_zsh::LANGUAGE.into(), "tree-sitter-zsh/0.63.4"),
        SyntaxLanguage::Powershell => (
            tree_sitter_powershell::LANGUAGE.into(),
            "tree-sitter-powershell/0.26.4",
        ),
        SyntaxLanguage::Python => (
            tree_sitter_python::LANGUAGE.into(),
            "tree-sitter-python/0.25.0",
        ),
        SyntaxLanguage::Rust => (tree_sitter_rust::LANGUAGE.into(), "tree-sitter-rust/0.24.2"),
        SyntaxLanguage::Verus => (
            crate::verus::language(),
            "tree-sitter-verus/0c939ef2ec0a188c3cf24518474fb8082db02ec4",
        ),
        SyntaxLanguage::Tlaplus => (
            tree_sitter_tlaplus::LANGUAGE.into(),
            "tree-sitter-tlaplus/1.5.0",
        ),
    }
}

pub(crate) fn version(language: SyntaxLanguage) -> String {
    format!("{RUNTIME}/{}/syntax/1", grammar(language).1)
}

pub(crate) struct CompiledSyntax {
    language: SyntaxLanguage,
    grammar: Language,
    query: Query,
    query_sha256: String,
}

impl CompiledSyntax {
    pub(crate) fn python_constant_string(
        source: &str,
        limits: &SyntaxLimits,
    ) -> Result<Self, String> {
        let compiled = Self::new(SyntaxLanguage::Python, source, limits)?;
        if !["scope", "value"]
            .iter()
            .all(|name| compiled.query.capture_names().contains(name))
        {
            return Err("Python constant-string queries require @scope and @value captures".into());
        }
        Ok(compiled)
    }

    pub(crate) fn constant_string(
        &self,
        bytes: &[u8],
        pointer: Option<&str>,
        limits: &SyntaxLimits,
    ) -> Result<(ResultState, Value), (ResultState, String)> {
        let observation = self
            .observe(
                bytes,
                pointer,
                limits,
                |root, text, captures, budget, interrupted| {
                    crate::python_value::observe(root, text, captures, budget, interrupted)
                        .map(Some)
                },
            )
            .map_err(|reason| (ResultState::NotEvaluated, reason))?;
        let proven = observation.pointer("/fields/constant_string/proven") == Some(&json!(true));
        Ok((
            if proven {
                ResultState::Pass
            } else {
                ResultState::NotEvaluated
            },
            observation,
        ))
    }

    pub(crate) fn new(
        language: SyntaxLanguage,
        source: &str,
        limits: &SyntaxLimits,
    ) -> Result<Self, String> {
        if source.trim().is_empty()
            || limits.input_bytes == 0
            || limits.nodes == 0
            || limits.captures == 0
            || limits.output_bytes == 0
            || limits.timeout_ms == 0
            || limits.match_limit == 0
            || limits.match_limit > 65_536
        {
            return Err("syntax requires a nonempty query and positive limits; match_limit must be 1..=65536".into());
        }
        let grammar = grammar(language).0;
        // Check ABI compatibility at installation, before scan execution.
        Parser::new()
            .set_language(&grammar)
            .map_err(|e| e.to_string())?;
        let query =
            Query::new(&grammar, source).map_err(|e| format!("invalid syntax query: {e}"))?;
        if query.capture_names().is_empty() {
            return Err("syntax query requires named captures".into());
        }
        for index in 0..query.pattern_count() {
            if !query.general_predicates(index).is_empty()
                || !query.property_predicates(index).is_empty()
                || !query.property_settings(index).is_empty()
            {
                return Err("syntax query has unsupported predicates or directives; only built-in text predicates are supported".into());
            }
        }
        Ok(Self {
            language,
            grammar,
            query,
            query_sha256: sha256(source.as_bytes()),
        })
    }

    pub(crate) fn evaluate(
        &self,
        bytes: &[u8],
        pointer: Option<&str>,
        limits: &SyntaxLimits,
    ) -> Result<(ResultState, Value), (ResultState, String)> {
        self.observe(bytes, pointer, limits, |_, _, _, _, _| Ok(None))
            .map(|observation| (ResultState::NotEvaluated, observation))
            .map_err(|reason| (ResultState::NotEvaluated, reason))
    }

    pub(crate) fn relation(
        &self,
        bytes: &[u8],
        pointer: &str,
        operator_pointer: &str,
        predicate: &crate::schema::TlaplusPredicate,
        fail_when: bool,
        limits: &SyntaxLimits,
    ) -> Result<(ResultState, Value), (ResultState, String)> {
        let frame: Value = json::parse(bytes).map_err(|e| (ResultState::Error, e))?;
        let observation = self
            .observe(
                bytes,
                Some(pointer),
                limits,
                |root, text, _, budget, interrupted| {
                    crate::tlaplus::observe(
                        root,
                        text,
                        &frame,
                        operator_pointer,
                        predicate,
                        budget,
                        interrupted,
                    )
                    .map(Some)
                },
            )
            .map_err(|e| (ResultState::NotEvaluated, e))?;
        let Some(value) = observation
            .pointer("/fields/relation/value")
            .and_then(Value::as_bool)
        else {
            return Err((
                ResultState::NotEvaluated,
                "TLA+ syntax is incomplete; no relation decided".into(),
            ));
        };
        Ok((
            if value == fail_when {
                ResultState::Fail
            } else {
                ResultState::Pass
            },
            observation,
        ))
    }

    fn observe<F>(
        &self,
        bytes: &[u8],
        pointer: Option<&str>,
        limits: &SyntaxLimits,
        extra: F,
    ) -> Result<Value, String>
    where
        F: FnOnce(
            Node<'_>,
            &str,
            &[Value],
            &mut Budget,
            &dyn Fn() -> bool,
        ) -> Result<Option<Value>, String>,
    {
        let frame: Option<Value> = pointer.map(|_| json::parse(bytes)).transpose()?;
        let text = match (pointer, &frame) {
            (Some(pointer), Some(frame)) => frame
                .pointer(pointer)
                .and_then(Value::as_str)
                .ok_or_else(|| format!("syntax source is absent or is not a string: {pointer}"))?,
            _ => std::str::from_utf8(bytes).map_err(|_| "syntax source is not UTF-8")?,
        };
        if !Budget::new(limits.input_bytes).try_allocate(text.len() as u64) {
            return Err("syntax input byte limit exceeded; no partial source parsed".into());
        }
        let started = Instant::now();
        let timeout = Duration::from_millis(limits.timeout_ms);
        let progress = || {
            if started.elapsed() >= timeout {
                ControlFlow::Break(())
            } else {
                ControlFlow::Continue(())
            }
        };
        let mut parser = Parser::new();
        parser
            .set_language(&self.grammar)
            .map_err(|e| e.to_string())?;
        let mut callback = |_: &tree_sitter::ParseState| progress();
        let tree = parser
            .parse_with_options(
                &mut |offset, _| text.as_bytes().get(offset..).unwrap_or_default(),
                None,
                Some(ParseOptions::new().progress_callback(&mut callback)),
            )
            .ok_or("syntax parsing interrupted; no complete result")?;
        let mut nodes = Budget::new(limits.nodes);
        let mut output = Budget::new(limits.output_bytes);
        let mut diagnostics = Vec::new();
        // Traverse the parser's own cursor, including anonymous and zero-width missing nodes.
        let mut cursor = tree.walk();
        loop {
            if progress().is_break() {
                return Err("syntax time limit exceeded".into());
            }
            if !nodes.try_allocate(1) {
                return Err("syntax node limit exceeded".into());
            }
            let node = cursor.node();
            if node.is_error() || node.is_missing() {
                let mut diagnostic = span(node, text, limits.output_bytes)?;
                json::object_mut(&mut diagnostic)?.insert(
                    "diagnostic".into(),
                    json!(if node.is_missing() {
                        "missing"
                    } else {
                        "error"
                    }),
                );
                retain(&mut diagnostics, diagnostic, &mut output)?;
            }
            if cursor.goto_first_child() {
                continue;
            }
            loop {
                if cursor.goto_next_sibling() {
                    break;
                }
                if !cursor.goto_parent() {
                    break;
                }
            }
            if cursor.node() == tree.root_node() {
                break;
            }
        }
        let complete = diagnostics.is_empty() && !tree.root_node().has_error();
        let mut observation = json!({
            "type":"syntax/1", "language":self.language, "runtime":RUNTIME,
            "grammar":grammar(self.language).1, "grammar_abi":self.grammar.abi_version(),
            "query_sha256":self.query_sha256, "selected_sha256":sha256(text.as_bytes()),
            "selected_bytes":text.len(), "json_string_pointer":pointer,
            "span_coordinates":"half-open UTF-8 bytes in selected string",
            "complete":complete, "diagnostics":diagnostics,
            "capability":"syntax query only; no name resolution, execution, data flow or macro expansion",
            "limits":limits, "nodes_visited":nodes.allocated(),
        });
        let observation_fields = json::object_mut(&mut observation)?;
        if complete {
            let mut captures = Vec::new();
            let mut capture_budget = Budget::new(limits.captures);
            let mut query_cursor = QueryCursor::new();
            query_cursor.set_match_limit(limits.match_limit);
            let mut callback = |_: &tree_sitter::QueryCursorState| progress();
            {
                let mut matches = query_cursor.matches_with_options(
                    &self.query,
                    tree.root_node(),
                    text.as_bytes(),
                    QueryCursorOptions::new().progress_callback(&mut callback),
                );
                while let Some(matched) = matches.next() {
                    if progress().is_break() {
                        return Err("syntax query time limit exceeded".into());
                    }
                    for capture in matched.captures() {
                        if !capture_budget.try_allocate(1) {
                            return Err("syntax capture limit exceeded".into());
                        }
                        let mut value = span(capture.node, text, limits.output_bytes)?;
                        let index = usize::try_from(capture.index)
                            .map_err(|_| "capture index exceeds usize")?;
                        let name = self
                            .query
                            .capture_names()
                            .get(index)
                            .ok_or("capture index has no query name")?;
                        let fields = json::object_mut(&mut value)?;
                        fields.insert("capture".into(), json!(name));
                        fields.insert("pattern".into(), json!(matched.pattern_index));
                        fields.insert("match".into(), json!(matched.id()));
                        retain(&mut captures, value, &mut output)?;
                    }
                }
            }
            if progress().is_break() {
                return Err("syntax query time limit exceeded".into());
            }
            if query_cursor.did_exceed_match_limit() {
                return Err("syntax query match limit exceeded; matches may be missing".into());
            }
            let additional = extra(tree.root_node(), text, &captures, &mut nodes, &|| {
                progress().is_break()
            })?;
            observation_fields.insert("fields".into(), json!({"captures":captures}));
            if let Some(relation) = additional {
                let python = relation.get("proven").is_some();
                observation_fields.insert(
                    "type".into(),
                    json!(if python {
                        "python-constant-string/1"
                    } else {
                        "tlaplus-relation/1"
                    }),
                );
                let fields = observation_fields
                    .get_mut("fields")
                    .ok_or("syntax output lacks capture fields")?;
                json::object_mut(fields)?.insert(
                    if python {
                        "constant_string"
                    } else {
                        "relation"
                    }
                    .into(),
                    relation,
                );
                observation_fields.insert("capability".into(), json!(
                    if python { "bounded ordinary-Python string-origin interpretation; no general execution, import resolution or runtime proof" } else { "written zero-argument operator relationship only; no definition expansion, imported name resolution or proof checking" }
                ));
                observation_fields.insert("nodes_visited".into(), json!(nodes.allocated()));
                observation_fields.insert("reason".into(), json!(
                    if python { "only proved source-authored string values pass; unsupported paths remain unresolved" } else { "local written relationship only; no proof or semantic name-resolution claim" }
                ));
            } else {
                observation_fields.insert("reason".into(), json!(
                    "syntax evidence only; a complete query is not a policy decision or complete language analysis"
                ));
            }
            observation_fields.insert(
                "captures_retained".into(),
                json!(capture_budget.allocated()),
            );
        } else {
            observation_fields.insert(
                "reason".into(),
                json!(
                    "syntax contains error or missing nodes; no complete capture fields supplied"
                ),
            );
        }
        // Include envelope overhead in the same canonical output allowance.
        let size = serde_json::to_vec(&observation)
            .map_err(|e| e.to_string())?
            .len() as u64;
        let overhead = size
            .checked_sub(output.allocated())
            .ok_or("syntax output accounting mismatch")?;
        if !output.try_allocate(overhead) {
            return Err("syntax output byte limit exceeded".into());
        }
        Ok(observation)
    }
}

pub(crate) fn span(node: Node<'_>, text: &str, limit: u64) -> Result<Value, String> {
    let range = node.byte_range();
    if !Budget::new(limit).try_allocate(range.len() as u64) {
        return Err("syntax capture/diagnostic exceeds output byte limit".into());
    }
    let quote = text
        .get(range.clone())
        .ok_or("syntax span is not on UTF-8 boundaries")?;
    Ok(json!({"node":node.kind(), "start_byte":range.start, "end_byte":range.end, "text":quote}))
}

fn retain(values: &mut Vec<Value>, value: Value, budget: &mut Budget) -> Result<(), String> {
    let size = serde_json::to_vec(&value).map_err(|e| e.to_string())?.len() as u64;
    if !budget.try_allocate(size) {
        return Err("syntax output byte limit exceeded".into());
    }
    values.push(value);
    Ok(())
}
