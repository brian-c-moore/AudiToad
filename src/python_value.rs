//! A conservative source-content predicate over ordinary Python syntax.
//! It proves only that selected values contain source-authored string content.
//! Python imports, arbitrary execution, reflection and library behavior are not modeled.
use automation_structures::Budget;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use tree_sitter::Node;

#[derive(Clone, Debug)]
enum Atom<'a> {
    Unknown,
    String(Option<&'a str>),
    Integer(i64),
    Boolean(bool),
    List(Vec<Self>),
}

type State<'a> = BTreeMap<&'a str, Atom<'a>>;
type Span = (usize, usize);

#[derive(Default)]
struct Selected<'a> {
    visited: bool,
    proven: bool,
    constant: Option<&'a str>,
}

struct Work<'a> {
    text: &'a str,
    budget: &'a mut Budget,
    interrupted: &'a dyn Fn() -> bool,
    selected: BTreeMap<Span, Selected<'a>>,
}

impl<'a> Work<'a> {
    fn step(&mut self, depth: u16) -> Result<(), String> {
        if (self.interrupted)() {
            return Err("Python constant-string time limit exceeded".into());
        }
        if depth > 128 || !self.budget.try_allocate(1) {
            return Err("Python constant-string traversal limit exceeded".into());
        }
        Ok(())
    }

    fn text(&self, node: Node<'_>) -> &'a str {
        self.text.get(node.byte_range()).unwrap_or_default()
    }

    fn copy_state(&mut self, state: &State<'a>) -> Result<State<'a>, String> {
        for value in state.values() {
            let size = match value {
                Atom::List(items) => items.len().saturating_add(1),
                _ => 1,
            };
            if !self.budget.try_allocate(size as u64) {
                return Err("Python constant-string state-copy limit exceeded".into());
            }
        }
        Ok(state.clone())
    }

    #[expect(
        clippy::arithmetic_side_effects,
        reason = "step refuses depth above 128 before recursive increments"
    )]
    fn expression(
        &mut self,
        node: Node<'_>,
        state: &mut State<'a>,
        depth: u16,
    ) -> Result<Atom<'a>, String> {
        self.step(depth)?;
        let value = match node.kind() {
            "identifier" => {
                let value = state.get(self.text(node)).cloned().unwrap_or(Atom::Unknown);
                if let Atom::List(items) = &value
                    && !self.budget.try_allocate(items.len() as u64)
                {
                    return Err("Python constant-string list-copy limit exceeded".into());
                }
                value
            }
            "integer" => self
                .text(node)
                .replace('_', "")
                .parse()
                .map(Atom::Integer)
                .unwrap_or(Atom::Unknown),
            "true" => Atom::Boolean(true),
            "false" => Atom::Boolean(false),
            "string" => {
                let source = self.text(node);
                let Some(quote) = source.find(['\'', '"']) else {
                    return Ok(Atom::Unknown);
                };
                let prefix = source.get(..quote).unwrap_or_default().to_ascii_lowercase();
                if prefix.contains('b') {
                    return Ok(Atom::Unknown);
                }
                let mut cursor = node.walk();
                let interpolations: Vec<_> = node
                    .named_children(&mut cursor)
                    .filter(|n| n.kind() == "interpolation")
                    .collect();
                if interpolations.is_empty() {
                    let tail = source.get(quote..).unwrap_or_default();
                    let delimiter = if tail.starts_with("\"\"\"") || tail.starts_with("'''") {
                        3
                    } else {
                        1
                    };
                    let content =
                        source.get(quote + delimiter..source.len().saturating_sub(delimiter));
                    Atom::String(content.filter(|s| !s.contains('\\') && !prefix.contains('f')))
                } else {
                    let mut constant = true;
                    for interpolation in interpolations {
                        let Some(expression) = interpolation.child_by_field_name("expression")
                        else {
                            constant = false;
                            continue;
                        };
                        constant &= matches!(
                            self.expression(expression, state, depth + 1)?,
                            Atom::String(_) | Atom::Integer(_) | Atom::Boolean(_)
                        );
                        // Dynamic format specifications are outside this bounded profile.
                        constant &= interpolation
                            .child_by_field_name("format_specifier")
                            .is_none();
                    }
                    if constant {
                        Atom::String(None)
                    } else {
                        invalidate(state);
                        Atom::Unknown
                    }
                }
            }
            "concatenated_string" => {
                let mut cursor = node.walk();
                let mut constant = true;
                for child in node.named_children(&mut cursor).filter(|n| !n.is_extra()) {
                    constant &=
                        matches!(self.expression(child, state, depth + 1)?, Atom::String(_));
                }
                if constant {
                    Atom::String(None)
                } else {
                    Atom::Unknown
                }
            }
            "parenthesized_expression" => {
                let mut cursor = node.walk();
                let mut children = node.named_children(&mut cursor).filter(|n| !n.is_extra());
                match (children.next(), children.next()) {
                    (Some(child), None) => self.expression(child, state, depth + 1)?,
                    _ => Atom::Unknown,
                }
            }
            "list" => {
                let mut cursor = node.walk();
                let mut items = Vec::new();
                for child in node.named_children(&mut cursor).filter(|n| !n.is_extra()) {
                    let value = self.expression(child, state, depth + 1)?;
                    // Nested mutable containers and their aliases are not modeled.
                    items.push(if matches!(value, Atom::List(_)) {
                        Atom::Unknown
                    } else {
                        value
                    });
                }
                Atom::List(items)
            }
            "subscript" => {
                let object = node.child_by_field_name("value");
                let index = node.child_by_field_name("subscript");
                match (object, index) {
                    (Some(object), Some(index)) => {
                        let value = self.expression(object, state, depth + 1)?;
                        let index = self.expression(index, state, depth + 1)?;
                        match (value, index) {
                            (Atom::List(items), Atom::Integer(index)) => {
                                position(index, items.len())
                                    .and_then(|i| items.get(i).cloned())
                                    .unwrap_or(Atom::Unknown)
                            }
                            (Atom::String(Some(value)), Atom::Integer(index))
                                if position(index, value.chars().count()).is_some() =>
                            {
                                Atom::String(None)
                            }
                            _ => {
                                invalidate(state);
                                Atom::Unknown
                            }
                        }
                    }
                    _ => Atom::Unknown,
                }
            }
            "binary_operator" => {
                let left = node.child_by_field_name("left");
                let right = node.child_by_field_name("right");
                let operator = node.child_by_field_name("operator").map(|n| self.text(n));
                match (left, right) {
                    (Some(left), Some(right)) => {
                        let left = self.expression(left, state, depth + 1)?;
                        let right = self.expression(right, state, depth + 1)?;
                        match (left, operator, right) {
                            (Atom::String(_), Some("+"), Atom::String(_)) => Atom::String(None),
                            (Atom::Integer(a), Some("+"), Atom::Integer(b)) => {
                                a.checked_add(b).map(Atom::Integer).unwrap_or(Atom::Unknown)
                            }
                            (Atom::Integer(a), Some("-"), Atom::Integer(b)) => {
                                a.checked_sub(b).map(Atom::Integer).unwrap_or(Atom::Unknown)
                            }
                            _ => {
                                invalidate(state);
                                Atom::Unknown
                            }
                        }
                    }
                    _ => {
                        invalidate(state);
                        Atom::Unknown
                    }
                }
            }
            "unary_operator" => {
                let argument = node.child_by_field_name("argument");
                match (
                    node.child_by_field_name("operator").map(|n| self.text(n)),
                    argument,
                ) {
                    (Some("-"), Some(argument)) => {
                        match self.expression(argument, state, depth + 1)? {
                            Atom::Integer(value) => value
                                .checked_neg()
                                .map(Atom::Integer)
                                .unwrap_or(Atom::Unknown),
                            _ => {
                                invalidate(state);
                                Atom::Unknown
                            }
                        }
                    }
                    (Some("not"), Some(argument)) => {
                        match truth(&self.expression(argument, state, depth + 1)?) {
                            Some(value) => Atom::Boolean(!value),
                            None => {
                                invalidate(state);
                                Atom::Unknown
                            }
                        }
                    }
                    _ => {
                        invalidate(state);
                        Atom::Unknown
                    }
                }
            }
            "call" => self.call(node, state, depth + 1)?,
            "keyword_argument" => {
                if let Some(value) = node.child_by_field_name("value") {
                    self.expression(value, state, depth + 1)?;
                }
                Atom::Unknown
            }
            _ => {
                invalidate(state);
                Atom::Unknown
            }
        };
        if let Some(selected) = self.selected.get_mut(&(node.start_byte(), node.end_byte())) {
            let proven = matches!(value, Atom::String(_));
            let constant = match &value {
                Atom::String(Some(value)) => Some(*value),
                _ => None,
            };
            selected.constant = if selected.visited {
                selected
                    .constant
                    .filter(|previous| Some(*previous) == constant)
            } else {
                constant
            };
            selected.proven = if selected.visited {
                selected.proven && proven
            } else {
                proven
            };
            selected.visited = true;
        }
        Ok(value)
    }

    #[expect(
        clippy::arithmetic_side_effects,
        reason = "step refuses depth above 128 before recursive increments"
    )]
    fn call(
        &mut self,
        node: Node<'_>,
        state: &mut State<'a>,
        depth: u16,
    ) -> Result<Atom<'a>, String> {
        self.step(depth)?;
        let Some(function) = node.child_by_field_name("function") else {
            return Ok(Atom::Unknown);
        };
        let known_list_method = function.kind() == "attribute"
            && function
                .child_by_field_name("object")
                .is_some_and(|object| {
                    object.kind() == "identifier"
                        && matches!(state.get(self.text(object)), Some(Atom::List(_)))
                })
            && function
                .child_by_field_name("attribute")
                .is_some_and(|method| matches!(self.text(method), "append" | "pop" | "copy"));
        if function.kind() != "identifier" && !known_list_method {
            // Python evaluates the receiver/callable before its arguments. Arbitrary
            // attribute hooks and computed callables may change reaching state first.
            invalidate(state);
        }
        let mut arguments = Vec::new();
        if let Some(list) = node.child_by_field_name("arguments") {
            let mut cursor = list.walk();
            for argument in list.named_children(&mut cursor).filter(|n| !n.is_extra()) {
                arguments.push(self.expression(argument, state, depth + 1)?);
            }
        }
        if function.kind() == "attribute"
            && let (Some(object), Some(method)) = (
                function.child_by_field_name("object"),
                function.child_by_field_name("attribute"),
            )
            && object.kind() == "identifier"
        {
            let name = self.text(object);
            if let Some(Atom::List(items)) = state.get_mut(name) {
                match (self.text(method), arguments.as_slice()) {
                    ("append", [value]) if !matches!(value, Atom::List(_)) => {
                        items.push(value.clone());
                        return Ok(Atom::Unknown);
                    }
                    ("pop", []) => return Ok(items.pop().unwrap_or(Atom::Unknown)),
                    ("pop", [Atom::Integer(index)]) => {
                        return Ok(position(*index, items.len())
                            .map(|i| items.remove(i))
                            .unwrap_or(Atom::Unknown));
                    }
                    ("copy", []) => {
                        if !self.budget.try_allocate(items.len() as u64) {
                            return Err("Python constant-string list-copy limit exceeded".into());
                        }
                        return Ok(Atom::List(items.clone()));
                    }
                    _ => {}
                }
            }
        }
        // Unknown calls may enter closures or mutate aliases. No state survives by
        // assuming that a function name or receiver implies harmless behavior.
        invalidate(state);
        Ok(Atom::Unknown)
    }

    #[expect(
        clippy::arithmetic_side_effects,
        reason = "step refuses depth above 128 before recursive increments"
    )]
    fn block(&mut self, node: Node<'_>, state: &mut State<'a>, depth: u16) -> Result<bool, String> {
        self.step(depth)?;
        let mut cursor = node.walk();
        for statement in node.named_children(&mut cursor).filter(|n| !n.is_extra()) {
            self.step(depth)?;
            match statement.kind() {
                "expression_statement" => {
                    let mut cursor = statement.walk();
                    for expression in statement
                        .named_children(&mut cursor)
                        .filter(|n| !n.is_extra())
                    {
                        match expression.kind() {
                            "assignment" | "augmented_assignment" => {
                                self.assign(expression, state, depth + 1)?
                            }
                            _ => {
                                self.expression(expression, state, depth + 1)?;
                            }
                        }
                    }
                }
                "return_statement" => {
                    let mut cursor = statement.walk();
                    for expression in statement
                        .named_children(&mut cursor)
                        .filter(|n| !n.is_extra())
                    {
                        self.expression(expression, state, depth + 1)?;
                    }
                    return Ok(false);
                }
                "if_statement" => {
                    let Some(condition) = statement.child_by_field_name("condition") else {
                        invalidate(state);
                        continue;
                    };
                    let value = self.expression(condition, state, depth + 1)?;
                    let Some(consequence) = statement.child_by_field_name("consequence") else {
                        invalidate(state);
                        continue;
                    };
                    let alternative = statement.child_by_field_name("alternative");
                    match truth(&value) {
                        Some(true) => {
                            if !self.block(consequence, state, depth + 1)? {
                                return Ok(false);
                            }
                        }
                        Some(false) => {
                            if let Some(alternative) = alternative
                                && !self.alternative(alternative, state, depth + 1)?
                            {
                                return Ok(false);
                            }
                        }
                        None => {
                            // Unknown truthiness can execute user code and mutate retained
                            // values. Only explicit assignments within each branch recover it.
                            invalidate(state);
                            let mut left = self.copy_state(state)?;
                            let mut right = self.copy_state(state)?;
                            let left_continues = self.block(consequence, &mut left, depth + 1)?;
                            let right_continues = if let Some(alternative) = alternative {
                                self.alternative(alternative, &mut right, depth + 1)?
                            } else {
                                true
                            };
                            match (left_continues, right_continues) {
                                (false, false) => return Ok(false),
                                (true, false) => *state = left,
                                (false, true) => *state = right,
                                (true, true) => {
                                    for (name, value) in &mut left {
                                        *value =
                                            join(value, right.get(name).unwrap_or(&Atom::Unknown));
                                    }
                                    for name in right.keys() {
                                        left.entry(name).or_insert(Atom::Unknown);
                                    }
                                    *state = left;
                                }
                            }
                        }
                    }
                }
                "function_definition" => {
                    // The body does not execute here; an unknown subsequent call invalidates
                    // state, including any value a nonlocal closure might have changed.
                    if let Some(name) = statement.child_by_field_name("name") {
                        state.insert(self.text(name), Atom::Unknown);
                    }
                    let parameters = statement.child_by_field_name("parameters");
                    if statement.child_by_field_name("return_type").is_some()
                        || parameters.is_some_and(|parameters| {
                            let mut cursor = parameters.walk();
                            parameters.named_children(&mut cursor).any(|child| {
                                !matches!(
                                    child.kind(),
                                    "identifier"
                                        | "list_splat_pattern"
                                        | "dictionary_splat_pattern"
                                )
                            })
                        })
                    {
                        invalidate(state);
                    }
                }
                "import_statement" | "import_from_statement" => {
                    // Imports may execute code and overwrite names, including star imports.
                    invalidate(state);
                }
                "pass_statement" => {}
                _ => {
                    // Loops, try/with, global/nonlocal, deletion and unsupported mutation
                    // can change reaching state. Preserve a possible continuing path
                    // with unknown values; this is not evidence of a return.
                    invalidate(state);
                    return Ok(true);
                }
            }
        }
        Ok(true)
    }

    #[expect(
        clippy::arithmetic_side_effects,
        reason = "step refuses depth above 128 before recursive increments"
    )]
    fn alternative(
        &mut self,
        node: Node<'_>,
        state: &mut State<'a>,
        depth: u16,
    ) -> Result<bool, String> {
        self.step(depth)?;
        if node.kind() == "else_clause"
            && let Some(body) = node.child_by_field_name("body")
        {
            return self.block(body, state, depth + 1);
        }
        // An unsupported alternative may continue with changed values.
        invalidate(state);
        Ok(true)
    }

    #[expect(
        clippy::arithmetic_side_effects,
        reason = "step refuses depth above 128 before recursive increments"
    )]
    fn assign(&mut self, node: Node<'_>, state: &mut State<'a>, depth: u16) -> Result<(), String> {
        self.step(depth)?;
        let (Some(left), Some(right)) = (
            node.child_by_field_name("left"),
            node.child_by_field_name("right"),
        ) else {
            invalidate(state);
            return Ok(());
        };
        let mut value = self.expression(right, state, depth + 1)?;
        if left.kind() != "identifier" {
            invalidate(state);
            return Ok(());
        }
        let name = self.text(left);
        if node.kind() == "augmented_assignment" {
            value = match (
                state.get(name),
                node.child_by_field_name("operator").map(|n| self.text(n)),
                value,
            ) {
                (Some(Atom::String(_)), Some("+="), Atom::String(_)) => Atom::String(None),
                _ => Atom::Unknown,
            };
        } else if right.kind() == "identifier" && matches!(value, Atom::List(_)) {
            // Assignment copies list references, not containers. Refuse both aliases.
            state.insert(self.text(right), Atom::Unknown);
            value = Atom::Unknown;
        }
        state.insert(name, value);
        Ok(())
    }
}

fn invalidate(state: &mut State<'_>) {
    state.values_mut().for_each(|value| *value = Atom::Unknown);
}

fn position(index: i64, length: usize) -> Option<usize> {
    let length = i64::try_from(length).ok()?;
    let index = if index < 0 {
        length.checked_add(index)?
    } else {
        index
    };
    (index >= 0 && index < length)
        .then(|| usize::try_from(index).ok())
        .flatten()
}

fn truth(value: &Atom<'_>) -> Option<bool> {
    match value {
        Atom::Boolean(value) => Some(*value),
        Atom::Integer(value) => Some(*value != 0),
        Atom::String(Some(value)) => Some(!value.is_empty()),
        Atom::List(value) => Some(!value.is_empty()),
        _ => None,
    }
}

fn join<'a>(left: &Atom<'a>, right: &Atom<'a>) -> Atom<'a> {
    match (left, right) {
        (Atom::String(a), Atom::String(b)) => Atom::String(if a == b { *a } else { None }),
        (Atom::Integer(a), Atom::Integer(b)) if a == b => Atom::Integer(*a),
        (Atom::Boolean(a), Atom::Boolean(b)) if a == b => Atom::Boolean(*a),
        // Mutable-container branch joins remain unsupported.
        _ => Atom::Unknown,
    }
}

pub(crate) fn observe(
    root: Node<'_>,
    text: &str,
    captures: &[Value],
    budget: &mut Budget,
    interrupted: &dyn Fn() -> bool,
) -> Result<Value, String> {
    let mut scopes = BTreeSet::new();
    let mut targets = BTreeSet::new();
    for capture in captures {
        let name = capture.get("capture").and_then(Value::as_str);
        if !matches!(name, Some("scope" | "value")) {
            continue;
        }
        let start = capture
            .get("start_byte")
            .and_then(Value::as_u64)
            .and_then(|v| usize::try_from(v).ok());
        let end = capture
            .get("end_byte")
            .and_then(Value::as_u64)
            .and_then(|v| usize::try_from(v).ok());
        let (Some(start), Some(end)) = (start, end) else {
            return Err("Python capture span is malformed".into());
        };
        if name == Some("scope") {
            scopes.insert((start, end));
        } else {
            targets.insert((start, end));
        }
    }
    let unknown = |reason: &str| json!({"proven":false,"reason":reason});
    if scopes.len() != 1 || targets.is_empty() {
        return Ok(unknown(
            "requires one unique function scope and at least one selected value",
        ));
    }
    let &(start, end) = scopes.first().ok_or("selected scope is absent")?;
    let Some(scope) = root.descendant_for_byte_range(start, end) else {
        return Ok(unknown("selected function scope is absent"));
    };
    if scope.kind() != "function_definition"
        || scope.start_byte() != start
        || scope.end_byte() != end
    {
        return Ok(unknown(
            "scope capture must be one complete function definition",
        ));
    }
    let mut work = Work {
        text,
        budget,
        interrupted,
        selected: targets
            .iter()
            .map(|span| (*span, Selected::default()))
            .collect(),
    };
    for &(start, end) in &targets {
        let Some(mut node) = root.descendant_for_byte_range(start, end) else {
            return Ok(unknown("selected value is absent"));
        };
        if node.start_byte() != start || node.end_byte() != end {
            return Ok(unknown("value capture must be a complete expression"));
        }
        loop {
            work.step(0)?;
            let Some(parent) = node.parent() else {
                return Ok(unknown("selected value is outside the function scope"));
            };
            if parent.kind() == "function_definition" {
                if parent != scope {
                    return Ok(unknown(
                        "selected value belongs to another or nested function",
                    ));
                }
                break;
            }
            node = parent;
        }
    }
    let Some(body) = scope.child_by_field_name("body") else {
        return Ok(unknown("function body is absent"));
    };
    work.block(body, &mut State::new(), 0)?;
    let proven = work
        .selected
        .values()
        .all(|value| value.visited && value.proven);
    let values = work
        .selected
        .iter()
        .map(|(&(start, end), value)| {
            json!({
                "start_byte":start,"end_byte":end,
                "expression":text.get(start..end),
                "proven":value.visited && value.proven,
                "source_authored":value.visited && value.proven,
                "constant":value.constant,
            })
        })
        .collect::<Vec<_>>();
    Ok(
        json!({"proven":proven,"values":values,"selected_values":work.selected.len(),"visited_values":work.selected.values().filter(|v| v.visited).count(),"reason":if proven { "all selected reaching values contain source-authored string content under the bounded ordinary-Python profile" } else { "a selected value is unvisited, unsupported or can contain unresolved content" }}),
    )
}
