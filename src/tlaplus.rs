//! Pure predicates on the installed TLA+ parser's tree. No proof or name resolution.
use crate::{schema::TlaplusPredicate, syntax::span};
use automation_structures::Budget;
use serde_json::{Value, json};
use tree_sitter::Node;

struct Work<'a> {
    budget: &'a mut Budget,
    interrupted: &'a dyn Fn() -> bool,
}

impl Work<'_> {
    fn step(&mut self) -> Result<(), String> {
        if (self.interrupted)() {
            return Err("TLA+ relation time limit exceeded".into());
        }
        if !self.budget.try_allocate(1) {
            return Err("TLA+ relation node limit exceeded".into());
        }
        Ok(())
    }

    fn unparenthesize<'tree>(&mut self, mut node: Node<'tree>) -> Result<Node<'tree>, String> {
        loop {
            self.step()?;
            if node.kind() != "parentheses" {
                return Ok(node);
            }
            let mut cursor = node.walk();
            let mut children = node.named_children(&mut cursor).filter(|n| !n.is_extra());
            node = children
                .next()
                .ok_or("parenthesized expression has no body")?;
            if children.next().is_some() {
                return Err("ambiguous parenthesized expression".into());
            }
        }
    }

    fn positive_path(&mut self, mut node: Node<'_>, body: Node<'_>) -> Result<bool, String> {
        while node != body {
            self.step()?;
            let Some(parent) = node.parent() else {
                return Ok(false);
            };
            let allowed = match parent.kind() {
                "parentheses" | "conj_item" | "conj_list" => true,
                "bound_infix_op" => parent
                    .child_by_field_name("symbol")
                    .is_some_and(|n| n.kind() == "land"),
                _ => false,
            };
            if !allowed {
                return Ok(false);
            }
            node = parent;
        }
        Ok(true)
    }

    fn conjunct<'tree>(
        &mut self,
        body: Node<'tree>,
        text: &str,
        reference: &str,
    ) -> Result<Option<Node<'tree>>, String> {
        let mut cursor = body.walk();
        loop {
            self.step()?;
            let node = cursor.node();
            if named_reference(node, text, reference) && self.positive_path(node, body)? {
                return Ok(Some(node));
            }
            if cursor.goto_first_child() {
                continue;
            }
            loop {
                if cursor.goto_next_sibling() {
                    break;
                }
                if !cursor.goto_parent() {
                    return Ok(None);
                }
            }
        }
    }
}

fn operand<'a>(frame: &'a Value, pointer: &str) -> Result<&'a str, String> {
    let name = frame
        .pointer(pointer)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("required TLA+ name is absent or not a string: {pointer}"))?;
    if name.is_empty()
        || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        || !name.bytes().any(|b| b.is_ascii_alphabetic() || b == b'_')
    {
        return Err(format!(
            "TLA+ relation requires a simple ASCII name: {pointer}"
        ));
    }
    Ok(name)
}

fn named_reference(node: Node<'_>, text: &str, name: &str) -> bool {
    node.kind() == "identifier_ref" && text.get(node.byte_range()) == Some(name)
}

pub(crate) fn observe(
    root: Node<'_>,
    text: &str,
    frame: &Value,
    operator_pointer: &str,
    predicate: &TlaplusPredicate,
    budget: &mut Budget,
    interrupted: &dyn Fn() -> bool,
) -> Result<Value, String> {
    let mut work = Work {
        budget,
        interrupted,
    };
    let operator = operand(frame, operator_pointer)?;
    let mut cursor = root.walk();
    let mut modules = root
        .named_children(&mut cursor)
        .filter(|n| n.kind() == "module");
    let module = modules
        .next()
        .ok_or("TLA+ relation requires one outer module")?;
    if modules.next().is_some() {
        return Err("multiple outer modules are ambiguous".into());
    }
    let mut cursor = module.walk();
    let mut selected = None;
    for node in module.named_children(&mut cursor) {
        work.step()?;
        if node.kind() != "operator_definition" {
            continue;
        }
        let Some(name) = node.child_by_field_name("name") else {
            continue;
        };
        if name.kind() != "identifier" || text.get(name.byte_range()) != Some(operator) {
            continue;
        }
        if selected.replace(node).is_some() {
            return Err("duplicate selected operator definitions".into());
        }
    }
    let definition = selected.ok_or("selected top-level operator definition is absent")?;
    let mut fields = definition.walk();
    if definition
        .children_by_field_name("parameter", &mut fields)
        .next()
        .is_some()
    {
        return Err("parameterized operator relationship is unsupported".into());
    }
    let body = definition
        .child_by_field_name("definition")
        .ok_or("operator body is absent")?;
    let (witness, operands) = match predicate {
        TlaplusPredicate::DirectAlias { reference_pointer } => {
            let reference = operand(frame, reference_pointer)?;
            let expression = work.unparenthesize(body)?;
            (
                named_reference(expression, text, reference).then_some(expression),
                json!({"reference":reference}),
            )
        }
        TlaplusPredicate::PositiveConjunct { reference_pointer } => {
            let reference = operand(frame, reference_pointer)?;
            (
                work.conjunct(body, text, reference)?,
                json!({"reference":reference}),
            )
        }
        TlaplusPredicate::WeakFairness {
            action_pointer,
            subscript_pointer,
        } => {
            let action = operand(frame, action_pointer)?;
            let subscript = operand(frame, subscript_pointer)?;
            let expression = work.unparenthesize(body)?;
            let witness = if expression.kind() != "fairness"
                || expression.child(0).is_none_or(|n| n.kind() != "WF_")
            {
                None
            } else {
                let mut cursor = expression.walk();
                let mut operands = expression
                    .named_children(&mut cursor)
                    .filter(|n| !n.is_extra());
                let sub = operands.next().ok_or("fairness subscript absent")?;
                let act = operands.next().ok_or("fairness action absent")?;
                if operands.next().is_some() {
                    return Err("unexpected fairness operands".into());
                }
                (named_reference(work.unparenthesize(sub)?, text, subscript)
                    && named_reference(work.unparenthesize(act)?, text, action))
                .then_some(expression)
            };
            (witness, json!({"action":action,"subscript":subscript}))
        }
    };
    Ok(
        json!({"value":witness.is_some(), "operator":operator, "predicate":predicate, "operands":operands,
        "definition":span(definition, text, text.len() as u64)?,
        "witness":witness.map(|n| span(n, text, text.len() as u64)).transpose()?,
        "scope":"one written zero-argument top-level definition; references are compared by spelling, not resolved"}),
    )
}
