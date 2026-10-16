//! Exact command-line interpretation: Windows argument tokenization, declared program
//! grammars and cmd.exe's documented /C remainder rule. Programs and options are baseline
//! content; this module neither executes nor decodes commands.
use crate::{json, schema::*, source::sha256};
use automation_structures::Budget;
use serde_json::{Value, json};

pub(crate) const VERSION: &str = "1/windows-argv/cmd-c";
const MAX_DEPTH: usize = 8;

struct Token {
    text: String,
    start: usize,
}

fn advance(position: usize, count: usize) -> Result<usize, String> {
    position
        .checked_add(count)
        .ok_or_else(|| "command position overflows".into())
}

/// Program name: a quoted name ends at the next quote, otherwise at whitespace.
/// Remaining arguments follow the Microsoft C runtime rules, including `""` inside quotes.
#[expect(
    clippy::integer_division,
    reason = "Microsoft argv grammar emits one backslash per pair; an odd remainder escapes the quote"
)]
fn tokenize(line: &str) -> Result<Vec<Token>, String> {
    let chars: Vec<(usize, char)> = line.char_indices().collect();
    let at = |i: usize| chars.get(i).map(|&(_, c)| c);
    let offset = |i: usize| chars.get(i).map_or(line.len(), |&(o, _)| o);
    let mut tokens = Vec::new();
    let mut i = 0;
    while at(i).is_some_and(char::is_whitespace) {
        i = advance(i, 1)?;
    }
    if at(i).is_none() {
        return Ok(tokens);
    }
    let start = i;
    let mut name = String::new();
    if at(i) == Some('"') {
        i = advance(i, 1)?;
        while let Some(c) = at(i).filter(|&c| c != '"') {
            name.push(c);
            i = advance(i, 1)?;
        }
        if at(i).is_some() {
            i = advance(i, 1)?;
        }
    } else {
        while let Some(c) = at(i).filter(|c| !c.is_whitespace()) {
            name.push(c);
            i = advance(i, 1)?;
        }
    }
    tokens.push(Token {
        text: name,
        start: offset(start),
    });
    loop {
        while at(i).is_some_and(char::is_whitespace) {
            i = advance(i, 1)?;
        }
        if at(i).is_none() {
            return Ok(tokens);
        }
        let start = i;
        let mut text = String::new();
        let mut quoted = false;
        while let Some(c) = at(i) {
            if c.is_whitespace() && !quoted {
                break;
            }
            if c == '\\' {
                let mut run = 0;
                while at(advance(i, run)?) == Some('\\') {
                    run = advance(run, 1)?;
                }
                let end = advance(i, run)?;
                if at(end) == Some('"') {
                    text.extend(std::iter::repeat_n('\\', run / 2));
                    if run % 2 == 1 {
                        text.push('"');
                        i = advance(end, 1)?;
                    } else {
                        i = end;
                    }
                } else {
                    text.extend(std::iter::repeat_n('\\', run));
                    i = end;
                }
                continue;
            }
            if c == '"' {
                if quoted && at(advance(i, 1)?) == Some('"') {
                    text.push('"');
                    i = advance(i, 2)?;
                } else {
                    quoted = !quoted;
                    i = advance(i, 1)?;
                }
                continue;
            }
            text.push(c);
            i = advance(i, 1)?;
        }
        tokens.push(Token {
            text,
            start: offset(start),
        });
    }
}

fn executable_name(program: &str) -> String {
    program
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(program)
        .to_lowercase()
}

/// cmd.exe /? documents when quotes around the /C remainder are preserved. Whether the quoted
/// text names an existing executable cannot be checked here; an executable file extension is the
/// declared approximation.
fn cmd_remainder(rest: &str, strip_quotes: bool) -> Result<String, String> {
    let text = rest.trim_start();
    let quotes: Vec<usize> = text.match_indices('"').map(|(i, _)| i).collect();
    if let (false, [first, last]) = (strip_quotes, quotes.as_slice()) {
        let inner = text
            .get(advance(*first, 1)?..*last)
            .ok_or("cmd quote boundaries are invalid")?;
        let lower = inner.to_lowercase();
        if !inner.contains(['&', '<', '>', '(', ')', '@', '^', '|'])
            && inner.contains(char::is_whitespace)
            && [".exe", ".com", ".bat", ".cmd"]
                .iter()
                .any(|extension| lower.ends_with(extension))
        {
            return Ok(text.into());
        }
    }
    Ok(match (text.strip_prefix('"'), text.rfind('"')) {
        (Some(_), Some(last)) if last > 0 => format!(
            "{}{}",
            text.get(1..last)
                .ok_or("cmd opening quote boundary is invalid")?,
            text.get(advance(last, 1)?..)
                .ok_or("cmd closing quote boundary is invalid")?
        ),
        (Some(stripped), _) => stripped.into(),
        _ => text.into(),
    })
}

/// Splits a cmd.exe command on unquoted `&` and `|`, removing `^` escapes outside quotes.
fn cmd_segments(command: &str) -> Vec<String> {
    let mut segments = Vec::new();
    let mut segment = String::new();
    let mut quoted = false;
    let mut chars = command.chars();
    while let Some(c) = chars.next() {
        match c {
            '"' => {
                quoted = !quoted;
                segment.push(c);
            }
            '^' if !quoted => {
                if let Some(next) = chars.next() {
                    segment.push(next);
                }
            }
            '&' | '|' if !quoted => segments.push(std::mem::take(&mut segment)),
            _ => segment.push(c),
        }
    }
    segments.push(segment);
    segments
        .into_iter()
        .map(|s| {
            s.trim()
                .trim_start_matches(['@', '('])
                .trim_end_matches(')')
                .trim()
                .to_string()
        })
        .filter(|s| !s.is_empty())
        .collect()
}

fn option_key<'a>(program: &CommandProgram, arg: &'a str) -> Option<(&'a str, usize)> {
    let first = arg.chars().next()?;
    if !program
        .option_prefixes
        .iter()
        .any(|p| p.chars().eq([first]))
    {
        return None;
    }
    let mut prefix = first.len_utf8();
    if program.repeated_prefix && arg.get(prefix..)?.starts_with(first) {
        prefix = prefix.checked_add(first.len_utf8())?;
    }
    Some((arg.get(prefix..)?, prefix))
}

fn match_option<'a>(
    program: &'a CommandProgram,
    key: &str,
) -> Option<(&'a CommandOption, &'a OptionWord)> {
    let lower = key.to_lowercase();
    program.options.iter().find_map(|option| {
        option
            .matches
            .iter()
            .find(|word| {
                if option.value == CommandValue::CmdCommand {
                    lower.starts_with(&word.word)
                } else {
                    lower.chars().count() >= word.shortest.chars().count()
                        && word.word.starts_with(&lower)
                }
            })
            .map(|word| (option, word))
    })
}

fn interpret(
    line: &str,
    programs: &std::collections::BTreeMap<String, CommandProgram>,
    depth_owner: &mut Budget,
    invocations: &mut Vec<Value>,
) -> Result<(), String> {
    let depth = depth_owner.allocated();
    if !depth_owner.try_allocate(1) {
        return Err(format!("command nesting exceeds {MAX_DEPTH} levels"));
    }
    let result = interpret_content(line, programs, depth, depth_owner, invocations);
    depth_owner.release(1).map_err(|e| e.to_string())?;
    result
}

fn interpret_content(
    line: &str,
    programs: &std::collections::BTreeMap<String, CommandProgram>,
    depth: u64,
    depth_owner: &mut Budget,
    invocations: &mut Vec<Value>,
) -> Result<(), String> {
    let tokens = tokenize(line)?;
    let Some(first) = tokens.first() else {
        return Ok(());
    };
    let executable = executable_name(&first.text);
    let Some((name, program)) = programs
        .iter()
        .find(|(_, p)| p.executables.contains(&executable))
    else {
        return Ok(());
    };
    let mut options = Vec::new();
    let mut remainder = Value::Null;
    let mut nested = Vec::new();
    let mut strip_quotes = false;
    let mut title = program.title_argument;
    let mut index = 1;
    while let Some(token) = tokens.get(index) {
        let raw_rest = line
            .get(token.start..)
            .ok_or("command token source boundary is invalid")?;
        let (value, matched) = match option_key(program, &token.text) {
            Some((key, prefix)) => match match_option(program, key) {
                Some((option, word)) => (
                    option.value,
                    Some((
                        option,
                        word,
                        token
                            .text
                            .get(..advance(prefix, key.len())?)
                            .ok_or("command option boundary is invalid")?,
                        prefix,
                    )),
                ),
                None => (program.unmatched, None),
            },
            None if title && raw_rest.starts_with('"') => {
                title = false;
                (CommandValue::None, None)
            }
            None => (program.positional, None),
        };
        if matched.is_none() && value == program.positional {
            title = false;
        }
        match value {
            CommandValue::Launch => {
                let command = match matched {
                    Some((option, _, text, _)) => {
                        options.push(json!({"option":option.name,"token":text,"value":null}));
                        match tokens.get(advance(index, 1)?) {
                            Some(token) => line
                                .get(token.start..)
                                .ok_or("launch source boundary is invalid")?,
                            None => "",
                        }
                    }
                    None => raw_rest,
                };
                remainder = json!({"launch":command});
                nested.push(command.to_string());
                break;
            }
            CommandValue::None | CommandValue::CmdStripQuotes => {
                if let Some((option, _, text, _)) = matched {
                    options.push(json!({"option":option.name,"token":text,"value":null}));
                }
                strip_quotes |= value == CommandValue::CmdStripQuotes;
                index = advance(index, 1)?;
            }
            CommandValue::Value => {
                let argument = tokens.get(advance(index, 1)?).map(|t| t.text.clone());
                if let Some((option, _, text, _)) = matched {
                    options.push(json!({"option":option.name,"token":text,"value":argument}));
                }
                index = advance(index, 2)?;
            }
            CommandValue::Rest => {
                let (option, arguments) = match matched {
                    Some((option, _, text, _)) => {
                        options.push(json!({"option":option.name,"token":text,"value":null}));
                        (
                            Some(&option.name),
                            tokens
                                .get(advance(index, 1)?..)
                                .ok_or("command remainder is not bound")?,
                        )
                    }
                    None => (
                        None,
                        tokens
                            .get(index..)
                            .ok_or("command remainder is not bound")?,
                    ),
                };
                remainder = json!({"option":option,
                    "arguments":arguments.iter().map(|t| &t.text).collect::<Vec<_>>()});
                break;
            }
            CommandValue::CmdCommand => {
                let (option, word, text, prefix) =
                    matched.ok_or("cmd command requires an option")?;
                let head = advance(prefix, word.word.len())?;
                let (Some(switch), Some(raw_switch), Some(tail)) =
                    (text.get(..head), raw_rest.get(..head), raw_rest.get(head..))
                else {
                    return Err("quoted or case-folded cmd switch is unsupported".into());
                };
                if !switch.eq_ignore_ascii_case(raw_switch) {
                    return Err("quoted or case-folded cmd switch is unsupported".into());
                }
                let command = cmd_remainder(tail, strip_quotes)?;
                options.push(json!({"option":option.name,"token":switch,"value":command}));
                nested = cmd_segments(&command);
                remainder = json!({"option":option.name,"command":command,"segments":nested});
                break;
            }
        }
    }
    invocations.push(json!({"program":name,"executable":first.text,"depth":depth,
        "options":options,"remainder":remainder}));
    for segment in nested {
        interpret(&segment, programs, depth_owner, invocations)?;
    }
    Ok(())
}

fn selected<'a>(
    frame: &'a Value,
    json_string_pointer: Option<&str>,
    array: Option<(&str, &str)>,
) -> Result<Vec<&'a str>, String> {
    if let Some(pointer) = json_string_pointer {
        return frame
            .pointer(pointer)
            .and_then(Value::as_str)
            .map(|s| vec![s])
            .ok_or_else(|| {
                format!("required JSON string is absent or has a different type: {pointer}")
            });
    }
    let (items, field) = array.ok_or("command-line check selects no strings")?;
    frame
        .pointer(items)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("required JSON array is absent: {items}"))?
        .iter()
        .map(|item| {
            item.pointer(field)
                .and_then(Value::as_str)
                .ok_or_else(|| format!("array item lacks a string command at {field}"))
        })
        .collect()
}

pub(crate) fn evaluate(
    bytes: &[u8],
    check: &Check,
    programs: &std::collections::BTreeMap<String, CommandProgram>,
) -> Result<(ResultState, Value), (ResultState, String)> {
    let Check::CommandLine {
        json_string_pointer,
        json_array_pointer,
        item_string_pointer,
        predicate,
        ..
    } = check
    else {
        return Err((
            ResultState::Error,
            "installed evaluator does not match rule".into(),
        ));
    };
    let frame: Value = json::parse(bytes).map_err(|e| (ResultState::Error, e))?;
    let commands = selected(
        &frame,
        json_string_pointer.as_deref(),
        json_array_pointer
            .as_deref()
            .zip(item_string_pointer.as_deref()),
    )
    .map_err(|e| (ResultState::NotEvaluated, e))?;
    let mut interpreted = Vec::new();
    let mut found = false;
    for command in commands {
        let mut invocations = Vec::new();
        interpret(
            command,
            programs,
            &mut Budget::new((MAX_DEPTH + 1) as u64),
            &mut invocations,
        )
        .map_err(|e| (ResultState::NotEvaluated, e))?;
        let matched = invocations
            .iter()
            .try_fold(false, |found, invocation| {
                let name = invocation
                    .get("program")
                    .and_then(Value::as_str)
                    .ok_or("interpreted invocation has no program binding")?;
                let program = programs
                    .get(name)
                    .ok_or("interpreted program is not installed")?;
                let matched = match predicate {
                    CommandPredicate::Invokes { programs: selected } => {
                        selected.iter().any(|p| p == name)
                    }
                    CommandPredicate::Option {
                        programs: selected,
                        option,
                    } => {
                        selected.iter().any(|p| p == name)
                            && invocation
                                .get("options")
                                .and_then(Value::as_array)
                                .ok_or("interpreted invocation has no option list")?
                                .iter()
                                .any(|o| {
                                    o.get("option").and_then(Value::as_str) == Some(option.as_str())
                                        && (program
                                            .options
                                            .iter()
                                            .find(|d| d.name == *option)
                                            .is_none_or(|d| d.value != CommandValue::Value)
                                            || o.get("value").is_some_and(|value| !value.is_null()))
                                })
                    }
                };
                Ok::<_, String>(found || matched)
            })
            .map_err(|e| (ResultState::Error, e))?;
        found |= matched;
        interpreted.push(json!({"command_sha256":sha256(command.as_bytes()),
            "matched":matched,"invocations":invocations}));
    }
    Ok((
        if found {
            ResultState::Fail
        } else {
            ResultState::Pass
        },
        json!({"type":"command-line/1","value":if found {"found"} else {"absent"},
            "predicate":predicate,"commands":interpreted}),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "test assertions fail the declared nesting and owner-restoration contract"
    )]
    fn nested_interpretation_refuses_at_depth_and_restores_its_owner() -> Result<(), String> {
        let programs = std::collections::BTreeMap::from([(
            "launcher".into(),
            CommandProgram {
                executables: vec!["x".into()],
                option_prefixes: vec![],
                repeated_prefix: false,
                options: vec![],
                unmatched: CommandValue::Launch,
                positional: CommandValue::Launch,
                title_argument: false,
            },
        )]);
        let mut owner = Budget::new((MAX_DEPTH + 1) as u64);
        let exact = std::iter::repeat_n("x", MAX_DEPTH + 1)
            .collect::<Vec<_>>()
            .join(" ");
        let mut invocations = Vec::new();
        interpret(&exact, &programs, &mut owner, &mut invocations)?;
        assert_eq!(invocations.len(), MAX_DEPTH + 1);
        assert_eq!(
            invocations.last().and_then(|v| v.get("depth")),
            Some(&json!(MAX_DEPTH))
        );
        assert_eq!(owner.allocated(), 0);
        assert!(
            interpret(
                &format!("x {exact}"),
                &programs,
                &mut owner,
                &mut Vec::new()
            )
            .is_err()
        );
        assert_eq!(owner.allocated(), 0);
        interpret("x", &programs, &mut owner, &mut Vec::new())?;
        assert_eq!(owner.available(), (MAX_DEPTH + 1) as u64);
        Ok(())
    }

    fn args(line: &str) -> Result<Vec<String>, String> {
        Ok(tokenize(line)?.into_iter().map(|t| t.text).collect())
    }

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "test assertions compare the literal Microsoft argv cases"
    )]
    fn tokenizes_with_documented_backslash_and_quote_rules() -> Result<(), String> {
        assert_eq!(
            args(r#""C:\Program Files\x.exe" a"b c"d"#)?,
            [r"C:\Program Files\x.exe", "ab cd"]
        );
        assert_eq!(args(r#"x a\\\"b "c\\" d"#)?, ["x", r#"a\"b"#, r"c\", "d"]);
        assert_eq!(args(r#"x "a""b" c\d"#)?, ["x", r#"a"b"#, r"c\d"]);
        assert_eq!(args("  ")?, Vec::<String>::new());
        Ok(())
    }

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "test assertions compare the literal cmd quote and segment cases"
    )]
    fn applies_cmd_quote_preservation_and_segment_rules() -> Result<(), String> {
        assert_eq!(
            cmd_remainder(r#" "C:\Program Files\p.exe" -e x"#, false)?,
            r#""C:\Program Files\p.exe" -e x"#
        );
        assert_eq!(cmd_remainder(r#""echo a & b""#, false)?, "echo a & b");
        assert_eq!(cmd_remainder(r#""p.exe -e x""#, true)?, "p.exe -e x");
        assert_eq!(
            cmd_segments(r#"echo "a & b" ^& c & (@d) || e"#),
            [r#"echo "a & b" & c"#, "d", "e"]
        );
        Ok(())
    }
}
