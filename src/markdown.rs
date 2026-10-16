//! Pure CommonMark content predicates over one selected UTF-8 document.
use crate::{json, schema::*, source::sha256};
use pulldown_cmark::{Event, Parser, Tag, TagEnd};
use serde::Serialize;
use serde_json::{Value, json};
use std::ops::Range;
use unicode_segmentation::UnicodeSegmentation;

pub(crate) const VERSION: &str = "3/pulldown-cmark-0.13.4/unicode-segmentation-1.13.3";

#[derive(Serialize)]
struct ListCount {
    source_bytes: Range<usize>,
    direct_items: usize,
}

#[derive(Serialize)]
struct ParagraphCount {
    source_bytes: Range<usize>,
    sentence_words: Vec<usize>,
}

#[derive(Serialize)]
struct TermMatch {
    term: String,
    matched_text: String,
    /// The containing Markdown block, not the decoded witness's exact source span.
    source_block_bytes: Range<usize>,
}

pub(crate) fn valid_term(term: &str) -> bool {
    if term
        .chars()
        .any(|ch| ch.is_control() && !ch.is_whitespace())
    {
        return false;
    }
    let mut words = term.unicode_word_indices();
    let Some(first) = words.next() else {
        return false;
    };
    let last = words.next_back().unwrap_or(first);
    first.0 == 0 && last.0.checked_add(last.1.len()) == Some(term.len())
}

fn normalized_word(word: &str) -> String {
    word.replace('\u{2019}', "'").to_lowercase()
}

fn term_witness<'a>(text: &'a str, term: &str) -> Option<&'a str> {
    let words: Vec<_> = text.unicode_word_indices().collect();
    let wanted: Vec<_> = term.unicode_word_indices().collect();
    if wanted.is_empty() {
        return None;
    }
    for window in words.windows(wanted.len()) {
        if !window
            .iter()
            .zip(&wanted)
            .all(|((_, word), (_, target))| normalized_word(word) == normalized_word(target))
        {
            continue;
        }
        let gaps_match = window
            .windows(2)
            .zip(wanted.windows(2))
            .all(|(pair, target)| {
                let ([(start, word), (end, _)], [(target_start, target_word), (target_end, _)]) =
                    (pair, target)
                else {
                    return false;
                };
                let Some(gap) = start
                    .checked_add(word.len())
                    .and_then(|start| text.get(start..*end))
                else {
                    return false;
                };
                let Some(expected) = target_start
                    .checked_add(target_word.len())
                    .and_then(|start| term.get(start..*target_end))
                else {
                    return false;
                };
                if expected.chars().all(char::is_whitespace) {
                    gap.chars().all(char::is_whitespace)
                } else {
                    gap == expected
                }
            });
        if gaps_match {
            let last = window.last()?;
            let first = window.first()?;
            let end = last.0.checked_add(last.1.len())?;
            return text.get(first.0..end);
        }
    }
    None
}

pub(crate) fn evaluate(
    bytes: &[u8],
    pointer: Option<&str>,
    predicate: &MarkdownPredicate,
) -> Result<(ResultState, Value), (ResultState, String)> {
    let frame: Option<Value> = pointer
        .map(|_| json::parse(bytes))
        .transpose()
        .map_err(|e| (ResultState::Error, e))?;
    let text = if let (Some(pointer), Some(frame)) = (pointer, &frame) {
        frame
            .pointer(pointer)
            .and_then(Value::as_str)
            .ok_or_else(|| {
                (
                    ResultState::NotEvaluated,
                    format!("required JSON string is absent or has a different type: {pointer}"),
                )
            })?
    } else {
        std::str::from_utf8(bytes).map_err(|_| {
            (
                ResultState::NotEvaluated,
                "Markdown input is not UTF-8".into(),
            )
        })?
    };
    let mut lists: Vec<ListCount> = Vec::new();
    let mut list_indices = Vec::new();
    let mut paragraphs = Vec::new();
    let mut paragraph: Option<(Range<usize>, String)> = None;
    let inspect_bold = matches!(predicate, MarkdownPredicate::ProseBold);
    let mut bold_spans = Vec::new();
    let mut strong: Vec<(Option<Range<usize>>, bool)> = Vec::new();
    let mut image_depth: usize = 0;
    let inspect_terms = matches!(predicate, MarkdownPredicate::ForbiddenTerms { .. });
    let mut prose_blocks = Vec::new();
    let mut prose_block: Option<(Range<usize>, String)> = None;
    let count_paragraphs = matches!(
        predicate,
        MarkdownPredicate::ParagraphSentenceLengths { .. } | MarkdownPredicate::ProseBold
    );
    for (event, range) in Parser::new(text).into_offset_iter() {
        if inspect_terms {
            match &event {
                Event::Start(Tag::Paragraph | Tag::Heading { .. } | Tag::Item) => {
                    if let Some(block) = prose_block.take() {
                        prose_blocks.push(block);
                    }
                    prose_block = Some((range.clone(), String::new()));
                }
                Event::End(TagEnd::Paragraph | TagEnd::Heading(_) | TagEnd::Item)
                | Event::Start(Tag::CodeBlock(_) | Tag::List(_) | Tag::BlockQuote(_)) => {
                    if let Some(block) = prose_block.take() {
                        prose_blocks.push(block);
                    }
                }
                Event::Text(part) if image_depth == 0 => {
                    if let Some((_, rendered)) = &mut prose_block {
                        rendered.push_str(part);
                    }
                }
                Event::Code(_) | Event::Start(Tag::Image { .. }) => {
                    if let Some((_, rendered)) = &mut prose_block {
                        // Excluded content must not join the surrounding words or phrase.
                        rendered.push('\0');
                    }
                }
                Event::SoftBreak | Event::HardBreak => {
                    if let Some((_, rendered)) = &mut prose_block {
                        rendered.push(' ');
                    }
                }
                _ => {}
            }
        }
        match event {
            Event::Start(Tag::List(_)) => {
                list_indices.push(lists.len());
                lists.push(ListCount {
                    source_bytes: range,
                    direct_items: 0,
                });
            }
            Event::Start(Tag::Item) => {
                if let Some(&index) = list_indices.last() {
                    let list = lists.get_mut(index).ok_or_else(|| {
                        (
                            ResultState::Error,
                            "Markdown list index is not bound".into(),
                        )
                    })?;
                    list.direct_items = list.direct_items.checked_add(1).ok_or_else(|| {
                        (ResultState::Error, "Markdown item count overflows".into())
                    })?;
                }
            }
            Event::End(TagEnd::List(_)) => {
                list_indices.pop();
            }
            Event::Start(Tag::Paragraph) if list_indices.is_empty() && count_paragraphs => {
                paragraph = Some((range, String::new()));
            }
            Event::End(TagEnd::Paragraph) => {
                if let Some((source_bytes, rendered)) = paragraph.take() {
                    paragraphs.push(ParagraphCount {
                        source_bytes,
                        sentence_words: rendered
                            .unicode_sentences()
                            .map(|sentence| sentence.unicode_words().count())
                            .collect(),
                    });
                }
            }
            Event::Start(Tag::Image { .. }) => {
                image_depth = image_depth
                    .checked_add(1)
                    .ok_or_else(|| (ResultState::Error, "Markdown image depth overflows".into()))?
            }
            Event::End(TagEnd::Image) => {
                image_depth = image_depth.checked_sub(1).ok_or_else(|| {
                    (
                        ResultState::Error,
                        "Markdown image end has no matching start".into(),
                    )
                })?
            }
            Event::Start(Tag::Strong) => strong.push((
                (inspect_bold && paragraph.is_some() && image_depth == 0).then_some(range),
                false,
            )),
            Event::End(TagEnd::Strong) => {
                if let Some((Some(range), true)) = strong.pop() {
                    bold_spans.push(range);
                }
            }
            Event::Text(part) | Event::Code(part) => {
                if image_depth == 0 && !part.trim().is_empty() {
                    for (_, visible) in &mut strong {
                        *visible = true;
                    }
                }
                if let Some((_, rendered)) = &mut paragraph {
                    rendered.push_str(&part);
                }
            }
            Event::SoftBreak | Event::HardBreak => {
                if let Some((_, rendered)) = &mut paragraph {
                    rendered.push(' ');
                }
            }
            Event::Html(_) | Event::InlineHtml(_) => {
                return Err((
                    ResultState::NotEvaluated,
                    format!(
                        "markdown/1 does not interpret raw HTML at source bytes {}..{}",
                        range.start, range.end
                    ),
                ));
            }
            _ => {}
        }
    }
    let mut term_matches = Vec::new();
    let violation = match predicate {
        MarkdownPredicate::ForbiddenTerms { terms } => {
            for (source_block_bytes, rendered) in prose_blocks {
                for term in terms {
                    if let Some(witness) = term_witness(&rendered, term) {
                        term_matches.push(TermMatch {
                            term: term.clone(),
                            matched_text: witness.into(),
                            source_block_bytes: source_block_bytes.clone(),
                        });
                    }
                }
            }
            !term_matches.is_empty()
        }
        MarkdownPredicate::ProseBold => !bold_spans.is_empty(),
        MarkdownPredicate::ListLength { forbidden_length } => lists
            .iter()
            .any(|list| list.direct_items == *forbidden_length),
        MarkdownPredicate::ParagraphSentenceLengths {
            shorter_than,
            longer_than,
        } => {
            if paragraphs.is_empty() {
                return Err((
                    ResultState::NotEvaluated,
                    "no prose paragraphs were found".into(),
                ));
            }
            paragraphs.iter().any(|paragraph| {
                !paragraph
                    .sentence_words
                    .iter()
                    .any(|words| words < shorter_than)
                    || !paragraph
                        .sentence_words
                        .iter()
                        .any(|words| words > longer_than)
            })
        }
    };
    let mut observation = json!({
        "type": "markdown/1", "predicate": predicate, "violation": violation,
        "selected_sha256": sha256(text.as_bytes()), "selected_bytes": text.len(),
        "lists": lists, "paragraphs": paragraphs, "bold_spans": bold_spans,
        "unicode_version": unicode_segmentation::UNICODE_VERSION,
    });
    if inspect_terms {
        json::object_mut(&mut observation)
            .map_err(|e| (ResultState::Error, e))?
            .insert("term_matches".into(), json!(term_matches));
    }
    if let Some(pointer) = pointer {
        json::object_mut(&mut observation)
            .map_err(|e| (ResultState::Error, e))?
            .insert("json_string_pointer".into(), json!(pointer));
    }
    Ok((
        if violation {
            ResultState::Fail
        } else {
            ResultState::Pass
        },
        observation,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn evaluated(
        bytes: &[u8],
        pointer: Option<&str>,
        policy: &MarkdownPredicate,
    ) -> Result<(ResultState, Value), String> {
        evaluate(bytes, pointer, policy).map_err(|(state, reason)| format!("{state:?}: {reason}"))
    }

    fn byte_range(value: &Value) -> Result<Range<usize>, Box<dyn std::error::Error>> {
        let start = usize::try_from(
            value
                .get("start")
                .and_then(Value::as_u64)
                .ok_or("range has no integer start")?,
        )?;
        let end = usize::try_from(
            value
                .get("end")
                .and_then(Value::as_u64)
                .ok_or("range has no integer end")?,
        )?;
        Ok(start..end)
    }

    #[test]
    fn terms_follow_unicode_words_case_and_phrase_punctuation() {
        for (text, term, expected) in [
            ("A VERY good result.", "very", Some("VERY")),
            ("delivery every ivory", "very", None),
            ("veryé évery very\u{301}", "very", None),
            ("A ‘very’ odd result.", "very", Some("very")),
            (
                "Keep\t in\n mind\u{a0}that it failed.",
                "keep in mind that",
                Some("Keep\t in\n mind\u{a0}that"),
            ),
            ("Keep in mind. That matters.", "keep in mind that", None),
            (
                "It's important to note this.",
                "it's important to note",
                Some("It's important to note"),
            ),
            (
                "It’s important to note this.",
                "it's important to note",
                Some("It’s important to note"),
            ),
            (
                "A CUTTING-EDGE device.",
                "cutting-edge",
                Some("CUTTING-EDGE"),
            ),
            ("A cutting edge device.", "cutting-edge", None),
            ("A cutting—edge device.", "cutting-edge", None),
            ("A NAÏVE view.", "naïve", Some("NAÏVE")),
            ("strasse", "straße", None),
            ("", "very", None),
        ] {
            assert_eq!(term_witness(text, term), expected, "{text}: {term}");
        }
        for term in ["very", "it's important to note", "cutting-edge", "naïve"] {
            assert!(valid_term(term), "{term}");
        }
        for term in ["", " ", "!!!", " very", "very ", "very!", "keep\0in mind"] {
            assert!(!valid_term(term), "{term}");
        }
    }

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "test assertions check rendered-block matches and exclusion boundaries"
    )]
    fn terms_scan_rendered_blocks_without_code_or_context_leakage()
    -> Result<(), Box<dyn std::error::Error>> {
        let policy = MarkdownPredicate::ForbiddenTerms {
            terms: vec!["robust".into(), "very".into(), "keep in mind".into()],
        };
        for (text, expected) in [
            ("A ro**bu**st result.", ResultState::Fail),
            ("A v&#101;ry good result.", ResultState::Fail),
            ("# ROBUST\n", ResultState::Fail),
            ("- Keep **in** mind the date.\n", ResultState::Fail),
            ("1. Plain\n2. Very good\n", ResultState::Fail),
            ("> A robust claim.\n", ResultState::Fail),
            ("A [robust result](https://example.org).", ResultState::Fail),
            ("- Outer\n  - A robust result\n", ResultState::Fail),
            ("- First\n\n  A very good result.\n", ResultState::Fail),
            ("Keep\nin mind the date.", ResultState::Fail),
            ("Keep  \nin mind the date.", ResultState::Fail),
            ("Keep\n\nin mind the date.", ResultState::Pass),
            ("- Keep\n- in mind\n", ResultState::Pass),
            ("Keep `unrelated code` in mind.", ResultState::Pass),
            ("A ro`x`bust result.", ResultState::Pass),
            ("A `robust` result.", ResultState::Pass),
            ("```text\nrobust very\n```\n", ResultState::Pass),
            ("    robust very\n", ResultState::Pass),
            ("- ```\n  robust very\n  ```\n", ResultState::Pass),
            ("![Very robust](image.png)", ResultState::Pass),
            ("Keep ![ignored](image.png) in mind.", ResultState::Pass),
            (
                "[Plain](https://example.org/robust \"very\")",
                ResultState::Pass,
            ),
            ("Every delivery arrived.", ResultState::Pass),
        ] {
            let (state, detail) = evaluated(text.as_bytes(), None, &policy)?;
            assert_eq!(state, expected, "{text}");
            for found in detail
                .get("term_matches")
                .and_then(Value::as_array)
                .ok_or("term observations have no match array")?
            {
                let range = byte_range(
                    found
                        .get("source_block_bytes")
                        .ok_or("term match has no source range")?,
                )?;
                assert!(
                    range.start < range.end && text.get(range).is_some(),
                    "{text}"
                );
                assert!(
                    !found
                        .get("matched_text")
                        .and_then(Value::as_str)
                        .ok_or("term match has no text")?
                        .is_empty()
                );
            }
        }
        let frame = json!({"subject":"A plain result.","context":"Very robust."});
        let (state, detail) = evaluated(&serde_json::to_vec(&frame)?, Some("/subject"), &policy)?;
        assert_eq!(state, ResultState::Pass);
        assert_eq!(
            detail.get("selected_sha256"),
            Some(&json!(sha256(b"A plain result.")))
        );
        for input in [b"<b>robust</b>".as_slice(), &[0xff]] {
            assert_eq!(
                evaluate(input, None, &policy)
                    .err()
                    .ok_or("unsupported Markdown input was evaluated")?
                    .0,
                ResultState::NotEvaluated
            );
        }
        Ok(())
    }

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "test assertions require exact visible-prose witnesses and source ranges"
    )]
    fn bold_requires_visible_prose_and_preserves_source_ranges()
    -> Result<(), Box<dyn std::error::Error>> {
        let policy = MarkdownPredicate::ProseBold;
        for (text, snippets) in [
            (
                "Café **must remain open** today.",
                vec!["**must remain open**"],
            ),
            ("Use __both doors__.", vec!["__both doors__"]),
            ("> A **quoted phrase**.\n", vec!["**quoted phrase**"]),
            (
                "A [**bold label**](https://example.org).",
                vec!["**bold label**"],
            ),
            (
                "A **phrase with *nested emphasis***.",
                vec!["**phrase with *nested emphasis***"],
            ),
            ("A **`code span`**.", vec!["**`code span`**"]),
            ("**![An image](image.png)**", vec![]),
            ("![**Alternative text**](image.png)", vec![]),
            (
                "**Text ![**image label**](image.png) after**.",
                vec!["**Text ![**image label**](image.png) after**"],
            ),
            (
                "# A **heading**\n\n- **List label**: detail.\n\n  More **list prose**.\n",
                vec![],
            ),
            ("A `**code span**` and \\*\\*escaped text\\*\\*.", vec![]),
            ("```\n**Code block**\n```\n", vec![]),
            ("A [link](https://example.org \"**title**\").", vec![]),
            ("A *single emphasis* and unfinished **delimiter.", vec![]),
            ("", vec![]),
        ] {
            let (state, detail) = evaluated(text.as_bytes(), None, &policy)?;
            assert_eq!(
                state,
                if snippets.is_empty() {
                    ResultState::Pass
                } else {
                    ResultState::Fail
                },
                "{text}"
            );
            let actual: Vec<_> = detail
                .get("bold_spans")
                .and_then(Value::as_array)
                .ok_or("bold observation has no span array")?
                .iter()
                .map(|range| {
                    text.get(byte_range(range)?)
                        .ok_or_else(|| "bold span is outside UTF-8 boundaries".into())
                })
                .collect::<Result<Vec<_>, Box<dyn std::error::Error>>>()?;
            assert_eq!(actual, snippets, "{text}");
        }
        let frame = json!({"subject":"Plain prose.", "context":"**Bold prose**."});
        let (state, detail) = evaluated(&serde_json::to_vec(&frame)?, Some("/subject"), &policy)?;
        assert_eq!(state, ResultState::Pass);
        assert_eq!(
            detail.get("selected_sha256"),
            Some(&json!(sha256(b"Plain prose.")))
        );
        assert_eq!(
            evaluate(b"Prose with <strong>HTML</strong>.", None, &policy)
                .err()
                .ok_or("raw HTML was evaluated")?
                .0,
            ResultState::NotEvaluated
        );
        Ok(())
    }

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "test assertions distinguish direct children, continuations and nested lists"
    )]
    fn list_items_are_direct_children_not_lines_or_nested_items()
    -> Result<(), Box<dyn std::error::Error>> {
        let policy = MarkdownPredicate::ListLength {
            forbidden_length: 3,
        };
        for (text, counts, expected) in [
            ("- one\n- two\n- three\n", vec![3], ResultState::Fail),
            (
                "- one\n\n  continuation\n\n- two\n",
                vec![2],
                ResultState::Pass,
            ),
            (
                "- outer\n  - inner\n  - another\n- final\n",
                vec![2, 2],
                ResultState::Pass,
            ),
            (
                "- outer\n  - one\n  - two\n  - three\n",
                vec![1, 3],
                ResultState::Fail,
            ),
            ("8. one\n9. two\n10. three\n", vec![3], ResultState::Fail),
            (
                "```\n- one\n- two\n- three\n```\n",
                vec![],
                ResultState::Pass,
            ),
            ("\\- one\n\\- two\n\\- three\n", vec![], ResultState::Pass),
            ("", vec![], ResultState::Pass),
        ] {
            let (state, detail) = evaluated(text.as_bytes(), None, &policy)?;
            assert_eq!(state, expected, "{text}");
            let lists = detail
                .get("lists")
                .and_then(Value::as_array)
                .ok_or("list observation has no list array")?;
            let actual: Vec<_> = lists
                .iter()
                .map(|list| {
                    list.get("direct_items")
                        .and_then(Value::as_u64)
                        .ok_or("list has no direct-item count")
                })
                .collect::<Result<Vec<_>, _>>()?;
            assert_eq!(actual, counts, "{text}");
            for list in lists {
                let range =
                    byte_range(list.get("source_bytes").ok_or("list has no source range")?)?;
                assert!(range.start < range.end && text.get(range).is_some());
            }
        }
        Ok(())
    }

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "test assertions check both exclusive sentence-length boundaries and every paragraph"
    )]
    fn sentence_lengths_use_exclusive_boundaries_and_each_paragraph()
    -> Result<(), Box<dyn std::error::Error>> {
        let policy = MarkdownPredicate::ParagraphSentenceLengths {
            shorter_than: 7,
            longer_than: 30,
        };
        // Explicitly numbered words make the boundary independent of linguistic interpretation.
        let thirty = (1..=30)
            .map(|n| format!("W{n}"))
            .collect::<Vec<_>>()
            .join(" ")
            + ".";
        let thirty_one = (1..=31)
            .map(|n| format!("W{n}"))
            .collect::<Vec<_>>()
            .join(" ")
            + ".";
        for (short, tail, expected) in [
            (
                "One two three four five six.",
                thirty_one.as_str(),
                ResultState::Pass,
            ),
            (
                "One two three four five six seven.",
                thirty_one.as_str(),
                ResultState::Fail,
            ),
            (
                "One two three four five six.",
                thirty.as_str(),
                ResultState::Fail,
            ),
        ] {
            let text = format!("{short} {tail}");
            let (state, detail) = evaluated(text.as_bytes(), None, &policy)?;
            assert_eq!(state, expected);
            assert_eq!(
                detail
                    .get("paragraphs")
                    .and_then(Value::as_array)
                    .ok_or("sentence observation has no paragraphs")?
                    .len(),
                1
            );
        }
        let text = format!("Short sentence. {thirty_one}\n\nAnother paragraph.");
        assert_eq!(
            evaluated(text.as_bytes(), None, &policy)?.0,
            ResultState::Fail
        );
        for text in [
            "",
            "# Heading\n",
            "- Just a list\n",
            "```\nJust code.\n```\n",
        ] {
            assert_eq!(
                evaluate(text.as_bytes(), None, &policy)
                    .err()
                    .ok_or("paragraph-free input was evaluated")?
                    .0,
                ResultState::NotEvaluated
            );
        }
        Ok(())
    }

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "test assertions check Unicode counting and exact Markdown source boundaries"
    )]
    fn markup_and_unicode_have_a_declared_counting_convention()
    -> Result<(), Box<dyn std::error::Error>> {
        let policy = MarkdownPredicate::ParagraphSentenceLengths {
            shorter_than: 7,
            longer_than: 30,
        };
        let text = "# Excluded heading\n\nCafé **can't** [jump](https://example.org/hidden) `32.3` feet.\nTwo &amp; three.  \n![A fox](image.png).\n\n- Excluded list paragraph.\n\n> Quoted prose counts.\n";
        let (_, detail) = evaluated(text.as_bytes(), None, &policy)?;
        let paragraphs = detail
            .get("paragraphs")
            .and_then(Value::as_array)
            .ok_or("Unicode observation has no paragraphs")?;
        assert_eq!(paragraphs.len(), 2);
        let [first, last] = paragraphs.as_slice() else {
            return Err("expected two Unicode paragraphs".into());
        };
        assert_eq!(first.get("sentence_words"), Some(&json!([5, 2, 2])));
        assert_eq!(last.get("sentence_words"), Some(&json!([3])));
        let range = byte_range(
            first
                .get("source_bytes")
                .ok_or("Unicode paragraph has no source range")?,
        )?;
        assert!(
            text.get(range)
                .ok_or("Unicode range is outside UTF-8 boundaries")?
                .starts_with("Café")
        );
        let (_, detail) = evaluated(b"Mr. Fox jumped.", None, &policy)?;
        assert_eq!(
            detail.pointer("/paragraphs/0/sentence_words"),
            Some(&json!([1, 2]))
        );
        let (_, detail) = evaluated(b"Short sentence. lowercase continuation.", None, &policy)?;
        assert_eq!(
            detail.pointer("/paragraphs/0/sentence_words"),
            Some(&json!([4]))
        );
        Ok(())
    }

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "test assertions check selected-text custody and unsupported-input refusal"
    )]
    fn selected_text_excludes_metadata_and_refuses_unsupported_inputs()
    -> Result<(), Box<dyn std::error::Error>> {
        let policy = MarkdownPredicate::ListLength {
            forbidden_length: 3,
        };
        let frame = json!({"subject":"- one\n- two", "context":"- one\n- two\n- three"});
        let (state, detail) = evaluated(&serde_json::to_vec(&frame)?, Some("/subject"), &policy)?;
        assert_eq!(state, ResultState::Pass);
        assert_eq!(
            detail.get("selected_sha256"),
            Some(&json!(sha256(b"- one\n- two")))
        );
        for frame in [json!({}), json!({"subject":null}), json!({"subject":32})] {
            assert_eq!(
                evaluate(&serde_json::to_vec(&frame)?, Some("/subject"), &policy)
                    .err()
                    .ok_or("absent or wrongly typed selected text was evaluated")?
                    .0,
                ResultState::NotEvaluated
            );
        }
        for text in ["<ul><li>one</li></ul>", "Prose with <b>HTML</b>."] {
            assert_eq!(
                evaluate(text.as_bytes(), None, &policy)
                    .err()
                    .ok_or("raw HTML was evaluated")?
                    .0,
                ResultState::NotEvaluated
            );
        }
        assert_eq!(
            evaluate(&[0xff], None, &policy)
                .err()
                .ok_or("non-UTF-8 text was evaluated")?
                .0,
            ResultState::NotEvaluated
        );
        Ok(())
    }
}
