//! Predicate computation and a local, explicitly experimental model test double.
use crate::{ScanError, baseline::CompiledCheck, json, schema::*, source::sha256};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

pub(crate) fn provider_state(
    check: &Check,
    bytes: &[u8],
    request_limit: u64,
) -> Result<Value, String> {
    let frame: Value = json::parse(bytes)?;
    let (projection, required_any, question_limit) = match check {
        Check::YesNo {
            state_projection,
            state_required_any,
            max_request_bytes,
            ..
        }
        | Check::Choice {
            state_projection,
            state_required_any,
            max_request_bytes,
            ..
        }
        | Check::Extract {
            state_projection,
            state_required_any,
            max_request_bytes,
            ..
        }
        | Check::Box {
            state_projection,
            state_required_any,
            max_request_bytes,
            ..
        } => (state_projection, state_required_any, max_request_bytes),
        _ => return Err("state projection requires a model question".into()),
    };
    let Some(fields) = projection else {
        return if required_any.is_empty() {
            Ok(frame)
        } else {
            Err("state_required_any requires a state projection".into())
        };
    };
    let limit = question_limit.map_or(request_limit, |own| own.min(request_limit));
    let mut budget = automation_structures::Budget::new(limit);
    let projected = fields
        .iter()
        .map(|(name, field)| {
            let pointer = field.pointer();
            let pointed = frame.pointer(pointer);
            let selected = if let (Some(capture), Some(pointed)) = (field.capture_name(), pointed) {
                let captures = pointed.as_array().ok_or_else(|| {
                    format!("state field {name} requires a syntax capture array: {pointer}")
                })?;
                let mut matching = captures.iter().filter(|value| {
                    value.get("capture").and_then(Value::as_str) == Some(capture)
                });
                let selected = matching.next();
                if matching.next().is_some() {
                    return Err(format!(
                        "state field {name} has multiple syntax captures named {capture}: {pointer}"
                    ));
                }
                selected.map(|value| {
                    value.get("text").filter(|text| {
                        text.as_str().is_some_and(|text| !text.is_empty())
                    }).ok_or_else(|| {
                        format!("state field {name} capture {capture} lacks nonempty string text: {pointer}")
                    })
                }).transpose()?
            } else {
                pointed
            };
            let value = match selected {
                Some(value) => value,
                None if field.optional() => &Value::Null,
                None => {
                    return Err(format!("required state field {name} is absent: {pointer}"));
                }
            };
            let size = serde_json::to_vec(value)
                .map_err(|e| e.to_string())?
                .len()
                .checked_add(serde_json::to_vec(name).map_err(|e| e.to_string())?.len())
                .and_then(|size| size.checked_add(3))
                .ok_or("state projection size overflows")?;
            if !budget.try_allocate(size as u64) {
                return Err(format!(
                    "state projection exceeds {limit}-byte request allowance"
                ));
            }
            Ok((name.clone(), value.clone()))
        })
        .collect::<Result<serde_json::Map<_, _>, _>>()?;
    for group in required_any {
        if !group
            .iter()
            .any(|name| projected.get(name).is_some_and(|value| !value.is_null()))
        {
            return Err(format!(
                "required state alternative group has no non-null value: {}",
                group.join(", ")
            ));
        }
    }
    Ok(Value::Object(projected))
}

/// Model questions are identified by the backend and model their role resolves to; without an
/// evaluator file the model is recorded as unconfigured.
pub(crate) fn identity(
    rule: &Rule,
    evaluators: Option<&crate::evaluators::Evaluators>,
) -> EvaluatorIdentity {
    let (binding, version) = match rule.check {
        Check::Yara {
            json_string_pointer: Some(_),
            ..
        } => ("yara-x", "1.20.0/no-modules/json-string/1".into()),
        Check::Yara { .. } => ("yara-x", "1.20.0/no-modules/1".into()),
        Check::Json { .. } => ("json-pointer-equals", "1".into()),
        Check::JsonCompare { .. } => ("json-pointer-compare", "1".into()),
        Check::JsonContains { .. } => ("json-pointer-contains", "1".into()),
        Check::JsonNumberRange { .. } => ("json-number-range", "1".into()),
        Check::TlaplusRelation { .. } => (
            "tlaplus-relation",
            format!(
                "1/{}",
                crate::syntax::version(crate::schema::SyntaxLanguage::Tlaplus)
            ),
        ),
        Check::Markdown { .. } => ("markdown", crate::markdown::VERSION.into()),
        Check::Syntax { language, .. } => ("syntax", crate::syntax::version(language)),
        Check::CommandLine { .. } => ("command-line", crate::command_line::VERSION.into()),
        Check::MockModel { .. } => ("mock-model", "1".into()),
        Check::YesNo { .. } | Check::Choice { .. } | Check::Extract { .. } | Check::Box { .. } => (
            "model",
            evaluators
                .and_then(|e| e.strategy(model_role(rule)).ok())
                .map_or_else(|| "unconfigured".into(), |s| s.version()),
        ),
        Check::Answers { .. } => ("answers", "1".into()),
    };
    EvaluatorIdentity {
        binding: binding.into(),
        version,
        contract: rule.evaluator.contract.clone(),
    }
}

pub(crate) fn model_role(rule: &Rule) -> &str {
    rule.evaluator
        .role
        .as_deref()
        .unwrap_or(crate::evaluators::DEFAULT_ROLE)
}

pub(crate) fn deterministic(
    rule: &Rule,
    compiled: &CompiledCheck,
    bytes: &[u8],
) -> Result<(ResultState, Value), (ResultState, String)> {
    match (&rule.check, compiled) {
        (
            Check::Yara {
                rule_name,
                fail_when,
                json_string_pointer,
                ..
            },
            CompiledCheck::Yara(rules),
        ) => {
            let frame: Option<Value> = json_string_pointer
                .as_ref()
                .map(|_| json::parse(bytes))
                .transpose()
                .map_err(|e| (ResultState::Error, e))?;
            let selected = match (json_string_pointer, &frame) {
                (Some(pointer), Some(frame)) => frame
                    .pointer(pointer)
                    .and_then(Value::as_str)
                    .ok_or_else(|| {
                        (
                            ResultState::NotEvaluated,
                            format!(
                                "required JSON string is absent or has a different type: {pointer}"
                            ),
                        )
                    })?
                    .as_bytes(),
                _ => bytes,
            };
            let mut scanner = yara_x::Scanner::new(rules);
            scanner.set_timeout(std::time::Duration::from_secs(2));
            let result = scanner
                .scan(selected)
                .map_err(|e| (ResultState::Error, e.to_string()))?;
            let observation = if result.matching_rules().any(|r| r.identifier() == rule_name) {
                YaraObservation::Match
            } else {
                YaraObservation::NoMatch
            };
            let mut details = json!({"type": "yara-x/1.20.0", "value": observation});
            if let Some(pointer) = json_string_pointer {
                let object = json::object_mut(&mut details).map_err(|e| (ResultState::Error, e))?;
                object.insert("json_string_pointer".into(), json!(pointer));
                object.insert("selected_sha256".into(), json!(sha256(selected)));
                object.insert("selected_bytes".into(), json!(selected.len()));
            }
            Ok((
                if observation == *fail_when {
                    ResultState::Fail
                } else {
                    ResultState::Pass
                },
                details,
            ))
        }
        (
            Check::Json {
                pointer,
                expected,
                fail_when,
            },
            CompiledCheck::Json,
        ) => {
            let value: Value = json::parse(bytes).map_err(|e| (ResultState::Error, e))?;
            let actual = value.pointer(pointer).ok_or_else(|| {
                (
                    ResultState::NotEvaluated,
                    format!("required JSON Pointer is absent: {pointer}"),
                )
            })?;
            let (result, observation) = json_equality(actual, expected, *fail_when);
            Ok((
                result,
                json!({"type": "json-pointer-equals/1", "value": observation, "actual": actual}),
            ))
        }
        (
            Check::JsonCompare {
                left,
                right,
                fail_when,
            },
            CompiledCheck::Json,
        ) => {
            let value: Value = json::parse(bytes).map_err(|e| (ResultState::Error, e))?;
            let operand = |pointer: &str| {
                value.pointer(pointer).ok_or_else(|| {
                    (
                        ResultState::NotEvaluated,
                        format!("required JSON comparison operand is absent: {pointer}"),
                    )
                })
            };
            let actual = operand(left)?;
            let expected = operand(right)?;
            let (result, observation) = json_equality(actual, expected, *fail_when);
            Ok((
                result,
                json!({"type":"json-pointer-compare/1", "value":observation,
                    "left_pointer":left, "right_pointer":right,
                    "left":actual, "right":expected}),
            ))
        }
        (
            Check::JsonNumberRange {
                pointer,
                minimum,
                maximum,
                fail_when_outside,
            },
            CompiledCheck::Json,
        ) => {
            let value: Value = json::parse(bytes).map_err(|e| (ResultState::Error, e))?;
            let actual = value
                .pointer(pointer)
                .and_then(Value::as_f64)
                .filter(|value| value.is_finite())
                .ok_or_else(|| {
                    (
                        ResultState::NotEvaluated,
                        format!("required finite JSON number is absent or mistyped: {pointer}"),
                    )
                })?;
            let outside = actual < *minimum || actual > *maximum;
            Ok((
                if outside == *fail_when_outside {
                    ResultState::Fail
                } else {
                    ResultState::Pass
                },
                json!({"type":"json-number-range/1","actual":actual,"minimum":minimum,
                    "maximum":maximum,"outside":outside}),
            ))
        }
        (
            Check::JsonContains {
                array_pointer,
                value_pointer,
                fail_when,
            },
            CompiledCheck::Json,
        ) => {
            let value: Value = json::parse(bytes).map_err(|e| (ResultState::Error, e))?;
            let array = value
                .pointer(array_pointer)
                .and_then(Value::as_array)
                .ok_or_else(|| {
                    (
                        ResultState::NotEvaluated,
                        format!("required JSON array is absent or not an array: {array_pointer}"),
                    )
                })?;
            let operand = value.pointer(value_pointer).ok_or_else(|| {
                (
                    ResultState::NotEvaluated,
                    format!("required JSON membership value is absent: {value_pointer}"),
                )
            })?;
            let contains = array.contains(operand);
            Ok((
                if contains == *fail_when {
                    ResultState::Fail
                } else {
                    ResultState::Pass
                },
                json!({"type":"json-pointer-contains/1", "value":contains,
                    "array_pointer":array_pointer, "value_pointer":value_pointer,
                    "operand":operand}),
            ))
        }
        (
            Check::TlaplusRelation {
                json_string_pointer,
                operator_pointer,
                predicate,
                fail_when,
                limits,
            },
            CompiledCheck::TlaplusRelation(compiled),
        ) => compiled.relation(
            bytes,
            json_string_pointer,
            operator_pointer,
            predicate,
            *fail_when,
            limits,
        ),
        (
            Check::Markdown {
                json_string_pointer,
                predicate,
            },
            CompiledCheck::Markdown,
        ) => crate::markdown::evaluate(bytes, json_string_pointer.as_deref(), predicate),
        (
            Check::Syntax {
                json_string_pointer,
                limits,
                ..
            },
            CompiledCheck::Syntax(syntax),
        ) => syntax.evaluate(bytes, json_string_pointer.as_deref(), limits),
        (Check::CommandLine { .. }, CompiledCheck::CommandLine(programs)) => {
            crate::command_line::evaluate(bytes, &rule.check, programs)
        }
        _ => Err((
            ResultState::Error,
            "installed evaluator does not match rule".into(),
        )),
    }
}

fn json_equality(
    left: &Value,
    right: &Value,
    fail_when: JsonObservation,
) -> (ResultState, JsonObservation) {
    let observation = if left == right {
        JsonObservation::Equal
    } else {
        JsonObservation::Unequal
    };
    let result = if observation == fail_when {
        ResultState::Fail
    } else {
        ResultState::Pass
    };
    (result, observation)
}

/// Stable local mock contract, deliberately distinct from every live backend protocol.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MockModel {
    schema: String,
    replies: Vec<MockReply>,
    #[serde(skip)]
    pub(crate) input_path: Option<std::path::PathBuf>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MockReply {
    rule: String,
    revision: String,
    target: Option<String>,
    /// The evaluator-file model this reply answers for; absent answers for every model.
    #[serde(default)]
    model: Option<String>,
    evidence_sha256: String,
    instructions_sha256: String,
    response: MockResponse,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum MockResponse {
    Probability {
        value: f64,
    },
    Choice {
        choice: String,
        confidence: f64,
        probabilities: std::collections::BTreeMap<String, f64>,
    },
    Extract {
        fields: serde_json::Map<String, Value>,
    },
    Timeout,
    Unavailable,
    StaleCheck,
    StaleGeneration,
    WrongVersion,
    Duplicate,
}

#[derive(Debug, Serialize)]
pub(crate) struct ProviderRequest<'a> {
    pub schema: &'static str,
    pub scan_id: &'a str,
    pub check_id: &'a str,
    pub rule: &'a str,
    pub revision: &'a str,
    pub target: &'a str,
    pub evidence_sha256: &'a str,
    pub instructions: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<&'a str>,
    pub state: &'a [u8],
    pub evaluator: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct ProviderResponse {
    pub scan_id: String,
    pub check_id: String,
    pub request_sha256: String,
    pub evaluator: String,
    pub probability: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub choice_answer: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extract_fields: Option<Value>,
}

impl MockModel {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ScanError> {
        if !automation_structures::Budget::new(2 * 1024 * 1024).try_allocate(bytes.len() as u64) {
            return Err(ScanError::invalid("mock script exceeds 2 MiB"));
        }
        let mock: Self = json::parse(bytes).map_err(ScanError::invalid)?;
        if mock.schema != "auditoad-mock-model/1" {
            return Err(ScanError::invalid("unknown mock schema"));
        }
        let mut identities = BTreeSet::new();
        let mut targeting = BTreeMap::new();
        for reply in &mock.replies {
            let identity = (
                &reply.rule,
                &reply.revision,
                &reply.evidence_sha256,
                &reply.instructions_sha256,
            );
            if targeting
                .insert(identity, reply.target.is_some())
                .is_some_and(|targeted| targeted != reply.target.is_some())
            {
                return Err(ScanError::invalid(
                    "generic and target-specific mock replies overlap",
                ));
            }
            if reply.rule.is_empty()
                || reply.revision.is_empty()
                || reply
                    .target
                    .as_ref()
                    .is_some_and(|target| target.trim().is_empty())
                || reply
                    .model
                    .as_ref()
                    .is_some_and(|model| model.trim().is_empty())
                || reply.evidence_sha256.len() != 64
                || reply.instructions_sha256.len() != 64
                || !identities.insert((
                    &reply.rule,
                    &reply.revision,
                    &reply.evidence_sha256,
                    &reply.instructions_sha256,
                    &reply.target,
                    &reply.model,
                ))
            {
                return Err(ScanError::invalid(
                    "empty, malformed or duplicate mock reply identity",
                ));
            }
            if let MockResponse::Probability { value } = reply.response
                && (!value.is_finite() || !(0.0..=1.0).contains(&value))
            {
                return Err(ScanError::invalid(
                    "mock probability must be finite and in [0,1]",
                ));
            }
        }
        Ok(mock)
    }

    pub(crate) fn evaluate(
        &self,
        request: &ProviderRequest<'_>,
        bytes: &[u8],
    ) -> Result<Vec<ProviderResponse>, String> {
        let instructions = sha256(request.instructions.as_bytes());
        let matches = |r: &&MockReply| {
            r.rule == request.rule
                && r.revision == request.revision
                && r.target
                    .as_deref()
                    .is_none_or(|target| target == request.target)
                && r.evidence_sha256 == request.evidence_sha256
                && r.instructions_sha256 == instructions
        };
        let reply = self
            .replies
            .iter()
            .filter(matches)
            .find(|r| r.model.is_some() && r.model.as_deref() == request.model)
            .or_else(|| {
                self.replies
                    .iter()
                    .filter(matches)
                    .find(|r| r.model.is_none())
            })
            .ok_or(
                "mock has no response for the exact rule, revision, evidence and instructions",
            )?;
        let mut response = ProviderResponse {
            scan_id: request.scan_id.into(),
            check_id: request.check_id.into(),
            request_sha256: sha256(bytes),
            evaluator: "mock-model/1".into(),
            probability: 0.5,
            choice_answer: None,
            extract_fields: None,
        };
        match &reply.response {
            MockResponse::Probability { value } => response.probability = *value,
            MockResponse::Choice {
                choice,
                confidence,
                probabilities,
            } => {
                response.choice_answer = Some(json!({"type":"choice","choice":choice,
                    "confidence":confidence,"probabilities":probabilities}));
            }
            MockResponse::Extract { fields } => {
                response.extract_fields = Some(Value::Object(fields.clone()));
            }
            MockResponse::Timeout => return Err("mock provider timeout; no retry".into()),
            MockResponse::Unavailable => return Err("mock provider unavailable; no retry".into()),
            MockResponse::StaleCheck => response.check_id = "stale".into(),
            MockResponse::StaleGeneration => response.scan_id = "stale".into(),
            MockResponse::WrongVersion => response.evaluator = "wrong-version".into(),
            MockResponse::Duplicate => return Ok(vec![response.clone(), response]),
        }
        Ok(vec![response])
    }
}
