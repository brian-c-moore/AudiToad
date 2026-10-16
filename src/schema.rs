//! Versioned application content. Canonical owners hold execution state elsewhere.
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Baseline {
    #[serde(rename = "$schema", skip_serializing_if = "Option::is_none")]
    pub json_schema: Option<String>,
    pub schema: String,
    pub baseline: BaselineInfo,
    pub sources: BTreeMap<String, SourceDeclaration>,
    pub evidence: BTreeMap<String, EvidenceDeclaration>,
    pub groups: Vec<Group>,
    /// Requirements the audit must cover; rules name the requirement revisions they check.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub requirements: Vec<Requirement>,
    /// Named program grammars referenced by `command-line/1` checks.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub command_grammars: BTreeMap<String, BTreeMap<String, CommandProgram>>,
    pub rules: Vec<Rule>,
    pub profiles: Vec<Profile>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_profile: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BaselineInfo {
    pub id: String,
    pub version: String,
    pub title: String,
    pub publisher: String,
    pub status: Admission,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Admission {
    Draft,
    Admitted,
    Retired,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceDeclaration {
    pub adapter: String,
    pub media: Vec<String>,
    /// Expose collection-computed subject and selected-peer file identities to checks.
    #[serde(default, skip_serializing_if = "is_false")]
    pub include_provenance: bool,
}

fn is_false(value: &bool) -> bool {
    !value
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceDeclaration {
    pub builder: String,
    pub builder_revision: String,
    pub required_roles: Option<Vec<String>>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Group {
    pub id: String,
    pub title: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Requirement {
    pub id: String,
    pub revision: String,
    pub title: String,
    /// Where the requirement is stated, such as a policy section or standard clause.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Risk {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub id: String,
    pub revision: String,
    pub source: String,
    pub group: String,
    pub risk: Risk,
    pub scope_kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<Scope>,
    pub title: String,
    pub evidence: String,
    pub evaluator: EvaluatorDeclaration,
    pub check: Check,
    /// Earlier rules whose committed answers and observations join this rule's evidence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consult: Option<Consult>,
    pub applicability: Applicability,
    pub falsifier: String,
    pub fixtures: Fixtures,
    /// Requirement id to the requirement revision this rule was written against.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub requirements: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Consult {
    pub rules: Vec<String>,
    #[serde(default)]
    pub run_when: ConsultGate,
}

/// Whether consulted answers decide if this rule is evaluated at all.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsultGate {
    /// Always evaluate; consulted answers are supporting evidence.
    #[default]
    Always,
    /// Evaluate only when a consulted rule fails. All passes resolve this rule as a pass;
    /// any unresolved answer without a failure leaves it unresolved.
    AnyFail,
    /// Evaluate only when a consulted rule passes.
    AnyPass,
    /// Evaluate only when a consulted rule has no pass or fail decision.
    AnyUnresolved,
    /// Evaluate only when every consulted rule has a pass or fail decision.
    AllResolved,
}

/// Reusable selection and context policy; it contains no issue locations.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Scope {
    pub unit: ScopeUnit,
    pub context: ScopeContext,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub related: Vec<RelatedEvidence>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RelatedEvidence {
    pub role: String,
    pub input: String,
    pub unit: ScopeUnit,
    pub on: Vec<KeyCorrespondence>,
    pub allow_empty: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct KeyCorrespondence {
    pub subject: String,
    pub related: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScopeUnit {
    Document,
    Paragraph,
    Sentence,
    Record,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScopeContext {
    None,
    Document,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AnswerCombination {
    AnyFail,
    AllFail,
    /// The first dependency, in declared order, with a pass or fail decision decides.
    FirstResolved,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AnswerResolution {
    #[default]
    AllAnswers,
    Decisive,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluatorDeclaration {
    pub kind: String,
    pub contract: String,
    /// For model questions: the evaluator-file role that answers this rule. Default `default`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "kind", deny_unknown_fields)]
pub enum Check {
    #[serde(rename = "answers/1")]
    Answers {
        rules: Vec<String>,
        fail_when: AnswerCombination,
        #[serde(default)]
        resolution: AnswerResolution,
        /// Why these prerequisites cover the larger claim.
        coverage: String,
    },
    #[serde(rename = "yara-x/1.20.0")]
    Yara {
        source: String,
        rule_name: String,
        fail_when: YaraObservation,
        /// Select a UTF-8 string from a JSON evidence frame; absent means raw bytes.
        #[serde(skip_serializing_if = "Option::is_none")]
        json_string_pointer: Option<String>,
    },
    #[serde(rename = "json-pointer-equals/1")]
    Json {
        pointer: String,
        expected: Value,
        fail_when: JsonObservation,
    },
    /// Compare two present values in the same frozen JSON evidence frame.
    #[serde(rename = "json-pointer-compare/1")]
    JsonCompare {
        left: String,
        right: String,
        fail_when: JsonObservation,
    },
    /// Test exact membership of a present value in a present JSON array.
    #[serde(rename = "json-pointer-contains/1")]
    JsonContains {
        array_pointer: String,
        value_pointer: String,
        fail_when: bool,
    },
    /// Compare a finite JSON number with inclusive, baseline-declared bounds.
    #[serde(rename = "json-number-range/1")]
    JsonNumberRange {
        pointer: String,
        minimum: f64,
        maximum: f64,
        fail_when_outside: bool,
    },
    #[serde(rename = "tlaplus-relation/1")]
    TlaplusRelation {
        json_string_pointer: String,
        operator_pointer: String,
        predicate: TlaplusPredicate,
        fail_when: bool,
        #[serde(default)]
        limits: SyntaxLimits,
    },
    #[serde(rename = "markdown/1")]
    Markdown {
        /// Select a UTF-8 string from a JSON evidence frame; absent means raw UTF-8.
        #[serde(skip_serializing_if = "Option::is_none")]
        json_string_pointer: Option<String>,
        predicate: MarkdownPredicate,
    },
    /// Syntax captures for later questions, with no policy decision of its own.
    #[serde(rename = "syntax/1")]
    Syntax {
        language: SyntaxLanguage,
        #[serde(skip_serializing_if = "Option::is_none")]
        json_string_pointer: Option<String>,
        query: String,
        #[serde(default)]
        limits: SyntaxLimits,
    },
    /// Prove that every selected reaching expression contains only source-authored strings.
    /// Unsupported expressions remain unresolved and retain syntax evidence for a fallback.
    #[serde(rename = "python-constant-string/1")]
    PythonConstantString {
        #[serde(skip_serializing_if = "Option::is_none")]
        json_string_pointer: Option<String>,
        query: String,
        #[serde(default)]
        limits: SyntaxLimits,
    },
    /// Interpret command lines with declared program grammars.
    #[serde(rename = "command-line/1")]
    CommandLine {
        /// Select one command string from a JSON evidence frame.
        #[serde(skip_serializing_if = "Option::is_none")]
        json_string_pointer: Option<String>,
        /// Or select an array whose items each hold a command string at `item_string_pointer`.
        #[serde(skip_serializing_if = "Option::is_none")]
        json_array_pointer: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        item_string_pointer: Option<String>,
        /// A key of the baseline's `command_grammars`.
        grammar: String,
        predicate: CommandPredicate,
    },
    #[serde(rename = "mock-model/1")]
    MockModel {
        instructions: String,
        pass_below: f64,
        fail_at_or_above: f64,
    },
    /// A model question answered with the probability that the true criterion holds. The
    /// operator's evaluator file chooses the model.
    #[serde(rename = "yes-no/1")]
    YesNo {
        instructions: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        image_assets: Option<BTreeMap<String, String>>,
        criteria_true: String,
        criteria_false: String,
        pass_below: f64,
        fail_at_or_above: f64,
        max_request_bytes: Option<u64>,
        /// Map provider state field names to JSON Pointers in the retained evidence frame.
        #[serde(skip_serializing_if = "Option::is_none")]
        state_projection: Option<BTreeMap<String, StateField>>,
        /// Each group requires at least one non-null projected field before dispatch.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        state_required_any: Vec<Vec<String>>,
    },
    /// A model question answered by choosing one named option.
    #[serde(rename = "choice/1")]
    Choice {
        instructions: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        image_assets: Option<BTreeMap<String, String>>,
        options: BTreeMap<String, ChoiceOption>,
        min_choice_probability: f64,
        min_confidence: f64,
        max_request_bytes: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        state_projection: Option<BTreeMap<String, StateField>>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        state_required_any: Vec<Vec<String>>,
    },
    /// A model task that returns declared fields for later questions to use. It makes no pass or
    /// fail suggestion of its own.
    #[serde(rename = "extract/1")]
    Extract {
        instructions: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        image_assets: Option<BTreeMap<String, String>>,
        fields: BTreeMap<String, ExtractField>,
        max_request_bytes: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        state_projection: Option<BTreeMap<String, StateField>>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        state_required_any: Vec<Vec<String>>,
    },
    /// A normalized image location supplied to later checks, without a policy verdict.
    #[serde(rename = "box/1")]
    Box {
        instructions: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        image_assets: Option<BTreeMap<String, String>>,
        max_request_bytes: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        state_projection: Option<BTreeMap<String, StateField>>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        state_required_any: Vec<Vec<String>>,
    },
}

impl Check {
    pub(crate) fn image_assets(&self) -> Option<&BTreeMap<String, String>> {
        match self {
            Self::YesNo { image_assets, .. }
            | Self::Choice { image_assets, .. }
            | Self::Extract { image_assets, .. }
            | Self::Box { image_assets, .. } => image_assets.as_ref(),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SyntaxLanguage {
    Bash,
    Zsh,
    Powershell,
    Python,
    Rust,
    Verus,
    Tlaplus,
}

/// Written relationships only; no definition expansion or proof checking.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum TlaplusPredicate {
    DirectAlias {
        reference_pointer: String,
    },
    PositiveConjunct {
        reference_pointer: String,
    },
    WeakFairness {
        action_pointer: String,
        subscript_pointer: String,
    },
}

/// Per-helper limits; scan-wide input and evidence limits still apply.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct SyntaxLimits {
    pub input_bytes: u64,
    pub nodes: u64,
    pub captures: u64,
    pub output_bytes: u64,
    pub timeout_ms: u64,
    pub match_limit: u32,
}

impl Default for SyntaxLimits {
    fn default() -> Self {
        Self {
            input_bytes: 1024 * 1024,
            nodes: 100_000,
            captures: 1_000,
            output_bytes: 1024 * 1024,
            timeout_ms: 2_000,
            match_limit: 256,
        }
    }
}

/// A provider state field: a JSON Pointer, optional value or unique named syntax capture text.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(untagged, deny_unknown_fields)]
pub enum StateField {
    Pointer(String),
    Capture {
        pointer: String,
        /// Select exactly one named syntax capture's nonempty source text.
        capture: String,
        optional: bool,
    },
    Declared {
        pointer: String,
        /// An absent optional value is sent as null instead of refusing the request.
        optional: bool,
    },
}

impl StateField {
    pub(crate) fn pointer(&self) -> &str {
        match self {
            Self::Pointer(pointer)
            | Self::Declared { pointer, .. }
            | Self::Capture { pointer, .. } => pointer,
        }
    }

    pub(crate) fn optional(&self) -> bool {
        matches!(
            self,
            Self::Declared { optional: true, .. } | Self::Capture { optional: true, .. }
        )
    }

    pub(crate) fn capture_name(&self) -> Option<&str> {
        match self {
            Self::Capture { capture, .. } => Some(capture),
            _ => None,
        }
    }
}

/// One field an extraction task must return.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExtractField {
    #[serde(rename = "type")]
    pub kind: ExtractType,
    pub description: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtractType {
    String,
    Boolean,
    Number,
    StringList,
    /// Text that must occur verbatim in the evidence sent to the model.
    Quote,
    /// A list of texts that must each occur verbatim in that evidence.
    QuoteList,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CommandProgram {
    /// Lowercase executable names compared with the program name's final path component.
    pub executables: Vec<String>,
    /// Single characters that introduce an option.
    pub option_prefixes: Vec<String>,
    /// Whether a doubled prefix character, such as `--`, introduces the same option.
    pub repeated_prefix: bool,
    /// Checked in order; the first matching option wins.
    pub options: Vec<CommandOption>,
    /// Handling of an option-like argument that matches no declared option.
    pub unmatched: CommandValue,
    /// Handling of an argument that is not option-like.
    pub positional: CommandValue,
    /// cmd.exe `start`: a first quoted positional argument is a window title, not a program.
    #[serde(default)]
    pub title_argument: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CommandOption {
    pub name: String,
    pub matches: Vec<OptionWord>,
    pub value: CommandValue,
}

/// An argument matches when it is a case-insensitive prefix of `word` at least as long as
/// `shortest`. For `cmd_command`, the argument must start with `word`.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OptionWord {
    pub word: String,
    pub shortest: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CommandValue {
    /// A switch without a value, or an ignored argument.
    None,
    /// The next argument is the value.
    Value,
    /// This and every later argument belong to the invoked script or command text.
    Rest,
    /// The remainder of the raw line is a cmd.exe command, as documented for `/C` and `/K`.
    CmdCommand,
    /// cmd.exe `/S`: always strip the outer quotes of a later `/C` or `/K` remainder.
    CmdStripQuotes,
    /// This argument and the rest of the raw line form another command line, as for launchers
    /// such as `start`, `call` or `conhost`.
    Launch,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CommandPredicate {
    /// Fail if any interpreted command invokes one of these programs.
    Invokes { programs: Vec<String> },
    /// Fail if an invocation of one of these programs binds this option, with a value when it takes one.
    Option {
        programs: Vec<String>,
        option: String,
    },
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ChoiceOption {
    pub description: String,
    pub result: ResultState,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum MarkdownPredicate {
    /// Fail if a listed word or phrase occurs in rendered prose.
    ForbiddenTerms { terms: Vec<String> },
    /// Fail if visible prose text has CommonMark strong emphasis.
    ProseBold,
    /// Fail if any CommonMark list has this many direct items.
    ListLength { forbidden_length: usize },
    /// Fail if any prose paragraph lacks either required sentence length.
    ParagraphSentenceLengths {
        shorter_than: usize,
        longer_than: usize,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum YaraObservation {
    Match,
    NoMatch,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum JsonObservation {
    Equal,
    Unequal,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Applicability {
    /// Raw bytes use `*` or the exact input filename; inventory uses exact kinds or `*`.
    pub include: Vec<String>,
    pub exclude: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Fixtures {
    pub fail: Vec<Fixture>,
    pub pass: Vec<Fixture>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Fixture {
    pub path: String,
    pub corpus_revision: String,
    pub source_sha256: String,
    pub evidence_sha256: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub id: String,
    pub select: Vec<String>,
    pub block_on: Vec<ResultState>,
    pub allowed_egress: Vec<String>,
    /// Requirements this profile must cover; absent means every declared requirement.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requirements: Option<Vec<String>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResultState {
    Pass,
    Fail,
    Review,
    Notapplicable,
    NotEvaluated,
    Error,
}

impl ResultState {
    pub const ALL: [Self; 6] = [
        Self::Pass,
        Self::Fail,
        Self::Review,
        Self::Notapplicable,
        Self::NotEvaluated,
        Self::Error,
    ];
    pub(crate) fn ordinal(self) -> u64 {
        self as u64
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    pub targets: usize,
    pub manifest_work: usize,
    pub checks: u64,
    pub evidence_bytes: u64,
    pub provider_calls: u64,
    pub request_bytes: u64,
    pub input_bytes: u64,
    pub fixture_checks: u64,
    pub fixture_bytes: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            targets: 10_000,
            manifest_work: 100_000,
            checks: 100_000,
            evidence_bytes: 32 * 1024 * 1024,
            provider_calls: 100,
            request_bytes: 1024 * 1024,
            input_bytes: 16 * 1024 * 1024,
            fixture_checks: 1_000,
            fixture_bytes: 16 * 1024 * 1024,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct BaselineIdentity {
    pub id: String,
    pub version: String,
    pub sha256: String,
}
#[derive(Debug, Clone, Serialize)]
pub struct RuleIdentity {
    pub id: String,
    pub revision: String,
}
#[derive(Debug, Clone, Serialize)]
pub struct SourceIdentity {
    pub binding: String,
    pub snapshot_id: String,
    pub input_sha256: String,
    pub serializer: String,
    pub metadata: Value,
}
#[derive(Debug, Clone, Serialize)]
pub struct TargetIdentity {
    pub id: String,
    pub kind: String,
    pub sha256: String,
    pub metadata: Value,
}
#[derive(Debug, Clone, Serialize)]
pub struct EvidenceIdentity {
    pub builder: String,
    pub revision: String,
    pub sha256: String,
    /// Exact retained bytes; see `encoded_bytes`.
    #[serde(serialize_with = "serialize_bytes")]
    pub bytes: Vec<u8>,
}

/// Retained bytes in reports: `{"encoding":"utf-8","text":...}` when the bytes are valid UTF-8,
/// otherwise `{"encoding":"hex","data":...}` with lowercase hexadecimal digits.
pub(crate) fn encoded_bytes(bytes: &[u8]) -> Value {
    match std::str::from_utf8(bytes) {
        Ok(text) => serde_json::json!({"encoding":"utf-8","text":text}),
        Err(_) => serde_json::json!({"encoding":"hex",
            "data":bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()}),
    }
}

fn serialize_bytes<S: serde::Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
    encoded_bytes(bytes).serialize(serializer)
}
#[derive(Debug, Clone, Serialize)]
pub struct EvaluatorIdentity {
    pub binding: String,
    pub version: String,
    pub contract: String,
}
#[derive(Debug, Clone, Serialize)]
pub struct Record {
    pub schema: String,
    pub scan_id: String,
    pub check_id: String,
    pub baseline: BaselineIdentity,
    pub profile: String,
    pub rule: RuleIdentity,
    pub source: SourceIdentity,
    pub target: TargetIdentity,
    pub evidence: Option<EvidenceIdentity>,
    pub evaluator: EvaluatorIdentity,
    pub observation: Option<Value>,
    pub result: ResultState,
    pub reason: Option<String>,
    pub run_at_unix_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Clear,
    Finding,
    Unresolved,
}

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub schema: String,
    pub scan_id: String,
    pub baseline: BaselineIdentity,
    pub profile: String,
    pub source: SourceIdentity,
    pub limits: Limits,
    pub target_count: usize,
    pub work_count: usize,
    pub manifest_sha256: String,
    #[serde(serialize_with = "serialize_bytes")]
    pub manifest_bytes: Vec<u8>,
    pub records: Vec<Record>,
    pub excluded: Vec<String>,
    pub counts: BTreeMap<ResultState, u64>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub requirements: Vec<RequirementCoverage>,
    pub outcome: Outcome,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outcome_reason: Option<String>,
    pub experimental: bool,
    pub usage: Usage,
    pub fixture_usage: Usage,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub model_usage: BTreeMap<String, Usage>,
}

/// How completely the scan checked one declared requirement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RequirementStatus {
    /// Every applicable linked result passed.
    Satisfied,
    /// A linked result failed or needs review.
    Finding,
    /// No rule checks this requirement.
    Missing,
    /// Rules check it, but the profile selected none of them.
    Unasked,
    /// A selected rule was written against another requirement revision.
    Stale,
    /// No selected linked rule applied to the supplied evidence.
    Unsupported,
    /// A linked result is an error or was not evaluated.
    Unresolved,
    /// The profile does not require this requirement.
    NotRequired,
}

impl RequirementStatus {
    pub fn blocks(self) -> bool {
        !matches!(self, Self::Satisfied | Self::Finding | Self::NotRequired)
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Satisfied => "satisfied",
            Self::Finding => "finding",
            Self::Missing => "missing",
            Self::Unasked => "unasked",
            Self::Stale => "stale",
            Self::Unsupported => "unsupported",
            Self::Unresolved => "unresolved",
            Self::NotRequired => "not_required",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct RequirementCoverage {
    pub id: String,
    pub revision: String,
    pub title: String,
    pub status: RequirementStatus,
    /// Linked rules selected by this profile.
    pub rules: Vec<String>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub counts: BTreeMap<ResultState, u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Usage {
    pub checks: u64,
    pub evidence_bytes: u64,
    pub provider_calls: u64,
    /// Answers taken from earlier reports' identical exchanges; no provider call was made.
    #[serde(skip_serializing_if = "is_zero")]
    pub reused_exchanges: u64,
}

fn is_zero(value: &u64) -> bool {
    *value == 0
}

#[derive(Debug, Clone, Serialize)]
pub struct PublicationReceipt {
    pub scan_id: String,
    pub report_sha256: String,
    pub destination: String,
    pub acknowledgment: String,
}
