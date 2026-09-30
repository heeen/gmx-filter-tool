//! The editable rules file: one `[[rule]]` table per rule, in rule order.
//!
//! Conditions and actions are typed TOML (`{ from.contains = "x" }`, `{ move = "INBOX/X" }`); anything
//! they cannot express is kept as JSON so it survives unchanged.

use std::fmt::Write as _;

use serde::{Deserialize, Deserializer, Serialize, de::Error as _};
use serde_json::Value;

use crate::{
    Action, Comparator, Condition, Effect, Error, HeaderField, KnownAction, KnownCondition, Mode,
    PriorityLevel, Result, Rule, Test, actions, condition, effects_of, spec::parse_size, tests_of,
};

const HEADER: &str = r#"# gmxf rules v2. File order is rule order. A rule is matched to the server by `id`, else by `name`.
#
#   from.contains = "x"     or ["x", "y"]: one row per value. Fields from | to | to-cc | subject, operators
#                           contains | not-contains | is | is-not | [not-]starts-with | [not-]ends-with
#   match = "any" | "all"   whether one or every row must hold (default "any")
#   when  = [ { from.contains = "x" }      from | to | to-cc | subject  .  contains | not-contains | is | is-not
#             { size.gt = "5MB" }            | starts-with | not-starts-with | ends-with | not-ends-with
#             { priority.is = "high" }     size . gt | lt  ("500KB", "5MB" or bytes);  priority . is | is-not
#             { contact = "saved" }        contact = saved | not-saved;  "all-new"
#   then  = [ { move = "INBOX/X" }, { copy = "INBOX/X" }, "read", "delete",
#             { forward = "a@b.de" }, { notify = "a@b.de" } ]
#   stop  = true            false lets later rules see the mail as well
#   condition_json / actions_json   raw API JSON for what the rows above cannot express
"#;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
enum MatchMode {
    #[default]
    Any,
    All,
}

impl From<MatchMode> for Mode {
    fn from(m: MatchMode) -> Self {
        match m {
            MatchMode::Any => Mode::Any,
            MatchMode::All => Mode::All,
        }
    }
}

impl From<Mode> for MatchMode {
    fn from(m: Mode) -> Self {
        match m {
            Mode::Any => MatchMode::Any,
            Mode::All => MatchMode::All,
        }
    }
}

/// One condition row: `{ <field>.<op> = <value> }` or a bare string for value-less rows.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
enum When {
    AllNew,
    From(HeaderOp),
    To(HeaderOp),
    ToCc(HeaderOp),
    Subject(HeaderOp),
    Size(SizeOp),
    Priority(PriorityOp),
    Contact(Contact),
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
enum HeaderOp {
    Contains(String),
    NotContains(String),
    Is(String),
    IsNot(String),
    StartsWith(String),
    NotStartsWith(String),
    EndsWith(String),
    NotEndsWith(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
enum SizeOp {
    Gt(Bytes),
    Lt(Bytes),
}

/// A byte count, written as `"5MB"`, `"300KB"`, `"120B"` or a plain integer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Bytes(u64);

impl<'de> Deserialize<'de> for Bytes {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            Count(u64),
            Text(String),
        }
        match Raw::deserialize(d)? {
            Raw::Count(n) => Ok(Bytes(n)),
            Raw::Text(s) => parse_size(&s).map(Bytes).ok_or_else(|| {
                D::Error::custom(format!("{s:?} is not a size like \"500KB\" or \"5MB\""))
            }),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
enum PriorityOp {
    Is(Level),
    IsNot(Level),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
enum Level {
    Low,
    Normal,
    High,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
enum Contact {
    Saved,
    NotSaved,
}

/// `"x"` or `["x", "y"]`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Values(Vec<String>);

impl<'de> Deserialize<'de> for Values {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = Values;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a string or an array of strings")
            }
            fn visit_str<E: serde::de::Error>(self, v: &str) -> std::result::Result<Values, E> {
                Ok(Values(vec![v.to_owned()]))
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> std::result::Result<Values, A::Error> {
                let mut out = Vec::new();
                while let Some(v) = seq.next_element::<String>()? {
                    out.push(v);
                }
                if out.is_empty() {
                    return Err(A::Error::custom(
                        "the list is empty; remove the key instead",
                    ));
                }
                Ok(Values(out))
            }
        }
        d.deserialize_any(V)
    }
}

/// Builds a condition row for one header field.
type Field = fn(HeaderOp) -> When;
/// Builds a header operation from its value.
type OpFn = fn(String) -> HeaderOp;

/// `from.contains = ...` and friends directly in a rule: one row per value.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
struct HeaderGroup {
    contains: Option<Values>,
    not_contains: Option<Values>,
    is: Option<Values>,
    is_not: Option<Values>,
    starts_with: Option<Values>,
    not_starts_with: Option<Values>,
    ends_with: Option<Values>,
    not_ends_with: Option<Values>,
}

impl HeaderGroup {
    fn rows(&self, field: Field) -> Vec<When> {
        let ops: [(&Option<Values>, OpFn); 8] = [
            (&self.contains, HeaderOp::Contains),
            (&self.not_contains, HeaderOp::NotContains),
            (&self.is, HeaderOp::Is),
            (&self.is_not, HeaderOp::IsNot),
            (&self.starts_with, HeaderOp::StartsWith),
            (&self.not_starts_with, HeaderOp::NotStartsWith),
            (&self.ends_with, HeaderOp::EndsWith),
            (&self.not_ends_with, HeaderOp::NotEndsWith),
        ];
        ops.into_iter()
            .flat_map(|(values, op)| values.iter().flat_map(|v| v.0.clone()).map(op))
            .map(field)
            .collect()
    }
}

/// Header fields in the order the grouped form is written.
const GROUPS: [(&str, Field); 4] = [
    ("from", When::From),
    ("to", When::To),
    ("to-cc", When::ToCc),
    ("subject", When::Subject),
];

/// One action row: `{ <action> = <target> }` or a bare string for target-less actions.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum Then {
    Move(String),
    Copy(String),
    Read,
    Delete,
    Forward(String),
    Notify(String),
}

impl HeaderOp {
    fn new(comparator: &Comparator, negated: bool, value: String) -> Option<Self> {
        Some(match (comparator, negated) {
            (Comparator::Contains, false) => HeaderOp::Contains(value),
            (Comparator::Contains, true) => HeaderOp::NotContains(value),
            (Comparator::Is, false) => HeaderOp::Is(value),
            (Comparator::Is, true) => HeaderOp::IsNot(value),
            (Comparator::StartsWith, false) => HeaderOp::StartsWith(value),
            (Comparator::StartsWith, true) => HeaderOp::NotStartsWith(value),
            (Comparator::EndsWith, false) => HeaderOp::EndsWith(value),
            (Comparator::EndsWith, true) => HeaderOp::NotEndsWith(value),
            (Comparator::Other(_), _) => return None,
        })
    }

    fn parts(&self) -> (&'static str, Comparator, bool, &str) {
        match self {
            HeaderOp::Contains(v) => ("contains", Comparator::Contains, false, v),
            HeaderOp::NotContains(v) => ("not-contains", Comparator::Contains, true, v),
            HeaderOp::Is(v) => ("is", Comparator::Is, false, v),
            HeaderOp::IsNot(v) => ("is-not", Comparator::Is, true, v),
            HeaderOp::StartsWith(v) => ("starts-with", Comparator::StartsWith, false, v),
            HeaderOp::NotStartsWith(v) => ("not-starts-with", Comparator::StartsWith, true, v),
            HeaderOp::EndsWith(v) => ("ends-with", Comparator::EndsWith, false, v),
            HeaderOp::NotEndsWith(v) => ("not-ends-with", Comparator::EndsWith, true, v),
        }
    }
}

impl Level {
    fn of(level: &PriorityLevel) -> Option<Self> {
        match level {
            PriorityLevel::Low => Some(Level::Low),
            PriorityLevel::Normal => Some(Level::Normal),
            PriorityLevel::High => Some(Level::High),
            PriorityLevel::Other(_) => None,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Level::Low => "low",
            Level::Normal => "normal",
            Level::High => "high",
        }
    }

    fn level(self) -> PriorityLevel {
        match self {
            Level::Low => PriorityLevel::Low,
            Level::Normal => PriorityLevel::Normal,
            Level::High => PriorityLevel::High,
        }
    }
}

impl When {
    /// `None` for values the file syntax has no name for (unknown comparators or levels).
    fn of(test: &Test) -> Option<Self> {
        Some(match test {
            Test::AllNewEmails => When::AllNew,
            Test::Header {
                field,
                comparator,
                negated,
                value,
            } => {
                let op = HeaderOp::new(comparator, *negated, value.clone())?;
                match field {
                    HeaderField::From => When::From(op),
                    HeaderField::To => When::To(op),
                    HeaderField::ToCc => When::ToCc(op),
                    HeaderField::Subject => When::Subject(op),
                }
            }
            Test::Size { larger, bytes } => When::Size(if *larger {
                SizeOp::Gt(Bytes(*bytes))
            } else {
                SizeOp::Lt(Bytes(*bytes))
            }),
            Test::Priority { negated, level } => {
                let level = Level::of(level)?;
                When::Priority(if *negated {
                    PriorityOp::IsNot(level)
                } else {
                    PriorityOp::Is(level)
                })
            }
            Test::Contact { saved } => When::Contact(if *saved {
                Contact::Saved
            } else {
                Contact::NotSaved
            }),
        })
    }

    fn test(&self) -> Test {
        let header = |field, op: &HeaderOp| {
            let (_, comparator, negated, value) = op.parts();
            Test::Header {
                field,
                comparator,
                negated,
                value: value.to_owned(),
            }
        };
        match self {
            When::AllNew => Test::AllNewEmails,
            When::From(op) => header(HeaderField::From, op),
            When::To(op) => header(HeaderField::To, op),
            When::ToCc(op) => header(HeaderField::ToCc, op),
            When::Subject(op) => header(HeaderField::Subject, op),
            When::Size(SizeOp::Gt(Bytes(bytes))) => Test::Size {
                larger: true,
                bytes: *bytes,
            },
            When::Size(SizeOp::Lt(Bytes(bytes))) => Test::Size {
                larger: false,
                bytes: *bytes,
            },
            When::Priority(PriorityOp::Is(l)) => Test::Priority {
                negated: false,
                level: l.level(),
            },
            When::Priority(PriorityOp::IsNot(l)) => Test::Priority {
                negated: true,
                level: l.level(),
            },
            When::Contact(c) => Test::Contact {
                saved: *c == Contact::Saved,
            },
        }
    }

    /// The row as TOML: `{ from.contains = "x" }` or `"all-new"`.
    fn toml(&self) -> String {
        let (field, op, value) = match self {
            When::AllNew => return toml_str("all-new"),
            When::Contact(c) => {
                let v = if *c == Contact::Saved {
                    "saved"
                } else {
                    "not-saved"
                };
                return format!("{{ contact = {} }}", toml_str(v));
            }
            When::From(op) | When::To(op) | When::ToCc(op) | When::Subject(op) => {
                let field = match self {
                    When::From(_) => "from",
                    When::To(_) => "to",
                    When::ToCc(_) => "to-cc",
                    _ => "subject",
                };
                let (name, _, _, value) = op.parts();
                (field, name, toml_str(value))
            }
            When::Size(op) => {
                let (name, Bytes(b)) = match op {
                    SizeOp::Gt(b) => ("gt", b),
                    SizeOp::Lt(b) => ("lt", b),
                };
                ("size", name, size_toml(*b))
            }
            When::Priority(op) => {
                let (name, level) = match op {
                    PriorityOp::Is(l) => ("is", l),
                    PriorityOp::IsNot(l) => ("is-not", l),
                };
                ("priority", name, toml_str(level.name()))
            }
        };
        format!("{{ {field}.{op} = {value} }}")
    }
}

fn size_toml(bytes: u64) -> String {
    const KB: u64 = 1024;
    match bytes {
        b if b > 0 && b % (KB * KB) == 0 => toml_str(&format!("{}MB", b / (KB * KB))),
        b if b > 0 && b % KB == 0 => toml_str(&format!("{}KB", b / KB)),
        b => b.to_string(),
    }
}

impl Then {
    fn of(effect: &Effect) -> Self {
        match effect.clone() {
            Effect::Move(f) => Then::Move(f),
            Effect::Copy(f) => Then::Copy(f),
            Effect::MarkRead => Then::Read,
            Effect::Delete => Then::Delete,
            Effect::Forward(a) => Then::Forward(a),
            Effect::Notify(a) => Then::Notify(a),
        }
    }

    fn effect(&self) -> Effect {
        match self.clone() {
            Then::Move(f) => Effect::Move(f),
            Then::Copy(f) => Effect::Copy(f),
            Then::Read => Effect::MarkRead,
            Then::Delete => Effect::Delete,
            Then::Forward(a) => Effect::Forward(a),
            Then::Notify(a) => Effect::Notify(a),
        }
    }

    fn toml(&self) -> String {
        let (key, value) = match self {
            Then::Read => return toml_str("read"),
            Then::Delete => return toml_str("delete"),
            Then::Move(v) => ("move", v),
            Then::Copy(v) => ("copy", v),
            Then::Forward(v) => ("forward", v),
            Then::Notify(v) => ("notify", v),
        };
        format!("{{ {key} = {} }}", toml_str(value))
    }
}

const fn yes() -> bool {
    true
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleEntry {
    #[serde(default)]
    id: Option<String>,
    name: String,
    #[serde(default = "yes")]
    active: bool,
    #[serde(default, rename = "match")]
    mode: MatchMode,
    #[serde(default)]
    from: Option<HeaderGroup>,
    #[serde(default)]
    to: Option<HeaderGroup>,
    #[serde(default, rename = "to-cc")]
    to_cc: Option<HeaderGroup>,
    #[serde(default)]
    subject: Option<HeaderGroup>,
    #[serde(default)]
    when: Vec<When>,
    #[serde(default)]
    then: Vec<Then>,
    #[serde(default)]
    stop: Option<bool>,
    #[serde(default)]
    condition_json: Option<String>,
    #[serde(default)]
    actions_json: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleFile {
    #[serde(default)]
    rule: Vec<RuleEntry>,
}

/// A rule as written in the file, already parsed and built.
#[derive(Debug, Clone)]
pub struct DesiredRule {
    pub id: Option<String>,
    pub name: String,
    pub active: bool,
    pub condition: Condition,
    pub actions: Vec<Action>,
    /// Normalized form, comparable with [`entry_of`] of a server rule.
    canon: RuleEntry,
}

/// Row order does not change what a rule matches ("any" or "all" of them).
fn sorted_rows(rows: &[When]) -> Vec<When> {
    let mut rows = rows.to_vec();
    rows.sort();
    rows
}

fn sorted(mut entry: RuleEntry) -> RuleEntry {
    entry.when.sort();
    entry
}

fn show_when(rows: &[When], sep: &str) -> String {
    rows.iter()
        .map(|w| w.test().to_string())
        .collect::<Vec<_>>()
        .join(sep)
}

fn show_then(rows: &[Then]) -> String {
    rows.iter()
        .map(|t| t.effect().to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

impl DesiredRule {
    /// One line for previews, in the `--when` / `--then` wording.
    pub fn summary(&self) -> String {
        let c = &self.canon;
        let when = if c.when.is_empty() {
            "raw condition".to_owned()
        } else {
            show_when(
                &c.when,
                if c.mode == MatchMode::All {
                    " AND "
                } else {
                    " OR "
                },
            )
        };
        let then = if c.then.is_empty() {
            "raw actions".to_owned()
        } else {
            let stop = if c.stop == Some(false) { "" } else { ", stop" };
            format!("{}{stop}", show_then(&c.then))
        };
        format!("if {when} -> {then}")
    }

    /// True when the server rule already says the same, however the file spells it.
    pub fn same_as(&self, remote: &Rule) -> bool {
        let mut theirs = entry_of(remote);
        theirs.id = self.canon.id.clone();
        sorted(theirs) == sorted(self.canon.clone())
    }

    /// Differences to `remote`, for display: `(field, before, after)`.
    pub fn changes(&self, remote: &Rule) -> Vec<(&'static str, String, String)> {
        let theirs = entry_of(remote);
        let ours = &self.canon;
        let mut out = Vec::new();
        let mut diff = |field, a: String, b: String| {
            if a != b {
                out.push((field, a, b));
            }
        };
        diff("name", theirs.name.clone(), ours.name.clone());
        diff("active", theirs.active.to_string(), ours.active.to_string());
        diff(
            "match",
            format!("{:?}", theirs.mode),
            format!("{:?}", ours.mode),
        );
        let (before, after) = if sorted_rows(&theirs.when) == sorted_rows(&ours.when) {
            (String::new(), String::new())
        } else {
            (show_when(&theirs.when, "; "), show_when(&ours.when, "; "))
        };
        diff("when", before, after);
        diff("then", show_then(&theirs.then), show_then(&ours.then));
        diff(
            "stop",
            theirs.stop.map_or(String::new(), |s| s.to_string()),
            ours.stop.map_or(String::new(), |s| s.to_string()),
        );
        diff(
            "condition_json",
            theirs.condition_json.unwrap_or_default(),
            ours.condition_json.clone().unwrap_or_default(),
        );
        diff(
            "actions_json",
            theirs.actions_json.unwrap_or_default(),
            ours.actions_json.clone().unwrap_or_default(),
        );
        out
    }

    /// The rule to send: `remote` with this file's edits applied, or a new rule.
    /// Forward and notify targets that already exist keep their confirmation state.
    pub fn to_rule(&self, remote: Option<&Rule>) -> Rule {
        let mut rule = remote
            .cloned()
            .unwrap_or_else(|| Rule::new(&self.name, self.condition.clone(), Vec::new()));
        rule.rule_name.clone_from(&self.name);
        rule.active = self.active;
        rule.condition = self.condition.clone();
        rule.actions = self
            .actions
            .iter()
            .map(|a| keep_confirmation(a, remote.map_or(&[][..], |r| &r.actions)))
            .collect();
        rule
    }
}

fn keep_confirmation(action: &Action, existing: &[Action]) -> Action {
    let Action::Known(new) = action else {
        return action.clone();
    };
    let found = existing.iter().find_map(|old| match (new, old) {
        (
            KnownAction::CopyForward { receivers, .. },
            Action::Known(KnownAction::CopyForward {
                receivers: r,
                pending,
            }),
        ) if receivers == r => Some(*pending),
        (
            KnownAction::TemplatedEmailNotify { pagers, .. },
            Action::Known(KnownAction::TemplatedEmailNotify { pagers: p, pending }),
        ) if pagers == p => Some(*pending),
        _ => None,
    });
    let Some(kept) = found else {
        return action.clone();
    };
    Action::Known(match new.clone() {
        KnownAction::CopyForward { receivers, .. } => KnownAction::CopyForward {
            pending: kept,
            receivers,
        },
        KnownAction::TemplatedEmailNotify { pagers, .. } => KnownAction::TemplatedEmailNotify {
            pending: kept,
            pagers,
        },
        other => other,
    })
}

/// Compact JSON with sorted keys, so equal values compare equal however they were produced.
fn canonical_json(value: &impl Serialize) -> Option<String> {
    serde_json::to_value(value).ok().map(|v| v.to_string())
}

fn compact(json: &str) -> std::result::Result<String, serde_json::Error> {
    serde_json::from_str::<Value>(json).map(|v| v.to_string())
}

/// The text form of a server rule; the inverse of building a rule from an entry.
fn entry_of(rule: &Rule) -> RuleEntry {
    let rows = tests_of(&rule.condition).and_then(|(mode, tests)| {
        let rows = tests.iter().map(When::of).collect::<Option<Vec<_>>>()?;
        // `match` only means something with several rows
        let mode = if rows.len() < 2 {
            MatchMode::Any
        } else {
            mode.into()
        };
        Some((mode, rows))
    });
    let (mode, when, condition_json) = match rows {
        Some((mode, rows)) => (mode, rows, None),
        None => (MatchMode::Any, Vec::new(), canonical_json(&rule.condition)),
    };
    let (then, stop, actions_json) = match effects_of(&rule.actions) {
        Some((effects, stop)) => (effects.iter().map(Then::of).collect(), Some(stop), None),
        None => (Vec::new(), None, canonical_json(&rule.actions)),
    };
    RuleEntry {
        id: rule.rule_id.clone(),
        name: rule.rule_name.clone(),
        active: rule.active,
        mode,
        from: None,
        to: None,
        to_cc: None,
        subject: None,
        when,
        then,
        stop,
        condition_json,
        actions_json,
    }
}

/// Why the web UI will not let you edit a rule, or which state deserves a look.
pub fn rule_notes(rule: &Rule) -> Vec<&'static str> {
    let mut notes = Vec::new();
    let has_recipient = matches!(
        &rule.condition,
        Condition::Known(KnownCondition::MultiToComparator { .. })
    ) || matches!(&rule.condition, Condition::Known(KnownCondition::AnyOf { conditions } | KnownCondition::AllOf { conditions })
            if conditions.iter().any(|c| matches!(c, Condition::Known(KnownCondition::MultiToComparator { .. }))));
    let forwards = rule
        .actions
        .iter()
        .any(|a| matches!(a, Action::Known(KnownAction::CopyForward { .. })));
    if has_recipient && forwards {
        notes.push("read-only in the web UI (recipient condition with a forward action)");
    }
    if rule
        .actions
        .iter()
        .any(|a| matches!(a, Action::Other(v) if v["type"] == "ExcludeFromSpamFilter"))
    {
        notes.push("legacy rule: excludes from the spam filter, not editable in the web UI");
    }
    let unconfirmed = rule.actions.iter().any(|a| {
        matches!(
            a,
            Action::Known(
                KnownAction::CopyForward { pending: true, .. }
                    | KnownAction::TemplatedEmailNotify { pending: true, .. }
            )
        )
    });
    if unconfirmed {
        notes.push("a forward/notify target has not confirmed yet");
    }
    notes
}

fn toml_str(s: &str) -> String {
    toml::Value::String(s.to_owned()).to_string()
}

/// `key = [...]` with already rendered TOML items, one per line when there are several.
fn toml_array(items: &[String], out: &mut String, key: &str) {
    match items {
        [] => {}
        [one] => {
            let _ = writeln!(out, "{key} = [{one}]");
        }
        many => {
            let _ = writeln!(out, "{key} = [");
            for item in many {
                let _ = writeln!(out, "  {item},");
            }
            out.push_str("]\n");
        }
    }
}

fn toml_json(key: &str, json: &str, out: &mut String) {
    let pretty = serde_json::from_str::<Value>(json)
        .and_then(|v| serde_json::to_string_pretty(&v))
        .unwrap_or_else(|_| json.to_owned());
    if pretty.contains("'''") {
        let _ = writeln!(out, "{key} = {}", toml_str(&pretty));
    } else {
        let _ = writeln!(out, "{key} = '''\n{pretty}\n'''");
    }
}

/// Header rows as `field.op = values` keys, the rest as `when = [...]`.
fn write_grouped(rows: &[When], out: &mut String) {
    for (field, variant) in GROUPS {
        let mut by_op: Vec<(&'static str, Vec<&str>)> = Vec::new();
        for row in rows {
            let op = match (row, variant(HeaderOp::Is(String::new()))) {
                (When::From(op), When::From(_))
                | (When::To(op), When::To(_))
                | (When::ToCc(op), When::ToCc(_))
                | (When::Subject(op), When::Subject(_)) => op,
                _ => continue,
            };
            let (name, _, _, value) = op.parts();
            match by_op.iter_mut().find(|(n, _)| *n == name) {
                Some((_, values)) => values.push(value),
                None => by_op.push((name, vec![value])),
            }
        }
        for (op, values) in by_op {
            let key = format!("{field}.{op}");
            let items: Vec<String> = values.iter().map(|v| toml_str(v)).collect();
            match &items[..] {
                [one] => {
                    let _ = writeln!(out, "{key} = {one}");
                }
                many if key.len() + many.iter().map(|i| i.len() + 2).sum::<usize>() <= 96 => {
                    let _ = writeln!(out, "{key} = [{}]", many.join(", "));
                }
                many => toml_array(many, out, &key),
            }
        }
    }
    let rest: Vec<String> = rows
        .iter()
        .filter(|r| {
            !matches!(
                r,
                When::From(_) | When::To(_) | When::ToCc(_) | When::Subject(_)
            )
        })
        .map(When::toml)
        .collect();
    toml_array(&rest, out, "when");
}

/// Renders the rules as a rules file.
pub fn export(rules: &[Rule]) -> String {
    let mut out = String::from(HEADER);
    for rule in rules {
        let entry = entry_of(rule);
        out.push('\n');
        for note in rule_notes(rule) {
            let _ = writeln!(out, "# {note}");
        }
        if entry.condition_json.is_some() || entry.actions_json.is_some() {
            out.push_str("# not expressible as when/then: edit the JSON or leave it as is\n");
        }
        out.push_str("[[rule]]\n");
        if let Some(id) = &entry.id {
            let _ = writeln!(out, "id = {}", toml_str(id));
        }
        let _ = writeln!(out, "name = {}", toml_str(&entry.name));
        let _ = writeln!(out, "active = {}", entry.active);
        if let Some(json) = &entry.condition_json {
            toml_json("condition_json", json, &mut out);
        } else {
            if entry.when.len() > 1 {
                let mode = if entry.mode == MatchMode::All {
                    "all"
                } else {
                    "any"
                };
                let _ = writeln!(out, "match = \"{mode}\"");
            }
            write_grouped(&entry.when, &mut out);
        }
        if let Some(json) = &entry.actions_json {
            toml_json("actions_json", json, &mut out);
        } else {
            let rows: Vec<String> = entry.then.iter().map(Then::toml).collect();
            toml_array(&rows, &mut out, "then");
            let _ = writeln!(out, "stop = {}", entry.stop.unwrap_or(true));
        }
    }
    out
}

/// Parses a rules file into the rules it asks for.
pub fn parse(text: &str) -> Result<Vec<DesiredRule>> {
    let file: RuleFile = toml::from_str(text).map_err(|e| {
        let hint = if uses_v1_strings(text) {
            "\nthis looks like a rules file from before v2 (rows as strings like \"from contains x\"); re-export it"
        } else {
            ""
        };
        Error::RuleFile(format!("{e}{hint}"))
    })?;
    file.rule
        .into_iter()
        .enumerate()
        .map(|(i, entry)| {
            build(entry).map_err(|e| Error::RuleFile(format!("rule #{}: {e}", i + 1)))
        })
        .collect()
}

/// v1 wrote rows as strings with blanks (`"from contains x"`); v2 only has blank-free bare strings.
fn uses_v1_strings(text: &str) -> bool {
    let Ok(table) = toml::from_str::<toml::Table>(text) else {
        return false;
    };
    let Some(rules) = table.get("rule").and_then(toml::Value::as_array) else {
        return false;
    };
    rules.iter().any(|r| {
        ["when", "then"].iter().any(|k| {
            r.get(k)
                .and_then(toml::Value::as_array)
                .is_some_and(|rows| {
                    rows.iter()
                        .any(|x| x.as_str().is_some_and(|s| s.contains(char::is_whitespace)))
                })
        })
    })
}

fn build(mut entry: RuleEntry) -> std::result::Result<DesiredRule, String> {
    let groups = [
        (&entry.from, When::From as Field),
        (&entry.to, When::To),
        (&entry.to_cc, When::ToCc),
        (&entry.subject, When::Subject),
    ];
    let mut rows: Vec<When> = groups
        .iter()
        .flat_map(|(g, field)| g.iter().flat_map(|g| g.rows(*field)))
        .collect();
    rows.append(&mut entry.when);
    entry.when = rows;
    (entry.from, entry.to, entry.to_cc, entry.subject) = (None, None, None, None);
    let ctx = |what: &str, e: &dyn std::fmt::Display| format!("{:?}: {what}: {e}", entry.name);
    let (condition, canon_when, canon_cond_json) = match (
        &entry.condition_json,
        entry.when.is_empty(),
    ) {
        (Some(_), false) => {
            return Err(ctx(
                "condition",
                &"use either condition rows or `condition_json`",
            ));
        }
        (Some(json), true) => {
            let value: Condition =
                serde_json::from_str(json).map_err(|e| ctx("condition_json", &e))?;
            let compact = compact(json).map_err(|e| ctx("condition_json", &e))?;
            (value, Vec::new(), Some(compact))
        }
        (None, true) => {
            return Err(ctx(
                "condition",
                &"needs at least one condition (e.g. `from.contains = \"x\"` or `when = [...]`)",
            ));
        }
        (None, false) => {
            let tests: Vec<Test> = entry.when.iter().map(When::test).collect();
            let built = condition(entry.mode.into(), &tests).map_err(|e| ctx("when", &e))?;
            (built, entry.when.clone(), None)
        }
    };
    let (actions_list, canon_then, canon_stop, canon_actions_json) =
        match (&entry.actions_json, entry.then.is_empty()) {
            (Some(_), false) => return Err(ctx("actions", &"use either `then` or `actions_json`")),
            (Some(_), true) if entry.stop.is_some() => {
                return Err(ctx("actions", &"`stop` belongs inside `actions_json`"));
            }
            (Some(json), true) => {
                let list: Vec<Action> =
                    serde_json::from_str(json).map_err(|e| ctx("actions_json", &e))?;
                let compact = compact(json).map_err(|e| ctx("actions_json", &e))?;
                (list, Vec::new(), None, Some(compact))
            }
            (None, true) => return Err(ctx("actions", &"needs at least one `then` row")),
            (None, false) => {
                let effects: Vec<Effect> = entry.then.iter().map(Then::effect).collect();
                let stop = entry.stop.unwrap_or(true);
                (actions(effects, stop), entry.then.clone(), Some(stop), None)
            }
        };
    let canon_when_len = canon_when.len();
    let canon = RuleEntry {
        id: entry.id.clone(),
        name: entry.name.clone(),
        active: entry.active,
        // `match` only means something with several `when` rows
        mode: if canon_when_len < 2 {
            MatchMode::Any
        } else {
            entry.mode
        },
        from: None,
        to: None,
        to_cc: None,
        subject: None,
        when: canon_when,
        then: canon_then,
        stop: canon_stop,
        condition_json: canon_cond_json,
        actions_json: canon_actions_json,
    };
    Ok(DesiredRule {
        id: entry.id,
        name: entry.name,
        active: entry.active,
        condition,
        actions: actions_list,
        canon,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use serde_json::json;

    use super::*;

    pub(crate) fn rules(v: Value) -> Vec<Rule> {
        serde_json::from_value(v).unwrap()
    }

    fn header(kind: &str, cmp: &str, key: &str, value: &str) -> Value {
        json!({"type": kind, "comparator": cmp, "inverted": false, key: value})
    }

    fn multi(kind: &str, headers: Vec<Value>) -> Value {
        json!({"type": kind, "operator": "OR", "inverted": false, "headerComparatorConditions": headers})
    }

    const TYPE: &str = "StoppingNamedOrderedConditionalMultiActionUser";

    /// The shapes found on a real account: legacy numeric ids, values under from/to/subject,
    /// `includeCcHeader`, a group of many values, an `AnyOf` of groups, a plain new-style rule.
    pub(crate) fn fixtures() -> Vec<Rule> {
        let mv =
            |folder: &str| json!([{"type": "MoveToFolder", "folder": folder}, {"type": "Stop"}]);
        rules(json!([
            {"type": TYPE, "ruleId": "5", "ruleName": "club-2", "active": true, "considerStopped": true,
             "uri": "https://backend/rest/Rule/User/5", "modified": "2025-02-07T10:33:21Z",
             "condition": multi("MultiFromComparator", vec![header("From", "CONTAINS", "from", "wiki@club-koeln.example")]),
             "actions": mv("INBOX/Club Köln")},
            {"type": TYPE, "ruleId": "4", "ruleName": "club köln", "active": true, "considerStopped": true,
             "condition": multi("MultiToComparator", vec![
                 json!({"type": "ToCc", "comparator": "CONTAINS", "inverted": false, "includeCcHeader": true, "to": "members@club-koeln.example"}),
                 json!({"type": "ToCc", "comparator": "CONTAINS", "inverted": false, "includeCcHeader": true, "to": "wiki@club-koeln.example"})]),
             "actions": mv("INBOX/Club Köln")},
            {"type": TYPE, "ruleId": "6", "ruleName": "unnamed", "active": true, "considerStopped": true,
             "condition": {"type": "AnyOf", "conditions": [
                 multi("MultiToComparator", vec![json!({"type": "ToCc", "comparator": "CONTAINS", "inverted": false, "includeCcHeader": true, "to": "volunteers@lists.uni.example"})]),
                 multi("MultiSubjectComparator", vec![header("Subject", "CONTAINS", "subject", "Makerspace-Volunteers")]),
                 multi("MultiFromComparator", vec![header("From", "CONTAINS", "from", "volunteers@makerspace.example")])]},
             "actions": mv("INBOX/Makerspace")},
            {"type": TYPE, "ruleId": "2", "ruleName": "chatter", "active": false, "considerStopped": true,
             "condition": multi("MultiFromComparator", vec![header("From", "CONTAINS", "from", "@chatter.example")]),
             "actions": mv("INBOX/chatter")},
            {"type": TYPE, "ruleId": "cef5ab49-8a55-48b3-b603-14303a79e7ca", "ruleName": "say \"hi\" \\ ünï", "active": true, "considerStopped": true,
             "condition": multi("MultiSubjectComparator", vec![header("Subject", "STARTS_WITH", "comparand", "[Firmware] it's")]),
             "actions": [{"type": "MoveToFolder", "folder": "INBOX/Firmware"}]},
        ]))
    }

    fn odd() -> Vec<Rule> {
        rules(json!([
            {"type": TYPE, "ruleId": "9", "ruleName": "odd", "active": true, "considerStopped": true,
             "condition": {"type": "Brand new", "x": [1, 2]},
             "actions": [{"type": "ExcludeFromSpamFilter"}, {"type": "Stop"}]},
            {"type": TYPE, "ruleId": "11", "ruleName": "not-either", "active": true, "considerStopped": true,
             "condition": {"type": "MultiFromComparator", "operator": "OR", "inverted": true, "headerComparatorConditions": [
                 {"type": "From", "comparator": "CONTAINS", "inverted": false, "comparand": "a"},
                 {"type": "From", "comparator": "CONTAINS", "inverted": false, "comparand": "b"}]},
             "actions": [{"type": "MarkSeen"}]},
            {"type": TYPE, "ruleId": "12", "ruleName": "explicit-false", "active": true, "considerStopped": true,
             "condition": multi("MultiToComparator", vec![json!({"type": "ToCc", "comparator": "CONTAINS", "inverted": false, "includeCcHeader": false, "comparand": "x@y.de"})]),
             "actions": [{"type": "MarkSeen"}]},
            {"type": TYPE, "ruleId": "10", "ruleName": "fwd", "active": true, "considerStopped": true,
             "condition": multi("MultiToComparator", vec![header("ToCc", "CONTAINS", "comparand", "me@gmx.de")]),
             "actions": [{"type": "CopyForward", "pending": false, "receivers": ["a@b.de"]},
                         {"type": "TemplatedEmailNotify", "pending": true, "pagers": ["c@d.de"]}]},
        ]))
    }

    #[test]
    fn export_then_parse_leaves_every_rule_unchanged() {
        for set in [fixtures(), odd()] {
            let text = export(&set);
            let desired = parse(&text).unwrap_or_else(|e| panic!("{e}\n{text}"));
            assert_eq!(desired.len(), set.len());
            for (d, r) in desired.iter().zip(&set) {
                assert!(
                    d.same_as(r),
                    "{} changed:\n{:?}\n{text}",
                    r.rule_name,
                    d.changes(r)
                );
                assert!(d.changes(r).is_empty());
            }
        }
    }

    #[test]
    fn output_is_readable() {
        let text = export(&fixtures());
        assert!(text.contains("id = \"5\""));
        assert!(text.contains("name = \"club köln\""));
        assert!(text.contains(
            "to-cc.contains = [\"members@club-koeln.example\", \"wiki@club-koeln.example\"]"
        ));
        assert!(
            !text.contains("match = \"any\"\nwhen = [{"),
            "no `match` for single rows"
        );
        assert!(text.contains("then = [{ move = \"INBOX/Club Köln\" }]"));
        assert!(text.contains("active = false"));
        assert!(text.contains("say \"hi\" \\ ünï") || text.contains("say \\\"hi\\\" \\\\ ünï"));
    }

    #[test]
    fn unexpressible_parts_are_kept_verbatim_and_flagged() {
        let set = odd();
        let text = export(&set);
        assert!(text.contains("# not expressible as when/then"));
        assert!(text.contains("condition_json = '''"));
        let d = parse(&text).unwrap();
        for i in [0, 1] {
            let rebuilt = d[i].to_rule(Some(&set[i]));
            assert_eq!(rebuilt.condition, set[i].condition);
            assert_eq!(rebuilt.actions, set[i].actions);
        }
        // a plain `to` written by the server with an explicit `includeCcHeader: false` stays readable
        assert!(text.contains("\nto.contains = \"x@y.de\"\n"));
    }

    #[test]
    fn notes_flag_readonly_legacy_and_unconfirmed() {
        let text = export(&odd());
        assert!(text.contains("# legacy rule"));
        assert!(text.contains("# read-only in the web UI"));
        assert!(text.contains("# a forward/notify target has not confirmed yet"));
    }

    #[test]
    fn edits_show_up_as_changes_and_keep_confirmation() {
        let set = odd();
        let text = export(&set)
            .replace("name = \"fwd\"", "name = \"forwarder\"")
            .replace("me@gmx.de", "you@gmx.de");
        let d = parse(&text).unwrap();
        let fields: Vec<_> = d[3].changes(&set[3]).into_iter().map(|c| c.0).collect();
        assert_eq!(fields, ["name", "when"]);
        let rule = d[3].to_rule(Some(&set[3]));
        assert_eq!(rule.rule_name, "forwarder");
        assert_eq!(rule.rule_id.as_deref(), Some("10"));
        // unchanged targets keep their state; new ones get the web UI defaults
        assert!(rule.actions.iter().any(|a| matches!(
            a,
            Action::Known(KnownAction::CopyForward { pending: false, .. })
        )));
        assert!(rule.actions.iter().any(|a| matches!(
            a,
            Action::Known(KnownAction::TemplatedEmailNotify { pending: true, .. })
        )));
        let edited = text.replace("forward = \"a@b.de\"", "forward = \"new@b.de\"");
        let rule = parse(&edited).unwrap()[3].to_rule(Some(&set[3]));
        assert!(rule.actions.iter().any(|a| matches!(a, Action::Known(KnownAction::CopyForward { pending: true, receivers }) if receivers == &["new@b.de"])));
    }

    #[test]
    fn spelling_variants_are_not_changes() {
        let set = fixtures();
        // a single row with a meaningless `match`, and the table written differently
        let text = export(&set).replacen(
            "when = [{ from.contains = \"wiki@club-koeln.example\" }]",
            "match = \"all\"\nwhen = [ {from = {contains=\"wiki@club-koeln.example\"}} ]",
            1,
        );
        let d = parse(&text).unwrap();
        assert!(d[0].same_as(&set[0]), "{:?}", d[0].changes(&set[0]));
        // sizes in any unit
        let size = |s: &str| {
            format!("[[rule]]\nname = \"n\"\nwhen = [{{ size.gt = {s} }}]\nthen = [\"read\"]\n")
        };
        let rule = |t: &str| parse(t).unwrap()[0].to_rule(None);
        assert_eq!(rule(&size("\"5MB\"")), rule(&size("5242880")));
        assert_eq!(rule(&size("\"5120KB\"")), rule(&size("\"5mb\"")));
    }

    #[test]
    fn values_are_kept_exactly() {
        let mut set = fixtures();
        let Condition::Known(KnownCondition::MultiSubjectComparator {
            header_comparator_conditions,
            ..
        }) = &mut set[4].condition
        else {
            unreachable!()
        };
        header_comparator_conditions[0] = serde_json::from_value(
            json!({"type": "Subject", "comparator": "STARTS_WITH", "inverted": false, "comparand": "  [x] \"q\" \\ "}),
        )
        .unwrap();
        let text = export(&set);
        assert!(!text.contains("condition_json ="), "{text}");
        let d = parse(&text).unwrap();
        assert!(d[4].same_as(&set[4]));
        assert_eq!(d[4].to_rule(Some(&set[4])).condition, set[4].condition);
    }

    #[test]
    fn new_rules_get_defaults() {
        let d = parse(
            "[[rule]]\nname = \"n\"\nwhen = [{ subject.contains = \"x\" }]\nthen = [\"read\"]\n",
        )
        .unwrap();
        let rule = d[0].to_rule(None);
        assert!(rule.active && rule.rule_id.is_none() && rule.consider_stopped);
        assert_eq!(rule.actions.last(), Some(&Action::Known(KnownAction::Stop)));
    }

    #[test]
    fn mistakes_are_reported_with_context() {
        let bad = |t: &str| parse(t).unwrap_err().to_string();
        let rule = |when: &str, then: &str| {
            format!("[[rule]]\nname = \"x\"\nwhen = [{when}]\nthen = [{then}]\n")
        };
        assert!(
            bad("[[rule]]\nname = \"x\"\nwhn = []\n").contains("whn"),
            "typos are rejected"
        );

        let e = bad(&rule("{ subject.wobbles = \"y\" }", "\"read\""));
        assert!(
            e.contains("line 3") && e.contains("wobbles") && e.contains("starts-with"),
            "{e}"
        );
        let e = bad(&rule("{ sender.contains = \"y\" }", "\"read\""));
        assert!(
            e.contains("sender") && e.contains("from"),
            "unknown fields list the valid ones: {e}"
        );
        let e = bad(&rule("{ size.gt = \"big\" }", "\"read\""));
        assert!(e.contains("\"big\" is not a size"), "{e}");
        let e = bad(&rule("{ priority.is = \"urgent\" }", "\"read\""));
        assert!(e.contains("urgent") && e.contains("normal"), "{e}");
        let e = bad(&rule("\"all-new\"", "{ move = 3 }"));
        assert!(e.contains("line 4"), "{e}");

        assert!(bad("[[rule]]\nname = \"x\"\nwhen = [\"all-new\"]\n").contains("`then`"));
        assert!(
            bad("[[rule]]\nname = \"x\"\nthen = [\"read\"]\n")
                .contains("needs at least one condition")
        );
        assert!(
            bad("[[rule]]\nname = \"x\"\nwhen = [\"all-new\"]\nthen = [\"read\"]\nstop = maybe\n")
                .contains("line"),
            "syntax errors carry a position"
        );
        assert!(
            bad("[[rule]]\nname = \"x\"\ncondition_json = '{'\nthen = [\"read\"]\n")
                .contains("condition_json")
        );
        assert!(
            bad(
                "[[rule]]\nname = \"x\"\nwhen = [\"all-new\"]\nactions_json = '[]'\nstop = false\n"
            )
            .contains("actions_json")
        );
    }

    #[test]
    fn v1_files_get_a_re_export_hint() {
        let e = parse(
            "[[rule]]\nname = \"x\"\nwhen = [\"from contains a\"]\nthen = [\"move INBOX/A\"]\n",
        )
        .unwrap_err()
        .to_string();
        assert!(e.contains("before v2") && e.contains("re-export"), "{e}");
        let e = parse("[[rule]]\nname = \"x\"\nwhen = [\"al-new\"]\nthen = [\"read\"]\n")
            .unwrap_err()
            .to_string();
        assert!(
            !e.contains("before v2"),
            "a plain typo is not mistaken for v1: {e}"
        );
    }

    #[test]
    fn header_rows_are_written_grouped_and_read_in_either_form() {
        let text = export(&fixtures());
        // the 3-row AnyOf of mixed fields: grouped by field, no `when` needed
        assert!(text.contains("from.contains = \"volunteers@makerspace.example\"\nto-cc.contains = \"volunteers@lists.uni.example\"\nsubject.contains = \"Makerspace-Volunteers\"\n"), "{text}");
        assert!(
            !text.contains("when = "),
            "only header rows in the fixtures: {text}"
        );

        let grouped = "[[rule]]\nname = \"n\"\nfrom.contains = [\"a\", \"b\"]\nsubject.not-starts-with = \"Re:\"\nwhen = [{ size.gt = \"1MB\" }]\nthen = [\"read\"]\n";
        let rows = "[[rule]]\nname = \"n\"\nwhen = [{ subject.not-starts-with = \"Re:\" }, { size.gt = \"1MB\" }, { from.contains = \"b\" }, { from.contains = \"a\" }]\nthen = [\"read\"]\n";
        let a = parse(grouped).unwrap();
        let b = parse(rows).unwrap();
        let built = a[0].to_rule(None);
        assert!(
            b[0].same_as(&built),
            "row order does not matter: {:?}",
            b[0].changes(&built)
        );

        // long groups go one per line, short ones stay on one line
        let long: Vec<String> = (0..8)
            .map(|i| format!("\"sender-number-{i}@example.com\""))
            .collect();
        let many = format!(
            "[[rule]]\nname = \"n\"\nfrom.contains = [{}]\nthen = [\"read\"]\n",
            long.join(", ")
        );
        let out = export(&[parse(&many).unwrap()[0].to_rule(None)]);
        assert!(
            out.contains("from.contains = [\n  \"sender-number-0@example.com\",\n"),
            "{out}"
        );
    }

    #[test]
    fn group_mistakes_are_reported() {
        let bad = |t: &str| parse(t).unwrap_err().to_string();
        let e = bad("[[rule]]\nname = \"x\"\nfrom.wobbles = \"a\"\nthen = [\"read\"]\n");
        assert!(
            e.contains("wobbles") && e.contains("not-ends-with") && e.contains("line 3"),
            "{e}"
        );
        let e = bad("[[rule]]\nname = \"x\"\nfrom.contains = []\nthen = [\"read\"]\n");
        assert!(e.contains("empty"), "{e}");
        let e = bad("[[rule]]\nname = \"x\"\nfrom.contains = 3\nthen = [\"read\"]\n");
        assert!(e.contains("a string or an array of strings"), "{e}");
        let e = bad("[[rule]]\nname = \"x\"\nsender.contains = \"a\"\nthen = [\"read\"]\n");
        assert!(e.contains("sender") && e.contains("subject"), "{e}");
    }
}
