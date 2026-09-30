//! Text specs for rule conditions and actions, and the assembly of a rule from them. The assembly
//! mirrors the payload builder of the GMX web UI (`mailset-organize-inbox`).

use std::{fmt, str::FromStr};

use crate::{
    Action, Comparator, Condition, Error, HeaderCondition, KnownAction, KnownCondition,
    KnownHeaderCondition, Operator, PriorityLevel, Result,
};

const KB: u64 = 1024;
const MB: u64 = KB * KB;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// At least one condition matches ("eine").
    Any,
    /// Every condition matches ("alle").
    All,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderField {
    From,
    /// The recipient as the current web UI writes it (no `includeCcHeader`).
    To,
    /// Recipient with `includeCcHeader: true`, as older rules carry it.
    ToCc,
    Subject,
}

/// One condition row of the web UI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Test {
    AllNewEmails,
    Header {
        field: HeaderField,
        comparator: Comparator,
        negated: bool,
        value: String,
    },
    Size {
        larger: bool,
        bytes: u64,
    },
    Priority {
        negated: bool,
        level: PriorityLevel,
    },
    Contact {
        saved: bool,
    },
}

/// One action row of the web UI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Effect {
    Move(String),
    Copy(String),
    MarkRead,
    Delete,
    Forward(String),
    Notify(String),
}

fn invalid(spec: &str, expected: &str) -> Error {
    Error::InvalidSpec(format!("{spec:?}: expected {expected}"))
}

impl FromStr for Test {
    type Err = Error;

    /// `all-new`, `<from|to|subject> <contains|not-contains|is|is-not|starts-with|ends-with> <text>`,
    /// `size <gt|lt> <n>[B|KB|MB]`, `priority <is|is-not> <low|normal|high>`, `contact <saved|not-saved>`.
    fn from_str(spec: &str) -> Result<Self> {
        let (field, rest) = split_word(spec);
        let (op, value) = rest.map_or((None, None), |r| {
            let (op, value) = split_word(r);
            (Some(op), value.filter(|v| !v.is_empty()))
        });
        let field = Some(field).filter(|f| !f.is_empty());
        match (field, op, value) {
            (Some("all-new"), None, None) => Ok(Test::AllNewEmails),
            (Some("contact"), Some("saved"), None) => Ok(Test::Contact { saved: true }),
            (Some("contact"), Some("not-saved"), None) => Ok(Test::Contact { saved: false }),
            (Some("size"), Some(op @ ("gt" | "lt")), Some(size)) => Ok(Test::Size {
                larger: op == "gt",
                bytes: parse_size(size).ok_or_else(|| invalid(spec, "a size like 500KB or 5MB"))?,
            }),
            (Some("priority"), Some(op @ ("is" | "is-not")), Some(level)) => Ok(Test::Priority {
                negated: op == "is-not",
                level: match level {
                    "low" => PriorityLevel::Low,
                    "normal" => PriorityLevel::Normal,
                    "high" => PriorityLevel::High,
                    _ => return Err(invalid(spec, "low, normal or high")),
                },
            }),
            (Some(field @ ("from" | "to" | "to-cc" | "subject")), Some(op), Some(value))
                if !value.is_empty() =>
            {
                let (comparator, negated) = match op {
                    "contains" => (Comparator::Contains, false),
                    "not-contains" => (Comparator::Contains, true),
                    "is" => (Comparator::Is, false),
                    "is-not" => (Comparator::Is, true),
                    "starts-with" => (Comparator::StartsWith, false),
                    "ends-with" => (Comparator::EndsWith, false),
                    "not-starts-with" => (Comparator::StartsWith, true),
                    "not-ends-with" => (Comparator::EndsWith, true),
                    _ => {
                        return Err(invalid(
                            spec,
                            "contains, not-contains, is, is-not, starts-with, not-starts-with, ends-with or not-ends-with",
                        ));
                    }
                };
                Ok(Test::Header {
                    field: match field {
                        "from" => HeaderField::From,
                        "to" => HeaderField::To,
                        "to-cc" => HeaderField::ToCc,
                        _ => HeaderField::Subject,
                    },
                    comparator,
                    negated,
                    value: value.to_owned(),
                })
            }
            _ => Err(invalid(
                spec,
                "`all-new`, `from|to|subject <op> <text>`, `size gt|lt <size>`, `priority is|is-not <level>` or `contact saved|not-saved`",
            )),
        }
    }
}

/// The first whitespace-delimited word and the trimmed remainder, if any.
fn split_word(s: &str) -> (&str, Option<&str>) {
    let s = s.trim();
    match s.split_once(char::is_whitespace) {
        Some((word, rest)) => (word, Some(rest.trim_start())),
        None => (s, None),
    }
}

pub(crate) fn parse_size(s: &str) -> Option<u64> {
    let s = s.trim();
    let digits = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    let (n, unit) = s.split_at_checked(digits)?;
    let unit = match unit.to_ascii_uppercase().as_str() {
        "" | "B" => 1,
        "KB" => KB,
        "MB" => MB,
        _ => return None,
    };
    n.parse::<u64>().ok()?.checked_mul(unit)
}

impl FromStr for Effect {
    type Err = Error;

    /// `move <folder>`, `copy <folder>`, `read`, `delete`, `forward <address>`, `notify <address>`.
    fn from_str(spec: &str) -> Result<Self> {
        let mut words = spec.trim().splitn(2, char::is_whitespace);
        match (words.next(), words.next().map(str::trim)) {
            (Some("read"), None) => Ok(Effect::MarkRead),
            (Some("delete"), None) => Ok(Effect::Delete),
            (Some("move"), Some(v)) if !v.is_empty() => Ok(Effect::Move(v.to_owned())),
            (Some("copy"), Some(v)) if !v.is_empty() => Ok(Effect::Copy(v.to_owned())),
            (Some("forward"), Some(v)) if !v.is_empty() => Ok(Effect::Forward(v.to_owned())),
            (Some("notify"), Some(v)) if !v.is_empty() => Ok(Effect::Notify(v.to_owned())),
            _ => Err(invalid(
                spec,
                "`move|copy <folder>`, `read`, `delete`, `forward|notify <address>`",
            )),
        }
    }
}

impl Effect {
    fn action(self) -> Action {
        Action::Known(match self {
            Effect::Move(folder) => KnownAction::MoveToFolder { folder },
            Effect::Copy(folder) => KnownAction::CopyToFolder { folder },
            Effect::MarkRead => KnownAction::MarkSeen,
            Effect::Delete => KnownAction::DeleteMailImmediately,
            Effect::Forward(to) => KnownAction::CopyForward {
                pending: true,
                receivers: vec![to],
            },
            Effect::Notify(to) => KnownAction::TemplatedEmailNotify {
                pending: false,
                pagers: vec![to],
            },
        })
    }
}

/// Actions in order, followed by `Stop` when further rules must not see the mail.
pub fn actions(effects: Vec<Effect>, stop: bool) -> Vec<Action> {
    let mut actions: Vec<Action> = effects.into_iter().map(Effect::action).collect();
    if stop {
        actions.push(Action::Known(KnownAction::Stop));
    }
    actions
}

impl HeaderField {
    fn keyword(self) -> &'static str {
        match self {
            HeaderField::From => "from",
            HeaderField::To => "to",
            HeaderField::ToCc => "to-cc",
            HeaderField::Subject => "subject",
        }
    }
}

impl fmt::Display for Test {
    /// The exact inverse of [`FromStr`] for every test it can produce.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Test::AllNewEmails => f.write_str("all-new"),
            Test::Header {
                field,
                comparator,
                negated,
                value,
            } => {
                let op = match (comparator, negated) {
                    (Comparator::Contains, false) => "contains",
                    (Comparator::Contains, true) => "not-contains",
                    (Comparator::Is, false) => "is",
                    (Comparator::Is, true) => "is-not",
                    (Comparator::StartsWith, false) => "starts-with",
                    (Comparator::StartsWith, true) => "not-starts-with",
                    (Comparator::EndsWith, false) => "ends-with",
                    (Comparator::EndsWith, true) => "not-ends-with",
                    (Comparator::Other(other), _) => other,
                };
                write!(f, "{} {op} {value}", field.keyword())
            }
            Test::Size { larger, bytes } => {
                let (n, unit) = match bytes {
                    b if *b > 0 && b % MB == 0 => (b / MB, "MB"),
                    b if *b > 0 && b % KB == 0 => (b / KB, "KB"),
                    b => (*b, "B"),
                };
                write!(f, "size {} {n}{unit}", if *larger { "gt" } else { "lt" })
            }
            Test::Priority { negated, level } => {
                let level = match level {
                    PriorityLevel::Low => "low",
                    PriorityLevel::Normal => "normal",
                    PriorityLevel::High => "high",
                    PriorityLevel::Other(other) => other,
                };
                write!(
                    f,
                    "priority {} {level}",
                    if *negated { "is-not" } else { "is" }
                )
            }
            Test::Contact { saved } => {
                write!(f, "contact {}", if *saved { "saved" } else { "not-saved" })
            }
        }
    }
}

impl fmt::Display for Effect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Effect::Move(folder) => write!(f, "move {folder}"),
            Effect::Copy(folder) => write!(f, "copy {folder}"),
            Effect::MarkRead => f.write_str("read"),
            Effect::Delete => f.write_str("delete"),
            Effect::Forward(to) => write!(f, "forward {to}"),
            Effect::Notify(to) => write!(f, "notify {to}"),
        }
    }
}

/// The condition rows of a rule, or `None` when the condition is not expressible as `--when` rows
/// with certainty (nested groups, `AND` operators, inverted multi-value groups, unknown comparators).
/// Structure may differ from what [`condition`] rebuilds (e.g. an `AnyOf` of single-value groups
/// collapses), but the meaning does not.
pub fn tests_of(c: &Condition) -> Option<(Mode, Vec<Test>)> {
    let Condition::Known(known) = c else {
        return None;
    };
    let (mode, rows) = match known {
        KnownCondition::AllOf { conditions } => (
            Mode::All,
            conditions
                .iter()
                .map(single_row)
                .collect::<Option<Vec<_>>>()?,
        ),
        KnownCondition::AnyOf { conditions } => (
            Mode::Any,
            conditions
                .iter()
                .map(any_rows)
                .collect::<Option<Vec<_>>>()?
                .concat(),
        ),
        _ => (Mode::Any, any_rows(c)?),
    };
    (!rows.is_empty()).then_some((mode, rows))
}

fn single_row(c: &Condition) -> Option<Test> {
    let mut rows = any_rows(c)?;
    (rows.len() == 1).then(|| rows.remove(0))
}

/// Rows that are alternatives of each other when the condition stands under an "any".
fn any_rows(c: &Condition) -> Option<Vec<Test>> {
    let Condition::Known(known) = c else {
        return None;
    };
    let (field, operator, inverted, headers) = match known {
        KnownCondition::AllNewEmails { inverted: false } => return Some(vec![Test::AllNewEmails]),
        KnownCondition::SizeOver {
            inverted,
            byte_size,
        } => {
            return Some(vec![Test::Size {
                larger: !inverted,
                bytes: *byte_size,
            }]);
        }
        KnownCondition::Priority { inverted, level } => {
            return Some(vec![Test::Priority {
                negated: *inverted,
                level: level.clone(),
            }]);
        }
        KnownCondition::AnyContact { inverted } => {
            return Some(vec![Test::Contact { saved: !inverted }]);
        }
        KnownCondition::MultiFromComparator {
            operator,
            inverted,
            header_comparator_conditions,
        } => (
            HeaderField::From,
            operator,
            *inverted,
            header_comparator_conditions,
        ),
        KnownCondition::MultiToComparator {
            operator,
            inverted,
            header_comparator_conditions,
        } => (
            HeaderField::To,
            operator,
            *inverted,
            header_comparator_conditions,
        ),
        KnownCondition::MultiSubjectComparator {
            operator,
            inverted,
            header_comparator_conditions,
        } => (
            HeaderField::Subject,
            operator,
            *inverted,
            header_comparator_conditions,
        ),
        _ => return None,
    };
    if *operator != Operator::Or || headers.is_empty() || (inverted && headers.len() != 1) {
        return None;
    }
    headers
        .iter()
        .map(|h| header_test(field, inverted, h))
        .collect()
}

fn header_test(group: HeaderField, negated: bool, h: &HeaderCondition) -> Option<Test> {
    let HeaderCondition::Known(known) = h else {
        return None;
    };
    let (field, comparator, inverted, value) = match known {
        KnownHeaderCondition::From {
            comparator,
            inverted,
            value,
        } => (HeaderField::From, comparator, inverted, value),
        KnownHeaderCondition::Subject {
            comparator,
            inverted,
            value,
        } => (HeaderField::Subject, comparator, inverted, value),
        KnownHeaderCondition::ToCc {
            comparator,
            inverted,
            include_cc_header,
            value,
        } => {
            // the server stores an absent flag as `false`, so the two are the same rule
            let field = match include_cc_header {
                Some(true) => HeaderField::ToCc,
                Some(false) | None => HeaderField::To,
            };
            (field, comparator, inverted, value)
        }
    };
    let group_matches = matches!(
        (group, field),
        (HeaderField::To, HeaderField::To | HeaderField::ToCc)
            | (HeaderField::From, HeaderField::From)
            | (HeaderField::Subject, HeaderField::Subject)
    );
    (group_matches && !inverted && !matches!(comparator, Comparator::Other(_))).then(|| {
        Test::Header {
            field,
            comparator: comparator.clone(),
            negated,
            value: value.clone(),
        }
    })
}

/// The effects of an action list and whether it ends in `Stop`, or `None` for anything the
/// `--then` syntax cannot express (legacy types, several receivers, `Stop` in the middle).
pub fn effects_of(actions: &[Action]) -> Option<(Vec<Effect>, bool)> {
    let (body, stop) = match actions.split_last() {
        Some((Action::Known(KnownAction::Stop), body)) => (body, true),
        _ => (actions, false),
    };
    let effects = body
        .iter()
        .map(|a| match a {
            Action::Known(KnownAction::MoveToFolder { folder }) => {
                Some(Effect::Move(folder.clone()))
            }
            Action::Known(KnownAction::CopyToFolder { folder }) => {
                Some(Effect::Copy(folder.clone()))
            }
            Action::Known(KnownAction::MarkSeen) => Some(Effect::MarkRead),
            Action::Known(KnownAction::DeleteMailImmediately) => Some(Effect::Delete),
            Action::Known(KnownAction::CopyForward { receivers, .. }) => match receivers.as_slice()
            {
                [one] => Some(Effect::Forward(one.clone())),
                _ => None,
            },
            Action::Known(KnownAction::TemplatedEmailNotify { pagers, .. }) => {
                match pagers.as_slice() {
                    [one] => Some(Effect::Notify(one.clone())),
                    _ => None,
                }
            }
            _ => None,
        })
        .collect::<Option<Vec<_>>>()?;
    (!effects.is_empty()).then_some((effects, stop))
}

fn row(test: &Test) -> Condition {
    Condition::Known(match test {
        Test::AllNewEmails => KnownCondition::AllNewEmails { inverted: false },
        Test::Size { larger, bytes } => KnownCondition::SizeOver {
            inverted: !larger,
            byte_size: *bytes,
        },
        Test::Priority { negated, level } => KnownCondition::Priority {
            inverted: *negated,
            level: level.clone(),
        },
        Test::Contact { saved } => KnownCondition::AnyContact { inverted: !saved },
        Test::Header {
            field,
            comparator,
            negated,
            value,
        } => {
            let header_comparator_conditions = vec![header_condition(*field, comparator, value)];
            multi(*field, *negated, header_comparator_conditions)
        }
    })
}

fn header_condition(field: HeaderField, comparator: &Comparator, value: &str) -> HeaderCondition {
    let (comparator, inverted, value) = (comparator.clone(), false, value.to_owned());
    HeaderCondition::Known(match field {
        HeaderField::From => KnownHeaderCondition::From {
            comparator,
            inverted,
            value,
        },
        HeaderField::To | HeaderField::ToCc => KnownHeaderCondition::ToCc {
            comparator,
            inverted,
            include_cc_header: (field == HeaderField::ToCc).then_some(true),
            value,
        },
        HeaderField::Subject => KnownHeaderCondition::Subject {
            comparator,
            inverted,
            value,
        },
    })
}

fn multi(
    field: HeaderField,
    inverted: bool,
    header_comparator_conditions: Vec<HeaderCondition>,
) -> KnownCondition {
    let operator = Operator::Or;
    match field {
        HeaderField::From => KnownCondition::MultiFromComparator {
            operator,
            inverted,
            header_comparator_conditions,
        },
        HeaderField::To | HeaderField::ToCc => KnownCondition::MultiToComparator {
            operator,
            inverted,
            header_comparator_conditions,
        },
        HeaderField::Subject => KnownCondition::MultiSubjectComparator {
            operator,
            inverted,
            header_comparator_conditions,
        },
    }
}

/// `condition` with `extra` rows added, for widening a rule. `Ok(None)` when every row is already
/// there. Refuses conditions that are not plain "any of these rows": adding to an "all of" rule
/// would narrow it, and raw conditions cannot be edited safely.
pub fn extend_condition(current: &Condition, extra: &[Test]) -> Result<Option<Condition>> {
    let Some((mode, mut tests)) = tests_of(current) else {
        return Err(Error::InvalidSpec(
            "this rule's condition cannot be edited as rows; use `gmxf edit`".into(),
        ));
    };
    if mode == Mode::All {
        return Err(Error::InvalidSpec(
            "this rule needs all of its conditions, so adding one would narrow it; use `gmxf edit`"
                .into(),
        ));
    }
    let before = tests.len();
    for t in extra {
        if !tests.contains(t) {
            tests.push(t.clone());
        }
    }
    if tests.len() == before {
        return Ok(None);
    }
    condition(Mode::Any, &tests).map(Some)
}

/// Builds the condition tree the way the web UI does: one row stands alone, `All` becomes
/// `AllOf`, and `Any` over plain (non-negated) rows of one header field collapses into a single
/// multi-comparator.
pub fn condition(mode: Mode, tests: &[Test]) -> Result<Condition> {
    let [first, rest @ ..] = tests else {
        return Err(Error::InvalidSpec(
            "a rule needs at least one condition".into(),
        ));
    };
    if rest.is_empty() {
        return Ok(row(first));
    }
    if mode == Mode::All {
        return Ok(Condition::Known(KnownCondition::AllOf {
            conditions: tests.iter().map(row).collect(),
        }));
    }
    if let Test::Header { field, .. } = first {
        let same_field_plain: Option<Vec<HeaderCondition>> = tests
            .iter()
            .map(|t| match t {
                Test::Header {
                    field: f,
                    comparator,
                    negated: false,
                    value,
                } if f == field => Some(header_condition(*field, comparator, value)),
                _ => None,
            })
            .collect();
        if let Some(conditions) = same_field_plain {
            return Ok(Condition::Known(multi(*field, false, conditions)));
        }
    }
    Ok(Condition::Known(KnownCondition::AnyOf {
        conditions: tests.iter().map(row).collect(),
    }))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn test(s: &str) -> Test {
        s.parse().unwrap()
    }

    fn json_of(c: &Condition) -> serde_json::Value {
        serde_json::to_value(c).unwrap()
    }

    #[test]
    fn parses_specs() {
        assert_eq!(
            test("from not-contains  spam@x.de "),
            Test::Header {
                field: HeaderField::From,
                comparator: Comparator::Contains,
                negated: true,
                value: "spam@x.de".into()
            }
        );
        assert_eq!(
            test("size gt 5MB"),
            Test::Size {
                larger: true,
                bytes: 5 * MB
            }
        );
        assert_eq!(
            test("size lt 300"),
            Test::Size {
                larger: false,
                bytes: 300
            }
        );
        assert_eq!(test("contact not-saved"), Test::Contact { saved: false });
        assert_eq!(
            "move INBOX/A B".parse::<Effect>().unwrap(),
            Effect::Move("INBOX/A B".into())
        );
        for bad in [
            "",
            "from contains",
            "size gt big",
            "priority is urgent",
            "subject starts-with-not x",
        ] {
            assert!(bad.parse::<Test>().is_err(), "{bad}");
        }
        assert!("move".parse::<Effect>().is_err());
    }

    #[test]
    fn single_header_row_matches_the_web_ui_payload() {
        let c = condition(Mode::Any, &[test("to is me@gmx.de")]).unwrap();
        assert_eq!(
            json_of(&c),
            json!({"type": "MultiToComparator", "operator": "OR", "inverted": false,
                "headerComparatorConditions": [
                    {"type": "ToCc", "comparator": "IS", "inverted": false, "comparand": "me@gmx.de"}]})
        );
    }

    #[test]
    fn negation_sets_the_outer_inverted_flag() {
        let c = condition(Mode::Any, &[test("subject not-contains promo")]).unwrap();
        assert_eq!(json_of(&c)["inverted"], true);
        assert_eq!(
            json_of(&c)["headerComparatorConditions"][0]["inverted"],
            false
        );
    }

    #[test]
    fn any_over_one_plain_field_collapses_else_any_of() {
        let merged = condition(
            Mode::Any,
            &[test("from contains a"), test("from ends-with b")],
        )
        .unwrap();
        assert_eq!(json_of(&merged)["type"], "MultiFromComparator");
        assert_eq!(
            json_of(&merged)["headerComparatorConditions"]
                .as_array()
                .unwrap()
                .len(),
            2
        );

        let mixed = condition(
            Mode::Any,
            &[test("from contains a"), test("subject contains b")],
        )
        .unwrap();
        assert_eq!(json_of(&mixed)["type"], "AnyOf");
        let negated =
            condition(Mode::Any, &[test("from contains a"), test("from is-not b")]).unwrap();
        assert_eq!(json_of(&negated)["type"], "AnyOf");
    }

    #[test]
    fn all_mode_and_non_header_rows() {
        let c = condition(
            Mode::All,
            &[
                test("size lt 1MB"),
                test("priority is-not low"),
                test("contact saved"),
            ],
        )
        .unwrap();
        assert_eq!(
            json_of(&c),
            json!({"type": "AllOf", "conditions": [
                {"type": "SizeOver", "inverted": true, "byteSize": 1048576},
                {"type": "Priority", "inverted": true, "level": "LOW"},
                {"type": "AnyContact", "inverted": false}]})
        );
        assert_eq!(
            json_of(&condition(Mode::Any, &[Test::AllNewEmails]).unwrap()),
            json!({"type": "AllNewEmails", "inverted": false})
        );
        assert!(condition(Mode::Any, &[]).is_err());
    }

    #[test]
    fn actions_end_with_stop() {
        let a = actions(
            vec![Effect::Forward("a@b.de".into()), Effect::MarkRead],
            true,
        );
        assert_eq!(
            serde_json::to_value(&a).unwrap(),
            json!([{"type": "CopyForward", "pending": true, "receivers": ["a@b.de"]},
                   {"type": "MarkSeen"}, {"type": "Stop"}])
        );
    }

    fn cond(v: serde_json::Value) -> Condition {
        serde_json::from_value(v).unwrap()
    }

    #[test]
    fn display_is_the_inverse_of_parse() {
        for spec in [
            "all-new",
            "from contains a@b",
            "to-cc not-contains x y",
            "subject is-not Re: hi",
            "subject starts-with [x]",
            "subject not-starts-with Re:",
            "from not-ends-with .de",
            "to ends-with @gmx.de",
            "size gt 5MB",
            "size lt 3KB",
            "size gt 1500B",
            "priority is-not high",
            "contact not-saved",
        ] {
            assert_eq!(test(spec).to_string(), spec);
        }
        for spec in [
            "move INBOX/A B",
            "copy X",
            "read",
            "delete",
            "forward a@b.de",
            "notify a@b.de",
        ] {
            assert_eq!(spec.parse::<Effect>().unwrap().to_string(), spec);
        }
    }

    #[test]
    fn built_conditions_read_back_to_the_same_tests() {
        let sets: Vec<(Mode, Vec<&str>)> = vec![
            (Mode::Any, vec!["from contains a"]),
            (Mode::Any, vec!["from contains a", "from is b"]),
            (
                Mode::Any,
                vec!["from contains a", "subject contains b", "size gt 1MB"],
            ),
            (Mode::Any, vec!["to contains a", "to-cc contains b"]),
            (Mode::Any, vec!["subject not-contains promo"]),
            (Mode::Any, vec!["all-new"]),
            (
                Mode::All,
                vec!["from contains a", "priority is high", "contact saved"],
            ),
            (Mode::All, vec!["size lt 1MB", "subject is-not x"]),
        ];
        for (mode, specs) in sets {
            let tests: Vec<Test> = specs.iter().map(|s| test(s)).collect();
            let built = condition(mode, &tests).unwrap();
            let (m, back) = tests_of(&built).unwrap_or_else(|| panic!("{specs:?}"));
            assert_eq!(back, tests, "{specs:?}");
            if tests.len() > 1 {
                assert_eq!(m, mode, "{specs:?}");
            }
            assert_eq!(condition(m, &back).unwrap(), built, "{specs:?}");
        }
    }

    #[test]
    fn legacy_and_hand_written_shapes() {
        // older rules: value under `from`, `to` with includeCcHeader, groups of several values
        let legacy = cond(
            json!({"type": "MultiToComparator", "operator": "OR", "inverted": false,
            "headerComparatorConditions": [
                {"type": "ToCc", "comparator": "CONTAINS", "inverted": false, "includeCcHeader": true, "to": "a@b"},
                {"type": "ToCc", "comparator": "CONTAINS", "inverted": false, "includeCcHeader": true, "to": "c@d"}]}),
        );
        let (mode, rows) = tests_of(&legacy).unwrap();
        assert_eq!(mode, Mode::Any);
        assert_eq!(
            rows,
            [test("to-cc contains a@b"), test("to-cc contains c@d")]
        );
        // an AnyOf of groups flattens into rows
        let any_of = cond(json!({"type": "AnyOf", "conditions": [
            {"type": "MultiFromComparator", "operator": "OR", "inverted": false, "headerComparatorConditions": [
                {"type": "From", "comparator": "CONTAINS", "inverted": false, "from": "x"},
                {"type": "From", "comparator": "CONTAINS", "inverted": false, "from": "y"}]},
            {"type": "MultiSubjectComparator", "operator": "OR", "inverted": false, "headerComparatorConditions": [
                {"type": "Subject", "comparator": "CONTAINS", "inverted": false, "subject": "z"}]}]}));
        assert_eq!(tests_of(&any_of).unwrap().1.len(), 3);
    }

    #[test]
    fn inexpressible_conditions_fall_back_to_raw() {
        let group = |extra: serde_json::Value| {
            let mut v = json!({"type": "MultiFromComparator", "operator": "OR", "inverted": false,
                "headerComparatorConditions": [
                    {"type": "From", "comparator": "CONTAINS", "inverted": false, "comparand": "a"},
                    {"type": "From", "comparator": "CONTAINS", "inverted": false, "comparand": "b"}]});
            v.as_object_mut()
                .unwrap()
                .extend(extra.as_object().unwrap().clone());
            cond(v)
        };
        assert!(tests_of(&group(json!({}))).is_some());
        assert!(
            tests_of(&group(json!({"inverted": true}))).is_none(),
            "NOT (a OR b) has no row form"
        );
        assert!(tests_of(&group(json!({"operator": "AND"}))).is_none());
        assert!(tests_of(&cond(json!({"type": "Weird"}))).is_none());
        let unknown_cmp = cond(
            json!({"type": "MultiFromComparator", "operator": "OR", "inverted": false,
            "headerComparatorConditions": [{"type": "From", "comparator": "MATCHES", "inverted": false, "comparand": "a"}]}),
        );
        assert!(tests_of(&unknown_cmp).is_none());
        let padded = cond(
            json!({"type": "MultiFromComparator", "operator": "OR", "inverted": false,
            "headerComparatorConditions": [{"type": "From", "comparator": "CONTAINS", "inverted": false, "comparand": " a "}]}),
        );
        assert!(
            matches!(&tests_of(&padded).unwrap().1[..], [Test::Header { value, .. }] if value == " a "),
            "the typed rules file keeps values exactly"
        );
        let explicit_false = cond(
            json!({"type": "MultiToComparator", "operator": "OR", "inverted": false,
            "headerComparatorConditions": [{"type": "ToCc", "comparator": "CONTAINS", "inverted": false, "includeCcHeader": false, "comparand": "a"}]}),
        );
        assert_eq!(
            tests_of(&explicit_false).unwrap().1,
            [test("to contains a")],
            "an explicit false is what the server stores for a plain `to`"
        );
        let nested = cond(
            json!({"type": "AllOf", "conditions": [group(json!({})), {"type": "AllNewEmails", "inverted": false}]}),
        );
        assert!(tests_of(&nested).is_none());
    }

    #[test]
    fn effects_read_back_and_legacy_falls_back() {
        let effects = vec![
            Effect::Copy("INBOX/A".into()),
            Effect::MarkRead,
            Effect::Notify("a@b.de".into()),
        ];
        for stop in [true, false] {
            assert_eq!(
                effects_of(&actions(effects.clone(), stop)),
                Some((effects.clone(), stop))
            );
        }
        let legacy: Vec<Action> =
            serde_json::from_value(json!([{"type": "ExcludeFromSpamFilter"}, {"type": "Stop"}]))
                .unwrap();
        assert_eq!(effects_of(&legacy), None);
        let two: Vec<Action> = serde_json::from_value(
            json!([{"type": "CopyForward", "pending": false, "receivers": ["a", "b"]}]),
        )
        .unwrap();
        assert_eq!(effects_of(&two), None);
        let mid_stop: Vec<Action> =
            serde_json::from_value(json!([{"type": "Stop"}, {"type": "MarkSeen"}])).unwrap();
        assert_eq!(effects_of(&mid_stop), None);
        assert_eq!(effects_of(&[]), None);
    }

    #[test]
    fn extending_adds_new_rows_and_skips_known_ones() {
        let base = condition(
            Mode::Any,
            &[test("from contains a"), test("from contains b")],
        )
        .unwrap();
        let wider = extend_condition(
            &base,
            &[
                test("from contains b"),
                test("from contains c"),
                test("subject contains s"),
            ],
        )
        .unwrap()
        .unwrap();
        let (mode, rows) = tests_of(&wider).unwrap();
        assert_eq!(mode, Mode::Any);
        assert_eq!(
            rows,
            [
                test("from contains a"),
                test("from contains b"),
                test("from contains c"),
                test("subject contains s")
            ]
        );
        assert_eq!(
            extend_condition(&base, &[test("from contains a")]).unwrap(),
            None
        );
        // a single-row rule becomes a group
        let one = condition(Mode::Any, &[test("from contains a")]).unwrap();
        assert_eq!(
            tests_of(
                &extend_condition(&one, &[test("from contains z")])
                    .unwrap()
                    .unwrap()
            )
            .unwrap()
            .1
            .len(),
            2
        );
    }

    #[test]
    fn extending_refuses_what_it_cannot_widen_safely() {
        let all = condition(Mode::All, &[test("from contains a"), test("size gt 1MB")]).unwrap();
        assert!(
            extend_condition(&all, &[test("from contains z")])
                .unwrap_err()
                .to_string()
                .contains("narrow")
        );
        assert!(extend_condition(&cond(json!({"type": "Weird"})), &[test("all-new")]).is_err());
    }
}
