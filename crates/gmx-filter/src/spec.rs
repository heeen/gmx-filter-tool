//! Text specs for rule conditions and actions, and the assembly of a rule from them. The assembly
//! mirrors the payload builder of the GMX web UI (`mailset-organize-inbox`).

use std::str::FromStr;

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
    To,
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
        let mut words = spec.trim().splitn(3, char::is_whitespace);
        let (field, op, value) = (words.next(), words.next(), words.next().map(str::trim));
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
            (Some(field @ ("from" | "to" | "subject")), Some(op), Some(value))
                if !value.is_empty() =>
            {
                let (comparator, negated) = match op {
                    "contains" => (Comparator::Contains, false),
                    "not-contains" => (Comparator::Contains, true),
                    "is" => (Comparator::Is, false),
                    "is-not" => (Comparator::Is, true),
                    "starts-with" => (Comparator::StartsWith, false),
                    "ends-with" => (Comparator::EndsWith, false),
                    _ => {
                        return Err(invalid(
                            spec,
                            "contains, not-contains, is, is-not, starts-with or ends-with",
                        ));
                    }
                };
                Ok(Test::Header {
                    field: match field {
                        "from" => HeaderField::From,
                        "to" => HeaderField::To,
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

fn parse_size(s: &str) -> Option<u64> {
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
        HeaderField::To => KnownHeaderCondition::ToCc {
            comparator,
            inverted,
            include_cc_header: None,
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
        HeaderField::To => KnownCondition::MultiToComparator {
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
}
