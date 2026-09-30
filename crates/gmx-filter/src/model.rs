use serde::{Deserialize, Serialize};
use serde_json::Value;

const RULE_TYPE: &str = "StoppingNamedOrderedConditionalMultiActionUser";

/// A server-side filter rule. `rule_id`, `uri` and `modified` are absent on rules not yet created.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Rule {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modified: Option<String>,
    pub rule_name: String,
    pub active: bool,
    pub consider_stopped: bool,
    pub condition: Condition,
    pub actions: Vec<Action>,
}

impl Rule {
    /// A new active rule. `considerStopped` is what the web UI always sends.
    pub fn new(name: impl Into<String>, condition: Condition, actions: Vec<Action>) -> Self {
        Self {
            kind: RULE_TYPE.into(),
            rule_id: None,
            uri: None,
            modified: None,
            rule_name: name.into(),
            active: true,
            consider_stopped: true,
            condition,
            actions,
        }
    }
}

/// Variants not modelled here are kept as raw JSON so they survive a read-modify-write.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Action {
    Known(KnownAction),
    Other(Value),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum KnownAction {
    MoveToFolder {
        folder: String,
    },
    CopyToFolder {
        folder: String,
    },
    MarkSeen,
    DeleteMailImmediately,
    /// `pending` marks a target that still has to confirm by mail (the web UI sends `true`).
    CopyForward {
        pending: bool,
        receivers: Vec<String>,
    },
    TemplatedEmailNotify {
        pending: bool,
        pagers: Vec<String>,
    },
    Stop,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Condition {
    Known(KnownCondition),
    Other(Value),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum KnownCondition {
    AnyOf {
        conditions: Vec<Condition>,
    },
    AllOf {
        conditions: Vec<Condition>,
    },
    /// Written as `AllNewEmails` (like the web UI); the server stores and returns it as `NewMail`
    /// without `inverted`, dropping a `true` silently.
    #[serde(alias = "NewMail")]
    AllNewEmails {
        #[serde(default)]
        inverted: bool,
    },
    #[serde(rename_all = "camelCase")]
    MultiFromComparator {
        operator: Operator,
        inverted: bool,
        header_comparator_conditions: Vec<HeaderCondition>,
    },
    #[serde(rename_all = "camelCase")]
    MultiSubjectComparator {
        operator: Operator,
        inverted: bool,
        header_comparator_conditions: Vec<HeaderCondition>,
    },
    #[serde(rename_all = "camelCase")]
    MultiToComparator {
        operator: Operator,
        inverted: bool,
        header_comparator_conditions: Vec<HeaderCondition>,
    },
    /// `inverted` means "smaller than".
    #[serde(rename_all = "camelCase")]
    SizeOver {
        inverted: bool,
        byte_size: u64,
    },
    Priority {
        inverted: bool,
        level: PriorityLevel,
    },
    /// Sender is (or with `inverted`, is not) in the address book.
    AnyContact {
        inverted: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum HeaderCondition {
    Known(KnownHeaderCondition),
    Other(Value),
}

/// The server returns the value under `from`/`to`/`subject` but expects `comparand` on writes;
/// reads accept both, writes always emit `comparand`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum KnownHeaderCondition {
    From {
        comparator: Comparator,
        inverted: bool,
        #[serde(rename = "comparand", alias = "from")]
        value: String,
    },
    Subject {
        comparator: Comparator,
        inverted: bool,
        #[serde(rename = "comparand", alias = "subject")]
        value: String,
    },
    #[serde(rename_all = "camelCase", alias = "To")]
    ToCc {
        comparator: Comparator,
        inverted: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        include_cc_header: Option<bool>,
        #[serde(rename = "comparand", alias = "to")]
        value: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Comparator {
    Contains,
    Is,
    StartsWith,
    EndsWith,
    #[serde(untagged)]
    Other(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Operator {
    Or,
    And,
    #[serde(untagged)]
    Other(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PriorityLevel {
    Low,
    Normal,
    High,
    #[serde(untagged)]
    Other(String),
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn reads_type_specific_key_and_writes_comparand() {
        let read = json!({
            "type": "ToCc", "comparator": "CONTAINS", "inverted": false,
            "includeCcHeader": true, "to": "me@gmx.de"
        });
        let h: HeaderCondition = serde_json::from_value(read).unwrap();
        assert_eq!(
            serde_json::to_value(&h).unwrap(),
            json!({
                "type": "ToCc", "comparator": "CONTAINS", "inverted": false,
                "includeCcHeader": true, "comparand": "me@gmx.de"
            })
        );
    }

    #[test]
    fn unknown_variants_round_trip_verbatim() {
        let rule = json!({
            "type": RULE_TYPE, "ruleId": "5", "ruleName": "x", "active": false,
            "considerStopped": true, "modified": "2025-02-07T10:33:21Z",
            "condition": {"type": "Weird", "foo": [1, 2]},
            "actions": [
                {"type": "MoveToFolder", "folder": "INBOX/X"},
                {"type": "Stop"},
                {"type": "SetFlag", "flag": "seen"}
            ]
        });
        let parsed: Rule = serde_json::from_value(rule.clone()).unwrap();
        assert!(matches!(parsed.condition, Condition::Other(_)));
        assert_eq!(serde_json::to_value(&parsed).unwrap(), rule);
    }

    #[test]
    fn unknown_comparator_survives() {
        let h = json!({"type": "Subject", "comparator": "STARTS_WITH", "inverted": true, "subject": "hi"});
        let parsed: HeaderCondition = serde_json::from_value(h).unwrap();
        let out = serde_json::to_value(&parsed).unwrap();
        assert_eq!(out["comparator"], "STARTS_WITH");
        assert_eq!(out["comparand"], "hi");
    }

    #[test]
    fn nested_any_of() {
        let c = json!({"type": "AnyOf", "conditions": [{
            "type": "MultiFromComparator", "operator": "OR", "inverted": false,
            "headerComparatorConditions": [
                {"type": "From", "comparator": "CONTAINS", "inverted": false, "from": "a@b"}
            ]
        }]});
        let parsed: Condition = serde_json::from_value(c).unwrap();
        let Condition::Known(KnownCondition::AnyOf { conditions }) = parsed else {
            panic!("not AnyOf");
        };
        assert_eq!(conditions.len(), 1);
    }

    #[test]
    fn the_servers_new_mail_is_all_new_emails() {
        let c: Condition = serde_json::from_value(json!({"type": "NewMail"})).unwrap();
        assert_eq!(
            c,
            Condition::Known(KnownCondition::AllNewEmails { inverted: false })
        );
        assert_eq!(
            serde_json::to_value(&c).unwrap(),
            json!({"type": "AllNewEmails", "inverted": false})
        );
    }
}
