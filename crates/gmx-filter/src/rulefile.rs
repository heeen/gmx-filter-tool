//! The editable rules file: one `[[rule]]` table per rule, in rule order.
//!
//! Conditions and actions are written as the one-line `--when` / `--then` specs of
//! [`crate::spec`]; anything those cannot express is kept as JSON so it survives unchanged.

use std::fmt::Write as _;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    Action, Condition, Effect, Error, KnownAction, KnownCondition, Mode, Result, Rule, Test,
    actions, condition, effects_of, tests_of,
};

const HEADER: &str = "\
# gmxf rules v1. File order is rule order. A rule is matched to the server by `id`, else by `name`.
#
#   match = \"any\" | \"all\"     whether one or every `when` line must hold
#   when  = [\"from|to|to-cc|subject contains|not-contains|is|is-not|starts-with|ends-with <text>\",
#            \"size gt|lt <n>[B|KB|MB]\", \"priority is|is-not low|normal|high\",
#            \"contact saved|not-saved\", \"all-new\"]
#   then  = [\"move <folder>\", \"copy <folder>\", \"read\", \"delete\", \"forward <address>\", \"notify <address>\"]
#   stop  = true             false lets later rules see the mail as well
#   condition_json / actions_json   raw API JSON for what the lines above cannot express
";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
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

const fn yes() -> bool {
    true
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleEntry {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    id: Option<String>,
    name: String,
    #[serde(default = "yes")]
    active: bool,
    #[serde(default, rename = "match")]
    mode: MatchMode,
    #[serde(default)]
    when: Vec<String>,
    #[serde(default)]
    then: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    stop: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    condition_json: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
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
    /// Normalized text form, comparable with [`entry_of`] of a server rule.
    canon: RuleEntry,
}

impl DesiredRule {
    /// True when the server rule already says the same, however the file spells it.
    pub fn same_as(&self, remote: &Rule) -> bool {
        let mut theirs = entry_of(remote);
        theirs.id = self.canon.id.clone();
        theirs == self.canon
    }

    /// Text-level differences to `remote`, for display: `(field, before, after)`.
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
        diff("when", theirs.when.join("; "), ours.when.join("; "));
        diff("then", theirs.then.join("; "), ours.then.join("; "));
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

fn compact(json: &str) -> std::result::Result<String, serde_json::Error> {
    serde_json::from_str::<Value>(json).map(|v| v.to_string())
}

/// The text form of a server rule; the inverse of building a rule from an entry.
fn entry_of(rule: &Rule) -> RuleEntry {
    let (mode, when, condition_json) = match tests_of(&rule.condition) {
        Some((mode, tests)) => (
            mode.into(),
            tests.iter().map(Test::to_string).collect(),
            None,
        ),
        None => (
            MatchMode::Any,
            Vec::new(),
            serde_json::to_string(&rule.condition).ok(),
        ),
    };
    let (then, stop, actions_json) = match effects_of(&rule.actions) {
        Some((effects, stop)) => (
            effects.iter().map(Effect::to_string).collect(),
            Some(stop),
            None,
        ),
        None => (Vec::new(), None, serde_json::to_string(&rule.actions).ok()),
    };
    RuleEntry {
        id: rule.rule_id.clone(),
        name: rule.rule_name.clone(),
        active: rule.active,
        mode,
        when,
        then,
        stop,
        condition_json,
        actions_json,
    }
}

/// Why the web UI will not let you edit a rule, or which state deserves a look.
fn notes_of(rule: &Rule) -> Vec<&'static str> {
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

fn toml_array(items: &[String], out: &mut String, key: &str) {
    match items {
        [] => {}
        [one] => {
            let _ = writeln!(out, "{key} = [{}]", toml_str(one));
        }
        many => {
            let _ = writeln!(out, "{key} = [");
            for item in many {
                let _ = writeln!(out, "  {},", toml_str(item));
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

/// Renders the rules as a rules file.
pub fn export(rules: &[Rule]) -> String {
    let mut out = String::from(HEADER);
    for rule in rules {
        let entry = entry_of(rule);
        out.push('\n');
        for note in notes_of(rule) {
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
            let mode = if entry.mode == MatchMode::All {
                "all"
            } else {
                "any"
            };
            let _ = writeln!(out, "match = \"{mode}\"");
            toml_array(&entry.when, &mut out, "when");
        }
        if let Some(json) = &entry.actions_json {
            toml_json("actions_json", json, &mut out);
        } else {
            toml_array(&entry.then, &mut out, "then");
            let _ = writeln!(out, "stop = {}", entry.stop.unwrap_or(true));
        }
    }
    out
}

/// Parses a rules file into the rules it asks for.
pub fn parse(text: &str) -> Result<Vec<DesiredRule>> {
    let file: RuleFile = toml::from_str(text).map_err(|e| Error::RuleFile(e.to_string()))?;
    file.rule
        .into_iter()
        .enumerate()
        .map(|(i, entry)| {
            build(entry).map_err(|e| Error::RuleFile(format!("rule #{}: {e}", i + 1)))
        })
        .collect()
}

fn build(entry: RuleEntry) -> std::result::Result<DesiredRule, String> {
    let ctx = |what: &str, e: &dyn std::fmt::Display| format!("{:?}: {what}: {e}", entry.name);
    let (condition, canon_when, canon_cond_json) =
        match (&entry.condition_json, entry.when.is_empty()) {
            (Some(_), false) => {
                return Err(ctx("condition", &"use either `when` or `condition_json`"));
            }
            (Some(json), true) => {
                let value: Condition =
                    serde_json::from_str(json).map_err(|e| ctx("condition_json", &e))?;
                let compact = compact(json).map_err(|e| ctx("condition_json", &e))?;
                (value, Vec::new(), Some(compact))
            }
            (None, true) => return Err(ctx("condition", &"needs at least one `when` line")),
            (None, false) => {
                let tests = entry
                    .when
                    .iter()
                    .map(|s| s.parse::<Test>().map_err(|e| ctx("when", &e)))
                    .collect::<std::result::Result<Vec<_>, _>>()?;
                let built = condition(entry.mode.into(), &tests).map_err(|e| ctx("when", &e))?;
                (built, tests.iter().map(Test::to_string).collect(), None)
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
            (None, true) => return Err(ctx("actions", &"needs at least one `then` line")),
            (None, false) => {
                let effects = entry
                    .then
                    .iter()
                    .map(|s| s.parse::<Effect>().map_err(|e| ctx("then", &e)))
                    .collect::<std::result::Result<Vec<_>, _>>()?;
                let stop = entry.stop.unwrap_or(true);
                let canon: Vec<String> = effects.iter().map(Effect::to_string).collect();
                (actions(effects, stop), canon, Some(stop), None)
            }
        };
    let canon_when_len = canon_when.len();
    let canon = RuleEntry {
        id: entry.id.clone(),
        name: entry.name.clone(),
        active: entry.active,
        // `match` only means something with several `when` lines
        mode: if canon_when_len < 2 {
            MatchMode::Any
        } else {
            entry.mode
        },
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
mod tests {
    use serde_json::json;

    use super::*;

    fn rules(v: Value) -> Vec<Rule> {
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
    fn fixtures() -> Vec<Rule> {
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
        assert!(text.contains("\"to-cc contains members@club-koeln.example\""));
        assert!(text.contains("then = [\"move INBOX/Club Köln\"]"));
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
        let rebuilt = d[0].to_rule(Some(&set[0]));
        assert_eq!(rebuilt.condition, set[0].condition);
        assert_eq!(rebuilt.actions, set[0].actions);
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
        let fields: Vec<_> = d[1].changes(&set[1]).into_iter().map(|c| c.0).collect();
        assert_eq!(fields, ["name", "when"]);
        let rule = d[1].to_rule(Some(&set[1]));
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
        let edited = text.replace("forward a@b.de", "forward new@b.de");
        let rule = parse(&edited).unwrap()[1].to_rule(Some(&set[1]));
        assert!(rule.actions.iter().any(|a| matches!(a, Action::Known(KnownAction::CopyForward { pending: true, receivers }) if receivers == &["new@b.de"])));
    }

    #[test]
    fn spelling_variants_are_not_changes() {
        let set = fixtures();
        let text = export(&set)
            .replacen(
                "\"from contains confluence",
                "\"from   contains confluence",
                1,
            )
            .replacen("match = \"any\"", "match = \"all\"", 1);
        let d = parse(&text).unwrap();
        assert!(d[0].same_as(&set[0]), "{:?}", d[0].changes(&set[0]));
    }

    #[test]
    fn new_rules_get_defaults() {
        let d =
            parse("[[rule]]\nname = \"n\"\nwhen = [\"subject contains x\"]\nthen = [\"read\"]\n")
                .unwrap();
        let rule = d[0].to_rule(None);
        assert!(rule.active && rule.rule_id.is_none() && rule.consider_stopped);
        assert_eq!(rule.actions.last(), Some(&Action::Known(KnownAction::Stop)));
    }

    #[test]
    fn mistakes_are_reported_with_context() {
        let bad = |t: &str| parse(t).unwrap_err().to_string();
        assert!(
            bad("[[rule]]\nname = \"x\"\nwhn = []\n").contains("whn"),
            "typos are rejected"
        );
        assert!(
            bad("[[rule]]\nname = \"x\"\nwhen = [\"from contains\"]\nthen = [\"read\"]\n")
                .contains("rule #1")
        );
        let e = bad("[[rule]]\nname = \"x\"\nwhen = [\"subject wobbles y\"]\nthen = [\"read\"]\n");
        assert!(
            e.contains("\"x\"") && e.contains("subject wobbles y"),
            "{e}"
        );
        assert!(bad("[[rule]]\nname = \"x\"\nwhen = [\"all-new\"]\n").contains("`then`"));
        assert!(bad("[[rule]]\nname = \"x\"\nthen = [\"read\"]\n").contains("`when`"));
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
}
