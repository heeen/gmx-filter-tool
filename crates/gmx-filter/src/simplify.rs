//! Rewrites a rule list into fewer, simpler rules that act on exactly the same mail.

use crate::{Action, KnownAction, Mode, Rule, Test, condition, tests_of};

/// The simplified rules and what was changed, one line per change.
#[derive(Debug, Clone)]
pub struct Simplified {
    pub rules: Vec<Rule>,
    pub notes: Vec<String>,
}

impl Simplified {
    /// Server rules that no longer appear because they were merged into another one.
    pub fn merged_away(&self) -> usize {
        self.notes
            .iter()
            .filter(|n| n.starts_with("merged"))
            .count()
    }
}

/// Only changes that keep the meaning:
/// - a condition listed twice in one rule is kept once;
/// - adjacent rules with identical actions that both stop, are both on (or both off) and match on
///   "any" of their conditions become one rule with all their conditions. Since the first one stopped
///   before, a mail it matched never reached the second, so "any of both" acts the same.
///
/// Rules held as raw JSON are left alone.
pub fn simplify(rules: &[Rule]) -> Simplified {
    let mut notes = Vec::new();
    let mut out: Vec<Rule> = Vec::new();
    for rule in rules {
        let mut rule = rule.clone();
        if let Some((mode, tests)) = tests_of(&rule.condition) {
            let unique = dedup(&tests);
            if unique.len() < tests.len()
                && let Ok(c) = condition(mode, &unique)
            {
                notes.push(format!(
                    "{:?}: removed {} repeated condition(s)",
                    rule.rule_name,
                    tests.len() - unique.len()
                ));
                rule.condition = c;
            }
        }
        if let Some(previous) = out.last_mut()
            && let Some(merged) = merge(previous, &rule)
        {
            notes.push(format!(
                "merged {:?} (id {}) into {:?}: same actions, adjacent, both stop",
                rule.rule_name,
                rule.rule_id.as_deref().unwrap_or("-"),
                previous.rule_name
            ));
            previous.condition = merged;
            continue;
        }
        out.push(rule);
    }
    Simplified { rules: out, notes }
}

fn dedup(tests: &[Test]) -> Vec<Test> {
    let mut unique: Vec<Test> = Vec::with_capacity(tests.len());
    for t in tests {
        if !unique.contains(t) {
            unique.push(t.clone());
        }
    }
    unique
}

/// The rows of a rule that matches on any of them, or `None`.
fn any_rows(rule: &Rule) -> Option<Vec<Test>> {
    match tests_of(&rule.condition)? {
        (_, tests) if tests.len() == 1 => Some(tests),
        (Mode::Any, tests) => Some(tests),
        (Mode::All, _) => None,
    }
}

fn merge(a: &Rule, b: &Rule) -> Option<crate::Condition> {
    let stops = matches!(a.actions.last(), Some(Action::Known(KnownAction::Stop)));
    let same = a.kind == b.kind
        && a.active == b.active
        && a.consider_stopped == b.consider_stopped
        && a.actions == b.actions;
    if !(same && stops) {
        return None;
    }
    let rows = dedup(&[any_rows(a)?, any_rows(b)?].concat());
    condition(Mode::Any, &rows).ok()
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::{Effect, actions};

    fn rule(
        id: &str,
        name: &str,
        mode: Mode,
        when: &[&str],
        then: Vec<Effect>,
        stop: bool,
    ) -> Rule {
        let tests: Vec<Test> = when.iter().map(|s| s.parse().unwrap()).collect();
        let mut r = Rule::new(name, condition(mode, &tests).unwrap(), actions(then, stop));
        r.rule_id = Some(id.into());
        r
    }

    fn rows(r: &Rule) -> Vec<String> {
        tests_of(&r.condition)
            .unwrap()
            .1
            .iter()
            .map(ToString::to_string)
            .collect()
    }

    fn mv(f: &str) -> Vec<Effect> {
        vec![Effect::Move(f.into())]
    }

    #[test]
    fn adjacent_stopping_rules_with_the_same_actions_merge() {
        let s = simplify(&[
            rule(
                "5",
                "club-2",
                Mode::Any,
                &["from contains wiki@club.example"],
                mv("INBOX/Club"),
                true,
            ),
            rule(
                "4",
                "club",
                Mode::Any,
                &[
                    "to contains members@club.example",
                    "to contains wiki@club.example",
                ],
                mv("INBOX/Club"),
                true,
            ),
            rule(
                "9",
                "other",
                Mode::Any,
                &["subject contains x"],
                mv("INBOX/Other"),
                true,
            ),
        ]);
        assert_eq!(s.rules.len(), 2);
        assert_eq!(
            s.rules[0].rule_id.as_deref(),
            Some("5"),
            "the first rule's id and name are kept"
        );
        assert_eq!(
            rows(&s.rules[0]),
            [
                "from contains wiki@club.example",
                "to contains members@club.example",
                "to contains wiki@club.example"
            ]
        );
        assert_eq!(s.merged_away(), 1);
        assert!(
            s.notes[0].contains("merged \"club\" (id 4) into \"club-2\""),
            "{:?}",
            s.notes
        );
    }

    #[test]
    fn chains_merge_and_repeats_go() {
        let s = simplify(&[
            rule(
                "1",
                "a",
                Mode::Any,
                &["from contains a", "from contains a"],
                mv("X"),
                true,
            ),
            rule(
                "2",
                "b",
                Mode::Any,
                &["from contains b", "from contains a"],
                mv("X"),
                true,
            ),
            rule("3", "c", Mode::Any, &["subject contains c"], mv("X"), true),
        ]);
        assert_eq!(s.rules.len(), 1);
        assert_eq!(
            rows(&s.rules[0]),
            ["from contains a", "from contains b", "subject contains c"]
        );
        assert_eq!(s.merged_away(), 2);
        assert!(s.notes[0].contains("removed 1 repeated condition"));
    }

    #[test]
    fn nothing_changes_when_the_meaning_would() {
        let base = || rule("1", "a", Mode::Any, &["from contains a"], mv("X"), true);
        let cases = [
            (
                "no stop",
                rule("2", "b", Mode::Any, &["from contains b"], mv("X"), false),
            ),
            (
                "other actions",
                rule("2", "b", Mode::Any, &["from contains b"], mv("Y"), true),
            ),
            (
                "all of",
                rule(
                    "2",
                    "b",
                    Mode::All,
                    &["from contains b", "size gt 1MB"],
                    mv("X"),
                    true,
                ),
            ),
            ("inactive", {
                let mut r = rule("2", "b", Mode::Any, &["from contains b"], mv("X"), true);
                r.active = false;
                r
            }),
            ("raw", {
                let mut r = rule("2", "b", Mode::Any, &["from contains b"], mv("X"), true);
                r.condition = serde_json::from_value(json!({"type": "Future"})).unwrap();
                r
            }),
        ];
        for (why, second) in cases {
            let s = simplify(&[base(), second]);
            assert_eq!(s.rules.len(), 2, "{why}");
            assert!(s.notes.is_empty(), "{why}: {:?}", s.notes);
        }
        let first_without_stop = rule("1", "a", Mode::Any, &["from contains a"], mv("X"), false);
        let s = simplify(&[
            first_without_stop,
            rule("2", "b", Mode::Any, &["from contains b"], mv("X"), false),
        ]);
        assert_eq!(s.rules.len(), 2);
        // not adjacent: a rule in between could catch the mail first
        let s = simplify(&[
            base(),
            rule("7", "m", Mode::Any, &["from contains m"], mv("Y"), true),
            rule("2", "b", Mode::Any, &["from contains b"], mv("X"), true),
        ]);
        assert_eq!(s.rules.len(), 3);
    }

    #[test]
    fn a_repeat_in_an_all_rule_is_also_removed() {
        let s = simplify(&[rule(
            "1",
            "a",
            Mode::All,
            &["from contains a", "size gt 1MB", "from contains a"],
            mv("X"),
            true,
        )]);
        assert_eq!(
            tests_of(&s.rules[0].condition).unwrap(),
            (
                Mode::All,
                vec![
                    "from contains a".parse().unwrap(),
                    "size gt 1MB".parse().unwrap()
                ]
            )
        );
    }
}
