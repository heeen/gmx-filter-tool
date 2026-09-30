//! Sanity checks on a rules file, beyond what parsing already rejects.

use std::{collections::HashSet, fmt};

use crate::{
    Action, Condition, DesiredRule, Effect, Folder, KnownAction, KnownCondition, Rule, Test,
    effects_of, tests_of,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// Worth knowing, nothing to fix.
    Note,
    /// Probably not what you meant.
    Warning,
    /// `apply` refuses to run.
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnostic {
    pub severity: Severity,
    /// 1-based position in the file.
    pub rule: usize,
    pub name: String,
    pub message: String,
}

impl fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let level = match self.severity {
            Severity::Note => "note",
            Severity::Warning => "warning",
            Severity::Error => "error",
        };
        write!(
            f,
            "{level}: rule #{} {:?}: {}",
            self.rule, self.name, self.message
        )
    }
}

pub fn has_errors(diagnostics: &[Diagnostic]) -> bool {
    diagnostics.iter().any(|d| d.severity == Severity::Error)
}

fn plausible_address(a: &str) -> bool {
    matches!(a.split_once('@'), Some((local, domain))
        if !local.is_empty() && domain.contains('.') && !a.contains(char::is_whitespace) && a.matches('@').count() == 1)
}

fn looks_like_a_pattern(value: &str) -> bool {
    value.contains(".*")
        || value.starts_with('^')
        || value.ends_with('$')
        || value.starts_with('*')
        || value.contains("\\d")
}

fn stops(actions: &[Action]) -> bool {
    matches!(actions.last(), Some(Action::Known(KnownAction::Stop)))
}

/// Checks `desired` in file order. `folders` enables the unknown-folder check; `remote` is used to
/// tell new forward/notify targets (which need confirming) from existing ones.
pub fn check(
    desired: &[DesiredRule],
    folders: Option<&[Folder]>,
    remote: &[Rule],
) -> Vec<Diagnostic> {
    let mut out = Vec::new();
    let mut push = |i: usize, d: &DesiredRule, severity, message: String| {
        out.push(Diagnostic {
            severity,
            rule: i + 1,
            name: d.name.clone(),
            message,
        });
    };

    let mut ids = HashSet::new();
    for (i, d) in desired.iter().enumerate() {
        if let Some(id) = &d.id
            && !ids.insert(id.clone())
        {
            push(
                i,
                d,
                Severity::Error,
                format!("id {id} appears more than once"),
            );
        }
        if d.name.trim().is_empty() {
            push(i, d, Severity::Error, "the name is empty".into());
        }
        let same_name = desired.iter().filter(|o| o.name == d.name).count();
        if same_name > 1 && i == desired.iter().position(|o| o.name == d.name).unwrap_or(i) {
            let ambiguous = desired.iter().any(|o| o.name == d.name && o.id.is_none());
            let severity = if ambiguous {
                Severity::Error
            } else {
                Severity::Warning
            };
            let hint = if ambiguous {
                " (give each of them an `id`, or rename)"
            } else {
                ""
            };
            push(
                i,
                d,
                severity,
                format!("{same_name} rules share this name{hint}"),
            );
        }

        if let Some((_, tests)) = tests_of(&d.condition) {
            for (k, t) in tests.iter().enumerate() {
                if tests[..k].contains(t) {
                    push(
                        i,
                        d,
                        Severity::Warning,
                        format!("the condition `{t}` is listed twice"),
                    );
                }
            }
            for t in &tests {
                match t {
                    Test::Size { bytes: 0, .. } => push(
                        i,
                        d,
                        Severity::Error,
                        "a size limit of 0 matches everything or nothing".into(),
                    ),
                    Test::Header { value, .. } if looks_like_a_pattern(value) => push(
                        i,
                        d,
                        Severity::Warning,
                        format!(
                            "{value:?} is matched literally, there are no wildcards or patterns"
                        ),
                    ),
                    _ => {}
                }
            }
        }

        let effects = effects_of(&d.actions).map(|(e, _)| e).unwrap_or_default();
        for e in &effects {
            match e {
                Effect::Forward(a) | Effect::Notify(a) if !plausible_address(a) => {
                    push(
                        i,
                        d,
                        Severity::Error,
                        format!("{a:?} is not an email address"),
                    );
                }
                Effect::Move(f) | Effect::Copy(f) => {
                    if f.eq_ignore_ascii_case("INBOX") {
                        push(
                            i,
                            d,
                            Severity::Warning,
                            "the mail is already in INBOX".into(),
                        );
                    }
                    if let Some(known) = folders
                        && !known.iter().any(|k| &k.full_name == f)
                    {
                        push(
                            i,
                            d,
                            Severity::Error,
                            format!("unknown folder {f:?}; folders can be created in the web UI"),
                        );
                    }
                }
                _ => {}
            }
        }
        let folders_of = |pick: fn(&Effect) -> Option<&String>| -> Vec<&String> {
            effects.iter().filter_map(pick).collect()
        };
        let copied = folders_of(|e| {
            if let Effect::Copy(f) = e {
                Some(f)
            } else {
                None
            }
        });
        if folders_of(|e| {
            if let Effect::Move(f) = e {
                Some(f)
            } else {
                None
            }
        })
        .iter()
        .any(|m| copied.contains(m))
        {
            push(
                i,
                d,
                Severity::Warning,
                "moves and copies to the same folder".into(),
            );
        }
        if effects.contains(&Effect::Delete) && effects.len() > 1 {
            push(
                i,
                d,
                Severity::Warning,
                "deletes the mail, so its other actions have nothing to act on".into(),
            );
        }

        let existing =
            d.id.as_ref()
                .and_then(|id| remote.iter().find(|r| r.rule_id.as_ref() == Some(id)))
                .or_else(|| {
                    let mut same = remote.iter().filter(|r| r.rule_name == d.name);
                    same.next().filter(|_| same.next().is_none())
                });
        let sent = d.to_rule(existing);
        for a in &sent.actions {
            let (kind, target) = match a {
                Action::Known(KnownAction::CopyForward {
                    pending: true,
                    receivers,
                }) => ("forward", receivers),
                Action::Known(KnownAction::TemplatedEmailNotify {
                    pending: true,
                    pagers,
                }) => ("notification", pagers),
                _ => continue,
            };
            push(
                i,
                d,
                Severity::Note,
                format!(
                    "the {kind} target {} has to confirm by mail before it takes effect",
                    target.join(", ")
                ),
            );
        }
        if !d.active {
            push(
                i,
                d,
                Severity::Note,
                "inactive: the rule is saved but does nothing".into(),
            );
        }
    }

    for (i, d) in desired.iter().enumerate() {
        for (j, earlier) in desired.iter().enumerate().take(i) {
            if !earlier.active || !d.active {
                continue;
            }
            let catch_all = matches!(
                &earlier.condition,
                Condition::Known(KnownCondition::AllNewEmails { inverted: false })
            );
            if stops(&earlier.actions) && (catch_all || earlier.condition == d.condition) {
                let why = if catch_all {
                    "matches all new mail and stops"
                } else {
                    "has the same condition and stops"
                };
                out.push(Diagnostic {
                    severity: Severity::Warning,
                    rule: i + 1,
                    name: d.name.clone(),
                    message: format!("never reached: rule #{} {:?} {why}", j + 1, earlier.name),
                });
                break;
            }
            if earlier.condition == d.condition && earlier.actions == d.actions {
                out.push(Diagnostic {
                    severity: Severity::Warning,
                    rule: i + 1,
                    name: d.name.clone(),
                    message: format!("duplicates rule #{} {:?}", j + 1, earlier.name),
                });
                break;
            }
        }
    }
    out.sort_by_key(|d| d.rule);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rulefile::tests::fixtures;
    use crate::{export, parse};

    fn folders(names: &[&str]) -> Vec<Folder> {
        names
            .iter()
            .map(|n| Folder {
                full_name: (*n).into(),
                folder_type: "USER_DEFINED".into(),
                system_folder: false,
            })
            .collect()
    }

    fn rule(body: &str) -> String {
        format!("[[rule]]\nname = \"r\"\n{body}\n")
    }

    fn lint(text: &str, known: Option<&[Folder]>) -> Vec<Diagnostic> {
        check(&parse(text).unwrap(), known, &[])
    }

    fn messages(d: &[Diagnostic], severity: Severity) -> Vec<&str> {
        d.iter()
            .filter(|d| d.severity == severity)
            .map(|d| d.message.as_str())
            .collect()
    }

    #[test]
    fn a_clean_export_has_no_errors_or_warnings() {
        let remote = fixtures();
        let diagnostics = check(
            &parse(&export(&remote)).unwrap(),
            Some(&folders(&[
                "INBOX/Club Köln",
                "INBOX/Makerspace",
                "INBOX/chatter",
                "INBOX/Firmware",
            ])),
            &remote,
        );
        assert!(
            diagnostics.iter().all(|d| d.severity == Severity::Note),
            "{diagnostics:?}"
        );
        assert_eq!(
            messages(&diagnostics, Severity::Note),
            ["inactive: the rule is saved but does nothing"]
        );
    }

    #[test]
    fn unknown_folders_are_errors_only_when_folders_are_known() {
        let t = rule(
            "when = [\"all-new\"]\nthen = [{ move = \"INBOX/Nope\" }, { copy = \"INBOX/Yes\" }]",
        );
        assert!(lint(&t, None).is_empty());
        let d = lint(&t, Some(&folders(&["INBOX/Yes"])));
        assert_eq!(
            messages(&d, Severity::Error),
            ["unknown folder \"INBOX/Nope\"; folders can be created in the web UI"]
        );
        assert!(has_errors(&d));
    }

    #[test]
    fn addresses_sizes_and_names_are_validated() {
        let d = lint(
            &rule(
                "when = [{ size.gt = 0 }]\nthen = [{ forward = \"not-an-address\" }, { notify = \"a@b\" }]",
            ),
            None,
        );
        let errors = messages(&d, Severity::Error);
        assert!(errors.iter().any(|m| m.contains("size limit of 0")));
        assert!(
            errors
                .iter()
                .any(|m| m.contains("\"not-an-address\" is not an email address"))
        );
        assert!(
            errors
                .iter()
                .any(|m| m.contains("\"a@b\" is not an email address"))
        );
        let d = lint(
            "[[rule]]\nname = \" \"\nwhen = [\"all-new\"]\nthen = [\"read\"]\n",
            None,
        );
        assert!(messages(&d, Severity::Error).contains(&"the name is empty"));
    }

    #[test]
    fn duplicate_names_and_ids() {
        let two = |a: &str, b: &str| {
            format!(
                "[[rule]]\n{a}name = \"same\"\nwhen = [{{ subject.contains = \"x\" }}]\nthen = [\"read\"]\n\n[[rule]]\n{b}name = \"same\"\nwhen = [{{ subject.contains = \"y\" }}]\nthen = [\"read\"]\n"
            )
        };
        let d = lint(&two("", ""), None);
        assert!(messages(&d, Severity::Error)[0].contains("2 rules share this name"));
        let d = lint(&two("id = \"1\"\n", "id = \"2\"\n"), None);
        assert!(!has_errors(&d));
        assert!(messages(&d, Severity::Warning)[0].contains("share this name"));
        let d = lint(&two("id = \"1\"\n", "id = \"1\"\n"), None);
        assert!(
            messages(&d, Severity::Error)
                .iter()
                .any(|m| m.contains("id 1 appears more than once"))
        );
    }

    #[test]
    fn shadowed_and_duplicate_rules() {
        let a =
            "[[rule]]\nname = \"catch\"\nwhen = [\"all-new\"]\nthen = [{ move = \"INBOX/A\" }]\n\n";
        let b = "[[rule]]\nname = \"late\"\nwhen = [{ from.contains = \"x\" }]\nthen = [{ move = \"INBOX/B\" }]\n";
        let d = lint(&format!("{a}{b}"), None);
        assert_eq!(d[0].rule, 2);
        assert!(
            d[0].message.contains("never reached") && d[0].message.contains("matches all new mail")
        );
        let same = "[[rule]]\nname = \"one\"\nwhen = [{ from.contains = \"x\" }]\nthen = [{ move = \"INBOX/A\" }]\nstop = false\n\n[[rule]]\nname = \"two\"\nwhen = [{ from.contains = \"x\" }]\nthen = [{ move = \"INBOX/A\" }]\nstop = false\n";
        assert!(lint(same, None)[0].message.contains("duplicates rule #1"));
        let same_condition = "[[rule]]\nname = \"one\"\nwhen = [{ from.contains = \"x\" }]\nthen = [\"read\"]\n\n[[rule]]\nname = \"two\"\nwhen = [{ from.contains = \"x\" }]\nthen = [\"delete\"]\n";
        assert!(
            lint(same_condition, None)[0]
                .message
                .contains("has the same condition and stops")
        );
        let inactive = a.replace("then", "active = false\nthen");
        assert!(
            lint(&format!("{inactive}{b}"), None)
                .iter()
                .all(|d| d.severity != Severity::Warning)
        );
    }

    #[test]
    fn repeated_conditions_are_flagged() {
        let d = lint(
            &rule("from.contains = [\"a\", \"b\", \"a\"]\nthen = [\"read\"]"),
            None,
        );
        assert_eq!(
            messages(&d, Severity::Warning),
            ["the condition `from contains a` is listed twice"]
        );
    }

    #[test]
    fn suspicious_but_legal_rules_get_warnings() {
        let d = lint(
            &rule(
                "when = [{ from.contains = \".*@spam.com\" }]\nthen = [{ move = \"INBOX\" }, { copy = \"INBOX/A\" }, { move = \"INBOX/A\" }, \"delete\"]",
            ),
            None,
        );
        let w = messages(&d, Severity::Warning);
        assert!(w.iter().any(|m| m.contains("matched literally")));
        assert!(w.iter().any(|m| m.contains("already in INBOX")));
        assert!(
            w.iter()
                .any(|m| m.contains("moves and copies to the same folder"))
        );
        assert!(w.iter().any(|m| m.contains("deletes the mail")));
    }

    #[test]
    fn forward_targets_needing_confirmation_are_noted_once_known() {
        let t = rule(
            "when = [\"all-new\"]\nthen = [{ forward = \"a@b.de\" }, { notify = \"c@d.de\" }]",
        );
        let notes = messages(&lint(&t, None), Severity::Note).join("|");
        assert!(notes.contains("forward target a@b.de"));
        assert!(
            !notes.contains("c@d.de"),
            "the web UI sends notifications as confirmed: {notes}"
        );

        let mut existing = fixtures().remove(0);
        existing.rule_name = "r".into();
        existing.actions = serde_json::from_value(serde_json::json!([
            {"type": "CopyForward", "pending": false, "receivers": ["a@b.de"]}, {"type": "Stop"}]))
        .unwrap();
        let t = rule("when = [\"all-new\"]\nthen = [{ forward = \"a@b.de\" }]");
        assert!(
            check(&parse(&t).unwrap(), None, &[existing]).is_empty(),
            "a confirmed target is not noted again"
        );
    }
}
