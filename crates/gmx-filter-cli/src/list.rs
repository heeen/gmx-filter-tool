//! `gmxf list`: one line per rule under a header.

use gmx_filter::{Mode, Rule, Test, effects_of, rule_notes, tests_of};

/// Values shown per condition group before `+N more`, unless `--long`.
const SHOWN_VALUES: usize = 3;

pub fn table(rules: &[Rule], long: bool) -> String {
    let header = ["ID", "NAME", "ENABLED", "RULE"].map(String::from);
    let rows: Vec<[String; 4]> = rules
        .iter()
        .map(|r| {
            [
                short_id(r.rule_id.as_deref().unwrap_or("-"), long),
                r.rule_name.clone(),
                if r.active { "yes" } else { "no" }.into(),
                describe(r, long),
            ]
        })
        .collect();
    let width = |col: usize| {
        std::iter::once(&header)
            .chain(&rows)
            .map(|row| row[col].chars().count())
            .max()
            .unwrap_or(0)
    };
    let widths = [width(0), width(1), width(2)];
    std::iter::once(&header)
        .chain(&rows)
        .map(|[id, name, enabled, rule]| {
            let line = format!(
                "{id:<w0$}  {name:<w1$}  {enabled:<w2$}  {rule}",
                w0 = widths[0],
                w1 = widths[1],
                w2 = widths[2]
            );
            format!("{}\n", line.trim_end())
        })
        .collect()
}

/// Ids longer than this are shown shortened (commands accept any unique start of an id).
const SHORT_ID: usize = 8;

fn short_id(id: &str, long: bool) -> String {
    match id.char_indices().nth(SHORT_ID) {
        Some((cut, _)) if !long => id[..cut].to_owned(),
        _ => id.to_owned(),
    }
}

/// `from contains ["a", "b"] or subject contains "x" -> move INBOX/X, stop`, plus notes.
fn describe(rule: &Rule, long: bool) -> String {
    let condition = match tests_of(&rule.condition) {
        Some((mode, tests)) => {
            let sep = if mode == Mode::All { " and " } else { " or " };
            groups(&tests)
                .iter()
                .map(|(key, values)| group_text(key, values, long))
                .collect::<Vec<_>>()
                .join(sep)
        }
        None => format!(
            "raw condition {}",
            raw(serde_json::to_string(&rule.condition))
        ),
    };
    let actions = match effects_of(&rule.actions) {
        Some((effects, stop)) => {
            let mut parts: Vec<String> = effects.iter().map(ToString::to_string).collect();
            if stop {
                parts.push("stop".into());
            }
            parts.join(", ")
        }
        None => format!("raw actions {}", raw(serde_json::to_string(&rule.actions))),
    };
    let notes: String = rule_notes(rule)
        .iter()
        .map(|n| format!("  [{n}]"))
        .collect();
    format!("{condition} -> {actions}{notes}")
}

/// Header conditions grouped by field and operator in order of appearance (`"from contains"` with
/// its values); every other condition is its own group without values.
fn groups(tests: &[Test]) -> Vec<(String, Vec<String>)> {
    let mut out: Vec<(String, Vec<String>)> = Vec::new();
    for test in tests {
        let Test::Header { value, .. } = test else {
            out.push((test.to_string(), Vec::new()));
            continue;
        };
        let mut blank = test.clone();
        if let Test::Header { value, .. } = &mut blank {
            value.clear();
        }
        let key = blank.to_string().trim_end().to_owned();
        match out.iter_mut().find(|(k, v)| *k == key && !v.is_empty()) {
            Some((_, values)) => values.push(value.clone()),
            None => out.push((key, vec![value.clone()])),
        }
    }
    out
}

fn group_text(key: &str, values: &[String], long: bool) -> String {
    match values {
        [] => key.to_owned(),
        [one] => format!("{key} {one:?}"),
        many => {
            let shown = if long {
                many.len()
            } else {
                SHOWN_VALUES.min(many.len())
            };
            let mut items: Vec<String> = many[..shown].iter().map(|v| format!("{v:?}")).collect();
            if shown < many.len() {
                items.push(format!("+{} more", many.len() - shown));
            }
            format!("{key} [{}]", items.join(", "))
        }
    }
}

/// Compact JSON, shortened.
fn raw(json: serde_json::Result<String>) -> String {
    const MAX_CHARS: usize = 60;
    let json = json.unwrap_or_default();
    match json.char_indices().nth(MAX_CHARS) {
        Some((cut, _)) => format!("{}…", &json[..cut]),
        None => json,
    }
}

#[cfg(test)]
mod tests {
    use gmx_filter::{Effect, actions, condition};
    use serde_json::json;

    use super::*;

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

    #[test]
    fn columns_fit_their_content_under_a_header() {
        let mut off = rule(
            "2",
            "chatter",
            Mode::Any,
            &["from contains @chatter.example"],
            vec![Effect::Move("INBOX/chatter".into())],
            true,
        );
        off.active = false;
        let rules = [
            rule(
                "5",
                "club köln",
                Mode::Any,
                &["to contains a@x.de", "to contains b@x.de"],
                vec![Effect::Move("INBOX/Club Köln".into())],
                true,
            ),
            off,
        ];
        let text = table(&rules, false);
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines[0], "ID  NAME       ENABLED  RULE");
        assert_eq!(
            lines[1],
            r#"5   club köln  yes      to contains ["a@x.de", "b@x.de"] -> move INBOX/Club Köln, stop"#
        );
        assert_eq!(
            lines[2],
            r#"2   chatter    no       from contains "@chatter.example" -> move INBOX/chatter, stop"#
        );
    }

    #[test]
    fn long_ids_are_shortened_unless_long() {
        let r = [rule(
            "cef5ab49-8a55-48b3-b603-14303a79e7ca",
            "u",
            Mode::Any,
            &["all-new"],
            vec![Effect::MarkRead],
            false,
        )];
        assert!(
            table(&r, false)
                .lines()
                .nth(1)
                .unwrap()
                .starts_with("cef5ab49  u")
        );
        assert!(table(&r, true).contains("cef5ab49-8a55-48b3-b603-14303a79e7ca  u"));
    }

    #[test]
    fn long_groups_are_shortened_unless_long() {
        let senders: Vec<String> = (1..=6)
            .map(|i| format!("from contains s{i}@x.de"))
            .collect();
        let mut when: Vec<&str> = senders.iter().map(String::as_str).collect();
        when.push("subject starts-with [news]");
        let r = [rule(
            "1",
            "Newsletter",
            Mode::Any,
            &when,
            vec![Effect::MarkRead],
            false,
        )];
        let short = table(&r, false);
        assert!(short.contains(r#"from contains ["s1@x.de", "s2@x.de", "s3@x.de", +3 more] or subject starts-with "[news]" -> read"#), "{short}");
        assert!(table(&r, true).contains(r#""s6@x.de"] or"#));
    }

    #[test]
    fn all_rules_join_with_and_and_raw_parts_are_marked() {
        let r = rule(
            "7",
            "big",
            Mode::All,
            &["from contains a", "size gt 5MB", "from contains b"],
            vec![Effect::Delete],
            true,
        );
        assert!(
            table(&[r], false)
                .contains(r#"from contains ["a", "b"] and size gt 5MB -> delete, stop"#)
        );
        let mut odd = rule(
            "8",
            "odd",
            Mode::Any,
            &["all-new"],
            vec![Effect::MarkRead],
            false,
        );
        odd.condition = serde_json::from_value(json!({"type": "Future", "x": 1})).unwrap();
        odd.actions = serde_json::from_value(json!([{"type": "ExcludeFromSpamFilter"}])).unwrap();
        let text = table(&[odd], false);
        assert!(text.contains(r#"raw condition {"type":"Future","x":1} -> raw actions [{"type":"ExcludeFromSpamFilter"}]"#), "{text}");
        assert!(text.contains("[legacy rule"));
    }
}
