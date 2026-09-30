//! GMX rules to Sieve text. Every rule is read back before it is written; a part that would not come
//! back the same is written as raw JSON instead, so export and re-import never change a rule.

use std::{collections::BTreeSet, fmt::Write as _};

use super::{ADDRESS_BOOK, EXTENSIONS, Group, PRIORITY_HEADER, parse_sieve};
use crate::{
    Action, Comparator, Condition, KnownAction, KnownCondition, KnownHeaderCondition, Operator,
    PriorityLevel, Rule,
};

const HEADER: &str = "\
# gmxf rules, Sieve form (experimental; docs/sieve.md). File order is rule order.
# `# rule:[name]` names the rule below it, `# gmxf-id:` ties it to a server rule, `allof(false, …)` disables it.
# `# gmxf-condition:` / `# gmxf-actions:` hold raw API JSON for what this Sieve subset cannot say.
";

type Caps = BTreeSet<&'static str>;

/// Renders the rules as a Sieve script.
pub fn export_sieve(rules: &[Rule]) -> String {
    let blocks: Vec<(String, Caps)> = rules.iter().map(rule_block).collect();
    let caps: Caps = blocks.iter().flat_map(|(_, c)| c.iter().copied()).collect();
    let mut out = String::from(HEADER);
    if !caps.is_empty() {
        let list: Vec<String> = caps.iter().map(|c| quote(c)).collect();
        let _ = writeln!(out, "require [{}];", list.join(", "));
    }
    for (text, _) in blocks {
        out.push('\n');
        out.push_str(&text);
    }
    out
}

fn rule_block(rule: &Rule) -> (String, Caps) {
    [(true, true), (false, true), (true, false)]
        .into_iter()
        .filter_map(|(native_condition, native_actions)| {
            render(rule, native_condition, native_actions)
        })
        .find(|(text, _)| round_trips(rule, text))
        .unwrap_or_else(|| render(rule, false, false).expect("raw JSON always renders"))
}

fn round_trips(rule: &Rule, text: &str) -> bool {
    let all: Vec<String> = EXTENSIONS.iter().map(|e| quote(e)).collect();
    let script = format!("require [{}];\n{text}", all.join(", "));
    parse_sieve(&script, false)
        .is_ok_and(|parsed| matches!(parsed.rules.as_slice(), [one] if one.same_as(rule)))
}

fn render(rule: &Rule, native_condition: bool, native_actions: bool) -> Option<(String, Caps)> {
    let mut caps = Caps::new();
    let mut out = String::new();
    if rule.rule_name.contains(['\n', '\r']) {
        let _ = writeln!(
            out,
            "# gmxf-name: {}",
            serde_json::to_string(&rule.rule_name).ok()?
        );
    } else {
        let _ = writeln!(out, "# rule:[{}]", rule.rule_name);
    }
    if let Some(id) = &rule.rule_id {
        let _ = writeln!(out, "# gmxf-id: {id}");
    }
    let test = if native_condition {
        let col = if rule.active {
            "if "
        } else {
            "if allof(false, "
        }
        .len();
        condition(&rule.condition, &mut caps, Some(At { line: 0, col }))?
    } else {
        let _ = writeln!(
            out,
            "# gmxf-condition: {}",
            serde_json::to_string(&rule.condition).ok()?
        );
        "true".to_owned()
    };
    let body = if native_actions {
        actions(&rule.actions, &mut caps)?
    } else {
        let _ = writeln!(
            out,
            "# gmxf-actions: {}",
            serde_json::to_string(&rule.actions).ok()?
        );
        vec!["keep;".to_owned()]
    };
    let test = if rule.active {
        test
    } else {
        format!("allof(false, {test})")
    };
    let _ = writeln!(out, "if {test} {{");
    for line in body {
        let _ = writeln!(out, "    {line}");
    }
    out.push_str("}\n");
    Some((out, caps))
}

fn quote(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

/// Where a test that may span several lines starts: the indent of its line and its column.
#[derive(Clone, Copy)]
struct At {
    line: usize,
    col: usize,
}

/// Key lists longer than this go one key per line.
const INLINE_KEYS: usize = 3;
const INLINE_WIDTH: usize = 60;

/// With `at`, the tests of an `anyof`/`allof` go one per line and long key lists break; without it
/// everything stays on one line.
fn condition(c: &Condition, caps: &mut Caps, at: Option<At>) -> Option<String> {
    let Condition::Known(known) = c else {
        return None;
    };
    let not = |inverted: bool| if inverted { "not " } else { "" };
    Some(match known {
        KnownCondition::AnyOf { conditions } | KnownCondition::AllOf { conditions } => {
            let name = if matches!(known, KnownCondition::AnyOf { .. }) {
                "anyof"
            } else {
                "allof"
            };
            let child = at.map(|at| {
                let col = at.col + name.len() + "(".len();
                At { line: col, col }
            });
            let parts = conditions
                .iter()
                .map(|c| condition(c, caps, child))
                .collect::<Option<Vec<_>>>()?;
            let sep = child.map_or_else(
                || ", ".to_owned(),
                |child| format!(",\n{}", " ".repeat(child.col)),
            );
            format!("{name}({})", parts.join(&sep))
        }
        KnownCondition::AllNewEmails { inverted: false } => "true".to_owned(),
        KnownCondition::AllNewEmails { inverted: true } => return None,
        KnownCondition::SizeOver {
            inverted,
            byte_size,
        } => format!("{}size :over {}", not(*inverted), size(*byte_size)),
        KnownCondition::Priority { inverted, level } => {
            let level = match level {
                PriorityLevel::Low => "low",
                PriorityLevel::Normal => "normal",
                PriorityLevel::High => "high",
                PriorityLevel::Other(_) => return None,
            };
            format!(
                "{}header :is {} {}",
                not(*inverted),
                quote(PRIORITY_HEADER),
                quote(level)
            )
        }
        KnownCondition::AnyContact { inverted } => {
            caps.insert("extlists");
            format!(
                "{}address :list \"from\" {}",
                not(*inverted),
                quote(ADDRESS_BOOK)
            )
        }
        other => group(&Group::of(other)?, at)?,
    })
}

fn size(bytes: u64) -> String {
    [(30, "G"), (20, "M"), (10, "K")]
        .into_iter()
        .find(|(shift, _)| bytes > 0 && bytes.is_multiple_of(1 << shift))
        .map_or_else(
            || bytes.to_string(),
            |(shift, unit)| format!("{}{unit}", bytes >> shift),
        )
}

/// Match type, header list and key of one header comparison.
fn entry(h: &KnownHeaderCondition) -> Option<(&'static str, &'static str, &str, &Comparator)> {
    let (fields, comparator, value) = match h {
        KnownHeaderCondition::From {
            comparator, value, ..
        } => ("\"from\"", comparator, value),
        KnownHeaderCondition::Subject {
            comparator, value, ..
        } => ("\"subject\"", comparator, value),
        KnownHeaderCondition::ToCc {
            comparator,
            include_cc_header,
            value,
            ..
        } => {
            let fields = if *include_cc_header == Some(true) {
                "[\"to\", \"cc\"]"
            } else {
                "\"to\""
            };
            (fields, comparator, value)
        }
    };
    let how = match comparator {
        Comparator::Contains => ":contains",
        Comparator::Is => ":is",
        Comparator::StartsWith | Comparator::EndsWith => ":matches",
        Comparator::Other(_) => return None,
    };
    Some((how, fields, value, comparator))
}

fn key(value: &str, comparator: &Comparator) -> String {
    // `:matches` treats `*`, `?` and `\` specially
    let escaped = || {
        value
            .replace('\\', "\\\\")
            .replace('*', "\\*")
            .replace('?', "\\?")
    };
    quote(&match comparator {
        Comparator::StartsWith => format!("{}*", escaped()),
        Comparator::EndsWith => format!("*{}", escaped()),
        _ => value.to_owned(),
    })
}

fn group(g: &Group, at: Option<At>) -> Option<String> {
    let parts = g
        .entries
        .iter()
        .map(|h| entry(h).map(|e| (e, *entry_is_inverted(h))))
        .collect::<Option<Vec<_>>>()?;
    let ((how, fields, _, _), _) = parts.first()?;
    let uniform = parts
        .iter()
        .all(|((h, f, _, _), inverted)| h == how && f == fields && !inverted);
    let body = if uniform && (g.op == Operator::Or || parts.len() == 1) {
        let keys: Vec<String> = parts.iter().map(|((_, _, v, c), _)| key(v, c)).collect();
        let inline = keys.join(", ");
        let keys = match (keys.as_slice(), at) {
            ([one], _) => one.clone(),
            (_, Some(at)) if keys.len() > INLINE_KEYS || inline.len() > INLINE_WIDTH => {
                let indent = " ".repeat(at.line + 4);
                format!(
                    "[\n{indent}{}\n{}]",
                    keys.join(&format!(",\n{indent}")),
                    " ".repeat(at.line)
                )
            }
            _ => format!("[{inline}]"),
        };
        format!("header {how} {fields} {keys}")
    } else {
        let name = match g.op {
            Operator::Or => "anyof",
            Operator::And => "allof",
            Operator::Other(_) => return None,
        };
        let tests: Vec<String> = parts
            .iter()
            .map(|((how, fields, v, c), inverted)| {
                let not = if *inverted { "not " } else { "" };
                format!("{not}header {how} {fields} {}", key(v, c))
            })
            .collect();
        format!("{name}({})", tests.join(", "))
    };
    Some(if g.inverted {
        format!("not {body}")
    } else {
        body
    })
}

fn entry_is_inverted(h: &KnownHeaderCondition) -> &bool {
    match h {
        KnownHeaderCondition::From { inverted, .. }
        | KnownHeaderCondition::Subject { inverted, .. }
        | KnownHeaderCondition::ToCc { inverted, .. } => inverted,
    }
}

fn actions(list: &[Action], caps: &mut Caps) -> Option<Vec<String>> {
    let (body, stop) = match list.split_last() {
        Some((Action::Known(KnownAction::Stop), body)) => (body, true),
        _ => (list, false),
    };
    let mut out = Vec::new();
    for a in body {
        let Action::Known(known) = a else {
            return None;
        };
        match known {
            KnownAction::MoveToFolder { folder } => {
                caps.insert("fileinto");
                out.push(format!("fileinto {};", quote(folder)));
            }
            KnownAction::CopyToFolder { folder } => {
                caps.extend(["fileinto", "copy"]);
                out.push(format!("fileinto :copy {};", quote(folder)));
            }
            KnownAction::MarkSeen => {
                caps.insert("imap4flags");
                out.push(r#"addflag "\\Seen";"#.to_owned());
            }
            KnownAction::DeleteMailImmediately => out.push("discard;".to_owned()),
            KnownAction::CopyForward { receivers, .. } if !receivers.is_empty() => {
                caps.insert("copy");
                out.extend(
                    receivers
                        .iter()
                        .map(|r| format!("redirect :copy {};", quote(r))),
                );
            }
            KnownAction::TemplatedEmailNotify { pagers, .. } if !pagers.is_empty() => {
                caps.insert("enotify");
                out.push(format!(
                    "notify {};",
                    quote(&format!("mailto:{}", pagers.join(",")))
                ));
            }
            _ => return None,
        }
    }
    if stop {
        out.push("stop;".to_owned());
    }
    (!out.is_empty()).then_some(out)
}
