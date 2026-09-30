//! Turning a desired rule list into the calls that make the server match it.

use std::fmt::Write as _;

use crate::{Client, DesiredRule, Error, Result, Rule, TokenSource};

/// A rule in the final order: one that exists on the server, or one this plan creates.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Key {
    Remote(usize),
    New(usize),
}

#[derive(Debug, Clone)]
pub enum Op {
    Create {
        rule: Rule,
        summary: String,
    },
    Update {
        id: String,
        rule: Rule,
        changes: Vec<(&'static str, String, String)>,
    },
    SetActive {
        id: String,
        name: String,
        active: bool,
    },
    Delete {
        id: String,
        name: String,
    },
    /// The complete rule order after everything else was applied; `None` marks a new rule.
    Reorder {
        order: Vec<(Option<String>, String)>,
    },
}

#[derive(Debug, Clone, Default)]
pub struct Plan {
    pub ops: Vec<Op>,
    /// Server rules the file does not mention (left alone, or deleted when pruning).
    pub unlisted: usize,
}

fn plan_err(msg: String) -> Error {
    Error::Plan(msg)
}

impl Plan {
    pub fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }

    pub fn deletes(&self) -> usize {
        self.ops
            .iter()
            .filter(|o| matches!(o, Op::Delete { .. }))
            .count()
    }

    /// What has to happen for the server to match `desired`. Server rules missing from the file are
    /// kept in their slot unless `prune`.
    pub fn diff(remote: &[Rule], desired: &[DesiredRule], prune: bool) -> Result<Self> {
        let mut matched: Vec<Option<usize>> = Vec::with_capacity(desired.len());
        let mut taken = vec![false; remote.len()];
        for d in desired {
            let found = match &d.id {
                Some(id) => Some(
                    remote
                        .iter()
                        .position(|r| r.rule_id.as_deref() == Some(id))
                        .ok_or_else(|| {
                            plan_err(format!(
                                "rule {:?}: id {id} does not exist on the server",
                                d.name
                            ))
                        })?,
                ),
                None => {
                    let same_name: Vec<usize> = remote
                        .iter()
                        .enumerate()
                        .filter(|(_, r)| r.rule_name == d.name)
                        .map(|(i, _)| i)
                        .collect();
                    match same_name[..] {
                        [] => None,
                        [one] => Some(one),
                        _ => {
                            return Err(plan_err(format!(
                                "rule {:?}: {} server rules have this name; add its `id`",
                                d.name,
                                same_name.len()
                            )));
                        }
                    }
                }
            };
            if let Some(i) = found
                && std::mem::replace(&mut taken[i], true)
            {
                return Err(plan_err(format!(
                    "rule {:?}: the server rule {:?} is already used by another entry",
                    d.name, remote[i].rule_name
                )));
            }
            matched.push(found);
        }

        let mut ops = Vec::new();
        let mut creates = Vec::new();
        for (di, d) in desired.iter().enumerate() {
            match matched[di] {
                None => {
                    let clash = remote.iter().any(|r| r.rule_name == d.name)
                        || desired
                            .iter()
                            .enumerate()
                            .any(|(j, o)| j != di && o.name == d.name);
                    if clash {
                        return Err(plan_err(format!(
                            "new rule {:?}: the name is not unique, so the new rule could not be told apart",
                            d.name
                        )));
                    }
                    creates.push(Op::Create {
                        rule: d.to_rule(None),
                        summary: d.summary(),
                    });
                }
                Some(ri) if !d.same_as(&remote[ri]) => {
                    let remote_rule = &remote[ri];
                    let id = remote_rule.rule_id.clone().ok_or(Error::MissingRuleId)?;
                    let changes = d.changes(remote_rule);
                    if changes.iter().any(|c| c.0 != "active") {
                        let mut rule = d.to_rule(Some(remote_rule));
                        rule.active = remote_rule.active;
                        let changes = changes.into_iter().filter(|c| c.0 != "active").collect();
                        ops.push(Op::Update {
                            id: id.clone(),
                            rule,
                            changes,
                        });
                    }
                    if d.active != remote_rule.active {
                        ops.push(Op::SetActive {
                            id,
                            name: d.name.clone(),
                            active: d.active,
                        });
                    }
                }
                Some(_) => {}
            }
        }
        if prune {
            for r in remote
                .iter()
                .zip(&taken)
                .filter(|(_, t)| !**t)
                .map(|(r, _)| r)
            {
                let id = r.rule_id.clone().ok_or(Error::MissingRuleId)?;
                ops.push(Op::Delete {
                    id,
                    name: r.rule_name.clone(),
                });
            }
        }
        ops.splice(0..0, creates);

        if let Some(order) = reorder(remote, desired, &matched, &taken, prune) {
            ops.push(Op::Reorder { order });
        }
        let unlisted = taken.iter().filter(|t| !**t).count();
        Ok(Plan { ops, unlisted })
    }

    /// Human-readable list of the operations.
    pub fn render(&self) -> String {
        if self.is_empty() {
            return "no changes\n".into();
        }
        let mut out = String::new();
        for op in &self.ops {
            match op {
                Op::Create { rule, summary } => {
                    let _ = writeln!(out, "+ create   {:?}\n      {summary}", rule.rule_name);
                }
                Op::Update { rule, changes, .. } => {
                    let _ = writeln!(out, "~ update   {:?}", rule.rule_name);
                    for (field, before, after) in changes {
                        let _ = writeln!(out, "      {field}: {before:?} -> {after:?}");
                    }
                }
                Op::SetActive { name, active, .. } => {
                    let _ = writeln!(
                        out,
                        "~ {}  {name:?}",
                        if *active { "enable   " } else { "disable  " }
                    );
                }
                Op::Delete { name, .. } => {
                    let _ = writeln!(out, "- delete   {name:?}");
                }
                Op::Reorder { order } => {
                    let _ = writeln!(out, "↕ reorder");
                    for (i, (_, name)) in order.iter().enumerate() {
                        let _ = writeln!(out, "      {:>2}. {name}", i + 1);
                    }
                }
            }
        }
        out
    }

    /// Applies the plan, then checks that the server now matches `desired`.
    pub fn execute<T: TokenSource>(
        &self,
        client: &Client<T>,
        desired: &[DesiredRule],
        prune: bool,
    ) -> Result<()> {
        let writes = |wanted: fn(&Op) -> bool| self.ops.iter().filter(move |o| wanted(o));
        for op in writes(|o| matches!(o, Op::Create { .. })) {
            if let Op::Create { rule, .. } = op {
                client.create_rule(rule)?;
            }
        }
        for op in writes(|o| matches!(o, Op::Update { .. })) {
            if let Op::Update { rule, .. } = op {
                client.update_rule(rule)?;
            }
        }
        for op in writes(|o| matches!(o, Op::SetActive { .. })) {
            if let Op::SetActive { id, active, .. } = op {
                client.set_active(id, *active)?;
            }
        }
        for op in writes(|o| matches!(o, Op::Delete { .. })) {
            if let Op::Delete { id, .. } = op {
                client.delete_rule(id)?;
            }
        }
        if let Some(Op::Reorder { order }) =
            self.ops.iter().find(|o| matches!(o, Op::Reorder { .. }))
        {
            let now = client.list_rules()?;
            let ordered = order
                .iter()
                .map(|(id, name)| {
                    let by_id = |r: &&Rule| id.is_some() && r.rule_id == *id;
                    let by_name = |r: &&Rule| id.is_none() && &r.rule_name == name;
                    now.iter()
                        .find(|r| by_id(r) || by_name(r))
                        .cloned()
                        .ok_or_else(|| {
                            plan_err(format!("rule {name:?} disappeared while applying"))
                        })
                })
                .collect::<Result<Vec<_>>>()?;
            let untouched: Vec<Rule> = now
                .iter()
                .filter(|r| !ordered.iter().any(|o| o.rule_id == r.rule_id))
                .cloned()
                .collect();
            client.reorder_rules(&[ordered, untouched].concat())?;
        }

        let left = Plan::diff(&client.list_rules()?, desired, prune)?;
        if left.is_empty() {
            Ok(())
        } else {
            Err(Error::Drift(left.render()))
        }
    }
}

/// The complete order the server should end up with, or `None` if creating the new rules at the
/// end and leaving the rest alone already gives it.
fn reorder(
    remote: &[Rule],
    desired: &[DesiredRule],
    matched: &[Option<usize>],
    taken: &[bool],
    prune: bool,
) -> Option<Vec<(Option<String>, String)>> {
    let kept: Vec<usize> = (0..remote.len()).filter(|i| taken[*i] || !prune).collect();
    let natural: Vec<Key> = kept
        .iter()
        .map(|i| Key::Remote(*i))
        .chain(
            (0..desired.len())
                .filter(|d| matched[*d].is_none())
                .map(Key::New),
        )
        .collect();

    // matched rules take the slots of matched rules, in file order; others stay where they are
    let mut in_file_order = matched.iter().flatten().map(|i| Key::Remote(*i));
    let mut wanted: Vec<Key> = kept
        .iter()
        .map(|i| {
            if taken[*i] {
                in_file_order.next().unwrap_or(Key::Remote(*i))
            } else {
                Key::Remote(*i)
            }
        })
        .collect();
    for di in (0..desired.len()).filter(|d| matched[*d].is_none()) {
        let anchor = (di + 1..desired.len())
            .find_map(|later| matched[later])
            .and_then(|ri| wanted.iter().position(|k| *k == Key::Remote(ri)));
        wanted.insert(anchor.unwrap_or(wanted.len()), Key::New(di));
    }
    if wanted == natural {
        return None;
    }
    Some(
        wanted
            .into_iter()
            .map(|k| match k {
                Key::Remote(i) => {
                    // show the name the rule will have after this plan
                    let renamed = matched
                        .iter()
                        .position(|m| *m == Some(i))
                        .map(|d| desired[d].name.clone());
                    (
                        remote[i].rule_id.clone(),
                        renamed.unwrap_or_else(|| remote[i].rule_name.clone()),
                    )
                }
                Key::New(d) => (None, desired[d].name.clone()),
            })
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use mockito::{Matcher, Server};
    use secrecy::SecretString;
    use serde_json::json;

    use super::*;
    use crate::rulefile::tests::fixtures;
    use crate::{export, parse};

    fn desired(text: &str) -> Vec<DesiredRule> {
        parse(text).unwrap()
    }

    fn plan(remote: &[Rule], text: &str, prune: bool) -> Result<Plan> {
        Plan::diff(remote, &desired(text), prune)
    }

    fn kinds(p: &Plan) -> Vec<&'static str> {
        p.ops
            .iter()
            .map(|o| match o {
                Op::Create { .. } => "create",
                Op::Update { .. } => "update",
                Op::SetActive { .. } => "active",
                Op::Delete { .. } => "delete",
                Op::Reorder { .. } => "reorder",
            })
            .collect()
    }

    /// The `[[rule]]` blocks of an export, so tests can move them around.
    fn blocks(text: &str) -> Vec<String> {
        text.split("\n[[rule]]\n")
            .skip(1)
            .map(|b| format!("[[rule]]\n{b}"))
            .collect()
    }

    fn order_names(p: &Plan) -> Vec<String> {
        match p.ops.last() {
            Some(Op::Reorder { order }) => order.iter().map(|(_, n)| n.clone()).collect(),
            other => panic!("no reorder: {other:?}"),
        }
    }

    #[test]
    fn an_exported_file_is_a_noop() {
        let remote = fixtures();
        let p = plan(&remote, &export(&remote), true).unwrap();
        assert!(p.is_empty(), "{}", p.render());
        assert_eq!(p.render(), "no changes\n");
    }

    #[test]
    fn rename_and_edit_are_updates_by_id() {
        let remote = fixtures();
        let text = export(&remote)
            .replace("name = \"chatter\"", "name = \"social\"")
            .replace("@chatter.example", "@fb.com");
        let p = plan(&remote, &text, false).unwrap();
        assert_eq!(kinds(&p), ["update"]);
        let Op::Update { id, rule, changes } = &p.ops[0] else {
            unreachable!()
        };
        assert_eq!(id, "2");
        assert_eq!(rule.rule_name, "social");
        assert!(!rule.active, "activation is a separate call");
        assert_eq!(
            changes.iter().map(|c| c.0).collect::<Vec<_>>(),
            ["name", "when"]
        );
        assert!(p.render().contains("~ update   \"social\""));
    }

    #[test]
    fn activation_alone_uses_the_activation_call() {
        let remote = fixtures();
        let text = export(&remote).replace("active = false", "active = true");
        let p = plan(&remote, &text, false).unwrap();
        assert_eq!(kinds(&p), ["active"]);
        assert!(matches!(&p.ops[0], Op::SetActive { id, active: true, .. } if id == "2"));
        let both = export(&remote)
            .replace("active = false", "active = true")
            .replace("@chatter.example", "@fb.com");
        assert_eq!(
            kinds(&plan(&remote, &both, false).unwrap()),
            ["update", "active"]
        );
    }

    #[test]
    fn new_rules_append_without_reorder_unless_placed_earlier() {
        let remote = fixtures();
        let new = "\n[[rule]]\nname = \"new\"\nwhen = [{ subject.contains = \"n\" }]\nthen = [\"read\"]\n";
        let at_end = plan(&remote, &format!("{}{new}", export(&remote)), false).unwrap();
        assert_eq!(kinds(&at_end), ["create"]);
        assert!(at_end.render().contains("+ create   \"new\""));

        let mut b = blocks(&export(&remote));
        b.insert(1, new.trim_start().to_owned());
        let text = b.join("\n");
        let middle = plan(&remote, &text, false).unwrap();
        assert_eq!(kinds(&middle), ["create", "reorder"]);
        assert_eq!(
            order_names(&middle)[..3],
            ["club-2", "new", "club köln"]
        );
        assert!(matches!(&middle.ops[1], Op::Reorder { order } if order[1].0.is_none()));
    }

    #[test]
    fn the_reorder_preview_uses_the_new_names() {
        let remote = fixtures();
        let mut b = blocks(&export(&remote));
        b.swap(0, 1);
        let text = b
            .join("\n")
            .replace("name = \"chatter\"", "name = \"social\"");
        let names = order_names(&plan(&remote, &text, false).unwrap());
        assert!(
            names.contains(&"social".to_owned()) && !names.contains(&"chatter".to_owned()),
            "{names:?}"
        );
    }

    #[test]
    fn moving_rules_is_a_reorder_with_the_complete_list() {
        let remote = fixtures();
        let mut b = blocks(&export(&remote));
        b.swap(0, 4);
        let p = plan(&remote, &b.join("\n"), false).unwrap();
        assert_eq!(kinds(&p), ["reorder"]);
        let names = order_names(&p);
        assert_eq!(names.len(), 5);
        assert_eq!(names[0], "say \"hi\" \\ ünï");
        assert_eq!(names[4], "club-2");
    }

    #[test]
    fn rules_missing_from_the_file_are_kept_in_place_unless_pruned() {
        let remote = fixtures();
        let mut b = blocks(&export(&remote));
        let dropped = b.remove(1);
        assert!(dropped.contains("club köln"));
        let kept = plan(&remote, &b.join("\n"), false).unwrap();
        assert!(kept.is_empty(), "{}", kept.render());

        let pruned = plan(&remote, &b.join("\n"), true).unwrap();
        assert_eq!(kinds(&pruned), ["delete"]);
        assert_eq!(pruned.deletes(), 1);
        assert!(pruned.render().contains("- delete   \"club köln\""));

        // a kept rule stays in its slot while the others are rearranged around it
        let mut b = blocks(&export(&remote));
        b.remove(1);
        b.swap(0, 3);
        let p = plan(&remote, &b.join("\n"), false).unwrap();
        assert_eq!(
            order_names(&p),
            [
                "say \"hi\" \\ ünï",
                "club köln",
                "unnamed",
                "chatter",
                "club-2"
            ]
        );
    }

    #[test]
    fn ambiguous_stale_and_clashing_entries_are_refused() {
        let mut remote = fixtures();
        remote.push(remote[0].clone());
        remote[5].rule_id = Some("77".into());
        let by_name = "[[rule]]\nname = \"club-2\"\nwhen = [\"all-new\"]\nthen = [\"read\"]\n";
        assert!(
            plan(&remote, by_name, false)
                .unwrap_err()
                .to_string()
                .contains("2 server rules")
        );

        let remote = fixtures();
        let stale =
            "[[rule]]\nid = \"404\"\nname = \"x\"\nwhen = [\"all-new\"]\nthen = [\"read\"]\n";
        assert!(
            plan(&remote, stale, false)
                .unwrap_err()
                .to_string()
                .contains("404")
        );

        let twice = format!(
            "{0}\n{0}",
            "[[rule]]\nid = \"5\"\nname = \"a\"\nwhen = [\"all-new\"]\nthen = [\"read\"]\n"
        );
        assert!(
            plan(&remote, &twice, false)
                .unwrap_err()
                .to_string()
                .contains("already used")
        );

        let clash = "[[rule]]\nname = \"n\"\nwhen = [\"all-new\"]\nthen = [\"read\"]\n\n[[rule]]\nname = \"n\"\nwhen = [\"all-new\"]\nthen = [\"read\"]\n";
        assert!(
            plan(&remote, clash, false)
                .unwrap_err()
                .to_string()
                .contains("not unique")
        );
    }

    fn server_with(rules: &[Rule]) -> (mockito::ServerGuard, Client<SecretString>) {
        let mut s = Server::new();
        s.mock("GET", "/filterRules")
            .with_body(serde_json::to_string(rules).unwrap())
            .expect_at_least(1)
            .create();
        let client = Client::with_base_urls(SecretString::from("t"), &s.url(), &s.url());
        (s, client)
    }

    #[test]
    fn execute_sends_each_write_once_and_verifies() {
        let remote = fixtures();
        // the server state after the plan: rule "2" renamed and enabled, a new rule added last
        let mut after = remote.clone();
        after[3].rule_name = "social".into();
        after[3].active = true;
        let mut created = desired(
            "[[rule]]\nname = \"new\"\nwhen = [{ subject.contains = \"n\" }]\nthen = [\"read\"]\n",
        )[0]
        .to_rule(None);
        created.rule_id = Some("11".into());
        after.push(created);

        let text = export(&after).replace("id = \"11\"\n", "");
        let want = desired(&text);
        let p = Plan::diff(&remote, &want, false).unwrap();
        assert_eq!(kinds(&p), ["create", "update", "active"]);

        let (mut s, client) = server_with(&after);
        let post = s
            .mock("POST", "/filterRules")
            .match_body(Matcher::PartialJson(json!({"ruleName": "new"})))
            .with_status(204)
            .expect(1)
            .create();
        let put = s
            .mock("PUT", "/filterRules/2")
            .match_body(Matcher::PartialJson(
                json!({"ruleName": "social", "active": false}),
            ))
            .with_status(204)
            .expect(1)
            .create();
        let activate = s
            .mock("POST", "/filterRules/2/activate")
            .with_status(204)
            .expect(1)
            .create();
        p.execute(&client, &want, false).unwrap();
        post.assert();
        put.assert();
        activate.assert();
    }

    #[test]
    fn execute_reorders_with_every_rule_and_reports_drift() {
        let remote = fixtures();
        let mut b = blocks(&export(&remote));
        b.swap(0, 1);
        let want = desired(&b.join("\n"));
        let p = Plan::diff(&remote, &want, false).unwrap();
        assert_eq!(kinds(&p), ["reorder"]);

        let mut swapped = remote.clone();
        swapped.swap(0, 1);
        let (mut s, client) = server_with(&swapped);
        let put = s
            .mock("PUT", "/filterRules")
            .match_body(Matcher::PartialJson(json!({"rules": [
                {"ruleName": "club köln"}, {"ruleName": "club-2"}, {"ruleName": "unnamed"},
                {"ruleName": "chatter"}, {"ruleName": "say \"hi\" \\ ünï"}]})))
            .with_status(204)
            .expect(1)
            .create();
        p.execute(&client, &want, false).unwrap();
        put.assert();

        // the server ignoring the write is not reported as success
        let (mut s, client) = server_with(&remote);
        s.mock("PUT", "/filterRules").with_status(204).create();
        let err = p.execute(&client, &want, false).unwrap_err();
        assert!(
            matches!(err, Error::Drift(ref d) if d.contains("reorder")),
            "{err}"
        );
    }
}
