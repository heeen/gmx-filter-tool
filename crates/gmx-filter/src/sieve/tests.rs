use serde_json::{Value, json};

use super::*;
use crate::{
    Rule,
    rulefile::tests::{fixtures, odd, rules},
};

const TYPE: &str = "StoppingNamedOrderedConditionalMultiActionUser";
const REQUIRE: &str =
    "require [\"fileinto\", \"copy\", \"imap4flags\", \"enotify\", \"extlists\"];\n";

fn rule(name: &str, condition: Value, actions: Value) -> Value {
    json!({"type": TYPE, "ruleId": name, "ruleName": name, "active": true, "considerStopped": true,
           "condition": condition, "actions": actions})
}

fn h(kind: &str, cmp: &str, value: &str, inverted: bool) -> Value {
    json!({"type": kind, "comparator": cmp, "inverted": inverted, "comparand": value})
}

fn group(kind: &str, op: &str, inverted: bool, entries: Vec<Value>) -> Value {
    json!({"type": kind, "operator": op, "inverted": inverted, "headerComparatorConditions": entries})
}

fn from(value: &str) -> Value {
    group(
        "MultiFromComparator",
        "OR",
        false,
        vec![h("From", "CONTAINS", value, false)],
    )
}

fn subject(value: &str) -> Value {
    group(
        "MultiSubjectComparator",
        "OR",
        false,
        vec![h("Subject", "CONTAINS", value, false)],
    )
}

fn move_stop(folder: &str) -> Value {
    json!([{"type": "MoveToFolder", "folder": folder}, {"type": "Stop"}])
}

/// Everything the wire format allows that Sieve can say.
fn wide() -> Vec<Rule> {
    rules(json!([
        rule(
            "size",
            json!({"type": "AllOf", "conditions": [
                {"type": "SizeOver", "inverted": false, "byteSize": 5_242_880},
                {"type": "SizeOver", "inverted": true, "byteSize": 1000}]}),
            json!([{"type": "CopyToFolder", "folder": "Big"}, {"type": "MarkSeen"}])
        ),
        rule(
            "prio",
            json!({"type": "AnyOf", "conditions": [
                {"type": "Priority", "inverted": false, "level": "HIGH"},
                {"type": "AnyContact", "inverted": true}]}),
            json!([{"type": "DeleteMailImmediately"}, {"type": "Stop"}])
        ),
        rule(
            "new",
            json!({"type": "AllNewEmails", "inverted": false}),
            json!([{"type": "TemplatedEmailNotify", "pending": false, "pagers": ["a@b.de", "c@d.de"]}])
        ),
        rule(
            "fwd",
            group(
                "MultiToComparator",
                "OR",
                false,
                vec![h("ToCc", "IS", "me@gmx.de", false)]
            ),
            json!([{"type": "CopyForward", "pending": true, "receivers": ["x@y.de", "z@y.de"]}])
        ),
        rule(
            "wild",
            group(
                "MultiSubjectComparator",
                "OR",
                false,
                vec![
                    h("Subject", "STARTS_WITH", "a*b?c\\", false),
                    h("Subject", "ENDS_WITH", "[x]", false)
                ]
            ),
            move_stop("INBOX/W")
        ),
        rule(
            "and-in-any",
            json!({"type": "AnyOf", "conditions": [
                group("MultiFromComparator", "AND", false, vec![h("From", "CONTAINS", "a", false), h("From", "CONTAINS", "b", false)]),
                subject("s")]}),
            move_stop("X")
        ),
        rule(
            "entry-not",
            group(
                "MultiFromComparator",
                "OR",
                false,
                vec![
                    h("From", "CONTAINS", "a", true),
                    h("From", "IS", "b", false)
                ]
            ),
            move_stop("X")
        ),
        rule(
            "all-same-field",
            json!({"type": "AllOf", "conditions": [from("a"), from("b")]}),
            move_stop("X")
        ),
        rule(
            "any-one",
            json!({"type": "AnyOf", "conditions": [from("a")]}),
            move_stop("X")
        ),
    ]))
}

/// Rules GMX accepts but Sieve cannot say, or says ambiguously: kept as raw JSON.
fn raw() -> Vec<Rule> {
    rules(json!([
        rule(
            "top-and",
            group(
                "MultiFromComparator",
                "AND",
                false,
                vec![
                    h("From", "CONTAINS", "a", false),
                    h("From", "CONTAINS", "b", false)
                ]
            ),
            move_stop("X")
        ),
        rule(
            "single-entry-not",
            group(
                "MultiFromComparator",
                "OR",
                false,
                vec![h("From", "CONTAINS", "a", true)]
            ),
            move_stop("X")
        ),
        rule(
            "legacy",
            from("a"),
            json!([{"type": "ForwardTo", "to": "x"}])
        ),
        rule(
            "stop-mid",
            from("a"),
            json!([{"type": "Stop"}, {"type": "MarkSeen"}])
        ),
    ]))
}

fn import(text: &str) -> Vec<DesiredRule> {
    parse_sieve(text, false)
        .unwrap_or_else(|e| panic!("{e}\n{text}"))
        .rules
}

fn condition_json(d: &DesiredRule) -> Value {
    serde_json::to_value(&d.condition).unwrap()
}

fn actions_json(d: &DesiredRule) -> Value {
    serde_json::to_value(&d.actions).unwrap()
}

#[test]
fn export_then_import_leaves_every_rule_unchanged() {
    for set in [fixtures(), odd(), wide(), raw()] {
        let text = export_sieve(&set);
        let desired = import(&text);
        assert_eq!(desired.len(), set.len(), "{text}");
        let again: Vec<Rule> = desired
            .iter()
            .zip(&set)
            .map(|(d, r)| {
                assert!(d.same_as(r), "{}: {:?}\n{text}", r.rule_name, d.changes(r));
                d.to_rule(Some(r))
            })
            .collect();
        assert_eq!(export_sieve(&again), text, "a second export is identical");
    }
}

#[test]
fn only_the_unsayable_falls_back_to_json() {
    let text = export_sieve(&wide());
    let raw_json = |t: &str| t.contains("\n# gmxf-condition: ") || t.contains("\n# gmxf-actions: ");
    assert!(!raw_json(&text), "{text}");
    for r in raw() {
        let text = export_sieve(std::slice::from_ref(&r));
        assert!(raw_json(&text), "{}: {text}", r.rule_name);
    }
    let text = export_sieve(&raw()[2..]);
    assert!(
        text.contains("# gmxf-actions: [{\"to\":\"x\",\"type\":\"ForwardTo\"}]"),
        "{text}"
    );
    assert!(
        text.contains("if header :contains \"from\" \"a\" {\n    keep;\n}"),
        "{text}"
    );
}

#[test]
fn output_reads_like_sieve() {
    let text = export_sieve(&fixtures());
    for expected in [
        "require [\"fileinto\"];",
        "# rule:[club-2]\n# gmxf-id: 5\nif header :contains \"from\" \"wiki@club-koeln.example\" {\n    fileinto \"INBOX/Club Köln\";\n    stop;\n}",
        "header :contains [\"to\", \"cc\"] [\"members@club-koeln.example\", \"wiki@club-koeln.example\"]",
        "if anyof(header :contains [\"to\", \"cc\"] \"volunteers@lists.uni.example\",\n         header :contains \"subject\" \"Makerspace-Volunteers\",",
        "if allof(false, header :contains \"from\" \"@chatter.example\")",
        "# rule:[say \"hi\" \\ ünï]",
        "header :matches \"subject\" \"[Firmware] it's*\"",
    ] {
        assert!(text.contains(expected), "missing {expected:?} in\n{text}");
    }
    let text = export_sieve(&wide());
    for expected in [
        "if allof(size :over 5M,\n         not size :over 1000) {",
        "fileinto :copy \"Big\";\n    addflag \"\\\\Seen\";",
        "anyof(header :is \"x-gmxf-priority\" \"high\",\n         not address :list \"from\" \":addrbook:default\")",
        "if true {\n    notify \"mailto:a@b.de,c@d.de\";\n}",
        "redirect :copy \"x@y.de\";\n    redirect :copy \"z@y.de\";",
        "header :matches \"subject\" [\"a\\\\*b\\\\?c\\\\\\\\*\", \"*[x]\"]",
        "anyof(allof(header :contains \"from\" \"a\", header :contains \"from\" \"b\"),\n",
        "anyof(not header :contains \"from\" \"a\", header :is \"from\" \"b\")",
        "if anyof(header :contains \"from\" \"a\") {",
    ] {
        assert!(text.contains(expected), "missing {expected:?} in\n{text}");
    }
}

#[test]
fn imports_a_handwritten_script() {
    let text = format!(
        "{REQUIRE}\
         # rule:[lists]\n\
         if address :all :comparator \"i;ascii-casemap\" \"from\" [\"a@x.de\", \"b@x.de\"] {{ fileinto \"L\"; stop; }}\n\
         # rule:[mixed]\n\
         if allof(not header :matches \"Subject\" \"*spam*\", size :under 1K) {{ addflag [\"\\\\Seen\"]; }}\n\
         # rule:[any]\n\
         if anyof(header :is \"from\" \"a\", header :contains \"from\" \"b\", not header :contains \"to\" \"c\") {{ discard; }}\n\
         # rule:[not-any]\n\
         if not anyof(header :contains \"from\" \"a\", header :contains \"subject\" \"b\") {{ notify \"mailto:n@x.de?subject=hi\"; }}\n"
    );
    let d = import(&text);
    assert_eq!(d.len(), 4);
    assert_eq!(
        condition_json(&d[0]),
        group(
            "MultiFromComparator",
            "OR",
            false,
            vec![
                h("From", "IS", "a@x.de", false),
                h("From", "IS", "b@x.de", false)
            ]
        )
    );
    assert_eq!(actions_json(&d[0]), move_stop("L"));
    assert_eq!(
        condition_json(&d[1]),
        json!({"type": "AllOf", "conditions": [
            group("MultiSubjectComparator", "OR", true, vec![h("Subject", "CONTAINS", "spam", false)]),
            {"type": "SizeOver", "inverted": true, "byteSize": 1023}]})
    );
    assert_eq!(actions_json(&d[1]), json!([{"type": "MarkSeen"}]));
    assert_eq!(
        condition_json(&d[2]),
        json!({"type": "AnyOf", "conditions": [
            group("MultiFromComparator", "OR", false, vec![h("From", "IS", "a", false), h("From", "CONTAINS", "b", false)]),
            group("MultiToComparator", "OR", true, vec![h("ToCc", "CONTAINS", "c", false)])]})
    );
    assert_eq!(
        condition_json(&d[3]),
        json!({"type": "AllOf", "conditions": [
            group("MultiFromComparator", "OR", true, vec![h("From", "CONTAINS", "a", false)]),
            group("MultiSubjectComparator", "OR", true, vec![h("Subject", "CONTAINS", "b", false)])]})
    );
    assert_eq!(
        actions_json(&d[3]),
        json!([{"type": "TemplatedEmailNotify", "pending": false, "pagers": ["n@x.de"]}])
    );
}

fn error(text: &str, split: bool) -> String {
    match parse_sieve(&format!("{REQUIRE}{text}"), split) {
        Ok(r) => panic!("accepted: {text}\n{r:?}"),
        Err(e) => e.to_string(),
    }
}

#[test]
fn refuses_what_gmx_cannot_store() {
    for (text, expected) in [
        (
            "# rule:[r]\nif header :regex \"from\" \"x\" { stop; }",
            "`:regex` is not supported",
        ),
        (
            "# rule:[r]\nif header :contains \"x-spam\" \"y\" { stop; }",
            "not \"x-spam\"",
        ),
        (
            "# rule:[r]\nif header :contains \"cc\" \"y\" { stop; }",
            "only together with To",
        ),
        (
            "# rule:[r]\nif exists \"x\" { stop; }",
            "`exists` test is not supported",
        ),
        (
            "# rule:[r]\nif address :domain \"from\" \"x\" { stop; }",
            "`:domain` is not supported",
        ),
        (
            "# rule:[r]\nif header :matches \"from\" \"a*b\" { stop; }",
            "only supports `*` at the start",
        ),
        (
            "# rule:[r]\nif true { redirect \"a@b\"; }",
            "redirect :copy",
        ),
        (
            "# rule:[r]\nif true { vacation \"away\"; }",
            "`vacation` is not supported",
        ),
        (
            "# rule:[r]\nif true { keep; }",
            "`keep` has no GMX equivalent",
        ),
        (
            "# rule:[r]\nif true { stop; discard; }",
            "comes after `stop`",
        ),
        ("# rule:[r]\nif true { }", "no actions"),
        ("# rule:[r]\nif not true { stop; }", "can never run"),
        ("if true { stop; }", "# rule:[name]"),
        ("fileinto \"x\";", "outside a rule"),
        (
            "# rule:[r]\nif true { if true { stop; } }",
            "nested `if` needs --split",
        ),
        (
            "# rule:[r]\nif true { stop; } else { discard; }",
            "`else` needs --split",
        ),
        (
            "# rule:[r]\nif anyof(allof(header :is \"from\" \"a\", header :is \"subject\" \"b\"), size :over 1) { stop; }",
            "nests deeper than GMX allows",
        ),
        (
            "# rule:[r]\n# gmxf-bogus: 1\nif true { stop; }",
            "unknown `gmxf-bogus: 1`",
        ),
    ] {
        let e = error(text, false);
        assert!(
            e.contains(expected),
            "{text}\n  gave: {e}\n  expected: {expected}"
        );
    }
    let e = parse_sieve("require \"vacation\";", false)
        .unwrap_err()
        .to_string();
    assert!(e.contains("cannot use the `vacation` extension"), "{e}");
    let e = parse_sieve("# rule:[r]\nif true { fileinto \"x\"; }", false)
        .unwrap_err()
        .to_string();
    assert!(
        e.contains("require \\\"fileinto\\\"") || e.contains("require \"fileinto\""),
        "{e}"
    );
    let e = parse_sieve("# rule:[r]\nif true { fileinto \"x\" }", false)
        .unwrap_err()
        .to_string();
    assert!(e.contains("2:"), "syntax errors have positions: {e}");
}

fn split(text: &str) -> SieveImport {
    parse_sieve(&format!("{REQUIRE}{text}"), true).unwrap_or_else(|e| panic!("{e}\n{text}"))
}

fn summary(d: &[DesiredRule]) -> Vec<(String, Value, Value)> {
    d.iter()
        .map(|d| (d.name.clone(), condition_json(d), actions_json(d)))
        .collect()
}

#[test]
fn split_turns_nested_ifs_into_rules_in_order() {
    let got = split(
        "# rule:[n]\n\
         if header :contains \"from\" \"a\" {\n\
             addflag \"\\\\Seen\";\n\
             if header :contains \"subject\" \"s\" { fileinto \"S\"; stop; }\n\
             fileinto \"A\";\n\
         }",
    );
    let and = json!({"type": "AllOf", "conditions": [from("a"), subject("s")]});
    assert_eq!(
        summary(&got.rules),
        [
            ("n #1".into(), from("a"), json!([{"type": "MarkSeen"}])),
            ("n #2".into(), and, move_stop("S")),
            (
                "n #3".into(),
                from("a"),
                json!([{"type": "MoveToFolder", "folder": "A"}])
            ),
        ]
    );
    assert!(
        got.notes[0].contains("split into 3 rules"),
        "{:?}",
        got.notes
    );
    assert!(got.notes[0].contains("unverified"));
}

#[test]
fn split_negates_earlier_branches() {
    let got = split(
        "# rule:[b]\n\
         if header :contains \"from\" \"a\" { fileinto \"A\"; stop; }\n\
         elsif header :contains \"subject\" \"s\" { fileinto \"S\"; stop; }\n\
         else { discard; stop; }",
    );
    let not = |v: Value| {
        let mut v = v;
        v["inverted"] = json!(true);
        v
    };
    assert_eq!(
        summary(&got.rules),
        [
            ("b #1".into(), from("a"), move_stop("A")),
            (
                "b #2".into(),
                json!({"type": "AllOf", "conditions": [not(from("a")), subject("s")]}),
                move_stop("S")
            ),
            (
                "b #3".into(),
                json!({"type": "AllOf", "conditions": [not(from("a")), not(subject("s"))]}),
                json!([{"type": "DeleteMailImmediately"}, {"type": "Stop"}])
            ),
        ]
    );
    assert!(!got.notes[0].contains("unverified"), "every piece stops");
}

#[test]
fn split_expands_deep_conditions() {
    let deep =
        "anyof(allof(header :is \"from\" \"a\", header :is \"subject\" \"b\"), size :over 1)";
    let is = |kind: &str, group_kind: &str, v: &str, inverted: bool| {
        group(group_kind, "OR", inverted, vec![h(kind, "IS", v, false)])
    };
    let size = |inverted: bool| json!({"type": "SizeOver", "inverted": inverted, "byteSize": 1});
    let a = is("From", "MultiFromComparator", "a", false);
    let b = is("Subject", "MultiSubjectComparator", "b", false);

    // with `stop` the first matching rule ends the chain, so overlapping rules are fine
    let got = split(&format!(
        "# rule:[d]\nif {deep} {{ fileinto \"X\"; stop; }}"
    ));
    assert_eq!(
        summary(&got.rules),
        [
            (
                "d #1".into(),
                json!({"type": "AllOf", "conditions": [a, b]}),
                move_stop("X")
            ),
            ("d #2".into(), size(false), move_stop("X")),
        ]
    );

    // without it the rules must not overlap, or the mail would be moved twice
    let got = split(&format!("# rule:[d]\nif {deep} {{ fileinto \"X\"; }}"));
    let conditions: Vec<Value> = got.rules.iter().map(condition_json).collect();
    let a_not_b = |a_neg: bool| {
        json!({"type": "AllOf", "conditions": [
            size(false),
            is("From", "MultiFromComparator", "a", a_neg),
        ]})
    };
    assert_eq!(conditions.len(), 3, "{conditions:#?}");
    assert_eq!(conditions[1], a_not_b(true));
    assert_eq!(
        conditions[2],
        json!({"type": "AllOf", "conditions": [size(false), is("From", "MultiFromComparator", "a", false), is("Subject", "MultiSubjectComparator", "b", true)]})
    );
}

#[test]
fn split_refuses_ids_and_runaway_expansion() {
    let e = error(
        "# rule:[r]\n# gmxf-id: 5\nif true { if true { discard; } discard; }",
        true,
    );
    assert!(e.contains("gmxf-id"), "{e}");
    let many: Vec<String> = (0..6)
        .map(|i| format!("anyof(header :is \"from\" \"{i}\", header :is \"subject\" \"{i}\")"))
        .collect();
    let e = error(
        &format!(
            "# rule:[r]\nif anyof(allof({}), size :over 1) {{ discard; }}",
            many.join(", ")
        ),
        true,
    );
    assert!(
        e.contains("too many rules") || e.contains("more than 16"),
        "{e}"
    );
}
