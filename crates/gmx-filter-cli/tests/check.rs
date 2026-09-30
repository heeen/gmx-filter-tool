use std::{fs, path::PathBuf, process::Command};

const GOOD: &str = r#"
[[rule]]
name = "news"
match = "any"
when = [{ from.contains = "newsletter" }, { subject.starts-with = "[news]" }]
then = [{ move = "INBOX/Newsletter" }]
"#;

fn scratch(name: &str, body: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("gmxf-check-{}-{name}", std::process::id()));
    fs::write(&path, body).unwrap();
    path
}

fn check(body: &str, name: &str) -> (bool, String) {
    run_check(body, &format!("{name}.toml"), &[])
}

fn run_check(body: &str, file_name: &str, args: &[&str]) -> (bool, String) {
    let file = scratch(file_name, body);
    let out = Command::new(env!("CARGO_BIN_EXE_gmxf"))
        .arg("check")
        .arg(&file)
        .args(args)
        .env_remove("GMXF_TOKEN_CMD")
        .output()
        .unwrap();
    let _ = fs::remove_file(file);
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    (out.status.success(), text)
}

#[test]
fn a_valid_file_passes_offline_without_a_login() {
    let (ok, text) = check(GOOD, "good");
    assert!(ok, "{text}");
    assert!(text.contains("1 rule(s) ok"), "{text}");
}

#[test]
fn syntax_errors_point_at_the_spot_and_list_the_options() {
    let (ok, text) = check(&GOOD.replace("starts-with", "wobbles"), "spec");
    assert!(!ok);
    assert!(
        text.contains("line 5") && text.contains("wobbles") && text.contains("not-ends-with"),
        "{text}"
    );
}

#[test]
fn old_string_rows_get_a_re_export_hint() {
    let (ok, text) = check(
        "[[rule]]\nname = \"x\"\nwhen = [\"from contains a\"]\nthen = [\"read\"]\n",
        "v1",
    );
    assert!(!ok);
    assert!(text.contains("re-export"), "{text}");
}

#[test]
fn toml_errors_carry_a_line_number() {
    let (ok, text) = check("[[rule]]\nname = \"x\"\nwhen = [\n", "toml");
    assert!(!ok);
    assert!(text.contains("line"), "{text}");
}

#[test]
fn sanity_errors_fail_and_warnings_do_not() {
    let (ok, text) = check(
        &GOOD.replace(
            r#"{ move = "INBOX/Newsletter" }"#,
            r#"{ forward = "nobody" }"#,
        ),
        "addr",
    );
    assert!(!ok);
    assert!(
        text.contains("error: rule #1 \"news\"") && text.contains("not an email address"),
        "{text}"
    );

    let (ok, text) = check(&GOOD.replace("INBOX/Newsletter", "INBOX"), "warn");
    assert!(ok, "{text}");
    assert!(
        text.contains("warning:") && text.contains("already in INBOX"),
        "{text}"
    );
}

const SIEVE: &str = r#"require ["fileinto"];
# rule:[news]
if anyof(header :contains "from" "newsletter", header :matches "subject" "[news]*") {
    fileinto "INBOX/Newsletter";
    stop;
}
"#;

const NESTED: &str = r#"require ["fileinto"];
# rule:[nested]
if header :contains "from" "a" {
    if header :contains "subject" "b" { fileinto "B"; stop; }
    fileinto "A";
}
"#;

#[test]
fn sieve_files_are_recognised_by_their_extension() {
    let (ok, text) = run_check(SIEVE, "good.sieve", &[]);
    assert!(ok, "{text}");
    assert!(text.contains("1 rule(s) ok"), "{text}");
    let (ok, text) = run_check(SIEVE, "good.txt", &["--format", "sieve"]);
    assert!(ok, "{text}");
    let (ok, _) = run_check(SIEVE, "good.toml", &[]);
    assert!(!ok, "a .toml file is read as TOML");
}

#[test]
fn sieve_errors_name_the_rule_and_the_spot() {
    let (ok, text) = run_check(&SIEVE.replace(":contains", ":regex"), "regex.sieve", &[]);
    assert!(!ok);
    assert!(
        text.contains("rule \"news\"") && text.contains("line 3") && text.contains(":regex"),
        "{text}"
    );
}

#[test]
fn nested_sieve_rules_need_split() {
    let (ok, text) = run_check(NESTED, "nested.sieve", &[]);
    assert!(!ok);
    assert!(text.contains("--split"), "{text}");
    let (ok, text) = run_check(NESTED, "nested.sieve", &["--split"]);
    assert!(ok, "{text}");
    assert!(
        text.contains("split into 2 rules") && text.contains("2 rule(s) ok"),
        "{text}"
    );
    let (ok, text) = run_check(GOOD, "good.toml", &["--split"]);
    assert!(!ok && text.contains("only applies to Sieve"), "{text}");
}
