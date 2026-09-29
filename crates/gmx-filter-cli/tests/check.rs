use std::{fs, path::PathBuf, process::Command};

const GOOD: &str = r#"
[[rule]]
name = "news"
match = "any"
when = ["from contains newsletter", "subject starts-with [news]"]
then = ["move INBOX/Newsletter"]
"#;

fn scratch(name: &str, body: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("gmxf-check-{}-{name}.toml", std::process::id()));
    fs::write(&path, body).unwrap();
    path
}

fn check(body: &str, name: &str) -> (bool, String) {
    let file = scratch(name, body);
    let out = Command::new(env!("CARGO_BIN_EXE_gmxf"))
        .arg("check")
        .arg(&file)
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
fn syntax_errors_name_the_rule_and_the_spec() {
    let (ok, text) = check(&GOOD.replace("starts-with", "wobbles"), "spec");
    assert!(!ok);
    assert!(
        text.contains("\"news\"") && text.contains("wobbles"),
        "{text}"
    );
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
        &GOOD.replace("move INBOX/Newsletter", "forward nobody"),
        "addr",
    );
    assert!(!ok);
    assert!(
        text.contains("error: rule #1 \"news\"") && text.contains("not an email address"),
        "{text}"
    );

    let (ok, text) = check(&GOOD.replace("move INBOX/Newsletter", "move INBOX"), "warn");
    assert!(ok, "{text}");
    assert!(
        text.contains("warning:") && text.contains("already in INBOX"),
        "{text}"
    );
}
