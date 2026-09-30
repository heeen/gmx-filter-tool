//! `check`, `apply` and `edit`: working with the rules file.

use std::{
    fs,
    io::{self, Write as _},
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{Context, Result, bail};
use gmx_filter::{
    Client, DesiredRule, Diagnostic, Folder, Plan, Rule, TokenSource, check, export, has_errors,
    parse,
};

pub fn read(file: &Path) -> Result<Vec<DesiredRule>> {
    let text = fs::read_to_string(file).with_context(|| file.display().to_string())?;
    Ok(parse(&text)?)
}

fn report(diagnostics: &[Diagnostic]) {
    for d in diagnostics {
        eprintln!("{d}");
    }
}

/// Lints `desired`; errors are printed and returned as `Err`.
pub fn lint(desired: &[DesiredRule], folders: Option<&[Folder]>, remote: &[Rule]) -> Result<()> {
    let diagnostics = check(desired, folders, remote);
    report(&diagnostics);
    if has_errors(&diagnostics) {
        let n = diagnostics
            .iter()
            .filter(|d| d.severity == gmx_filter::Severity::Error)
            .count();
        bail!("{n} error(s) in the rules file; nothing was changed");
    }
    Ok(())
}

fn confirm(question: &str) -> Result<bool> {
    ask(question, false)
}

/// A yes/no question on stderr; an empty answer means `default`.
fn ask(question: &str, default: bool) -> Result<bool> {
    eprint!("{question} {} ", if default { "[Y/n]" } else { "[y/N]" });
    io::stderr().flush()?;
    let mut line = String::new();
    io::stdin().read_line(&mut line)?;
    Ok(match line.trim() {
        "" => default,
        answer => matches!(answer, "y" | "Y" | "yes"),
    })
}

/// Shows what applying `desired` would do and, unless `dry_run`, does it after confirmation.
/// Returns whether anything is (or would be) changed.
pub fn apply<T: TokenSource>(
    client: &Client<T>,
    desired: &[DesiredRule],
    prune: bool,
    dry_run: bool,
    yes: bool,
) -> Result<bool> {
    let remote = client.list_rules()?;
    let folders = client.folders()?;
    lint(desired, Some(&folders), &remote)?;
    let plan = Plan::diff(&remote, desired, prune)?;
    print!("{}", plan.render());
    if plan.unlisted > 0 && !prune {
        eprintln!(
            "{} server rule(s) are not in the file and stay untouched (--prune deletes them)",
            plan.unlisted
        );
    }
    if plan.is_empty() || dry_run {
        return Ok(!plan.is_empty());
    }
    let deletes = plan.deletes();
    let warn = if deletes > 0 {
        format!(", including {deletes} deletion(s)")
    } else {
        String::new()
    };
    if !yes && !confirm(&format!("Apply {} change(s){warn}?", plan.ops.len()))? {
        bail!("aborted; nothing was changed");
    }
    plan.execute(client, desired, prune)?;
    println!("applied; the server now matches the file");
    Ok(true)
}

/// Lines `gmxf edit` appends to the file to report problems; removed again before parsing. They go
/// at the end so the line numbers in the messages stay right for the file you see.
const MARK: &str = "# gmxf: ";

/// `text` with a fresh block of `messages` at the end, replacing any earlier block.
pub fn annotate(text: &str, messages: &[String]) -> String {
    let mut out = strip_annotations(text);
    if !messages.is_empty() {
        out.push_str(&format!(
            "\n{MARK}fix the problems below and save, or save an empty file to abort\n"
        ));
        for line in messages.iter().flat_map(|m| m.lines()) {
            out.push_str(&format!("{MARK}{line}\n"));
        }
    }
    out
}

/// `text` without the block written by [`annotate`].
pub fn strip_annotations(text: &str) -> String {
    let mut lines: Vec<&str> = text.lines().collect();
    let mut had_block = false;
    while let Some(last) = lines.last()
        && (last.starts_with(MARK) || (had_block && last.trim().is_empty()))
    {
        had_block |= last.starts_with(MARK);
        lines.pop();
    }
    if !had_block {
        return text.to_owned();
    }
    lines.iter().map(|l| format!("{l}\n")).collect()
}

/// Nothing but blank lines and comments: the way to abort an edit.
pub fn is_effectively_empty(text: &str) -> bool {
    text.lines()
        .map(str::trim)
        .all(|l| l.is_empty() || l.starts_with('#'))
}

fn edit_header(all: bool, count: usize) -> String {
    let scope = if all {
        "# Delete a [[rule]] block to delete that rule, move blocks to reorder, add blocks to create rules.\n"
    } else {
        "# Only this rule is shown; other rules are not touched. Add [[rule]] blocks to create rules.\n"
    };
    format!(
        "# gmxf edit: {count} rule(s). Save and quit to review the changes; nothing is applied without asking.\n\
         {scope}# Save an empty file (comments only) to abort.\n\n"
    )
}

fn scratch_path() -> PathBuf {
    let dir = std::env::var_os("XDG_RUNTIME_DIR").map_or_else(std::env::temp_dir, PathBuf::from);
    dir.join(format!("gmxf-edit-{}.toml", std::process::id()))
}

fn write_private(path: &Path, text: &str) -> io::Result<()> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    options.open(path)?.write_all(text.as_bytes())
}

fn same_rules(a: &[Rule], b: &[Rule]) -> bool {
    serde_json::to_value(a).ok() == serde_json::to_value(b).ok()
}

/// What one pass over the edited file came to.
enum Pass {
    Abort,
    NoChanges,
    Problems(Vec<String>),
    Ready(Vec<gmx_filter::DesiredRule>, Plan, Vec<Diagnostic>),
}

/// `crontab -e` for filter rules: edit `only` (or all `rules`) in `$VISUAL`/`$EDITOR`, get errors back in
/// the file until it is valid, review the plan, apply after confirmation. Your edits are never thrown
/// away: on any failure the file is kept and its path printed.
pub fn edit<T: TokenSource>(
    client: &Client<T>,
    rules: Vec<Rule>,
    only: Option<Rule>,
) -> Result<()> {
    let all = only.is_none();
    let shown = only.map_or_else(|| rules.clone(), |r| vec![r]);
    let original = edit_header(all, shown.len()) + &export(&shown);
    let path = scratch_path();
    write_private(&path, &original)?;
    let kept = |why: &str| {
        anyhow::anyhow!(
            "{why}\nyour edits are saved in {0}; re-run `gmxf edit`, or apply them with `gmxf apply {0}{1}`",
            path.display(),
            if all { " --prune" } else { "" }
        )
    };
    let editor = std::env::var("VISUAL")
        .or_else(|_| std::env::var("EDITOR"))
        .unwrap_or_else(|_| "vi".into());

    loop {
        let status = Command::new("sh")
            .arg("-c")
            .arg(format!("{editor} \"$0\""))
            .arg(&path)
            .status()
            .with_context(|| format!("starting {editor}"))?;
        if !status.success() {
            return Err(kept(&format!("{editor} exited with {status}")));
        }
        let edited = fs::read_to_string(&path)?;
        let body = strip_annotations(&edited);
        let body = body.as_str();

        let pass = if is_effectively_empty(body) {
            Pass::Abort
        } else if body == original {
            Pass::NoChanges
        } else {
            examine(client, &rules, body, all)?
        };
        match pass {
            Pass::Abort => {
                let _ = fs::remove_file(&path);
                eprintln!("empty file: aborted, nothing changed");
                return Ok(());
            }
            Pass::NoChanges => {
                let _ = fs::remove_file(&path);
                println!("no changes");
                return Ok(());
            }
            Pass::Problems(messages) => {
                for m in &messages {
                    eprintln!("{m}");
                }
                write_private(&path, &annotate(body, &messages))?;
                if !ask("Edit again?", true)? {
                    return Err(kept("not applied"));
                }
            }
            Pass::Ready(desired, plan, notes) => {
                report(&notes);
                print!("{}", plan.render());
                let deletes = plan.deletes();
                let warn = if deletes > 0 {
                    format!(", including {deletes} deletion(s)")
                } else {
                    String::new()
                };
                if !confirm(&format!("Apply {} change(s){warn}?", plan.ops.len()))? {
                    return Err(kept("not applied"));
                }
                plan.execute(client, &desired, all)
                    .map_err(|e| kept(&format!("{e:#}")))?;
                let _ = fs::remove_file(&path);
                println!("applied; the server now matches your edit");
                return Ok(());
            }
        }
    }
}

/// Parses and checks the edited text against the server as it is now.
fn examine<T: TokenSource>(
    client: &Client<T>,
    snapshot: &[Rule],
    body: &str,
    prune: bool,
) -> Result<Pass> {
    let desired = match gmx_filter::parse(body) {
        Ok(d) => d,
        Err(e) => return Ok(Pass::Problems(vec![format!("error: {e}")])),
    };
    let remote = client.list_rules()?;
    if !same_rules(snapshot, &remote) {
        return Ok(Pass::Problems(vec![
            "error: the rules on the server changed since this file was written (e.g. in the web UI);\n\
             applying it now could undo those changes. Save an empty file and re-run `gmxf edit`."
                .into(),
        ]));
    }
    let diagnostics = check(&desired, Some(&client.folders()?), &remote);
    if has_errors(&diagnostics) {
        return Ok(Pass::Problems(
            diagnostics.iter().map(ToString::to_string).collect(),
        ));
    }
    let plan = match Plan::diff(&remote, &desired, prune) {
        Ok(plan) => plan,
        Err(e) => return Ok(Pass::Problems(vec![format!("error: {e}")])),
    };
    if plan.is_empty() {
        return Ok(Pass::NoChanges);
    }
    Ok(Pass::Ready(desired, plan, diagnostics))
}

#[cfg(test)]
mod tests {
    use super::*;

    const FILE: &str = "# header\n\n[[rule]]\nname = \"x\"\n";

    #[test]
    fn annotations_go_last_replace_each_other_and_strip_cleanly() {
        let once = annotate(
            FILE,
            &["error: first\n  | detail".into(), "warning: second".into()],
        );
        assert!(
            once.starts_with(FILE),
            "the edited text keeps its line numbers"
        );
        assert!(
            once.ends_with("# gmxf: error: first\n# gmxf:   | detail\n# gmxf: warning: second\n")
        );
        assert_eq!(strip_annotations(&once), FILE);
        let twice = annotate(&once, &["error: third".into()]);
        assert!(!twice.contains("first") && twice.contains("third"));
        assert_eq!(strip_annotations(&twice), FILE);
        assert_eq!(annotate(FILE, &[]), FILE);
        assert_eq!(strip_annotations(FILE), FILE);
        let own_comment = format!("{FILE}# my own note\n");
        assert_eq!(
            strip_annotations(&own_comment),
            own_comment,
            "only gmxf's lines are removed"
        );
    }

    #[test]
    fn only_comments_count_as_empty() {
        assert!(is_effectively_empty(""));
        assert!(is_effectively_empty("# a\n\n   # b\n"));
        assert!(!is_effectively_empty(FILE));
        assert!(is_effectively_empty(&edit_header(false, 1)));
    }
}
