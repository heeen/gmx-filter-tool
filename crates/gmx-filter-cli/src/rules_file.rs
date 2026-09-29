//! `check`, `apply` and `edit`: working with the rules file.

use std::{fs, io, path::Path, process::Command};

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
    eprint!("{question} [y/N] ");
    io::Write::flush(&mut io::stderr())?;
    let mut line = String::new();
    io::stdin().read_line(&mut line)?;
    Ok(matches!(line.trim(), "y" | "Y" | "yes"))
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

/// Export to a temp file, open the editor until the file is valid, then show and apply the plan.
/// Rules deleted from the file are deleted on the server (after confirmation).
pub fn edit<T: TokenSource>(client: &Client<T>) -> Result<()> {
    let remote = client.list_rules()?;
    let path = std::env::temp_dir().join(format!("gmxf-rules-{}.toml", std::process::id()));
    fs::write(&path, export(&remote))?;
    let result = edit_loop(client, &path);
    let _ = fs::remove_file(&path);
    result
}

fn edit_loop<T: TokenSource>(client: &Client<T>, path: &Path) -> Result<()> {
    let editor = std::env::var("VISUAL")
        .or_else(|_| std::env::var("EDITOR"))
        .unwrap_or_else(|_| "vi".into());
    loop {
        let status = Command::new("sh")
            .arg("-c")
            .arg(format!("{editor} \"$0\""))
            .arg(path)
            .status()
            .with_context(|| format!("starting {editor}"))?;
        if !status.success() {
            bail!("{editor} failed; nothing was changed");
        }
        let outcome = read(path).and_then(|desired| {
            let changed = apply(client, &desired, true, true, false)?;
            Ok((desired, changed))
        });
        match outcome {
            Ok((desired, changed)) => {
                if changed && confirm("Apply these changes?")? {
                    apply(client, &desired, true, false, true)?;
                }
                return Ok(());
            }
            Err(e) => {
                eprintln!("{e:#}");
                if !confirm("Edit again?")? {
                    bail!("aborted; nothing was changed");
                }
            }
        }
    }
}
