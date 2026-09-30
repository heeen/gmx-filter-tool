use std::{
    fs,
    io::{self, Write},
    path::PathBuf,
};

mod list;
mod rules_file;

use rules_file::{Format, Syntax};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use gmx_filter::{
    Client, CommandTokenSource, Config, Effect, Mode, Rule, Test, TokenSource, actions, condition,
    extend_condition, login, logout, password_from_command, stored_token_source,
};
use secrecy::SecretString;

/// Manage GMX server-side mail filter rules.
#[derive(Parser)]
#[command(name = "gmxf")]
struct Cli {
    /// Shell command printing a Bearer token for settings-bff.gmx.net on stdout.
    /// Overrides a stored login session.
    #[arg(long, env = "GMXF_TOKEN_CMD", global = true)]
    token_cmd: Option<String>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Log in to GMX webmail and store the session.
    ///
    /// The email comes from --user, else the config, else a prompt; the password from
    /// --password-stdin, else `password_cmd` in the config, else a prompt.
    Login {
        #[arg(long)]
        user: Option<String>,
        /// Read password from stdin instead of prompting (for scripts).
        #[arg(long)]
        password_stdin: bool,
    },
    /// Show or change the settings in ~/.config/gmxf/config.toml.
    ///
    /// With `password_cmd` set (e.g. `rbw get gmx.net name@gmx.de`), expired sessions are
    /// renewed without asking.
    Config {
        #[arg(long)]
        email: Option<String>,
        /// Shell command printing the password; an empty string removes it.
        #[arg(long)]
        password_cmd: Option<String>,
    },
    /// Forget the stored session (the config stays).
    Logout,
    /// Check a rules file for syntax errors and suspicious rules (add --online to check folders).
    Check {
        file: PathBuf,
        /// Also compare against the server: unknown folders, new forward targets.
        #[arg(long)]
        online: bool,
        #[command(flatten)]
        syntax: Syntax,
    },
    #[command(flatten)]
    Api(ApiCommand),
}

#[derive(Subcommand)]
enum ApiCommand {
    /// List rules: id, name, whether enabled, and what they do.
    List {
        /// Show full ids and every value instead of the first few per condition.
        #[arg(long, short)]
        long: bool,
    },
    /// Write all rules as an editable rules file (stdout without FILE).
    Export {
        file: Option<PathBuf>,
        /// Print the raw API JSON instead (a backup, not meant for editing).
        #[arg(long, conflicts_with_all = ["file", "format"])]
        raw: bool,
        /// Rules file format; by default `.sieve` files are Sieve, anything else TOML.
        #[arg(long, value_enum)]
        format: Option<Format>,
        /// Overwrite FILE if it exists.
        #[arg(long)]
        force: bool,
        /// Merge adjacent rules that do the same thing and drop repeated conditions; the rules still
        /// act on exactly the same mail. Apply the result with --prune to remove the merged rules.
        #[arg(long, conflicts_with = "raw")]
        simplify: bool,
    },
    /// Make the server match a rules file; shows the plan first.
    ///
    /// Rules are matched by `id`, else by name. Server rules missing from the file are left alone
    /// unless --prune. Exit status 2 with --dry-run means there are changes.
    Apply {
        file: PathBuf,
        /// Only show what would change.
        #[arg(long)]
        dry_run: bool,
        /// Delete server rules that are not in the file.
        #[arg(long)]
        prune: bool,
        /// Do not ask for confirmation.
        #[arg(long, short)]
        yes: bool,
        #[command(flatten)]
        syntax: Syntax,
    },
    /// Edit rules in $EDITOR like `crontab -e`: problems are shown in the file until it is valid,
    /// then the changes are listed and applied after confirmation.
    ///
    /// Without RULE all rules are shown and removing a block deletes that rule; with RULE (id or
    /// name) only that rule is shown. Saving an empty file aborts; failed edits are kept on disk.
    Edit {
        rule: Option<String>,
        #[command(flatten)]
        syntax: Syntax,
        /// Start from the simplified rules (see `export --simplify`); saving applies the
        /// simplification, including deleting the merged rules.
        #[arg(long)]
        simplify: bool,
    },
    /// Rename a rule.
    Rename {
        /// Rule id (or a unique start of it, as `gmxf list` shows) or name.
        rule: String,
        name: String,
    },
    /// List folders; rules refer to them by full name.
    Folders,
    /// Create a rule.
    ///
    /// CONDITIONS (--when, repeatable): `all-new`; `from|to|subject <contains|not-contains|is|is-not|starts-with|ends-with> <text>`;
    /// `size <gt|lt> <n>[B|KB|MB]`; `priority <is|is-not> <low|normal|high>`; `contact <saved|not-saved>`.
    /// ACTIONS (--then, repeatable): `move <folder>`, `copy <folder>`, `read`, `delete`, `forward <address>`, `notify <address>`.
    Add {
        name: String,
        #[arg(long = "when", required = true)]
        tests: Vec<Test>,
        #[arg(long = "then", required = true)]
        effects: Vec<Effect>,
        /// Require all conditions instead of any one.
        #[arg(long)]
        all: bool,
        /// Let later rules see mail this rule handled.
        #[arg(long)]
        no_stop: bool,
    },
    /// Widen a rule: add addresses or patterns as extra conditions (any of them matches).
    ///
    /// VALUES become `from contains <value>` rows (`--field` picks another header); `--when` adds
    /// arbitrary condition rows. Rows the rule already has are skipped.
    Extend {
        /// Rule id or exact name (case-insensitive).
        rule: String,
        values: Vec<String>,
        #[arg(long, default_value = "from", value_parser = ["from", "to", "to-cc", "subject"])]
        field: String,
        #[arg(long = "when")]
        tests: Vec<Test>,
        /// Show the change without saving it.
        #[arg(long)]
        dry_run: bool,
    },
    /// Move a rule to a 1-based position in the rule order.
    Move {
        /// Rule id (or a unique start of it, as `gmxf list` shows) or name.
        rule: String,
        position: usize,
    },
    /// Switch a rule on.
    Enable {
        /// Rule id (or a unique start of it, as `gmxf list` shows) or name.
        rule: String,
    },
    /// Switch a rule off; it stays saved.
    Disable {
        /// Rule id (or a unique start of it, as `gmxf list` shows) or name.
        rule: String,
    },
    /// Delete a rule.
    Delete {
        /// Rule id (or a unique start of it, as `gmxf list` shows) or name.
        rule: String,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Login {
            user,
            password_stdin,
        } => {
            let cfg = Config::load()?;
            let user = match user.or(cfg.email) {
                Some(u) => u,
                None => {
                    eprint!("Email: ");
                    io::stderr().flush()?;
                    let mut line = String::new();
                    io::stdin().read_line(&mut line)?;
                    let u = line.trim().to_owned();
                    if u.is_empty() {
                        bail!("email is required");
                    }
                    u
                }
            };
            let password = if password_stdin {
                let mut line = String::new();
                io::stdin().read_line(&mut line)?;
                SecretString::from(line.trim_end_matches(['\r', '\n']).to_owned())
            } else if let Some(cmd) = &cfg.password_cmd {
                password_from_command(cmd)?
            } else {
                SecretString::from(rpassword::prompt_password("Password: ")?)
            };
            login(&user, &password)?;
            println!("logged in as {user}");
            Ok(())
        }
        Command::Config {
            email,
            password_cmd,
        } => {
            let mut cfg = Config::load()?;
            if email.is_some() || password_cmd.is_some() {
                if let Some(email) = email {
                    cfg.email = Some(email);
                }
                if let Some(cmd) = password_cmd {
                    cfg.password_cmd = Some(cmd).filter(|c| !c.trim().is_empty());
                }
                cfg.save()?;
            }
            println!("# {}", Config::path()?.display());
            print!("{}", toml::to_string(&cfg)?);
            Ok(())
        }
        Command::Logout => {
            logout()?;
            println!("logged out");
            Ok(())
        }
        Command::Check {
            file,
            online,
            syntax,
        } => {
            let desired = rules_file::read(&file, syntax)?;
            if online {
                let client = connect(cli.token_cmd)?;
                rules_file::lint(&desired, Some(&client.folders()?), &client.list_rules()?)?;
            } else {
                rules_file::lint(&desired, None, &[])?;
            }
            println!("{}: {} rule(s) ok", file.display(), desired.len());
            Ok(())
        }
        Command::Api(cmd) => run_api(cmd, &connect(cli.token_cmd)?),
    }
}

/// A rule by id, else by exact name (case-insensitive) if that is unambiguous.
/// A rule by exact id, by a unique start of its id, or by exact name (case-insensitive).
fn find_rule<'a>(rules: &'a [Rule], key: &str) -> Result<&'a Rule> {
    if let Some(r) = rules.iter().find(|r| r.rule_id.as_deref() == Some(key)) {
        return Ok(r);
    }
    let by_prefix: Vec<&Rule> = rules
        .iter()
        .filter(|r| r.rule_id.as_deref().is_some_and(|id| id.starts_with(key)))
        .collect();
    let by_name: Vec<&Rule> = rules
        .iter()
        .filter(|r| r.rule_name.eq_ignore_ascii_case(key))
        .collect();
    match (&by_prefix[..], &by_name[..]) {
        ([one], []) | ([], [one]) => Ok(one),
        ([a], [b]) if a.rule_id == b.rule_id => Ok(a),
        ([], []) => bail!("no rule with id or name {key:?}"),
        _ => bail!("{key:?} matches several rules; use more of the id from `gmxf list`"),
    }
}

/// The id of the rule `key` names (see [`find_rule`]).
fn rule_id(client: &Client<Box<dyn TokenSource>>, key: &str) -> Result<String> {
    let rules = client.list_rules()?;
    let rule = find_rule(&rules, key)?;
    rule.rule_id.clone().context("the rule has no id")
}

fn connect(token_cmd: Option<String>) -> Result<Client<Box<dyn TokenSource>>> {
    let tokens: Box<dyn TokenSource> = match token_cmd {
        Some(cmd) => Box::new(CommandTokenSource(cmd)),
        None => Box::new(stored_token_source().context("no token source")?),
    };
    Ok(Client::new(tokens))
}

fn run_api(cmd: ApiCommand, client: &Client<Box<dyn TokenSource>>) -> Result<()> {
    match cmd {
        ApiCommand::List { long } => print!("{}", list::table(&client.list_rules()?, long)),
        ApiCommand::Export {
            file,
            raw,
            format,
            force,
            simplify,
        } => {
            let mut rules = client.list_rules()?;
            let mut notes = String::new();
            if simplify {
                let simplified = gmx_filter::simplify(&rules);
                for note in &simplified.notes {
                    eprintln!("simplified: {note}");
                }
                if simplified.merged_away() > 0 {
                    eprintln!(
                        "{} rule(s) were merged into others; `gmxf apply FILE --prune` removes them on the server",
                        simplified.merged_away()
                    );
                }
                notes = rules_file::simplify_comment(&simplified.notes);
                rules = simplified.rules;
            }
            let text = if raw {
                serde_json::to_string_pretty(&rules)?
            } else {
                notes + &Format::pick(format, file.as_deref()).export(&rules)
            };
            match file {
                None => println!("{}", text.trim_end()),
                Some(file) => {
                    if file.exists() && !force {
                        bail!("{} exists; use --force to overwrite", file.display());
                    }
                    fs::write(&file, text).with_context(|| file.display().to_string())?;
                    eprintln!("wrote {} rule(s) to {}", rules.len(), file.display());
                }
            }
        }
        ApiCommand::Apply {
            file,
            dry_run,
            prune,
            yes,
            syntax,
        } => {
            let desired = rules_file::read(&file, syntax)?;
            let changes = rules_file::apply(client, &desired, prune, dry_run, yes)?;
            if dry_run && changes {
                std::process::exit(2);
            }
        }
        ApiCommand::Edit {
            rule,
            syntax,
            simplify,
        } => {
            let rules = client.list_rules()?;
            let only = rule
                .map(|key| find_rule(&rules, &key).cloned())
                .transpose()?;
            rules_file::edit(client, rules, only, syntax, simplify)?;
        }
        ApiCommand::Rename { rule, name } => {
            let mut rule = find_rule(&client.list_rules()?, &rule)?.clone();
            rule.rule_name = name;
            client.update_rule(&rule)?;
        }
        ApiCommand::Folders => {
            for f in client.folders()? {
                println!("{}", f.full_name);
            }
        }
        ApiCommand::Add {
            name,
            tests,
            effects,
            all,
            no_stop,
        } => {
            let folders = client.folders()?;
            for effect in &effects {
                if let Effect::Move(f) | Effect::Copy(f) = effect
                    && !folders.iter().any(|known| &known.full_name == f)
                {
                    bail!("unknown folder {f:?}; see `gmxf folders`");
                }
            }
            let mode = if all { Mode::All } else { Mode::Any };
            let rule = Rule::new(&name, condition(mode, &tests)?, actions(effects, !no_stop));
            client.create_rule(&rule)?;
            println!("created {name}");
        }
        ApiCommand::Extend {
            rule,
            values,
            field,
            mut tests,
            dry_run,
        } => {
            for v in values {
                tests.push(format!("{field} contains {v}").parse()?);
            }
            if tests.is_empty() {
                bail!("nothing to add: give values or --when");
            }
            let rules = client.list_rules()?;
            let mut target = find_rule(&rules, &rule)?.clone();
            let Some(wider) = extend_condition(&target.condition, &tests)? else {
                println!("{:?} already has all of these", target.rule_name);
                return Ok(());
            };
            let added: Vec<String> = tests.iter().map(ToString::to_string).collect();
            println!("{:?} += {}", target.rule_name, added.join(", "));
            if !dry_run {
                target.condition = wider;
                client.update_rule(&target)?;
            }
        }
        ApiCommand::Move { rule, position } => {
            let mut rules = client.list_rules()?;
            let id = find_rule(&rules, &rule)?.rule_id.clone();
            let from = rules
                .iter()
                .position(|r| r.rule_id == id)
                .unwrap_or_default();
            let rule = rules.remove(from);
            rules.insert(position.saturating_sub(1).min(rules.len()), rule);
            client.reorder_rules(&rules)?;
        }
        ApiCommand::Enable { rule } => client.set_active(&rule_id(client, &rule)?, true)?,
        ApiCommand::Disable { rule } => client.set_active(&rule_id(client, &rule)?, false)?,
        ApiCommand::Delete { rule } => client.delete_rule(&rule_id(client, &rule)?)?,
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules() -> Vec<Rule> {
        let mk = |id: &str, name: &str| {
            let mut r = Rule::new(
                name,
                condition(Mode::Any, &["all-new".parse().unwrap()]).unwrap(),
                vec![],
            );
            r.rule_id = Some(id.into());
            r
        };
        vec![
            mk("5", "club"),
            mk("cef5ab49-8a55", "deluge"),
            mk("ce12", "Club"),
            mk("5f00-aa", "five"),
        ]
    }

    #[test]
    fn rules_are_found_by_id_prefix_or_name() {
        let rules = rules();
        let id = |key: &str| find_rule(&rules, key).map(|r| r.rule_id.clone().unwrap());
        assert_eq!(
            id("5").unwrap(),
            "5",
            "an exact id wins over a prefix of another"
        );
        assert_eq!(id("cef5").unwrap(), "cef5ab49-8a55");
        assert_eq!(id("DELUGE").unwrap(), "cef5ab49-8a55");
        assert_eq!(id("5f").unwrap(), "5f00-aa");
        assert!(id("ce").unwrap_err().to_string().contains("several"));
        assert!(
            id("club").unwrap_err().to_string().contains("several"),
            "two rules named club"
        );
        assert!(id("nope").unwrap_err().to_string().contains("no rule"));
    }
}
