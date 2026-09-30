use std::{
    fs,
    io::{self, Write},
    path::PathBuf,
};

mod rules_file;

use rules_file::{Format, Syntax};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use gmx_filter::{
    Action, Client, CommandTokenSource, Condition, Config, Effect, HeaderCondition, KnownAction,
    KnownCondition, KnownHeaderCondition, Mode, Rule, Test, TokenSource, actions, condition,
    extend_condition, login, logout, password_from_command, rule_notes, stored_token_source,
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
    /// List rules.
    List,
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
    },
    /// Rename a rule.
    Rename {
        rule_id: String,
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
        rule_id: String,
        position: usize,
    },
    Enable {
        rule_id: String,
    },
    Disable {
        rule_id: String,
    },
    Delete {
        rule_id: String,
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
fn find_rule<'a>(rules: &'a [Rule], key: &str) -> Result<&'a Rule> {
    if let Some(r) = rules.iter().find(|r| r.rule_id.as_deref() == Some(key)) {
        return Ok(r);
    }
    let mut named = rules
        .iter()
        .filter(|r| r.rule_name.eq_ignore_ascii_case(key));
    match (named.next(), named.next()) {
        (Some(r), None) => Ok(r),
        (None, _) => bail!("no rule with id or name {key:?}"),
        (Some(_), Some(_)) => bail!("several rules are named {key:?}; use the id from `gmxf list`"),
    }
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
        ApiCommand::List => {
            for rule in client.list_rules()? {
                println!("{}", summary(&rule));
            }
        }
        ApiCommand::Export {
            file,
            raw,
            format,
            force,
        } => {
            let rules = client.list_rules()?;
            let text = if raw {
                serde_json::to_string_pretty(&rules)?
            } else {
                Format::pick(format, file.as_deref()).export(&rules)
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
        ApiCommand::Edit { rule, syntax } => {
            let rules = client.list_rules()?;
            let only = rule
                .map(|key| find_rule(&rules, &key).cloned())
                .transpose()?;
            rules_file::edit(client, rules, only, syntax)?;
        }
        ApiCommand::Rename { rule_id, name } => {
            let mut rule = client
                .list_rules()?
                .into_iter()
                .find(|r| r.rule_id.as_deref() == Some(&rule_id))
                .with_context(|| format!("no rule with id {rule_id}"))?;
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
        ApiCommand::Move { rule_id, position } => {
            let mut rules = client.list_rules()?;
            let Some(from) = rules
                .iter()
                .position(|r| r.rule_id.as_deref() == Some(&rule_id))
            else {
                bail!("no rule with id {rule_id}");
            };
            let rule = rules.remove(from);
            rules.insert(position.saturating_sub(1).min(rules.len()), rule);
            client.reorder_rules(&rules)?;
        }
        ApiCommand::Enable { rule_id } => client.set_active(&rule_id, true)?,
        ApiCommand::Disable { rule_id } => client.set_active(&rule_id, false)?,
        ApiCommand::Delete { rule_id } => client.delete_rule(&rule_id)?,
    }
    Ok(())
}

fn summary(rule: &Rule) -> String {
    let actions: Vec<String> = rule.actions.iter().map(describe_action).collect();
    format!(
        "{:<38} {} {:<20} if {} -> {}",
        rule.rule_id.as_deref().unwrap_or("-"),
        if rule.active { "on " } else { "off" },
        rule.rule_name,
        describe_condition(&rule.condition),
        actions.join(", "),
    ) + &rule_notes(rule)
        .iter()
        .map(|n| format!("  [{n}]"))
        .collect::<String>()
}

fn describe_action(action: &Action) -> String {
    match action {
        Action::Known(KnownAction::MoveToFolder { folder }) => format!("move {folder}"),
        Action::Known(KnownAction::CopyToFolder { folder }) => format!("copy {folder}"),
        Action::Known(KnownAction::MarkSeen) => "read".into(),
        Action::Known(KnownAction::DeleteMailImmediately) => "delete".into(),
        Action::Known(KnownAction::CopyForward { receivers, .. }) => {
            format!("forward {}", receivers.join(","))
        }
        Action::Known(KnownAction::TemplatedEmailNotify { pagers, .. }) => {
            format!("notify {}", pagers.join(","))
        }
        Action::Known(KnownAction::Stop) => "stop".into(),
        Action::Other(v) => v["type"].as_str().unwrap_or("?").to_owned(),
    }
}

fn describe_condition(condition: &Condition) -> String {
    let joined = |conditions: &[Condition], sep: &str| {
        let parts: Vec<_> = conditions.iter().map(describe_condition).collect();
        format!("({})", parts.join(sep))
    };
    let headers = |field: &str, inverted: bool, conds: &[HeaderCondition]| {
        let parts: Vec<_> = conds
            .iter()
            .map(|c| describe_header(field, inverted, c))
            .collect();
        if parts.len() == 1 {
            parts.join("")
        } else {
            format!("({})", parts.join(" or "))
        }
    };
    match condition {
        Condition::Known(KnownCondition::AnyOf { conditions }) => joined(conditions, " or "),
        Condition::Known(KnownCondition::AllOf { conditions }) => joined(conditions, " and "),
        Condition::Known(KnownCondition::AllNewEmails { .. }) => "all new mail".into(),
        Condition::Known(KnownCondition::MultiFromComparator {
            inverted,
            header_comparator_conditions,
            ..
        }) => headers("from", *inverted, header_comparator_conditions),
        Condition::Known(KnownCondition::MultiToComparator {
            inverted,
            header_comparator_conditions,
            ..
        }) => headers("to", *inverted, header_comparator_conditions),
        Condition::Known(KnownCondition::MultiSubjectComparator {
            inverted,
            header_comparator_conditions,
            ..
        }) => headers("subject", *inverted, header_comparator_conditions),
        Condition::Known(KnownCondition::SizeOver {
            inverted,
            byte_size,
        }) => {
            format!("size {} {byte_size}B", if *inverted { "<" } else { ">" })
        }
        Condition::Known(KnownCondition::Priority { inverted, level }) => {
            format!(
                "priority {} {level:?}",
                if *inverted { "is not" } else { "is" }
            )
        }
        Condition::Known(KnownCondition::AnyContact { inverted }) => if *inverted {
            "sender not in address book"
        } else {
            "sender in address book"
        }
        .into(),
        Condition::Other(v) => v["type"].as_str().unwrap_or("?").to_owned(),
    }
}

fn describe_header(field: &str, inverted: bool, cond: &HeaderCondition) -> String {
    let HeaderCondition::Known(
        KnownHeaderCondition::From {
            comparator, value, ..
        }
        | KnownHeaderCondition::Subject {
            comparator, value, ..
        }
        | KnownHeaderCondition::ToCc {
            comparator, value, ..
        },
    ) = cond
    else {
        return format!("{field} ?");
    };
    format!(
        "{field} {}{comparator:?} {value:?}",
        if inverted { "not " } else { "" }
    )
}
