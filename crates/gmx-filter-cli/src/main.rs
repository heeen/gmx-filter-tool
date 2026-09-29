use std::{
    fs,
    io::{self, Write},
    path::PathBuf,
};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use gmx_filter::{
    Action, Client, CommandTokenSource, Condition, Effect, HeaderCondition, KnownAction,
    KnownCondition, KnownHeaderCondition, Mode, Rule, Test, TokenSource, actions, condition, login,
    logout, stored_token_source,
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
    /// Log in to GMX webmail with email + password and store the session.
    Login {
        #[arg(long)]
        user: Option<String>,
        /// Read password from stdin instead of prompting (for scripts).
        #[arg(long)]
        password_stdin: bool,
    },
    /// Remove the stored session and config.
    Logout,
    #[command(flatten)]
    Api(ApiCommand),
}

#[derive(Subcommand)]
enum ApiCommand {
    /// List rules.
    List,
    /// Print all rules as JSON.
    Export,
    /// Create the rules from a JSON file produced by `export`.
    Import {
        file: PathBuf,
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
            let user = match user {
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
            } else {
                SecretString::from(rpassword::prompt_password("Password: ")?)
            };
            login(&user, &password)?;
            println!("logged in as {user}");
            Ok(())
        }
        Command::Logout => {
            logout()?;
            println!("logged out");
            Ok(())
        }
        Command::Api(cmd) => {
            let tokens: Box<dyn TokenSource> = match cli.token_cmd {
                Some(cmd) => Box::new(CommandTokenSource(cmd)),
                None => Box::new(stored_token_source().context("no token source")?),
            };
            run_api(cmd, &Client::new(tokens))
        }
    }
}

fn run_api(cmd: ApiCommand, client: &Client<Box<dyn TokenSource>>) -> Result<()> {
    match cmd {
        ApiCommand::List => {
            for rule in client.list_rules()? {
                println!("{}", summary(&rule));
            }
        }
        ApiCommand::Export => println!("{}", serde_json::to_string_pretty(&client.list_rules()?)?),
        ApiCommand::Import { file } => {
            let text = fs::read_to_string(&file).with_context(|| file.display().to_string())?;
            let rules: Vec<Rule> = serde_json::from_str(&text)?;
            for mut rule in rules {
                rule.rule_id = None;
                rule.uri = None;
                rule.modified = None;
                client.create_rule(&rule)?;
                println!("created {}", rule.rule_name);
            }
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
    )
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
