#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{what} command failed: {detail}")]
    Command { what: &'static str, detail: String },
    #[error(
        "not logged in or session expired; run `gmxf login`, or set `password_cmd` in the config to renew sessions automatically"
    )]
    NotLoggedIn,
    #[error("login rejected at {step} step (HTTP {status}): {body}")]
    LoginRejected {
        step: &'static str,
        status: u16,
        body: String,
    },
    #[error(
        "login needs more than a password (flow state {flow_state:?}), e.g. a captcha or second factor; complete it in the browser first"
    )]
    LoginIncomplete { flow_state: String },
    #[error("login page lacks or has a malformed {0}; GMX may have changed the login")]
    LoginPage(&'static str),
    #[error("login ended at an unexpected page: {0}")]
    LoginUnexpectedRedirect(String),
    #[error("login produced no session cookie for the token endpoint")]
    LoginNoSession,
    #[error("login succeeded but the session cannot mint filter tokens: {0}")]
    LoginSessionUnusable(Box<Error>),
    #[error(
        "the session expired and logging in again with `password_cmd` failed: {0}\nrun `gmxf login`"
    )]
    Relogin(Box<Error>),
    #[error("OAuth2 error (HTTP {status}): {body}")]
    OAuth { status: u16, body: String },
    #[error("unexpected HTTP {status} from {url}: {body}")]
    Api {
        status: u16,
        url: String,
        body: String,
    },
    #[error("cannot apply: {0}")]
    Plan(String),
    #[error("applied, but the server does not match the file yet:\n{0}")]
    Drift(String),
    #[error("rules file: {0}")]
    RuleFile(String),
    #[error("invalid rule spec: {0}")]
    InvalidSpec(String),
    #[error("rule has no ruleId; use a rule returned by list_rules")]
    MissingRuleId,
    #[error("{}: {message}", path.display())]
    Config {
        path: std::path::PathBuf,
        message: String,
    },
    #[error("no config directory available")]
    NoConfigDir,
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
