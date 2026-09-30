use std::{
    process::Command,
    sync::{Mutex, PoisonError},
    time::{Duration, Instant},
};

use base64::{Engine, engine::general_purpose::STANDARD};
use reqwest::blocking::Client as Http;
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;

use crate::login::USER_AGENT;
use crate::{Error, Result};

/// Scopes settings-bff / mailset need for filter CRUD (from the webmail HAR).
const FILTER_SCOPES: &str = "mail_mailbox_w webmailer_setting_r webmailer_setting_w mail_confix_w";
const SHARED_LOGIN_COOKIE_GRANT: &str = "urn:mam:oauth:grant-type:shared_login_cookie";
const ORIGIN: &str = "https://mailset-root.gmx.net";
/// The settings web app's OAuth client. Browser apps ship a placeholder secret; the server only
/// checks the client id together with the session cookie.
const CLIENT_ID: &str = "gmxnet_mailset_root_live";
const CLIENT_SECRET_PLACEHOLDER: &str = "*******";

/// Yields a Bearer token accepted by `settings-bff.gmx.net`.
pub trait TokenSource {
    fn token(&self) -> Result<SecretString>;
}

impl<T: TokenSource + ?Sized> TokenSource for Box<T> {
    fn token(&self) -> Result<SecretString> {
        (**self).token()
    }
}

/// A command's stderr for an error message: control characters dropped, at most a few lines.
fn readable(stderr: &[u8]) -> String {
    const MAX_CHARS: usize = 300;
    let text: String = String::from_utf8_lossy(stderr)
        .chars()
        .filter(|c| !c.is_control() || *c == '\n')
        .collect();
    let text = text.trim();
    match text.char_indices().nth(MAX_CHARS) {
        Some((cut, _)) => format!("{}…", &text[..cut]),
        None => text.to_owned(),
    }
}

/// Runs `cmd` with `sh -c` and returns its stdout. `what` names the command in errors.
pub(crate) fn run_secret_command(what: &'static str, cmd: &str) -> Result<SecretString> {
    let fail = |detail: String| Error::Command { what, detail };
    let out = Command::new("sh").arg("-c").arg(cmd).output()?;
    if !out.status.success() {
        return Err(fail(format!("{}: {}", out.status, readable(&out.stderr))));
    }
    let stdout = String::from_utf8(out.stdout).map_err(|_| fail("stdout is not UTF-8".into()))?;
    Ok(SecretString::from(stdout))
}

/// Runs a shell command on every call and uses its trimmed stdout as the token.
pub struct CommandTokenSource(pub String);

impl TokenSource for CommandTokenSource {
    fn token(&self) -> Result<SecretString> {
        let out = run_secret_command("token", &self.0)?;
        let token = out.expose_secret().trim();
        if token.is_empty() {
            return Err(Error::Command {
                what: "token",
                detail: "empty output".into(),
            });
        }
        Ok(SecretString::from(token.to_owned()))
    }
}

#[derive(Deserialize)]
pub(crate) struct TokenResponse {
    access_token: SecretString,
    expires_in: Option<u64>,
}

/// `btoa(encodeURIComponent(ua))`, the encoding the web apps use for `userAgentB64`.
fn user_agent_b64(ua: &str) -> String {
    let mut escaped = String::new();
    for b in ua.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.!~*'()".contains(&b) {
            escaped.push(char::from(b));
        } else {
            escaped.push_str(&format!("%{b:02X}"));
        }
    }
    STANDARD.encode(escaped)
}

/// Exchanges the webmail session cookie for a scoped access token (`shared_login_cookie` grant).
pub(crate) fn mint(http: &Http, token_url: &str, cookie: &SecretString) -> Result<TokenResponse> {
    let resp = http
        .post(token_url)
        .basic_auth(CLIENT_ID, Some(CLIENT_SECRET_PLACEHOLDER))
        .header("Cookie", cookie.expose_secret())
        .header("Accept", "application/json")
        .header("Origin", ORIGIN)
        .header("User-Agent", USER_AGENT)
        .form(&[
            ("grant_type", SHARED_LOGIN_COOKIE_GRANT),
            ("scope", FILTER_SCOPES),
            ("userAgentB64", &user_agent_b64(USER_AGENT)),
        ])
        .send()?;
    let status = resp.status();
    if status.is_success() {
        return Ok(resp.json()?);
    }
    let body = resp.text().unwrap_or_default();
    Err(Error::OAuth {
        status: status.as_u16(),
        body: body.chars().take(200).collect(),
    })
}

/// Renew this long before the access token actually expires.
const EXPIRY_LEEWAY: Duration = Duration::from_secs(60);
/// Assumed lifetime when the server omits `expires_in`.
const DEFAULT_LIFETIME: Duration = Duration::from_mins(5);

/// Logs in again and returns fresh session cookies.
pub(crate) type Relogin = Box<dyn Fn() -> Result<SecretString>>;

struct State {
    cookie: Option<SecretString>,
    cached: Option<(SecretString, Instant)>,
}

/// Mints filter-scoped access tokens from the webmail session, caching them until they expire.
/// With a [`Relogin`], an expired (or missing) session is renewed once per call instead of failing.
pub struct SessionTokenSource {
    http: Http,
    token_url: String,
    state: Mutex<State>,
    relogin: Option<Relogin>,
}

impl SessionTokenSource {
    pub(crate) fn new(
        cookie: Option<SecretString>,
        token_url: &str,
        relogin: Option<Relogin>,
    ) -> Result<Self> {
        if cookie.is_none() && relogin.is_none() {
            return Err(Error::NotLoggedIn);
        }
        Ok(Self {
            http: Http::new(),
            token_url: token_url.to_owned(),
            state: Mutex::new(State {
                cookie,
                cached: None,
            }),
            relogin,
        })
    }

    fn renew(&self, state: &mut State) -> Result<()> {
        let relogin = self.relogin.as_ref().ok_or(Error::NotLoggedIn)?;
        state.cookie = Some(relogin().map_err(|e| Error::Relogin(Box::new(e)))?);
        Ok(())
    }
}

impl TokenSource for SessionTokenSource {
    fn token(&self) -> Result<SecretString> {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some((token, expires)) = &state.cached
            && Instant::now() + EXPIRY_LEEWAY < *expires
        {
            return Ok(SecretString::from(token.expose_secret().to_owned()));
        }

        if state.cookie.is_none() {
            self.renew(&mut state)?;
        }
        let mut renewed = false;
        let resp = loop {
            let Some(cookie) = &state.cookie else {
                return Err(Error::NotLoggedIn);
            };
            match mint(&self.http, &self.token_url, cookie) {
                Err(Error::OAuth {
                    status: 400 | 401 | 403,
                    ..
                }) if !renewed && self.relogin.is_some() => {
                    self.renew(&mut state)?;
                    renewed = true;
                }
                Err(Error::OAuth {
                    status: 400 | 401 | 403,
                    ..
                }) => return Err(Error::NotLoggedIn),
                other => break other?,
            }
        };
        let lifetime = resp
            .expires_in
            .map_or(DEFAULT_LIFETIME, Duration::from_secs);
        let access = SecretString::from(resp.access_token.expose_secret().to_owned());
        state.cached = Some((resp.access_token, Instant::now() + lifetime));
        Ok(access)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::cell::RefCell;

    use mockito::{Matcher, Server};
    use serde_json::json;

    use super::*;

    #[derive(Default)]
    pub(crate) struct MemStore(pub RefCell<Option<String>>);

    impl crate::store::SecretStore for MemStore {
        fn load(&self) -> Result<SecretString> {
            let cookie = self.0.borrow().clone();
            cookie.map(SecretString::from).ok_or(Error::NotLoggedIn)
        }
        fn save(&self, c: &SecretString) -> Result<()> {
            *self.0.borrow_mut() = Some(c.expose_secret().to_owned());
            Ok(())
        }
        fn delete(&self) -> Result<()> {
            *self.0.borrow_mut() = None;
            Ok(())
        }
    }

    #[test]
    fn user_agent_is_encoded_like_btoa_of_encode_uri_component() {
        // btoa(encodeURIComponent("Mozilla/5.0 (X11; Linux)"))
        assert_eq!(
            user_agent_b64("Mozilla/5.0 (X11; Linux)"),
            "TW96aWxsYSUyRjUuMCUyMChYMTElM0IlMjBMaW51eCk="
        );
    }

    #[test]
    fn command_output_is_trimmed() {
        let t = CommandTokenSource("echo '  abc  '".into()).token().unwrap();
        assert_eq!(t.expose_secret(), "abc");
    }

    #[test]
    fn failing_command_is_an_error() {
        assert!(
            CommandTokenSource("echo nope >&2; exit 3".into())
                .token()
                .is_err()
        );
        assert!(CommandTokenSource("true".into()).token().is_err());
    }

    #[test]
    fn mints_with_cookie_and_caches_until_expiry() {
        let mut s = Server::new();
        let m = s
            .mock("POST", "/token")
            .match_header("cookie", "sso=abc")
            .match_header(
                "authorization",
                "Basic Z214bmV0X21haWxzZXRfcm9vdF9saXZlOioqKioqKio=",
            )
            .match_body(Matcher::AllOf(vec![
                Matcher::Regex(
                    "grant_type=urn%3Amam%3Aoauth%3Agrant-type%3Ashared_login_cookie".into(),
                ),
                Matcher::Regex("scope=mail_mailbox_w\\+webmailer_setting_r".into()),
            ]))
            .with_body(json!({"access_token": "at", "expires_in": 7200}).to_string())
            .expect(1)
            .create();
        let src =
            SessionTokenSource::new(Some("sso=abc".into()), &format!("{}/token", s.url()), None)
                .unwrap();
        assert_eq!(src.token().unwrap().expose_secret(), "at");
        assert_eq!(src.token().unwrap().expose_secret(), "at");
        m.assert();
    }

    #[test]
    fn expiring_token_is_reminted() {
        let mut s = Server::new();
        let m = s
            .mock("POST", "/token")
            .with_body(json!({"access_token": "at", "expires_in": 1}).to_string())
            .expect(2)
            .create();
        let src = SessionTokenSource::new(Some("c=1".into()), &format!("{}/token", s.url()), None)
            .unwrap();
        src.token().unwrap();
        src.token().unwrap();
        m.assert();
    }

    #[test]
    fn expired_session_means_not_logged_in() {
        let mut s = Server::new();
        s.mock("POST", "/token")
            .with_status(400)
            .with_body(r#"{"error":"invalid_grant"}"#)
            .create();
        let src = SessionTokenSource::new(Some("c=1".into()), &format!("{}/token", s.url()), None)
            .unwrap();
        assert!(matches!(src.token(), Err(Error::NotLoggedIn)));
    }

    #[test]
    fn server_errors_are_not_mistaken_for_expiry() {
        let mut s = Server::new();
        s.mock("POST", "/token").with_status(503).create();
        let src = SessionTokenSource::new(Some("c=1".into()), &format!("{}/token", s.url()), None)
            .unwrap();
        assert!(matches!(src.token(), Err(Error::OAuth { status: 503, .. })));
    }

    #[test]
    fn missing_store_entry_means_not_logged_in() {
        assert!(matches!(
            SessionTokenSource::new(None, "http://unused", None),
            Err(Error::NotLoggedIn)
        ));
    }

    fn counting_relogin(
        cookie: &'static str,
        calls: &std::rc::Rc<std::cell::Cell<u32>>,
    ) -> Relogin {
        let calls = std::rc::Rc::clone(calls);
        Box::new(move || {
            calls.update(|n| n + 1);
            Ok(cookie.into())
        })
    }

    #[test]
    fn an_expired_session_is_renewed_once_and_used() {
        let mut s = Server::new();
        s.mock("POST", "/token")
            .match_header("cookie", "old=1")
            .with_status(400)
            .expect(1)
            .create();
        let fresh = s
            .mock("POST", "/token")
            .match_header("cookie", "new=1")
            .with_body(json!({"access_token": "at", "expires_in": 7200}).to_string())
            .expect(1)
            .create();
        let calls = std::rc::Rc::new(std::cell::Cell::new(0));
        let src = SessionTokenSource::new(
            Some("old=1".into()),
            &format!("{}/token", s.url()),
            Some(counting_relogin("new=1", &calls)),
        )
        .unwrap();
        assert_eq!(src.token().unwrap().expose_secret(), "at");
        assert_eq!(src.token().unwrap().expose_secret(), "at", "cached");
        assert_eq!(calls.get(), 1);
        fresh.assert();
    }

    #[test]
    fn a_missing_session_logs_in_first() {
        let mut s = Server::new();
        s.mock("POST", "/token")
            .match_header("cookie", "new=1")
            .with_body(json!({"access_token": "at"}).to_string())
            .create();
        let calls = std::rc::Rc::new(std::cell::Cell::new(0));
        let src = SessionTokenSource::new(
            None,
            &format!("{}/token", s.url()),
            Some(counting_relogin("new=1", &calls)),
        )
        .unwrap();
        assert_eq!(src.token().unwrap().expose_secret(), "at");
        assert_eq!(calls.get(), 1);
    }

    #[test]
    fn a_failing_relogin_is_reported_and_not_retried_forever() {
        let mut s = Server::new();
        s.mock("POST", "/token").with_status(401).create();
        let failing: Relogin = Box::new(|| {
            Err(Error::LoginRejected {
                step: "password",
                status: 401,
                body: String::new(),
            })
        });
        let src = SessionTokenSource::new(
            Some("old=1".into()),
            &format!("{}/token", s.url()),
            Some(failing),
        )
        .unwrap();
        let err = src.token().unwrap_err();
        assert!(matches!(err, Error::Relogin(_)), "{err}");
        assert!(err.to_string().contains("gmxf login"));

        // a fresh session that is rejected as well ends the attempt
        let calls = std::rc::Rc::new(std::cell::Cell::new(0));
        let src = SessionTokenSource::new(
            Some("old=1".into()),
            &format!("{}/token", s.url()),
            Some(counting_relogin("new=1", &calls)),
        )
        .unwrap();
        assert!(matches!(src.token(), Err(Error::NotLoggedIn)));
        assert_eq!(calls.get(), 1);
    }

    #[test]
    fn command_errors_are_readable() {
        let err = CommandTokenSource(
            "printf 'locked\\0\\0\\0\\n' >&2; head -c 2000 /dev/zero | tr '\\0' x >&2; exit 1"
                .into(),
        )
        .token()
        .unwrap_err()
        .to_string();
        assert!(err.contains("locked") && !err.contains('\0'), "{err}");
        assert!(err.chars().count() < 400, "{} chars", err.chars().count());
    }
}
