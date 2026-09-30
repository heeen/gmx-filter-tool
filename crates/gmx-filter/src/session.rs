use reqwest::blocking::Client as Http;
use secrecy::{ExposeSecret, SecretString};

use crate::login::{START_URL, TOKEN_URL, web_login};
use crate::store::{Config, FileStore, SecretStore};
use crate::token::{Relogin, SessionTokenSource, mint, run_secret_command};
use crate::{Error, Result};

/// Web login; stores the session and remembers the email in the config.
pub fn login(email: &str, password: &SecretString) -> Result<()> {
    login_with(
        START_URL,
        TOKEN_URL,
        &FileStore::session()?,
        email,
        password,
    )?;
    let mut cfg = Config::load()?;
    if cfg.email.as_deref() != Some(email) {
        cfg.email = Some(email.to_owned());
        cfg.save()?;
    }
    Ok(())
}

/// Forgets the session; the config stays.
pub fn logout() -> Result<()> {
    FileStore::session()?.delete()
}

/// The password printed by `password_cmd` (one trailing newline removed).
pub fn password_from_command(cmd: &str) -> Result<SecretString> {
    let out = run_secret_command("password", cmd)?;
    let password = out.expose_secret().trim_end_matches(['\r', '\n']);
    if password.is_empty() {
        return Err(Error::Command {
            what: "password",
            detail: "empty output".into(),
        });
    }
    Ok(SecretString::from(password.to_owned()))
}

/// Token source for the stored session, renewed through `password_cmd` when it is configured.
pub fn stored_token_source() -> Result<SessionTokenSource> {
    let cfg = Config::load()?;
    let session = FileStore::session()?;
    let cookie = match session.load() {
        Ok(c) => Some(c),
        Err(Error::NotLoggedIn) => None,
        Err(e) => return Err(e),
    };
    let relogin = match (cfg.email, cfg.password_cmd) {
        (Some(email), Some(cmd)) => Some(Box::new(move || {
            let password = password_from_command(&cmd)?;
            login_with(START_URL, TOKEN_URL, &session, &email, &password)
        }) as Relogin),
        _ => None,
    };
    SessionTokenSource::new(cookie, TOKEN_URL, relogin)
}

/// Logs in, checks the session can mint the filter scopes, stores and returns it.
fn login_with(
    start_url: &str,
    token_url: &str,
    store: &impl SecretStore,
    user: &str,
    password: &SecretString,
) -> Result<SecretString> {
    let cookie = web_login(start_url, token_url, user, password)?;
    mint(&Http::new(), token_url, &cookie).map_err(|e| Error::LoginSessionUnusable(Box::new(e)))?;
    store.save(&cookie)?;
    Ok(cookie)
}

#[cfg(test)]
mod tests {
    use mockito::{Matcher, Mock, Server, ServerGuard};
    use secrecy::ExposeSecret;
    use serde_json::json;

    use super::*;
    use crate::token::tests::MemStore;

    fn run(s: &Server, store: &MemStore) -> Result<SecretString> {
        login_with(
            &format!("{}/go", s.url()),
            &format!("{}/token", s.url()),
            store,
            "me@gmx.de",
            &SecretString::from("hunter2"),
        )
    }

    fn script(id: &str, json: serde_json::Value) -> String {
        format!(r#"<script id="{id}" type="application/json">{json}</script>"#)
    }

    /// start page -> authorize -> login page with the embedded login service config
    fn browser_pages(s: &mut ServerGuard) -> Vec<Mock> {
        let url = s.url();
        let start = script(
            "application-config",
            json!({
                "clientId": "alligator", "oAuthEndpointAuthorize": format!("{url}/authorize"),
                "redirectUri": format!("{url}/start/"), "scopes": ["navigator_start"],
                "statePayload": "pl", "xUiAppHeader": "gmxnet.alligator/2.2.1",
            }),
        );
        let login = [
            script(
                "application-properties",
                json!({"appName": "authentication-fe", "appVersion": "2.2.16", "brand": "gmxnet"}),
            ),
            script(
                "view-properties",
                json!({"loginServiceKuli": {
                    "serviceId": "oauth2", "serviceUrl": format!("{url}/rest/login-flow"),
                    "successUrl": format!("{url}/authcode"), "failureUrl": "https://f/",
                    "errorUrl": "https://e/", "statistics": "stat",
                }}),
            ),
            script(
                "query-parameters",
                json!({"authCodeContext": "ctx", "tld": null}),
            ),
        ]
        .concat();
        vec![
            s.mock("GET", "/go").with_body(start).create(),
            s.mock("GET", "/authorize")
                .match_query(Matcher::AllOf(vec![
                    Matcher::UrlEncoded("client_id".into(), "alligator".into()),
                    Matcher::UrlEncoded("response_type".into(), "code".into()),
                    Matcher::UrlEncoded("code_challenge_method".into(), "S256".into()),
                    Matcher::UrlEncoded("scope".into(), "navigator_start".into()),
                    Matcher::Regex("code_challenge=[A-Za-z0-9_-]{43}".into()),
                ]))
                .with_status(303)
                .with_header("location", "/login?prompt=none")
                .create(),
            s.mock("GET", "/login")
                .match_query(Matcher::Any)
                .with_body(login)
                .create(),
        ]
    }

    fn identification(s: &mut ServerGuard) -> Mock {
        let target = format!("{}/authcode?authcode-context=ctx", s.url());
        s.mock("POST", "/rest/login-flow/identification")
            .match_header("x-ui-app", "gmxnet.authentication-fe/2.2.16")
            .match_header("origin", s.url().as_str())
            .match_header("user-agent", Matcher::Regex("^Mozilla/".into()))
            .match_body(Matcher::PartialJson(json!({
                "username": "me@gmx.de", "statistics": "stat", "targetUrl": target,
                "targetServiceId": "oauth2", "totpLoginErrorUrl": "https://e/",
                "totpLoginFailedUrl": "https://f/", "keepMeSignedIn": true,
            })))
            .with_body(json!({"sessionId": "sess", "flowState": "ONGOING"}).to_string())
            .create()
    }

    fn password_ok(s: &mut ServerGuard) -> Mock {
        let redirect = format!("{}/proceed", s.url());
        s.mock("POST", "/rest/login-flow/authentication/password")
            .match_header("x-ui-app", "gmxnet.authentication-fe/2.2.16")
            .match_body(Matcher::PartialJson(
                json!({"factorValue": "hunter2", "sessionId": "sess"}),
            ))
            .with_body(json!({"flowState": "SUCCESS", "redirectUrl": redirect}).to_string())
            .create()
    }

    /// netID proceed -> oauth2 authcode (sets the cookie) -> `end`
    fn redirect_chain(s: &mut ServerGuard, end: &str) -> Vec<Mock> {
        vec![
            s.mock("GET", "/proceed")
                .with_status(303)
                .with_header("location", "/authcode")
                .create(),
            s.mock("GET", "/authcode")
                .with_status(303)
                .with_header("set-cookie", "sso=abc; Path=/; HttpOnly")
                .with_header("location", end)
                .create(),
        ]
    }

    #[test]
    fn full_login_stores_the_cookie_and_leaves_the_code_unspent() {
        let mut s = Server::new();
        browser_pages(&mut s);
        identification(&mut s);
        password_ok(&mut s);
        redirect_chain(&mut s, "/start/?code=c&state=st");
        let start_app = s
            .mock("GET", "/start/")
            .match_query(Matcher::Any)
            .expect(0)
            .create();
        let token = s
            .mock("POST", "/token")
            .match_header("cookie", "sso=abc")
            .with_body(json!({"access_token": "at", "expires_in": 7200}).to_string())
            .create();

        let store = MemStore::default();
        run(&s, &store).unwrap();
        start_app.assert();
        token.assert();
        assert_eq!(store.load().unwrap().expose_secret(), "sso=abc");
    }

    #[test]
    fn rejected_password_is_reported_with_status() {
        let mut s = Server::new();
        browser_pages(&mut s);
        identification(&mut s);
        s.mock("POST", "/rest/login-flow/authentication/password")
            .with_status(401)
            .with_body(r#"{"error":"bad credentials"}"#)
            .create();
        let store = MemStore::default();
        let err = run(&s, &store).unwrap_err();
        assert!(matches!(
            err,
            Error::LoginRejected {
                step: "password",
                status: 401,
                ..
            }
        ));
        assert!(!err.to_string().contains("hunter2"));
        assert!(store.load().is_err());
    }

    #[test]
    fn second_factor_or_captcha_is_incomplete() {
        let mut s = Server::new();
        browser_pages(&mut s);
        identification(&mut s);
        s.mock("POST", "/rest/login-flow/authentication/password")
            .with_body(
                json!({"flowState": "ONGOING", "nextStep": [{"type": "CAPTCHA_SLIDE"}]})
                    .to_string(),
            )
            .create();
        let err = run(&s, &MemStore::default()).unwrap_err();
        assert!(
            matches!(err, Error::LoginIncomplete { ref flow_state } if flow_state == "ONGOING")
        );
    }

    #[test]
    fn chain_ending_elsewhere_is_an_unexpected_redirect() {
        let mut s = Server::new();
        browser_pages(&mut s);
        identification(&mut s);
        password_ok(&mut s);
        redirect_chain(&mut s, "/consent?secret=1");
        s.mock("GET", "/consent").match_query(Matcher::Any).create();
        let err = run(&s, &MemStore::default()).unwrap_err();
        assert!(matches!(err, Error::LoginUnexpectedRedirect(ref p) if p.ends_with("/consent")));
        assert!(!err.to_string().contains("secret"));
    }

    #[test]
    fn changed_login_page_is_reported() {
        let mut s = Server::new();
        s.mock("GET", "/go")
            .with_body("<html>redesigned</html>")
            .create();
        let err = run(&s, &MemStore::default()).unwrap_err();
        assert!(matches!(err, Error::LoginPage("application-config")));
    }

    #[test]
    fn unusable_session_is_not_stored() {
        let mut s = Server::new();
        browser_pages(&mut s);
        identification(&mut s);
        password_ok(&mut s);
        redirect_chain(&mut s, "/start/?code=c&state=st");
        s.mock("POST", "/token")
            .with_status(400)
            .with_body(r#"{"error":"invalid_grant"}"#)
            .create();
        let store = MemStore::default();
        let err = run(&s, &store).unwrap_err();
        assert!(matches!(err, Error::LoginSessionUnusable(_)));
        assert!(store.load().is_err());
    }

    #[test]
    fn password_command_output_keeps_everything_but_the_newline() {
        let pw = password_from_command("printf ' pa ss \\n'").unwrap();
        assert_eq!(pw.expose_secret(), " pa ss ");
        assert!(password_from_command("printf ''").is_err());
        let err = password_from_command("echo locked >&2; exit 1")
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("password command failed") && err.contains("locked"),
            "{err}"
        );
    }
}
