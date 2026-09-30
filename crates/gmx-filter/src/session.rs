use reqwest::blocking::Client as Http;
use secrecy::SecretString;

use crate::login::{START_URL, TOKEN_URL, web_login};
use crate::store::{Config, KeyringStore, SecretStore};
use crate::token::{Relogin, SessionTokenSource, mint};
use crate::{Error, Result};

/// Web login; stores the session in the keyring and the account name in the config. With
/// `remember`, the password is kept in the keyring too so expired sessions renew themselves.
pub fn login(user: &str, password: &SecretString, remember: bool) -> Result<()> {
    let previous = Config::load().ok().filter(|c| c.user != user);
    login_with(
        START_URL,
        TOKEN_URL,
        &KeyringStore::session(user),
        user,
        password,
    )?;
    let stored = KeyringStore::password(user);
    if remember {
        stored.save(password)?;
    } else {
        stored.delete()?;
    }
    Config {
        user: user.to_owned(),
    }
    .save()?;
    if let Some(prev) = previous {
        forget(&prev.user)?;
    }
    Ok(())
}

pub fn logout() -> Result<()> {
    match Config::load() {
        Ok(cfg) => {
            forget(&cfg.user)?;
            Config::clear()
        }
        Err(Error::NotLoggedIn) => Ok(()),
        Err(e) => Err(e),
    }
}

fn forget(user: &str) -> Result<()> {
    KeyringStore::session(user).delete()?;
    KeyringStore::password(user).delete()
}

/// Token source for the account from the last `login`, renewing the session with the
/// remembered password when there is one.
pub fn stored_token_source() -> Result<SessionTokenSource> {
    let cfg = Config::load()?;
    let session = KeyringStore::session(&cfg.user);
    let cookie = optional(session.load())?;
    let relogin = optional(KeyringStore::password(&cfg.user).load())?.map(|_| {
        let user = cfg.user.clone();
        Box::new(move || {
            let password = KeyringStore::password(&user).load()?;
            login_with(
                START_URL,
                TOKEN_URL,
                &KeyringStore::session(&user),
                &user,
                &password,
            )
        }) as Relogin
    });
    SessionTokenSource::new(cookie, TOKEN_URL, relogin)
}

/// `NotLoggedIn` from a store just means the entry is not there.
fn optional<T>(r: Result<T>) -> Result<Option<T>> {
    match r {
        Ok(v) => Ok(Some(v)),
        Err(Error::NotLoggedIn) => Ok(None),
        Err(e) => Err(e),
    }
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
}
