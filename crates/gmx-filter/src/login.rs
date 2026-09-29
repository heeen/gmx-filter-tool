//! The webmail login as the browser performs it (recorded from a HAR, front-end logic read from
//! the public JS bundles):
//!
//! 1. `alligator.navigator.gmx.net/go/` serves the OAuth client config of the navigator start app.
//! 2. `oauth2.gmx.net/authorize` (PKCE) redirects to the `auth.gmx.net` login page, which embeds
//!    the login service parameters and an `authcode-context`.
//! 3. The login page's JSON API (`identification`, `authentication/password`) answers with a
//!    `redirectUrl`.
//! 4. That redirect chain (netID -> `oauth2.gmx.net/authcode`) plants the shared login cookies and
//!    ends at the start app's `redirect_uri` with a `code`. We stop there: the code is not needed,
//!    the cookies are.
//!
//! The cookies for the token endpoint are then read back from the jar.

use std::sync::Arc;

use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use reqwest::{
    Url,
    blocking::{Client as Http, Response},
    cookie::{CookieStore, Jar},
    redirect::Policy,
};
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::{Error, Result};

pub(crate) const START_URL: &str = "https://alligator.navigator.gmx.net/go/?targetURI=https%3A%2F%2Fweblink.gmx.net%2Fmail%2FshowStartView&ref=weblink";
pub(crate) const TOKEN_URL: &str = "https://oauth2.gmx.net/token";

/// The login and token APIs reject requests without a browser-like `User-Agent`.
pub(crate) const USER_AGENT: &str =
    "Mozilla/5.0 (X11; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0";
const MAX_REDIRECTS: usize = 10;

/// Embedded in the start page as `<script id="application-config">`.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct StartConfig {
    client_id: String,
    o_auth_endpoint_authorize: String,
    redirect_uri: String,
    scopes: Vec<String>,
    state_payload: String,
    x_ui_app_header: String,
}

/// Embedded in the login page as `<script id="view-properties">`.
#[derive(Deserialize)]
struct ViewProperties {
    #[serde(rename = "loginServiceKuli")]
    login_service: LoginService,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct LoginService {
    service_id: String,
    service_url: String,
    success_url: String,
    failure_url: String,
    error_url: String,
    statistics: String,
}

/// `<script id="query-parameters">`
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct QueryParameters {
    auth_code_context: String,
    tld: Option<String>,
}

/// `<script id="application-properties">`
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AppProperties {
    app_name: String,
    app_version: String,
    brand: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Identification {
    session_id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Authentication {
    flow_state: Option<String>,
    redirect_url: Option<String>,
}

enum Step {
    Page(Url, Response),
    /// The redirect chain reached a URL the caller asked not to fetch.
    Stopped(Url),
}

/// Logs in and returns the `Cookie` header value to present to the token endpoint.
pub(crate) fn web_login(
    start_url: &str,
    token_url: &str,
    user: &str,
    password: &SecretString,
) -> Result<SecretString> {
    let jar = Arc::new(Jar::default());
    let http = Http::builder()
        .cookie_provider(Arc::clone(&jar))
        .redirect(Policy::none())
        .user_agent(USER_AGENT)
        .build()?;

    let start_url = Url::parse(start_url).map_err(|_| Error::LoginPage("start url"))?;
    let (_, page) = get_page(&http, start_url)?;
    let start: StartConfig = embedded_json(&page.text()?, "application-config")?;

    let authorize = authorize_url(&start)?;
    let (login_page_url, page) = get_page(&http, authorize)?;
    let html = page.text()?;
    let view: ViewProperties = embedded_json(&html, "view-properties")?;
    let query: QueryParameters = embedded_json(&html, "query-parameters")?;
    let app: AppProperties = embedded_json(&html, "application-properties")?;
    let service = view.login_service;
    let headers = FlowHeaders {
        origin: login_page_url.origin().ascii_serialization(),
        x_ui_app: format!("{}.{}/{}", app.brand, app.app_name, app.app_version),
    };

    let mut target_url =
        Url::parse(&service.success_url).map_err(|_| Error::LoginPage("successUrl"))?;
    target_url
        .query_pairs_mut()
        .append_pair("authcode-context", &query.auth_code_context);
    if let Some(tld) = &query.tld {
        target_url.query_pairs_mut().append_pair("tld", tld);
    }
    let ident: Identification = flow_post(
        "identification",
        &http,
        &headers,
        &format!("{}/identification", service.service_url),
        &json!({
            "username": user,
            "statistics": service.statistics,
            "targetUrl": target_url.as_str(),
            "targetServiceId": service.service_id,
            "totpLoginErrorUrl": service.error_url,
            "totpLoginFailedUrl": service.failure_url,
            "keepMeSignedIn": true,
            "tld": query.tld,
        }),
    )?;

    let auth: Authentication = flow_post(
        "password",
        &http,
        &headers,
        &format!("{}/authentication/password", service.service_url),
        &json!({
            "factorValue": password.expose_secret(),
            "sessionId": ident.session_id,
        }),
    )?;
    let Some(redirect) = auth.redirect_url else {
        return Err(Error::LoginIncomplete {
            flow_state: auth.flow_state.unwrap_or_default(),
        });
    };

    let redirect = Url::parse(&redirect).map_err(|_| Error::LoginPage("redirectUrl"))?;
    let start_redirect = start.redirect_uri.as_str();
    let reached_start_app = |u: &Url| {
        u.as_str().starts_with(start_redirect) && u.query_pairs().any(|(k, _)| k == "code")
    };
    match walk(&http, redirect, reached_start_app)? {
        Step::Stopped(_) => {}
        Step::Page(url, _) => return Err(Error::LoginUnexpectedRedirect(describe(&url))),
    }

    let token_url = Url::parse(token_url).map_err(|_| Error::LoginNoSession)?;
    let cookies = jar.cookies(&token_url).ok_or(Error::LoginNoSession)?;
    let cookies = cookies.to_str().map_err(|_| Error::LoginNoSession)?;
    Ok(SecretString::from(cookies.to_owned()))
}

fn authorize_url(start: &StartConfig) -> Result<Url> {
    let verifier = URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>());
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    let state = json!({
        "id": URL_SAFE_NO_PAD.encode(rand::random::<[u8; 16]>()),
        "clientId": start.client_id,
        "xUiApp": start.x_ui_app_header,
        "payload": start.state_payload,
    });
    let mut url = Url::parse(&start.o_auth_endpoint_authorize)
        .map_err(|_| Error::LoginPage("oAuthEndpointAuthorize"))?;
    url.query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("state", &STANDARD.encode(state.to_string()))
        .append_pair("client_id", &start.client_id)
        .append_pair("redirect_uri", &start.redirect_uri)
        .append_pair("code_challenge_method", "S256")
        .append_pair("code_challenge", &challenge)
        .append_pair("scope", &start.scopes.join(" "));
    Ok(url)
}

fn get_page(http: &Http, url: Url) -> Result<(Url, Response)> {
    match walk(http, url, |_| false)? {
        Step::Page(url, resp) => Ok((url, resp)),
        Step::Stopped(url) => Err(Error::LoginUnexpectedRedirect(describe(&url))),
    }
}

/// GETs `url` and follows redirects by hand (cookies are kept by the client's jar), so that the
/// walk can end before a URL whose one-time query we do not want to spend.
fn walk(http: &Http, mut url: Url, stop_before: impl Fn(&Url) -> bool) -> Result<Step> {
    for _ in 0..MAX_REDIRECTS {
        if stop_before(&url) {
            return Ok(Step::Stopped(url));
        }
        let resp = http.get(url.clone()).header("Accept", "text/html").send()?;
        if !resp.status().is_redirection() {
            return if resp.status().is_success() {
                Ok(Step::Page(url, resp))
            } else {
                Err(Error::LoginUnexpectedRedirect(describe(&url)))
            };
        }
        let location = resp
            .headers()
            .get("location")
            .and_then(|l| l.to_str().ok())
            .ok_or_else(|| Error::LoginUnexpectedRedirect(describe(&url)))?;
        url = url
            .join(location)
            .map_err(|_| Error::LoginUnexpectedRedirect(describe(&url)))?;
    }
    Err(Error::LoginUnexpectedRedirect(format!(
        "more than {MAX_REDIRECTS} redirects"
    )))
}

/// Contents of `<script id="{id}" type="application/json">…</script>`.
fn embedded_json<T: for<'de> Deserialize<'de>>(html: &str, id: &'static str) -> Result<T> {
    let marker = format!("id=\"{id}\"");
    let after_id = html.split_once(&marker).ok_or(Error::LoginPage(id))?.1;
    let body = after_id.split_once('>').ok_or(Error::LoginPage(id))?.1;
    let json = body.split_once("</script>").ok_or(Error::LoginPage(id))?.0;
    serde_json::from_str(json).map_err(|_| Error::LoginPage(id))
}

/// Host and path only: the query holds one-time tokens.
fn describe(url: &Url) -> String {
    format!("{}{}", url.host_str().unwrap_or("?"), url.path())
}

struct FlowHeaders {
    origin: String,
    x_ui_app: String,
}

fn flow_post<T: for<'de> Deserialize<'de>>(
    step: &'static str,
    http: &Http,
    headers: &FlowHeaders,
    url: &str,
    body: &serde_json::Value,
) -> Result<T> {
    let resp = http
        .post(url)
        .header("Accept", "*/*")
        .header("Origin", &headers.origin)
        .header("X-UI-App", &headers.x_ui_app)
        .json(body)
        .send()?;
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().unwrap_or_default();
        return Err(Error::LoginRejected {
            step,
            status: status.as_u16(),
            body: body.chars().take(200).collect(),
        });
    }
    Ok(resp.json()?)
}
