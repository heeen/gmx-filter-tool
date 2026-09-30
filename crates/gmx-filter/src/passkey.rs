//! The passkey signer behind `gmxf login --passkey`: the "use a phone" (hybrid) flow browsers offer.
//! A QR code links the phone; the phone checks it is nearby over Bluetooth and signs through a
//! relay. The passkey never leaves the phone; gmxf only gets the signed answer, like a browser.

use serde_json::Value;
use webauthn_authenticator_rs::cable::connect_cable_authenticator;
use webauthn_authenticator_rs::prelude::{
    PublicKeyCredential, RequestChallengeResponse, Url, WebauthnAuthenticator, WebauthnCError,
};
use webauthn_authenticator_rs::types::CableRequestType;
use webauthn_authenticator_rs::ui::Cli;

use crate::{Error, Result};

fn failed(e: WebauthnCError) -> Error {
    let hint = if e == WebauthnCError::PermissionDenied {
        " (Bluetooth access denied)"
    } else {
        ""
    };
    Error::Passkey(format!("{e:?}{hint}"))
}

/// Signs the login page's WebAuthn request as `origin` and returns the credential JSON the page
/// would post.
pub(crate) fn sign(options_json: &str, origin: &str) -> Result<String> {
    let options = request_options(options_json)?;
    let origin =
        Url::parse(origin).map_err(|e| Error::Passkey(format!("origin {origin:?}: {e}")))?;
    // The library drives Bluetooth and the relay with tokio and blocks inside its sync calls, so
    // everything runs inside one multi-threaded runtime, as in its own examples.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let credential = runtime.block_on(async {
        let ui = Cli {};
        let mut authenticator = connect_cable_authenticator(CableRequestType::GetAssertion, &ui)
            .await
            .map_err(failed)?;
        authenticator
            .do_authentication(origin, options)
            .map_err(failed)
    })?;
    browser_json(&credential)
}

/// The request as GMX sends it, with the fields browsers default filled in.
fn request_options(options_json: &str) -> Result<RequestChallengeResponse> {
    let bad = |e: String| Error::Passkey(format!("unexpected WebAuthn request: {e}"));
    let mut value: Value = serde_json::from_str(options_json).map_err(|e| bad(e.to_string()))?;
    let public_key = value
        .get_mut("publicKey")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| bad("no publicKey".into()))?;
    public_key
        .entry("allowCredentials")
        .or_insert(Value::Array(Vec::new()));
    public_key
        .entry("userVerification")
        .or_insert(Value::String("preferred".into()));
    serde_json::from_value(value).map_err(|e| bad(e.to_string()))
}

/// `PublicKeyCredential.toJSON()` as a browser writes it: the library calls the extension results
/// `extensions` and has no `authenticatorAttachment`.
fn browser_json(credential: &PublicKeyCredential) -> Result<String> {
    let mut value = serde_json::to_value(credential)?;
    if let Some(object) = value.as_object_mut() {
        let extensions = object
            .remove("extensions")
            .unwrap_or_else(|| Value::Object(Default::default()));
        object.insert("clientExtensionResults".into(), extensions);
        object.insert(
            "authenticatorAttachment".into(),
            Value::String("cross-platform".into()),
        );
    }
    Ok(value.to_string())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn gmx_requests_parse_with_browser_defaults() {
        let r = request_options(
            r#"{"publicKey":{"challenge":"Y2hhbGxlbmdl","rpId":"gmx.net","timeout":60000}}"#,
        )
        .unwrap();
        assert_eq!(r.public_key.challenge, b"challenge");
        assert_eq!(r.public_key.rp_id, "gmx.net");
        assert!(r.public_key.allow_credentials.is_empty());
        assert!(request_options(r#"{"nope":1}"#).is_err());
    }

    #[test]
    fn answers_look_like_the_browsers() {
        let credential: PublicKeyCredential = serde_json::from_value(json!({
            "id": "Y3JlZA", "rawId": "Y3JlZA", "type": "public-key",
            "response": {"authenticatorData": "YQ", "clientDataJSON": "Yg", "signature": "Yw", "userHandle": "ZA"},
        }))
        .unwrap();
        let out: Value = serde_json::from_str(&browser_json(&credential).unwrap()).unwrap();
        assert_eq!(out["rawId"], "Y3JlZA");
        assert_eq!(out["response"]["clientDataJSON"], "Yg");
        assert_eq!(out["authenticatorAttachment"], "cross-platform");
        assert!(out["clientExtensionResults"].is_object());
        assert!(out.get("extensions").is_none());
    }
}
