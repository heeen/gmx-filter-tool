use reqwest::blocking::{Client as Http, RequestBuilder, Response};
use secrecy::ExposeSecret;
use serde::Deserialize;
use serde_json::json;

use crate::login::USER_AGENT;
use crate::{Error, Result, Rule, TokenSource};

const SETTINGS_BFF: &str = "https://settings-bff.gmx.net";
const SETTINGS_CATS: &str = "https://settings-cats.gmx.net";
const JSON: &str = "application/json";
const FOLDERS_MEDIA_TYPE: &str = "application/vnd.ui.trinity.folders-v5+json";
const X_UI_APP: &str = "gmxnet.mailset-organize-inbox/1.0.7-build.195";
const ORIGIN: &str = "https://mailset-root.gmx.net";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Folder {
    pub full_name: String,
    pub folder_type: String,
    pub system_folder: bool,
}

fn request_id() -> String {
    let b = rand::random::<[u8; 16]>();
    format!(
        "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
        u32::from_be_bytes([b[0], b[1], b[2], b[3]]),
        u16::from_be_bytes([b[4], b[5]]),
        u16::from_be_bytes([b[6], b[7]]),
        u16::from_be_bytes([b[8], b[9]]),
        u64::from_be_bytes([0, 0, b[10], b[11], b[12], b[13], b[14], b[15]]),
    )
}

pub struct Client<T> {
    http: Http,
    tokens: T,
    bff: String,
    cats: String,
}

impl<T: TokenSource> Client<T> {
    pub fn new(tokens: T) -> Self {
        Self::with_base_urls(tokens, SETTINGS_BFF, SETTINGS_CATS)
    }

    pub fn with_base_urls(tokens: T, bff: &str, cats: &str) -> Self {
        Self {
            http: Http::new(),
            tokens,
            bff: bff.trim_end_matches('/').to_owned(),
            cats: cats.trim_end_matches('/').to_owned(),
        }
    }

    pub fn list_rules(&self) -> Result<Vec<Rule>> {
        let resp =
            self.send(self.request(self.http.get(format!("{}/filterRules", self.bff)), JSON)?)?;
        Ok(resp.json()?)
    }

    /// The API answers `204` without the new id; re-list to find the created rule.
    pub fn create_rule(&self, rule: &Rule) -> Result<()> {
        let req = self
            .http
            .post(format!("{}/filterRules", self.bff))
            .json(rule);
        self.send(self.request(req, JSON)?)?;
        Ok(())
    }

    /// `rule` must carry the `rule_id` it was listed with.
    pub fn update_rule(&self, rule: &Rule) -> Result<()> {
        let id = rule.rule_id.as_deref().ok_or(Error::MissingRuleId)?;
        let req = self
            .http
            .put(format!("{}/filterRules/{id}", self.bff))
            .json(rule);
        self.send(self.request(req, JSON)?)?;
        Ok(())
    }

    pub fn set_active(&self, rule_id: &str, active: bool) -> Result<()> {
        let verb = if active { "activate" } else { "deactivate" };
        let req = self
            .http
            .post(format!("{}/filterRules/{rule_id}/{verb}", self.bff));
        self.send(self.request(req, JSON)?)?;
        Ok(())
    }

    pub fn delete_rule(&self, rule_id: &str) -> Result<()> {
        let req = self
            .http
            .delete(format!("{}/filterRules/{rule_id}", self.bff));
        self.send(self.request(req, JSON)?)?;
        Ok(())
    }

    /// Replaces the rule order with `rules` (full rules, in the new order).
    pub fn reorder_rules(&self, rules: &[Rule]) -> Result<()> {
        let req = self
            .http
            .put(format!("{}/filterRules", self.bff))
            .json(&json!({ "rules": rules }));
        self.send(self.request(req, JSON)?)?;
        Ok(())
    }

    /// All folders, depth-first. Rules reference folders by `full_name`.
    pub fn folders(&self) -> Result<Vec<Folder>> {
        #[derive(Deserialize)]
        struct Tree {
            folders: Vec<Node>,
        }
        /// Virtual folders (unread, favorites, categories) have no full name and are no rule targets.
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Attribute {
            #[serde(rename = "folderFullname")]
            full_name: Option<String>,
            folder_type: String,
            #[serde(default)]
            system_folder: bool,
        }
        #[derive(Deserialize)]
        struct Node {
            attribute: Attribute,
            #[serde(default)]
            folders: Vec<Node>,
        }
        fn flatten(nodes: Vec<Node>, out: &mut Vec<Folder>) {
            for node in nodes {
                if let Some(full_name) = node.attribute.full_name {
                    out.push(Folder {
                        full_name,
                        folder_type: node.attribute.folder_type,
                        system_folder: node.attribute.system_folder,
                    });
                }
                flatten(node.folders, out);
            }
        }

        let req = self
            .http
            .get(format!(
                "{}/mailbox/primary/folder?absoluteURI=false",
                self.cats
            ))
            .header("Content-Type", FOLDERS_MEDIA_TYPE);
        let req = self.request(req, FOLDERS_MEDIA_TYPE)?;
        let tree: Tree = self.send(req)?.json()?;
        let mut folders = Vec::new();
        flatten(tree.folders, &mut folders);
        Ok(folders)
    }

    fn request(&self, req: RequestBuilder, accept: &str) -> Result<RequestBuilder> {
        let token = self.tokens.token()?;
        Ok(req
            .bearer_auth(token.expose_secret())
            .header("Accept", accept)
            .header("X-UI-App", X_UI_APP)
            .header("Origin", ORIGIN)
            .header("User-Agent", USER_AGENT)
            .header("X-Request-Id", request_id()))
    }

    fn send(&self, req: RequestBuilder) -> Result<Response> {
        let resp = req.send()?;
        if resp.status().is_success() {
            return Ok(resp);
        }
        Err(Error::Api {
            status: resp.status().as_u16(),
            url: resp.url().to_string(),
            body: resp.text().unwrap_or_default(),
        })
    }
}

#[cfg(test)]
mod tests {
    use mockito::Server;
    use secrecy::SecretString;
    use serde_json::json;

    use super::*;

    impl TokenSource for SecretString {
        fn token(&self) -> Result<SecretString> {
            Ok(SecretString::from(self.expose_secret().to_owned()))
        }
    }

    fn client(server: &Server) -> Client<SecretString> {
        Client::with_base_urls(SecretString::from("tok"), &server.url(), &server.url())
    }

    #[test]
    fn lists_rules_with_bearer_auth() {
        let mut s = Server::new();
        let body = json!([{
            "type": "StoppingNamedOrderedConditionalMultiActionUser",
            "ruleId": "5", "ruleName": "n", "active": true, "considerStopped": true,
            "condition": {"type": "AnyOf", "conditions": []},
            "actions": [{"type": "Stop"}]
        }]);
        let m = s
            .mock("GET", "/filterRules")
            .match_header("authorization", "Bearer tok")
            .match_header("user-agent", mockito::Matcher::Regex("^Mozilla/".into()))
            .with_body(body.to_string())
            .create();
        let rules = client(&s).list_rules().unwrap();
        m.assert();
        assert_eq!(rules[0].rule_id.as_deref(), Some("5"));
    }

    #[test]
    fn create_posts_comparand_without_server_fields() {
        let mut s = Server::new();
        let m = s
            .mock("POST", "/filterRules")
            .match_body(mockito::Matcher::PartialJson(json!({
                "ruleName": "r",
                "condition": {"headerComparatorConditions": [{"comparand": "a@b"}]}
            })))
            .with_status(204)
            .create();
        let rule = Rule::new(
            "r",
            crate::condition(crate::Mode::Any, &["from contains a@b".parse().unwrap()]).unwrap(),
            crate::actions(vec![crate::Effect::Move("INBOX/X".into())], true),
        );
        client(&s).create_rule(&rule).unwrap();
        m.assert();
    }

    #[test]
    fn api_errors_carry_status_and_body() {
        let mut s = Server::new();
        s.mock("DELETE", "/filterRules/9")
            .with_status(404)
            .with_body("gone")
            .create();
        let err = client(&s).delete_rule("9").unwrap_err();
        assert!(matches!(err, Error::Api { status: 404, ref body, .. } if body == "gone"));
    }

    #[test]
    fn reorder_puts_the_rules_wrapper() {
        let mut s = Server::new();
        let m = s
            .mock("PUT", "/filterRules")
            .match_body(mockito::Matcher::PartialJson(
                json!({"rules": [{"ruleName": "a"}, {"ruleName": "b"}]}),
            ))
            .with_status(204)
            .create();
        let rule = |n: &str| {
            Rule::new(
                n,
                crate::condition(crate::Mode::Any, &[crate::Test::AllNewEmails]).unwrap(),
                vec![],
            )
        };
        client(&s).reorder_rules(&[rule("a"), rule("b")]).unwrap();
        m.assert();
    }

    #[test]
    fn folder_tree_is_flattened_with_browser_headers() {
        let mut s = Server::new();
        let folder = |name: &str, kids: serde_json::Value| {
            json!({"attribute": {"folderName": name, "folderFullname": name, "folderType": "USER_DEFINED",
                "systemFolder": false, "flags": []}, "folders": kids})
        };
        let virtual_folder = json!({"attribute": {"folderName": "unread", "folderType": "unread",
            "virtual": true, "flags": []}, "folders": []});
        let m = s
            .mock("GET", "/mailbox/primary/folder")
            .match_query(mockito::Matcher::UrlEncoded("absoluteURI".into(), "false".into()))
            .match_header("accept", "application/vnd.ui.trinity.folders-v5+json")
            .match_header("content-type", "application/vnd.ui.trinity.folders-v5+json")
            .match_header("x-request-id", mockito::Matcher::Regex("^[0-9a-f-]{36}$".into()))
            .with_body(
                json!({"folders": [folder("INBOX", json!([folder("INBOX/A", json!([]))])), virtual_folder, folder("Papierkorb", json!([]))]})
                    .to_string(),
            )
            .create();
        let names: Vec<_> = client(&s)
            .folders()
            .unwrap()
            .into_iter()
            .map(|f| f.full_name)
            .collect();
        m.assert();
        assert_eq!(names, ["INBOX", "INBOX/A", "Papierkorb"]);
    }
}
