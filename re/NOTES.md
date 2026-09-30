# GMX reverse-engineering notes

Source: GMX Mail Android `de.gmx.mobile.android.mail` 9.17.2 (versionCode 405209),
signed `CN=Danijel Nevistic, OU=WebProd, O=GMX GmbH`. Decompiled with jadx 1.5.6.
Class paths below are relative to jadx `sources/`.

## Filters: `settings-bff.gmx.net` (webmail settings backend)

The Android app has **no** filter-rule API (it only reads spam mode,
`GET Setting?name=@spam`). The webmail settings app ("mailset-organize-inbox") uses:

| op | request | response |
|---|---|---|
| list | `GET https://settings-bff.gmx.net/filterRules` | `200` JSON array of rules |
| create | `POST /filterRules` (rule without `ruleId`/`uri`/`modified`) | `204`, no body - re-list to learn the new id |
| update | `PUT /filterRules/{ruleId}` (full rule) | `204` |
| enable | `POST /filterRules/{ruleId}/activate` | `204` |
| disable | `POST /filterRules/{ruleId}/deactivate` | `204` |
| delete | `DELETE /filterRules/{ruleId}` | `204` |

Headers: `Accept: application/json`, `Content-Type: application/json`,
`X-UI-App: gmxnet.mailset-organize-inbox/1.0.7-build.195`, `Origin: https://mailset-root.gmx.net`,
plus `Authorization: Bearer` (Chrome strips it from HAR exports; inferred from the token calls below).
No reorder call appeared in the trace; the rule type name says "Ordered" but there
is no position field, so order is presumably list order (open question).

Folders: `GET https://settings-cats.gmx.net/mailbox/primary/folder` returns a nested
`folders[].attribute.folderFullname` tree. Rules reference folders **by full name**
(`"INBOX/Club Köln"`, `"Papierkorb"`), not by id.

### Rule schema (observed)

```json
{
  "type": "StoppingNamedOrderedConditionalMultiActionUser",
  "ruleId": "5" | "b9e39f88-0d29-4b54-992c-e28e019c63f4",
  "uri": "https://trinity-mac-rest-…:8443/rest/MailAccount/<acct>/Rule/User/<ruleId>",
  "ruleName": "…", "active": true, "considerStopped": true,
  "modified": "2025-02-07T10:33:21Z",
  "condition": <Condition>,
  "actions": [ {"type": "MoveToFolder", "folder": "INBOX/X"}, {"type": "Stop"} ]
}
```

Conditions (recursive):
- `{"type": "AnyOf", "conditions": [<Condition>…]}`
- `{"type": "MultiFromComparator" | "MultiToComparator" | "MultiSubjectComparator",
   "operator": "OR", "inverted": false, ["includeCcHeader": true,]
   "headerComparatorConditions": [<HeaderCond>…]}`
- HeaderCond: `{"type": "From"|"ToCc"|"Subject", "comparator": "CONTAINS", "inverted": false, ...}`.
  **Read/write asymmetry:** GET returns the value under a type-specific key
  (`"from"`, `"to"`, `"subject"`); POST/PUT send it as `"comparand"`.
  PUT echoes back `ruleId`/`uri`/`modified` from the GET.

Only the variants above were seen in the traces; the model must round-trip unknown ones verbatim.

### Full option set (from the organize-inbox bundle, confirmed live)

Web UI rows: mode `eine` (any) / `alle` (all); conditions `allNewEmails`, `sender`, `recipient`, `subject`,
`size`, `priority`, `addressBook`; actions move, mark read, delete, copy, forward, notify; a "stop" switch.

Extra condition types: `AllNewEmails{inverted}`, `AllOf{conditions}`, `SizeOver{inverted, byteSize}`
(inverted = smaller than), `Priority{inverted, level: LOW|NORMAL|HIGH}`, `AnyContact{inverted}`
(sender is in the address book; inverted = is not); `operator` may be `OR` or `AND`.
Comparators: `CONTAINS`, `IS`, `STARTS_WITH`, `ENDS_WITH` (UI offers contains / not contains / is / is not;
negation is the outer `inverted` of the Multi* condition, the inner one stays false).
Header condition `type` also accepts `To` on read. The UI writes `ToCc` without `includeCcHeader`; the server
stores that as `includeCcHeader: false` (seen live), while rules made by older UIs carry `true`. gmxf's spec
language therefore has `to` (absent/false) and `to-cc` (true).

### Rules file, apply semantics (verified live)

`PUT /filterRules/{id}` with the full rule updates name, condition and actions; activation only through
`.../activate|deactivate`. Reorder always sends every rule (`PUT /filterRules {"rules": [...]}`); a partial list
was deliberately never tried, as the server might drop the omitted rules. Creating answers 204 without the id, so
`apply` re-lists and finds the new rule by its (unique) name.

Actions: `MoveToFolder{folder}`, `CopyToFolder{folder}`, `MarkSeen`, `DeleteMailImmediately`,
`CopyForward{pending: true, receivers[]}` (target must confirm by mail), `TemplatedEmailNotify{pending: false, pagers[]}`,
`Stop`. Legacy types the UI still reads: `MarkAsRead`, `Delete`, `Discard`, `ForwardTo`, `NotifyByEmail`,
`ExcludeFromSpamFilter`. A rule with a `To` condition plus a forward action is read-only in the UI.

UI payload builder: one row stands alone; mode all -> `AllOf`; mode any over rows of one header field ->
a single Multi* condition, else `AnyOf`. New rules are named `"unnamed"`, `considerStopped: true`.

Reorder: `PUT /filterRules` with `{"rules": [full rules in the new order]}` -> 204 (order = list order).
Calls need `X-UI-App: gmxnet.mailset-organize-inbox/1.0.7-build.195` and a browser `User-Agent` (POST
without it: 400 `request.httpUserAgent: rejected value [null]`).

Probed live with inactive throwaway rules (2026-09-30):
- `AnyOf`/`AllOf` nested in each other (any depth, any mix): **400, empty body**. One level only.
- `Multi*` groups with `operator: "AND"`, with outer `inverted: true` (OR and AND), and header conditions
  with inner `inverted: true`: accepted and returned unchanged. `AnyOf` with a single child: unchanged.
- `AllNewEmails` (what the web UI writes) is stored and returned as `{"type": "NewMail"}`, without
  `inverted`; `inverted: true` is dropped silently (the rule then matches all mail). An `inverted` field on
  `AnyOf` is dropped silently too.

### Folders (`settings-cats`)

`GET https://settings-cats.gmx.net/mailbox/primary/folder?absoluteURI=false` needs `Accept` **and**
`Content-Type: application/vnd.ui.trinity.folders-v5+json` (other Accept values: 406, or a masked 403) plus
`X-Request-Id`. The response is a tree: `folders[].{folderIdentifier, quota, attribute{folderName, folderFullname,
folderType, flags, systemFolder, pop3Include, virtual, allowSubfolders}, folders[]}`. Virtual folders (unread,
favorites, general, allemails) have no `folderFullname`. Creating a folder (not used by gmxf):
`POST /mailbox/primary/folderupdate?absoluteURI=false`, `Content-Type: application/vnd.ui.trinity.folder.create+json`,
`Accept: application/vnd.ui.trinity.folder-v2+json`, body `{folderName, folderType: "USER_DEFINED", pop3include: true,
expire: 1, ignoreFolderFlags: false, ignoreFolderQuota: false, flags: []}`.

### Token for settings-bff

Webmail obtains it from `POST https://oauth2.gmx.net/token` with
`grant_type=urn:mam:oauth:grant-type:shared_login_cookie` (cookie-authenticated,
no client credentials) and
`scope=mail_mailbox_w webmailer_setting_r webmailer_setting_w mail_confix_w`,
response `token_type=Bearer, expires_in=7200`.

The `uri` field shows settings-bff is a thin proxy over the Trinity mail REST API
(`/rest/MailAccount/<acct>/Rule/User/<id>`).

## Auth for gmxf

Recorded from a second HAR (`bap.navigator.gmx.net.har`, raw, gitignored) plus the public JS of
`alligator.navigator.gmx.net` (`/start` bundle) and `auth.gmx.net` (`StandaloneFlow.js`).

Login = OAuth authorization code + PKCE of the browser app `alligator` (`gmxnet_alligator_live`,
scope `navigator_start`), with a JSON login API in the middle:

1. `GET alligator.navigator.gmx.net/go/?targetURI=…&ref=weblink` -> `/start/?state=…` (HTML).
   `<script id="application-config">` holds clientId, oAuthEndpointAuthorize, redirectUri, scopes,
   statePayload, xUiAppHeader.
2. `GET oauth2.gmx.net/authorize?response_type=code&state&client_id&redirect_uri&code_challenge_method=S256&code_challenge&scope`
   where `state = base64(JSON{id, clientId, xUiApp, payload})`. 303 -> `login.gmx.net/keep_me_signed_in`
   -> 303 -> `auth.gmx.net/login?prompt=none&state&authcode-context` (HTML).
3. That page embeds `view-properties.loginServiceKuli` {serviceId, serviceUrl, successUrl,
   failureUrl, errorUrl, statistics}, `query-parameters` {authCodeContext, tld} and
   `application-properties` {brand, appName, appVersion}.
4. `POST {serviceUrl}/identification` `{username, statistics, targetUrl: successUrl?authcode-context=…,
   targetServiceId, totpLoginErrorUrl: errorUrl, totpLoginFailedUrl: failureUrl, keepMeSignedIn: true, tld}`
   -> `{sessionId, nextStep:[PASSWORD, WEBAUTHN_START], flowState:ONGOING}`. Passkey is optional.
5. `POST {serviceUrl}/authentication/password` `{factorValue, sessionId}` -> `{flowState:SUCCESS, redirectUrl}`.
   Steps 4-5 need `X-UI-App: {brand}.{appName}/{appVersion}`, `Origin: https://auth.gmx.net` and a
   browser `User-Agent` (missing header -> 400 `missing-request-header`). Captcha (CaptchaFox /
   reCAPTCHA) appears as another `nextStep`.
6. `redirectUrl` (`gmx.netid.de/proceed`) -> 303 `oauth2.gmx.net/authcode?authcode-context&auth_time&ott`
   -> 303 `alligator…/start/?code&state`. gmxf stops here (the code is not needed).
   The browser continues: alligator -> `bap.navigator.gmx.net/login?autologin&ott` -> `halogin?tz`
   -> `/?sid=…`.

Tokens: webmail apps call `POST oauth2.gmx.net/token` with `shared_login_cookie` (cookie only).
Navigator itself uses `POST oauthbridge.navigator.gmx.net/navigator/oauth2/token?sid=<sid>`
(`grant_type=urn:mam:oauth:grant-type:spa`, `X-UI-App: gmxde.navigator/28.39.1`), which also
issued `mail_confix_w`/`mail_mailbox_w`; `webmailer_setting_*` was never requested in this HAR.

gmxf uses steps 1-6 with a cookie jar and then the `shared_login_cookie` grant (`login.rs`).
Unverified live: that the cookie is planted by `/authcode` alone (otherwise continue through
alligator/`halogin`, or switch to the `sid` + oauthbridge route above).

The APK's mobile OAuth client is unusable for this: the password grant answers
`invalid_grant: Perm.USE_AUTHORIZATION_CODE_GRANT`.

### Token client (found in the public `mailset-root.gmx.net/build/p-*.js`)

`shared_login_cookie` needs `Authorization: Basic base64(clientId:clientSecret)`; Chrome strips that
header from HARs, and without it the endpoint answers `401 invalid_client`. The settings app
(`mailset-root`, mode SHARED_LOGIN for gmxnet) uses client `gmxnet_mailset_root_live` with the
placeholder secret `*******` (browser apps hold no real secret), scopes exactly
`mail_mailbox_w webmailer_setting_r webmailer_setting_w mail_confix_w`, `Origin: https://mailset-root.gmx.net`,
no `X-UI-App` on that call. Bridge-mode apps (webmailer, navigator) instead call
`oauthbridge.navigator.gmx.net` with `?sid=` and the `spa` grant.
