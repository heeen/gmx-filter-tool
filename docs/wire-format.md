# GMX filter rules: wire format

The HTTP API behind the GMX webmail settings ("Filterregeln"), as used by gmxf. None of it is documented by
GMX; everything here comes from browser traces, the public JavaScript of the web apps, and live probes on a
real account with inactive throwaway rules. Marks: **✔** sent and verified live, **◇** read back from the
server or seen in the web app's code, never sent by gmxf.

There is no machine-readable description: with a valid token, settings-bff (Spring Boot) answers 404
`no-resource-found` for `/v3/api-docs`, `/v2/api-docs`, `/openapi.*`, `/swagger-ui*`, `/actuator/**`, `/`,
and settings-cats answers 403 for everything outside its allowlist, including guesses at the backend's
rule and setting resources (probed 2026-09-30). Without a token both answer 401 to every path.

`settings-bff.gmx.net` is a thin proxy: the `uri` of a rule points at GMX's internal mail backend
("Trinity", `…/rest/MailAccount/<account>/Rule/User/<id>`).

## Notation

EBNF over JSON. `{ "k": v, … }` is an object with exactly those keys (`[ "k": v ]` optional), `[ x… ]` an
array of `x`, `STRING`, `BOOL`, `UINT` JSON values. Every object carries its own `"type"` discriminator,
even where the parent already implies it.

## Endpoints

Base `https://settings-bff.gmx.net`. All answers of writes are `204 No Content` without a body.

| call | request | answer |
|---|---|---|
| list ✔ | `GET /filterRules` | `200`, `[ stored-rule… ]` in execution order |
| create ✔ | `POST /filterRules`, body `rule` | `204`; the id is not returned, list again to find it |
| update ✔ | `PUT /filterRules/{ruleId}`, body the full `rule` (may include the read-only fields) | `204` |
| enable ✔ | `POST /filterRules/{ruleId}/activate` | `204` |
| disable ✔ | `POST /filterRules/{ruleId}/deactivate` | `204` |
| delete ✔ | `DELETE /filterRules/{ruleId}` | `204` |
| reorder ✔ | `PUT /filterRules`, body `{ "rules": [ stored-rule… ] }` in the new order | `204` |

`active` in a create or update body is honoured on create; to switch an existing rule on or off use the
activate/deactivate calls. Reorder was only ever sent with **every** rule; what a partial list does is unknown
(it might drop the missing rules).

### Request headers

```
Authorization: Bearer <access token>                   (see Authentication)
Accept:        application/json
Content-Type:  application/json                        (bodies)
Origin:        https://mailset-root.gmx.net
X-UI-App:      gmxnet.mailset-organize-inbox/1.0.7-build.195
User-Agent:    <a browser user agent>                  required on writes, see Errors
X-Request-Id:  <uuid>                                  optional here, required by settings-cats
```

## Rules

```ebnf
rule          = { "type": "StoppingNamedOrderedConditionalMultiActionUser",   (* the only type ✔ *)
                  "ruleName": STRING,                   (* the web UI always sends "unnamed" *)
                  "active": BOOL,
                  "considerStopped": BOOL,              (* the web UI always sends true *)
                  "condition": condition,
                  "actions": [ action… ] } ;

stored-rule   = rule + { "ruleId": STRING,              (* UUID; small numbers on old rules *)
                         "uri": STRING,                 (* backend URL of the rule *)
                         "modified": STRING } ;         (* RFC 3339 UTC, e.g. "2025-02-07T10:33:21Z" *)
```

### Conditions

```ebnf
condition     = group | leaf ;

group         = { "type": "AnyOf" | "AllOf",            (* ✔ *)
                  "conditions": [ leaf… ] } ;           (* ✔ one child is fine; a group inside a group: 400 *)

leaf          = header-group | size | priority | contact | all-new ;

header-group  = { "type": "MultiFromComparator" | "MultiToComparator" | "MultiSubjectComparator",   (* ✔ *)
                  "operator": "OR" | "AND",             (* how the entries combine; AND ✔ *)
                  "inverted": BOOL,                     (* NOT (whole group) ✔, also with several entries *)
                  "headerComparatorConditions": [ header… ] } ;

header        = { "type": "From" | "Subject",
                  "comparator": comparator,
                  "inverted": BOOL,                     (* NOT (this entry) ✔ *)
                  "comparand": STRING }
              | { "type": "ToCc",
                  "comparator": comparator,
                  "inverted": BOOL,
                  [ "includeCcHeader": BOOL, ]          (* ✔ absent (current UI); ◇ true on older rules *)
                  "comparand": STRING } ;

comparator    = "CONTAINS" | "IS" | "STARTS_WITH" | "ENDS_WITH" ;                       (* ✔ all four *)

size          = { "type": "SizeOver", "inverted": BOOL, "byteSize": UINT } ;           (* ✔ inverted = smaller *)
priority      = { "type": "Priority", "inverted": BOOL,
                  "level": "LOW" | "NORMAL" | "HIGH" } ;                               (* ✔ *)
contact       = { "type": "AnyContact", "inverted": BOOL } ;                           (* ◇ sender in address book *)
all-new       = { "type": "AllNewEmails", [ "inverted": BOOL ] } ;                     (* ✔ *)
```

Entries must belong to their group's field (`From` in `MultiFromComparator`, `ToCc` in `MultiToComparator`,
`Subject` in `MultiSubjectComparator`); a mismatch is rejected ✔. An entry of type `To` is accepted and stored
as `ToCc` with `includeCcHeader: false` ✔.

There are no other header fields. Probed and rejected as unreadable (`http-message-not-readable`) ✔: groups
`MultiCcComparator`, `MultiBccComparator`, `MultiReplyToComparator`, `MultiSenderComparator`,
`MultiListIdComparator`, `MultiReturnPathComparator`, `MultiBodyComparator`, `MultiHeaderComparator` (also
with a `headerName`/`name`/`header` key), `MultiToCcComparator`; leaves `HasAttachment`, `Attachment`,
`BodyContains`, `Body`, `Spam`, `HeaderComparator`. That error comes from settings-bff's own JSON model, so it
only knows the types listed here, whatever the backend behind it may support. The web UI never
writes `operator: "AND"`, inverted groups with several entries, or inverted entries; the server accepts
and returns them unchanged.

The web UI cannot represent such groups ✔ (tested 2026-09-30): it shows every entry of every group as its own
row under the rule's "alle"/"eine" mode, ignoring `operator`. Saving the rule in the UI rewrites it into that
flat form (one single-entry `OR` group per row), which changes its meaning whenever a group combines its
entries differently from the rule: `AllOf [ Subject OR [YYY, WWW] ]` came back as `AllOf [ Subject YYY,
Subject WWW ]`, i.e. both required. Nothing in the UI warns about this.

### Actions

Executed in array order.

```ebnf
action        = { "type": "MoveToFolder", "folder": folder }                          (* ✔ *)
              | { "type": "CopyToFolder", "folder": folder }                          (* ✔ *)
              | { "type": "MarkSeen" }                                                (* ✔ mark as read *)
              | { "type": "DeleteMailImmediately" }                                   (* ◇ not to the trash *)
              | { "type": "CopyForward", "pending": BOOL, "receivers": [ STRING… ] }  (* ◇ *)
              | { "type": "TemplatedEmailNotify", "pending": BOOL, "pagers": [ STRING… ] }   (* ◇ *)
              | { "type": "Stop" } ;                    (* ✔ last; later rules do not see the mail *)

folder        = STRING ;                                (* full folder name, "/"-separated: "INBOX/News" *)
```

`pending: true` marks a forward/notify target that has not confirmed yet; the web UI sends `true` for new
forward targets and `false` for notifications. Legacy action types the web UI still reads but never writes
(◇, acceptance on create unknown): `MarkAsRead`, `Delete`, `Discard`, `ForwardTo`, `NotifyByEmail`,
`ExcludeFromSpamFilter`. The web UI shows a rule with a recipient condition and a forward action as read-only.

### Reads differ from writes

- `AllNewEmails` is stored and returned as `{ "type": "NewMail" }`, without `inverted`; a sent
  `inverted: true` is dropped silently, so the rule then matches all mail. ✔
- An `inverted` key on `AnyOf`/`AllOf` is dropped silently. ✔
- Older rules return the header value under `"from"`, `"to"` or `"subject"` instead of `"comparand"`, and
  may use entry type `"To"`. A `ToCc` entry sent without `includeCcHeader` is returned with
  `includeCcHeader: false`. ◇
- Otherwise a stored rule comes back exactly as sent, plus the read-only fields.

## Folders

`https://settings-cats.gmx.net`; the same bearer token and headers as above, and `X-Request-Id` is required.

```
GET /mailbox/primary/folder?absoluteURI=false                                        ✔
Accept:       application/vnd.ui.trinity.folders-v5+json
Content-Type: application/vnd.ui.trinity.folders-v5+json      (required on the GET, too)
```

Other `Accept` types answer 406, or 403 "masked by CATS".

```ebnf
folder-tree   = { "folders": [ node… ], "_links": … } ;
node          = { "folderIdentifier": STRING, "quota": { … },
                  "attribute": attribute, "folders": [ node… ], "_links": … } ;
attribute     = { "folderName": STRING,
                  [ "folderFullname": STRING, ]         (* absent on virtual folders *)
                  "folderType": "INBOX" | "SENT" | "DRAFTS" | "TRASH" | "SPAM" | "OUTBOX"
                              | "USER_DEFINED" | STRING,   (* virtual: "unread", "favorites", … *)
                  "flags": [ STRING… ], [ "systemFolder": BOOL, ] [ "pop3Include": BOOL, ]
                  "virtual": BOOL, "allowSubfolders": BOOL } ;
```

Create a folder (◇, from the web app, not used by gmxf):
`POST /mailbox/primary/folderupdate?absoluteURI=false`, `Content-Type: application/vnd.ui.trinity.folder.create+json`,
`Accept: application/vnd.ui.trinity.folder-v2+json`, body
`{ "folderName": STRING, "folderType": "USER_DEFINED", "pop3include": true, "expire": 1, "ignoreFolderFlags": false,
"ignoreFolderQuota": false, "flags": [] }`.

## Authentication

A webmail login session (cookies) is exchanged for a short-lived bearer token:

```
POST https://oauth2.gmx.net/token                                                   ✔
Authorization: Basic base64("gmxnet_mailset_root_live:*******")   (the settings app's client; placeholder secret)
Cookie:        <session cookies of the webmail login>
Origin:        https://mailset-root.gmx.net
User-Agent:    <browser user agent>
Content-Type:  application/x-www-form-urlencoded

grant_type=urn:mam:oauth:grant-type:shared_login_cookie
&scope=mail_mailbox_w webmailer_setting_r webmailer_setting_w mail_confix_w
&userAgentB64=<base64 of encodeURIComponent(User-Agent)>
```

Answer `200 { "access_token": STRING, "token_type": "Bearer", "expires_in": 7200, "scope": STRING }`.
Missing client authentication: `401 invalid_client`; missing `userAgentB64`: `400 invalid_request`; an
expired session: 400/401/403. The login that produces the session cookies is described in `re/NOTES.md`.

### Passkey login ✔

The login page's JSON flow (`https://login.gmx.net/rest/login-flow`, headers as for the password step; the
full login is in `re/NOTES.md`) offers passkeys next to the password:

1. `POST /identification` answers `nextStep: [{"type": "PASSWORD"}, {"type": "WEBAUTHN_START"}]`.
2. `POST /authentication/webauthn-start {"sessionId"}` answers
   `nextStep: [{"type": "PASSWORD"}, {"type": "WEBAUTHN_FINISH", "optionsJson": STRING}]`, where
   `optionsJson` is `{"publicKey": {challenge, rpId, timeout, userVerification, allowCredentials?}}` (base64url).
3. The browser runs `navigator.credentials.get` with it (origin `https://auth.gmx.net`).
4. `POST /authentication/webauthn-finish {"sessionId", "factorValue": STRING}` with `factorValue` the
   `PublicKeyCredential.toJSON()` string: `{id, rawId, type, response: {authenticatorData, clientDataJSON,
   signature, userHandle}, authenticatorAttachment, clientExtensionResults}`, all binaries base64url without
   padding. Success: `{"flowState": "SUCCESS", "redirectUrl"}`, continued as after a password. Rejected:
   `{"flowState": "ONGOING", "stepSuccess": false, "nextStep": [...]}`.

The server checks `clientDataJSON` exactly: an origin of `https://auth.gmx.net/` (trailing slash, as
`url::Url` prints it) is rejected; `{"type":"webauthn.get","challenge":…,"origin":"https://auth.gmx.net",
"crossOrigin":false}` is accepted.

## Errors

Mostly RFC 7807 problem objects:

```json
{ "type": "urn:problem:neo:method-argument-not-valid", "detail": "MethodArgumentNotValidException",
  "status": 400, "failures": { "request.httpUserAgent": "rejected value [null]" }, "requestid": "…" }
```

Seen: `urn:problem:neo:http-message-not-readable` (unknown `type`, or an entry that does not fit its group),
`method-argument-not-valid` (write without `User-Agent`), `urn:problem:mam:cats:request-not-acceptable`
(406, wrong media type), `urn:problem:mam:cats:access-forbidden` (403). A structurally invalid rule, such as
a nested group, gets a bare `400` with an empty body.
