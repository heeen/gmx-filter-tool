# gmxf – GMX mail filter rules from the command line

`gmxf` lists, edits and syncs the server-side filter rules ("Filterregeln") of a **GMX** mailbox
(gmx.net). Rules live in a readable TOML file you can keep in git, edit in your editor, check, and apply
with a dry run, instead of clicking through the web settings.

```console
$ gmxf list
5                                      on  club-2   if from Contains "wiki@club-koeln.example" -> move INBOX/Club Köln, stop
2                                      off chatter  if from Contains "@chatter.example" -> move INBOX/chatter, stop
$ gmxf extend newsletter news@shop.example        # add a sender to an existing rule
$ gmxf edit newsletter                            # or edit it in $EDITOR, crontab -e style
```

> **Unofficial.** GMX offers no public API for this. gmxf talks to the same internal endpoints as the GMX
> webmail settings page, found by watching the web app (see [docs/wire-format.md](docs/wire-format.md)). It
> can break whenever GMX changes their web app. Only gmx.net accounts are supported.

## Install

Requires Rust 1.91 or newer (edition 2024).

```sh
cargo install --path crates/gmx-filter-cli     # installs the `gmxf` binary
```

## Log in

```sh
gmxf config --email you@gmx.de --password-cmd "rbw get gmx.net you@gmx.de"
gmxf login
```

- `password_cmd` is any shell command that prints your password; above it is the Bitwarden CLI `rbw`
  (`pass`, `secret-tool lookup …` or a `gpg -d` pipe work just as well). With it set, gmxf renews an expired
  session by itself; without it, `gmxf login` prompts, and you log in again when the session expires.
- `gmxf login --password-stdin` reads the password from stdin instead.
- The settings live in `~/.config/gmxf/config.toml`; `gmxf config` shows them.
- The webmail session (cookies) is stored in `~/.local/state/gmxf/session`, readable only by you. Your
  password is never stored by gmxf. `gmxf logout` removes the session.
- Accounts that need a captcha or second factor at login are not supported; gmxf reports that and stops.
- `--token-cmd` / `GMXF_TOKEN_CMD` bypasses all of this with a bearer token you provide.

## Rules file

```sh
gmxf export rules.toml          # all rules, in execution order
$EDITOR rules.toml
gmxf check rules.toml --online  # syntax and sanity checks (unknown folders, duplicates, unreachable rules, …)
gmxf apply rules.toml --dry-run # show what would change; exit status 2 if anything would
gmxf apply rules.toml           # apply after confirmation, then verify the server matches
```

```toml
[[rule]]
id = "1"                        # omit for new rules; without it, rules are matched by name
name = "Newsletter"
match = "any"                   # "any" or "all" of the conditions
from.contains = ["newsletter", "news@", "noreply@video.example"]
subject.starts-with = "[Newsletter]"
when = [{ size.gt = "5MB" }]    # size, priority, address book and all-new conditions
then = [{ move = "INBOX/Newsletter" }, "read"]
stop = true                     # later rules do not see the mail
```

Conditions cover everything GMX supports: `from`, `to`, `to-cc` and `subject` with `contains`, `is`,
`starts-with`, `ends-with` and their `not-` forms, message size, priority, "sender in address book" and "all
new mail". Actions: move, copy, mark as read, delete, forward, notify. The complete grammar and its meaning:
[docs/rules-file.md](docs/rules-file.md).

- File order is rule order; moving a block reorders the rules.
- `apply` keeps server rules that are missing from the file; `--prune` deletes them.
- Rules gmxf cannot express exactly (rare, e.g. created by other clients) are exported as raw JSON
  (`condition_json`, `actions_json`) and written back unchanged.

### Editing in place

`gmxf edit` exports all rules to a temporary file and opens `$VISUAL`/`$EDITOR`. After you save, problems
are written into the file as comments and it reopens until it is valid; then the changes are listed and
applied after confirmation. Deleting a rule's block deletes the rule, saving an empty file aborts, and your
edits are kept on disk if anything fails. `gmxf edit RULE` edits a single rule (by id or name). If the rules
change on the server while you edit (e.g. in the web UI), the edit is refused instead of undoing that change.

## Quick commands

| command | |
|---|---|
| `gmxf list` | rules with their conditions and actions |
| `gmxf folders` | folder names usable in `move` / `copy` |
| `gmxf add NAME --when "from contains x@y.de" --then "move INBOX/X"` | create a rule (`--all`, `--no-stop`) |
| `gmxf extend RULE VALUE…` | add `from contains VALUE` conditions to an "any" rule (`--field`, `--when`, `--dry-run`) |
| `gmxf rename ID NAME` | rename a rule |
| `gmxf move ID POSITION` | move a rule to a 1-based position |
| `gmxf enable ID` / `disable ID` / `delete ID` | |
| `gmxf export --raw` | the rules as the API's JSON, as a backup |

## Things to know

- Rules can be combined in ways the web UI does not offer (see the raw fallback above). The web UI then
  shows them simplified, and **saving such a rule in the web UI changes what it matches**.
- Creating folders is not supported; create them in the web UI.
- A forward target has to confirm by mail before forwarding starts.

## Development

```sh
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

- `crates/gmx-filter` – library: login and tokens, API client, rule model, rules file, diff/apply, checks.
- `crates/gmx-filter-cli` – the `gmxf` binary.
- `docs/` – [rules file grammar](docs/rules-file.md) and [wire format](docs/wire-format.md) of the GMX API.
- `re/` – reverse-engineering notes; `re/sanitize_har.py` strips secrets from browser HAR recordings.

## License

MIT
