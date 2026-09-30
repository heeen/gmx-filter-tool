# gmxf – GMX mail filter rules from the command line

`gmxf` lists, edits and syncs the server-side filter rules ("Filterregeln") of a **GMX** mailbox
(gmx.net). Rules live in a readable TOML file you can keep in git, edit in your editor, check, and apply
with a dry run, instead of clicking through the web settings.

```console
$ gmxf list
ID        NAME        ENABLED  RULE
1         newsletter  yes      from contains ["news@", "promotion", "noreply@video.example", +5 more] -> move INBOX/Newsletter, stop
5         club        yes      from contains "wiki@club-koeln.example" or to contains ["members@club-koeln.example", "board@club-koeln.example"] -> move INBOX/Club Köln, stop
2         chatter     no       from contains "@chatter.example" -> move INBOX/chatter, stop
b1e2c3d4  firmware    yes      subject contains "FirmwareUpdates" -> move INBOX/Firmware
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
- `gmxf export --simplify` (and `gmxf edit --simplify`) merges adjacent rules that do the same thing and
  drops repeated conditions, without changing which mail is affected. The merged rule keeps the first
  rule's id and name; apply with `--prune` so the merged-away rules are deleted.
- Rules gmxf cannot express exactly (rare, e.g. created by other clients) are exported as raw JSON
  (`condition_json`, `actions_json`) and written back unchanged.

### Editing in place

`gmxf edit` exports all rules to a temporary file and opens `$VISUAL`/`$EDITOR`. After you save, problems
are written into the file as comments and it reopens until it is valid; then the changes are listed and
applied after confirmation. Deleting a rule's block deletes the rule, saving an empty file aborts, and your
edits are kept on disk if anything fails. `gmxf edit RULE` edits a single rule (by id or name). If the rules
change on the server while you edit (e.g. in the web UI), the edit is refused instead of undoing that change.

### Sieve (experimental)

The same rules can be written in Sieve, the filter language of most IMAP servers: files ending in `.sieve`
(or `--format sieve`) work with `export`, `check`, `apply` and `edit`.

```sieve
require ["fileinto"];

# rule:[Newsletter]
if header :contains "from" ["newsletter", "news@"] {
    fileinto "INBOX/Newsletter";
    stop;
}
```

GMX does not run Sieve. gmxf translates the subset GMX rules can store and refuses the rest with a reason.
With `--split`, nested `if`, `elsif`/`else` and conditions nested too deep become several GMX rules.
Details and open questions: [docs/sieve.md](docs/sieve.md).

## Quick commands

| command | |
|---|---|
| `gmxf list` | rules with their conditions and actions; long lists shortened to `+N more`, long ids to 8 characters (`--long` shows everything) |
| `gmxf folders` | folder names usable in `move` / `copy` |
| `gmxf add NAME --when "from contains x@y.de" --then "move INBOX/X"` | create a rule (`--all`, `--no-stop`) |
| `gmxf extend RULE VALUE…` | add `from contains VALUE` conditions to an "any" rule (`--field`, `--when`, `--dry-run`) |
| `gmxf rename RULE NAME` | rename a rule |
| `gmxf move RULE POSITION` | move a rule to a 1-based position |
| `gmxf enable RULE` / `disable RULE` / `delete RULE` | |
| `gmxf export --raw` | the rules as the API's JSON, as a backup |

`RULE` is an id, any unambiguous start of one (as `gmxf list` shows it), or a rule name.

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
- `docs/` – [rules file grammar](docs/rules-file.md), its [Sieve form](docs/sieve.md) and the
  [wire format](docs/wire-format.md) of the GMX API.
- `re/` – reverse-engineering notes; `re/sanitize_har.py` strips secrets from browser HAR recordings.

## License

MIT, see [LICENSE](LICENSE).
