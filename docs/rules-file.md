# gmxf rules file (format v2)

`gmxf export` writes it, `gmxf check` validates it, `gmxf apply` and `gmxf edit` make the server match it.
It is TOML (1.1). This document is the complete grammar, its meaning, and how it maps to what GMX stores.
An experimental Sieve form of the same file is described in [sieve.md](sieve.md).

## Grammar

EBNF over TOML values. `"…"` is a literal, `STRING` any TOML string, `UINT` a non-negative TOML integer.
Every table rejects keys not listed here.

```ebnf
file          = { rule } ;                               (* only [[rule]] tables at top level *)

rule          = "[[rule]]"
                [ "id"     "=" STRING ]                  (* server rule id; omit for new rules *)
                  "name"   "=" STRING
                [ "active" "=" BOOL ]                    (* default true *)
                [ "match"  "=" ( '"any"' | '"all"' ) ]   (* default "any" *)
                condition-part
                action-part ;

condition-part = rows | "condition_json" "=" JSON-STRING ;
rows          = { header-key } [ "when" "=" "[" row { "," row } [ "," ] "]" ] ;
                (* at least one row in total, from header keys and/or `when` *)

header-key    = field "." operator "=" values ;
field         = "from" | "to" | "to-cc" | "subject" ;
operator      = "contains" | "not-contains" | "is" | "is-not"
              | "starts-with" | "not-starts-with" | "ends-with" | "not-ends-with" ;
values        = STRING | "[" STRING { "," STRING } [ "," ] "]" ;    (* non-empty *)

row           = '"all-new"'
              | "{" field "." operator "=" STRING "}"
              | "{" "size" "." ( "gt" | "lt" ) "=" size "}"
              | "{" "priority" "." ( "is" | "is-not" ) "=" level "}"
              | "{" "contact" "=" ( '"saved"' | '"not-saved"' ) "}" ;
size          = UINT                                     (* bytes *)
              | '"' DIGITS [ "B" | "KB" | "MB" ] '"' ;   (* unit case-insensitive, no space, 1 KB = 1024 B *)
level         = '"low"' | '"normal"' | '"high"' ;

action-part   = "then" "=" "[" action { "," action } [ "," ] "]" [ "stop" "=" BOOL ]   (* stop: default true *)
              | "actions_json" "=" JSON-STRING ;         (* no `stop` next to it *)
action        = '"read"' | '"delete"'
              | "{" ( "move" | "copy" ) "=" folder "}"
              | "{" ( "forward" | "notify" ) "=" address "}" ;
folder        = STRING ;                                 (* full name as in `gmxf folders`, e.g. "INBOX/News" *)
address       = STRING ;
```

`JSON-STRING` is a TOML string holding API JSON (see [wire-format.md](wire-format.md)); export writes it as a
`'''…'''` multi-line literal.

Example:

```toml
[[rule]]
id = "1"
name = "Newsletter"
match = "any"
from.contains = ["newsletter", "news@", "noreply@video.example"]
subject.starts-with = "[Newsletter]"
when = [{ size.gt = "5MB" }]
then = [{ move = "INBOX/Newsletter" }, "read"]
stop = true
```

## Meaning

**Rows.** Every value of a header key is one row, and so is every `when` entry; the order of rows does not
matter. `match = "any"`: the rule applies when at least one row holds; `"all"`: when every row holds. With a
single row `match` is irrelevant (export omits it).

| row | holds when |
|---|---|
| `from.contains = "x"` | the From header contains `x` (other operators: equals, starts / ends with) |
| `from.not-contains = "x"` | it does not (likewise `is-not`, `not-starts-with`, `not-ends-with`) |
| `to.…` | the recipient (To) header …, as the current web UI writes it |
| `to-cc.…` | To or Cc (`includeCcHeader`, written by older web UIs) |
| `subject.…` | the Subject header … |
| `size.gt` / `size.lt` | the message is larger / smaller than the size |
| `priority.is` / `is-not` | the message priority is / is not the level |
| `contact = "saved"` / `"not-saved"` | the sender is / is not in the address book |
| `"all-new"` | always (every new message) |

Beware: several negated values under `match = "any"` (`from.not-contains = ["a", "b"]`) mean "not a **or**
not b", which almost every message satisfies. Use `match = "all"` for "neither a nor b".

**Actions** run in the listed order: `move` and `copy` to a folder, `read` (mark as read), `delete`
(immediately, not to the trash), `forward` (a copy to an address), `notify` (a notification mail to an
address). A new `forward` target has to confirm by mail before it takes effect; targets that already exist
on the server keep their confirmation state when the rule is edited. `stop = true` (the default) keeps
later rules from seeing the message.

**The file as a whole.** File order is rule order. A rule is matched to the server by `id`; without one, by
its `name` (which must then be unique on the server and in the file). `gmxf apply` creates, updates,
enables/disables and reorders to match; server rules missing from the file are kept unless `--prune`.
`gmxf edit` (all rules) prunes: deleting a block deletes the rule.

**Raw fallback.** A server rule the rows above cannot express exactly is exported with `condition_json` and/or
`actions_json` and a comment; it is compared and written back verbatim. `check` and `edit` report problems
(unknown folders, bad addresses, duplicate names, unreachable or duplicate rules, …) with the rule number.

## One-line syntax (`gmxf add --when/--then`, `gmxf extend --when`)

The same rows and actions as single strings, for the shell:

```ebnf
when-spec = "all-new"
          | field WS operator WS TEXT                    (* TEXT: rest of the line, trimmed *)
          | "size" WS ( "gt" | "lt" ) WS DIGITS [ "B" | "KB" | "MB" ]
          | "priority" WS ( "is" | "is-not" ) WS ( "low" | "normal" | "high" )
          | "contact" WS ( "saved" | "not-saved" ) ;
then-spec = "read" | "delete" | ( "move" | "copy" | "forward" | "notify" ) WS TEXT ;
```

`gmxf add NAME --when … [--when …] --then … [--all] [--no-stop]`, and
`gmxf extend RULE VALUE… [--field from|to|to-cc|subject]` for adding `contains` rows.

## Mapping to the wire format

The API grammar is in [wire-format.md](wire-format.md). How the file maps onto it:

- A single row becomes a single leaf; `match = "all"` over several rows becomes `AllOf`; `"any"` over
  several non-negated rows of one header field becomes one `Multi…Comparator` (operator `OR`); any other
  `"any"` becomes `AnyOf`. This is what the web UI does.
- A header row is a one-entry `Multi…Comparator`; `not-…` operators set its outer `inverted`, the entry's own
  `inverted` stays `false`. `to` writes `ToCc` without `includeCcHeader` (stored as `false`), `to-cc` with `true`.
- `size.lt` is `SizeOver` with `inverted: true`; `contact = "not-saved"` is `AnyContact` with `inverted: true`.
- `read` = `MarkSeen`, `delete` = `DeleteMailImmediately`, `forward` = `CopyForward`, `notify` =
  `TemplatedEmailNotify`; `stop = true` appends `Stop`.
- Accepted by the server but only reachable through `*_json`: `operator: "AND"` groups, inverted groups
  with several entries (`NOT (a OR b)`), inverted header entries, forwards/notifications to several
  addresses, and legacy action types (`MarkAsRead`, `Delete`, `Discard`, `ForwardTo`, `NotifyByEmail`,
  `ExcludeFromSpamFilter`) that the web UI still reads.
