# gmxf rules as Sieve (experimental)

A second form of the rules file ([rules-file.md](rules-file.md)) in Sieve (RFC 5228), the mail filter
language of most IMAP servers. `gmxf export`, `check`, `apply` and `edit` read and write it: files ending in
`.sieve`, or any file with `--format sieve`.

GMX does not run Sieve. gmxf translates the part of Sieve that GMX rules can store (see
[wire-format.md](wire-format.md)) and refuses the rest with a message that says what GMX cannot do. It is
experimental because some mappings rest on assumptions about GMX that are not verified yet; see the end.

```sieve
require ["fileinto", "copy", "imap4flags"];

# rule:[Newsletter]
# gmxf-id: 1
if anyof(header :contains "from" ["newsletter", "news@"],
         header :matches "subject" "[Newsletter]*") {
    fileinto "INBOX/Newsletter";
    addflag "\\Seen";
    stop;
}

# rule:[Old]
if allof(false, header :is "to" "old@gmx.de") {
    discard;
}
```

## The file

- **One top-level `if` per rule**, in rule order. Actions outside an `if` are refused.
- **`# rule:[name]`** on a line right above the `if` names the rule, as Roundcube writes it. Every rule
  needs one. If a name contains a line break, export writes `# gmxf-name: "…"` (a JSON string) instead.
- **`# gmxf-id: ID`** (optional) ties the rule to a server rule. Without an id, rules are matched by name.
  This is the same as `id` in the TOML file.
- **Disabled rules** have a leading `false`: `if allof(false, TEST)`, or `if false` for a disabled
  "all new mail" rule. Sieve interpreters read this correctly too.
- **`require`** has to list the extensions the file uses (`fileinto`, `copy`, `imap4flags`, `enotify`,
  `extlists`). Any other extension is refused.
- **`# gmxf-condition: JSON` / `# gmxf-actions: JSON`** carry raw API JSON for what this subset cannot say.
  The test is then `true` (`allof(false, true)` when disabled), and the block is `{ keep; }` as a
  placeholder. This is the counterpart of `condition_json`/`actions_json` in TOML.

## Tests

| Sieve | GMX condition |
|---|---|
| `true` | `AllNewEmails` |
| `header :is\|:contains\|:matches "from" KEYS` (also `address :all`) | `MultiFromComparator`, one entry per key |
| `header … "to" KEYS` | `MultiToComparator`, `ToCc` entries without `includeCcHeader` |
| `header … ["to", "cc"] KEYS` | the same with `includeCcHeader: true` |
| `header … "subject" KEYS` | `MultiSubjectComparator` |
| `:matches "x*"`, `"*x"`, `"*x*"` | `STARTS_WITH`, `ENDS_WITH`, `CONTAINS` (`\*`, `\?` are literal) |
| `size :over N` / `not size :over N` | `SizeOver`, `inverted` = smaller; `N` may end in K, M, G (×1024ⁿ) |
| `size :under N` | read as `not size :over N-1`; export never writes it |
| `header :is "x-gmxf-priority" "low\|normal\|high"` | `Priority` (a stand-in: GMX's priority test has no Sieve form) |
| `address :list "from" ":addrbook:default"` (RFC 6134) | `AnyContact` (the sender is in the address book) |
| `not T` | `inverted` on the group or leaf; over `anyof`/`allof` by De Morgan |
| `anyof(…)` / `allof(…)` | `AnyOf` / `AllOf` |

A key list is an "or": `header :contains "from" ["a", "b"]` is one group with operator `OR`. Tests on the
same header inside `anyof` join into one group; inside a nested `allof` they join into an `AND` group. A
top-level `allof` stays `AllOf`, which is how the web UI writes "all of these".

GMX allows one level of `AnyOf`/`AllOf` above the header groups and leaves. For example,
`anyof(allof(header :is "from" "a", header :is "from" "b"), header :is "subject" "s")` fits: the inner
`allof` becomes one `AND` group. But `anyof(allof(<from>, <subject>), …)` does not fit, and needs `--split`.

**Refused:** `:regex`, `:count`, `:value`, `:comparator` other than `"i;ascii-casemap"`, `address
:localpart`/`:domain`/…, headers other than from, to, to+cc and subject (`cc` alone too), `exists`,
`envelope`, `body`, and `not true`.

## Actions

| Sieve | GMX action |
|---|---|
| `fileinto "INBOX/X"` | `MoveToFolder` (full folder name as in `gmxf folders`) |
| `fileinto :copy "INBOX/X"` | `CopyToFolder` |
| `addflag "\\Seen"` (or `setflag`) | `MarkSeen` |
| `discard` | `DeleteMailImmediately` |
| `redirect :copy "a@b.de"` | `CopyForward`; adjacent ones become one action with several receivers |
| `notify "mailto:a@b.de,c@d.de"` (RFC 5435) | `TemplatedEmailNotify` with those addresses |
| `stop` (last) | `Stop` |

A new forward or notify target still has to confirm by mail; targets that already exist keep their state.
**Refused:** plain `redirect` (GMX always keeps the mail), `keep`, `reject`, `vacation`, `removeflag`, flags
other than `\Seen`, `fileinto :create`/`:flags`, and anything after `stop`.

## Export

`gmxf export rules.sieve` writes every rule in the forms above, and then reads each rule back. If the
condition or the actions would not come back exactly the same, only that part is written as
`# gmxf-condition`/`# gmxf-actions` JSON. So an export applied again is always "no changes". Shapes that
fall back to JSON include:

- an `AND` group at the top level (it would read back as `AllOf`);
- a single header entry that is itself inverted;
- `Stop` in the middle of the actions;
- legacy action types;
- two separate forward actions next to each other.

## `--split`

GMX rules cannot nest, have no `else`, and allow only one level of `anyof`/`allof`. With `--split`, gmxf
compiles such a Sieve rule into several GMX rules named `NAME #1`, `NAME #2`, …, in order:

- **Nested `if`:** actions before, inside and after a nested `if` become separate rules. An inner rule gets
  the outer test AND its own test. A `stop` inside makes that rule stop, and GMX's `Stop` then keeps the
  later pieces from running.
- **`elsif`/`else`:** each branch gets the negated tests of the branches before it.
- **Conditions nested too deep** are expanded into an OR of ANDs, with one rule per AND. If the actions end
  in `stop`, the first matching rule ends processing. If they don't, the rules are made non-overlapping so
  that the actions run once.

`check` and `apply` print how a rule was split. A split rule cannot carry `# gmxf-id` (the pieces are matched
by their generated names), and more than 16 pieces from one rule is refused. The split is one-way: export
shows the pieces as separate rules.

## Open questions

- **Rules without `stop`:** splitting a rule whose pieces don't stop relies on later rules still running.
  The web UI suggests they do: `Stop` is only added by its option "Keine andere Filterregel auf diese
  E-Mails anwenden". Untested: whether a later rule sees a message an earlier rule already moved, and what
  two moves in a row do (last wins, or two copies). Check the result on a test message.
- **`["to", "cc"]`:** `includeCcHeader: true` has so far only been seen on rules made by older web UIs.
- **`size :under N`:** reading it as "not over N-1" assumes that GMX's "smaller than" is strict.
