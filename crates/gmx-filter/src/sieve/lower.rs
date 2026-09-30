//! Sieve commands to GMX rules: what each test and action means, and whether GMX can store it.

use std::collections::HashSet;

use super::{
    ADDRESS_BOOK, EXTENSIONS, Group, Kind, PRIORITY_HEADER, SieveImport, entry_inverted,
    leaf_inverted,
    syntax::{Arg, Command, Pos, Test},
};
use crate::{
    Action, Comparator, Condition, DesiredRule, KnownAction, KnownCondition, KnownHeaderCondition,
    Operator, PriorityLevel,
};

type Res<T> = std::result::Result<T, String>;

/// More rules than this from one Sieve rule is almost certainly a mistake.
const SPLIT_LIMIT: usize = 16;

fn at<T>(pos: Pos, msg: impl std::fmt::Display) -> Res<T> {
    Err(format!("{pos}: {msg}"))
}

/// A Sieve test with its meaning attached, before it is fitted to GMX's shape.
#[derive(Debug, Clone, PartialEq)]
enum Expr {
    True,
    False,
    Not(Box<Expr>),
    Any(Vec<Expr>),
    All(Vec<Expr>),
    /// One header comparison, never inverted.
    Header(KnownHeaderCondition),
    /// A size, priority or contact condition.
    Leaf(KnownCondition),
}

impl Expr {
    fn not(self) -> Self {
        Self::Not(Box::new(self))
    }

    fn all(mut parts: Vec<Self>) -> Self {
        match parts.len() {
            0 => Self::True,
            1 => parts.remove(0),
            _ => Self::All(parts),
        }
    }
}

/// Removes `true`/`false` from inside `anyof`/`allof` and double negations; the result is `True`,
/// `False`, or free of both.
fn fold(e: Expr) -> Expr {
    match e {
        Expr::Not(x) => match fold(*x) {
            Expr::True => Expr::False,
            Expr::False => Expr::True,
            Expr::Not(y) => *y,
            y => y.not(),
        },
        Expr::Any(xs) => {
            let xs: Vec<Expr> = xs
                .into_iter()
                .map(fold)
                .filter(|x| *x != Expr::False)
                .collect();
            if xs.contains(&Expr::True) {
                Expr::True
            } else if xs.is_empty() {
                Expr::False
            } else {
                Expr::Any(xs)
            }
        }
        Expr::All(xs) => {
            let xs: Vec<Expr> = xs
                .into_iter()
                .map(fold)
                .filter(|x| *x != Expr::True)
                .collect();
            if xs.contains(&Expr::False) {
                Expr::False
            } else if xs.is_empty() {
                Expr::True
            } else {
                Expr::All(xs)
            }
        }
        e => e,
    }
}

/// A condition in GMX's terms; valid to send only if [`to_condition`] accepts it.
#[derive(Debug, Clone)]
enum Node {
    New,
    Group(Group),
    Leaf(KnownCondition),
    Any(Vec<Node>),
    All(Vec<Node>),
}

fn negate(node: Node) -> Option<Node> {
    Some(match node {
        // the server drops `inverted` on AllNewEmails
        Node::New => return None,
        Node::Group(mut g) => {
            g.inverted = !g.inverted;
            Node::Group(g)
        }
        Node::Leaf(mut c) => {
            let inverted = leaf_inverted(&mut c)?;
            *inverted = !*inverted;
            Node::Leaf(c)
        }
        // De Morgan: the server drops `inverted` on AnyOf/AllOf
        Node::Any(cs) => Node::All(cs.into_iter().map(negate).collect::<Option<_>>()?),
        Node::All(cs) => Node::Any(cs.into_iter().map(negate).collect::<Option<_>>()?),
    })
}

/// Fits a folded expression to GMX's shapes. Tests on one header under `anyof` (and, below the top,
/// `allof`) become one `Multi*` group; a top-level `allof` stays `AllOf`, as the web UI writes it.
fn node(e: Expr, top: bool) -> Res<Node> {
    Ok(match e {
        Expr::True => Node::New,
        Expr::False => return Err("the condition can never match".into()),
        Expr::Header(h) => Node::Group(Group {
            kind: Kind::of(&h),
            op: Operator::Or,
            inverted: false,
            entries: vec![h],
        }),
        Expr::Leaf(c) => Node::Leaf(c),
        Expr::Not(x) => negate(node(*x, top)?).ok_or("`not true` can never match")?,
        Expr::Any(xs) => combine(xs, &Operator::Or, true)?,
        Expr::All(xs) => combine(xs, &Operator::And, !top)?,
    })
}

fn combine(xs: Vec<Expr>, op: &Operator, merge: bool) -> Res<Node> {
    let mut nodes: Vec<Node> = Vec::new();
    for x in xs {
        match (node(x, false)?, op) {
            (Node::Any(cs), Operator::Or) | (Node::All(cs), Operator::And) => nodes.extend(cs),
            (n, _) => nodes.push(n),
        }
    }
    if merge {
        let (joined, any) = join_fields(nodes, op);
        nodes = joined;
        if any && nodes.len() == 1 {
            return Ok(nodes.remove(0));
        }
    }
    Ok(match op {
        Operator::And => Node::All(nodes),
        _ => Node::Any(nodes),
    })
}

/// The entries of `g` joined with `op` into a bigger group, if that means the same.
fn joinable(g: &Group, op: &Operator) -> Option<Vec<KnownHeaderCondition>> {
    if let [single] = g.entries.as_slice() {
        let mut e = single.clone();
        *entry_inverted(&mut e) ^= g.inverted;
        Some(vec![e])
    } else {
        (g.op == *op && !g.inverted).then(|| g.entries.clone())
    }
}

/// Joins the groups among `nodes` that test the same header into one group with `op`, placed where
/// the first of them was; a group without partner stays as it is. Also says whether anything joined.
fn join_fields(nodes: Vec<Node>, op: &Operator) -> (Vec<Node>, bool) {
    let kinds: Vec<Option<Kind>> = nodes
        .iter()
        .map(|n| match n {
            Node::Group(g) => joinable(g, op).map(|_| g.kind),
            _ => None,
        })
        .collect();
    let partnered = |k: Kind| kinds.iter().filter(|x| **x == Some(k)).count() > 1;
    let mut out: Vec<Node> = Vec::new();
    let mut slots: Vec<(Kind, usize)> = Vec::new();
    let mut joined = false;
    for (n, kind) in nodes.into_iter().zip(&kinds) {
        let (Node::Group(g), Some(kind)) = (&n, kind.filter(|k| partnered(*k))) else {
            out.push(n);
            continue;
        };
        let entries = joinable(g, op).unwrap_or_default();
        if let Some(&(_, i)) = slots.iter().find(|(k, _)| *k == kind)
            && let Node::Group(target) = &mut out[i]
        {
            target.entries.extend(entries);
            joined = true;
        } else {
            slots.push((kind, out.len()));
            out.push(Node::Group(Group {
                kind,
                op: op.clone(),
                inverted: false,
                entries,
            }));
        }
    }
    (out, joined)
}

/// The condition to send, or `None` when it nests deeper than GMX allows (one `AnyOf`/`AllOf` over
/// groups and leaves).
fn to_condition(node: Node) -> Option<Condition> {
    fn leaf(n: Node) -> Option<Condition> {
        match n {
            Node::Group(g) => Some(Condition::Known(g.into_condition())),
            Node::Leaf(c) => Some(Condition::Known(c)),
            _ => None,
        }
    }
    let known = match node {
        Node::New => KnownCondition::AllNewEmails { inverted: false },
        Node::Any(cs) => KnownCondition::AnyOf {
            conditions: cs.into_iter().map(leaf).collect::<Option<_>>()?,
        },
        Node::All(cs) => KnownCondition::AllOf {
            conditions: cs.into_iter().map(leaf).collect::<Option<_>>()?,
        },
        n => return leaf(n),
    };
    Some(Condition::Known(known))
}

// --- splitting: disjunctive normal form over single comparisons ---

#[derive(Debug, Clone, PartialEq)]
struct Lit {
    /// `Expr::Header` or `Expr::Leaf`, not inverted.
    atom: Expr,
    negated: bool,
}

type Cube = Vec<Lit>;

fn literal(e: &Expr, negated: bool) -> Lit {
    let mut atom = e.clone();
    let mut negated = negated;
    if let Expr::Leaf(c) = &mut atom
        && let Some(inverted) = leaf_inverted(c)
    {
        negated ^= std::mem::take(inverted);
    }
    Lit { atom, negated }
}

fn complement(l: &Lit) -> Lit {
    Lit {
        atom: l.atom.clone(),
        negated: !l.negated,
    }
}

/// `a ∧ b`, or `None` if it contains a literal and its complement.
fn conjoin(a: &Cube, b: &Cube) -> Option<Cube> {
    let mut out = a.clone();
    for l in b {
        if out.contains(&complement(l)) {
            return None;
        }
        if !out.contains(l) {
            out.push(l.clone());
        }
    }
    Some(out)
}

/// `e` (negated if `negated`) as an OR of ANDs of literals.
fn dnf(e: &Expr, negated: bool) -> Res<Vec<Cube>> {
    Ok(match (e, negated) {
        (Expr::True, false) | (Expr::False, true) => vec![Vec::new()],
        (Expr::True, true) | (Expr::False, false) => Vec::new(),
        (Expr::Not(x), n) => dnf(x, !n)?,
        (Expr::Any(xs), false) | (Expr::All(xs), true) => {
            let mut out = Vec::new();
            for x in xs {
                out.extend(dnf(x, negated)?);
            }
            out
        }
        (Expr::All(xs), false) | (Expr::Any(xs), true) => {
            let mut out = vec![Vec::new()];
            for x in xs {
                let terms = dnf(x, negated)?;
                out = out
                    .iter()
                    .flat_map(|a| terms.iter().filter_map(|b| conjoin(a, b)))
                    .collect();
                if out.len() > SPLIT_LIMIT * 4 {
                    return Err(format!(
                        "the condition expands into too many rules (more than {SPLIT_LIMIT})"
                    ));
                }
            }
            out
        }
        (atom, n) => vec![vec![literal(atom, n)]],
    })
}

/// `p` without the mail `r` matches, as cubes that do not overlap.
fn sharp(p: &Cube, r: &Cube) -> Vec<Cube> {
    if r.iter().any(|l| p.contains(&complement(l))) {
        return vec![p.clone()];
    }
    let missing: Vec<&Lit> = r.iter().filter(|l| !p.contains(l)).collect();
    (0..missing.len())
        .map(|j| {
            let mut cube = p.clone();
            cube.extend(missing[..j].iter().map(|l| (*l).clone()));
            cube.push(complement(missing[j]));
            cube
        })
        .collect()
}

/// The same mail as `cubes`, but each mail in exactly one cube, so actions without `stop` run once.
fn disjoint(cubes: &[Cube]) -> Vec<Cube> {
    let mut out = Vec::new();
    for (i, c) in cubes.iter().enumerate() {
        let mut parts = vec![c.clone()];
        for prev in &cubes[..i] {
            parts = parts.iter().flat_map(|p| sharp(p, prev)).collect();
        }
        out.extend(parts);
    }
    out
}

fn cube_condition(cube: &Cube) -> Condition {
    let mut parts: Vec<Condition> = cube
        .iter()
        .map(|l| {
            Condition::Known(match &l.atom {
                Expr::Header(h) => Group {
                    kind: Kind::of(h),
                    op: Operator::Or,
                    inverted: l.negated,
                    entries: vec![h.clone()],
                }
                .into_condition(),
                Expr::Leaf(c) => {
                    let mut c = c.clone();
                    if let Some(inverted) = leaf_inverted(&mut c) {
                        *inverted = l.negated;
                    }
                    c
                }
                other => unreachable!("not a literal: {other:?}"),
            })
        })
        .collect();
    match parts.len() {
        0 => Condition::Known(KnownCondition::AllNewEmails { inverted: false }),
        1 => parts.remove(0),
        _ => Condition::Known(KnownCondition::AllOf { conditions: parts }),
    }
}

// --- rules ---

/// What the comments above a rule say.
#[derive(Default)]
struct Meta {
    name: Option<String>,
    id: Option<String>,
    condition: Option<Condition>,
    actions: Option<Vec<Action>>,
}

impl Meta {
    fn of(comments: &[String]) -> Res<Self> {
        let mut meta = Self::default();
        for c in comments {
            let c = c.trim();
            let json = |what: &str, v: &str| format!("`gmxf-{what}`: {v}");
            if let Some(name) = c.strip_prefix("rule:[").and_then(|n| n.strip_suffix(']')) {
                meta.name = Some(name.to_owned());
            } else if let Some(v) = c.strip_prefix("gmxf-name:") {
                meta.name =
                    Some(serde_json::from_str(v.trim()).map_err(|e| json("name", &e.to_string()))?);
            } else if let Some(v) = c.strip_prefix("gmxf-id:") {
                meta.id = Some(v.trim().to_owned());
            } else if let Some(v) = c.strip_prefix("gmxf-condition:") {
                meta.condition =
                    Some(serde_json::from_str(v).map_err(|e| json("condition", &e.to_string()))?);
            } else if let Some(v) = c.strip_prefix("gmxf-actions:") {
                meta.actions =
                    Some(serde_json::from_str(v).map_err(|e| json("actions", &e.to_string()))?);
            } else if c.starts_with("gmxf-") {
                return Err(format!(
                    "unknown `{c}`; known are gmxf-name, gmxf-id, gmxf-condition, gmxf-actions"
                ));
            }
        }
        Ok(meta)
    }
}

/// A run of actions and the condition under which it runs.
struct Piece {
    guard: Vec<Expr>,
    actions: Vec<Action>,
}

struct Lowering {
    requires: HashSet<String>,
    split: bool,
    notes: Vec<String>,
}

pub(super) fn lower(commands: &[Command], split: bool) -> Res<SieveImport> {
    let mut l = Lowering {
        requires: HashSet::new(),
        split,
        notes: Vec::new(),
    };
    for c in commands.iter().filter(|c| c.name == "require") {
        let [Arg::Strings(exts, pos)] = c.args.as_slice() else {
            return at(c.pos, "`require` takes a string or a list of strings");
        };
        for ext in exts {
            if !EXTENSIONS.contains(&ext.as_str()) {
                return at(
                    *pos,
                    format!("GMX filters cannot use the `{ext}` extension"),
                );
            }
            l.requires.insert(ext.clone());
        }
    }
    let mut rules = Vec::new();
    let mut i = 0;
    while let Some(c) = commands.get(i) {
        match c.name.as_str() {
            "require" => i += 1,
            "if" => {
                let end = chain_end(commands, i);
                rules.extend(l.rule(&commands[i..end])?);
                i = end;
            }
            "elsif" | "else" => return at(c.pos, format!("`{}` without `if`", c.name)),
            other => {
                return at(
                    c.pos,
                    format!(
                        "`{other}` outside a rule: put it in `if … {{ }}` with a `# rule:[name]` line above"
                    ),
                );
            }
        }
    }
    Ok(SieveImport {
        rules,
        notes: l.notes,
    })
}

/// The index after the `if` at `start` and its `elsif`/`else` branches.
fn chain_end(commands: &[Command], start: usize) -> usize {
    let mut end = start + 1;
    while let Some(c) = commands.get(end)
        && (c.name == "elsif" || c.name == "else")
    {
        end += 1;
        if c.name == "else" {
            break;
        }
    }
    end
}

/// A leading `false` in the rule's test (`allof(false, …)`, or just `false`) marks it disabled.
fn strip_disabled(test: Expr) -> (bool, Expr) {
    match test {
        Expr::False => (false, Expr::True),
        Expr::All(mut xs) if xs.len() > 1 && xs[0] == Expr::False => {
            xs.remove(0);
            (false, Expr::all(xs))
        }
        t => (true, t),
    }
}

fn stops(actions: &[Action]) -> bool {
    matches!(actions.last(), Some(Action::Known(KnownAction::Stop)))
}

/// Adjacent `redirect :copy` commands are one forward action with several receivers.
fn push_action(actions: &mut Vec<Action>, a: Action) {
    if let Action::Known(KnownAction::CopyForward { receivers: new, .. }) = &a
        && let Some(Action::Known(KnownAction::CopyForward { receivers, .. })) = actions.last_mut()
    {
        receivers.extend(new.iter().cloned());
        return;
    }
    actions.push(a);
}

impl Lowering {
    fn need(&self, ext: &str, pos: Pos) -> Res<()> {
        if self.requires.contains(ext) {
            Ok(())
        } else {
            at(pos, format!("this needs `require \"{ext}\";` at the top"))
        }
    }

    fn rule(&mut self, chain: &[Command]) -> Res<Vec<DesiredRule>> {
        let head = &chain[0];
        let meta = Meta::of(&head.comments).or_else(|e| at(head.pos, e))?;
        let Some(name) = meta.name.clone() else {
            return at(
                head.pos,
                "a rule needs its name in a `# rule:[name]` line right above the `if`",
            );
        };
        self.rule_body(chain, meta, &name)
            .map_err(|e| format!("rule {name:?}: {e}"))
    }

    fn rule_body(&mut self, chain: &[Command], meta: Meta, name: &str) -> Res<Vec<DesiredRule>> {
        let head = &chain[0];
        let (active, test) = strip_disabled(self.if_test(head)?);
        if chain.len() > 1 && !self.split {
            return at(
                chain[1].pos,
                format!(
                    "`{}` needs --split (GMX rules have no else branch)",
                    chain[1].name
                ),
            );
        }

        if meta.condition.is_some() || meta.actions.is_some() {
            return self
                .raw_rule(head, meta, name, active, test)
                .map(|r| vec![r]);
        }

        let mut pieces = Vec::new();
        self.chain(chain, &[], Some(test), &mut pieces)?;
        let mut parts: Vec<(Condition, Vec<Action>)> = Vec::new();
        for p in pieces {
            let guard = fold(Expr::all(p.guard));
            if guard == Expr::False {
                return Err("a branch of this rule can never run".into());
            }
            if let Some(c) = to_condition(node(guard.clone(), true)?) {
                parts.push((c, p.actions));
            } else if !self.split {
                return Err(
                    "the condition nests deeper than GMX allows (one anyof/allof over single tests); \
                     simplify it or use --split"
                        .into(),
                );
            } else {
                let cubes = dnf(&guard, false)?;
                // without `stop`, overlapping rules would run the actions twice
                let cubes = if stops(&p.actions) {
                    cubes
                } else {
                    disjoint(&cubes)
                };
                parts.extend(cubes.iter().map(|c| (cube_condition(c), p.actions.clone())));
            }
            if parts.len() > SPLIT_LIMIT {
                return Err(format!("splits into more than {SPLIT_LIMIT} rules"));
            }
        }
        if parts.is_empty() {
            return at(head.pos, "the rule has no actions");
        }
        let split = parts.len() > 1;
        if split {
            if meta.id.is_some() {
                return Err("`gmxf-id` cannot be used on a rule that splits into several".into());
            }
            let chained = if parts.iter().all(|(_, a)| stops(a)) {
                ""
            } else {
                "; some have no `stop`, which relies on GMX letting later rules see the mail (unverified)"
            };
            self.notes.push(format!(
                "rule {name:?}: split into {} rules \"{name} #1\"…\"{name} #{}\"{chained}",
                parts.len(),
                parts.len()
            ));
        }
        Ok(parts
            .into_iter()
            .enumerate()
            .map(|(k, (condition, actions))| {
                let name = if split {
                    format!("{name} #{}", k + 1)
                } else {
                    name.to_owned()
                };
                DesiredRule::from_parts(meta.id.clone(), name, active, condition, actions)
            })
            .collect())
    }

    /// A rule with `gmxf-condition` and/or `gmxf-actions`: raw JSON for what Sieve cannot say.
    fn raw_rule(
        &self,
        head: &Command,
        meta: Meta,
        name: &str,
        active: bool,
        test: Expr,
    ) -> Res<DesiredRule> {
        let condition = match meta.condition {
            Some(c) if test == Expr::True => c,
            Some(_) => {
                return at(
                    head.pos,
                    "with `gmxf-condition` the test must be `true` (or `allof(false, true)` when disabled)",
                );
            }
            None => to_condition(node(fold(test), true)?).ok_or(
                "the condition nests deeper than GMX allows; `gmxf-condition` rules cannot be split",
            )?,
        };
        let block = head.block.as_deref().unwrap_or_default();
        let actions = match meta.actions {
            Some(a) if block.iter().all(|c| c.name == "keep") => a,
            Some(_) => {
                return at(
                    head.pos,
                    "with `gmxf-actions` the block must be `{ keep; }`",
                );
            }
            None => {
                let mut pieces = Vec::new();
                self.block(block, &[], &mut pieces)?;
                match <[Piece; 1]>::try_from(pieces) {
                    Ok([p]) if p.guard.is_empty() => p.actions,
                    _ => return at(head.pos, "a rule with `gmxf-condition` cannot be split"),
                }
            }
        };
        Ok(DesiredRule::from_parts(
            meta.id,
            name.to_owned(),
            active,
            condition,
            actions,
        ))
    }

    fn if_test(&self, c: &Command) -> Res<Expr> {
        match (c.args.as_slice(), c.tests.as_slice(), &c.block) {
            ([], [t], Some(_)) => self.expr(t),
            (_, _, None) => at(c.pos, format!("`{}` needs a {{ block }}", c.name)),
            _ => at(c.pos, format!("`{}` takes exactly one test", c.name)),
        }
    }

    /// `if`/`elsif`/`else` under `guard`; `first` replaces the `if`'s own test.
    fn chain(
        &self,
        branches: &[Command],
        guard: &[Expr],
        mut first: Option<Expr>,
        out: &mut Vec<Piece>,
    ) -> Res<()> {
        let mut earlier = Vec::new();
        for b in branches {
            let mut g = guard.to_vec();
            g.extend(earlier.iter().cloned());
            if b.name != "else" {
                let t = match first.take() {
                    Some(t) => t,
                    None => self.if_test(b)?,
                };
                g.push(t.clone());
                earlier.push(t.not());
            } else if !b.args.is_empty() || !b.tests.is_empty() {
                return at(b.pos, "`else` takes no test");
            }
            let Some(block) = &b.block else {
                return at(b.pos, format!("`{}` needs a {{ block }}", b.name));
            };
            self.block(block, &g, out)?;
        }
        Ok(())
    }

    fn block(&self, commands: &[Command], guard: &[Expr], out: &mut Vec<Piece>) -> Res<()> {
        let mut actions = Vec::new();
        let flush = |actions: &mut Vec<Action>, out: &mut Vec<Piece>| {
            if !actions.is_empty() {
                out.push(Piece {
                    guard: guard.to_vec(),
                    actions: std::mem::take(actions),
                });
            }
        };
        let mut i = 0;
        while let Some(c) = commands.get(i) {
            match c.name.as_str() {
                "if" => {
                    if !self.split {
                        return at(c.pos, "a nested `if` needs --split (GMX rules cannot nest)");
                    }
                    flush(&mut actions, out);
                    let end = chain_end(commands, i);
                    self.chain(&commands[i..end], guard, None, out)?;
                    i = end;
                    continue;
                }
                "elsif" | "else" => return at(c.pos, format!("`{}` without `if`", c.name)),
                "stop" => {
                    if !c.args.is_empty() || !c.tests.is_empty() || c.block.is_some() {
                        return at(c.pos, "`stop` takes nothing");
                    }
                    actions.push(Action::Known(KnownAction::Stop));
                    flush(&mut actions, out);
                    if let Some(next) = commands.get(i + 1) {
                        return at(next.pos, "never runs: it comes after `stop`");
                    }
                    return Ok(());
                }
                _ => push_action(&mut actions, self.action(c)?),
            }
            i += 1;
        }
        flush(&mut actions, out);
        Ok(())
    }

    fn action(&self, c: &Command) -> Res<Action> {
        if !c.tests.is_empty() || c.block.is_some() {
            return at(c.pos, format!("`{}` takes no test or block", c.name));
        }
        let mut tags = Vec::new();
        let mut strings = Vec::new();
        for a in &c.args {
            match a {
                Arg::Tag(t, p) => tags.push((t.as_str(), *p)),
                Arg::Strings(s, _) => strings.push(s),
                Arg::Number(..) => return at(a.pos(), "unexpected number"),
            }
        }
        let single = |what: &str| match strings.as_slice() {
            [one] if one.len() == 1 => Ok(one[0].clone()),
            _ => at(c.pos, format!("`{}` takes one {what}", c.name)),
        };
        let only_tags = |allowed: &[&str]| match tags.iter().find(|(t, _)| !allowed.contains(t)) {
            Some((t, p)) => at(*p, format!("`:{t}` is not supported by GMX filters")),
            None => Ok(()),
        };
        let known = match c.name.as_str() {
            "fileinto" => {
                self.need("fileinto", c.pos)?;
                only_tags(&["copy"])?;
                let folder = single("folder")?;
                if let Some((_, p)) = tags.first() {
                    self.need("copy", *p)?;
                    KnownAction::CopyToFolder { folder }
                } else {
                    KnownAction::MoveToFolder { folder }
                }
            }
            "addflag" | "setflag" => {
                self.need("imap4flags", c.pos)?;
                only_tags(&[])?;
                match strings.as_slice() {
                    [flags]
                        if !flags.is_empty()
                            && flags.iter().all(|f| f.eq_ignore_ascii_case("\\seen")) =>
                    {
                        KnownAction::MarkSeen
                    }
                    _ => {
                        return at(
                            c.pos,
                            "GMX can only mark mail as read: `addflag \"\\\\Seen\";`",
                        );
                    }
                }
            }
            "discard" => {
                only_tags(&[])?;
                if !strings.is_empty() {
                    return at(c.pos, "`discard` takes nothing");
                }
                KnownAction::DeleteMailImmediately
            }
            "redirect" => {
                only_tags(&["copy"])?;
                let Some((_, p)) = tags.first() else {
                    return at(
                        c.pos,
                        "GMX forwards a copy and keeps the mail: write `redirect :copy` (require \"copy\")",
                    );
                };
                self.need("copy", *p)?;
                KnownAction::CopyForward {
                    pending: true,
                    receivers: vec![single("address")?],
                }
            }
            "notify" => {
                self.need("enotify", c.pos)?;
                only_tags(&[])?;
                let method = single("`mailto:` URI")?;
                let pagers: Vec<String> = match method.split_once(':') {
                    Some((scheme, rest)) if scheme.eq_ignore_ascii_case("mailto") => rest
                        .split_once('?')
                        .map_or(rest, |(to, _)| to)
                        .split(',')
                        .map(str::trim)
                        .filter(|a| !a.is_empty())
                        .map(str::to_owned)
                        .collect(),
                    _ => Vec::new(),
                };
                if pagers.is_empty() {
                    return at(
                        c.pos,
                        "GMX notifies by mail only: `notify \"mailto:a@b.de\";`",
                    );
                }
                KnownAction::TemplatedEmailNotify {
                    pending: false,
                    pagers,
                }
            }
            "keep" => {
                return at(
                    c.pos,
                    "`keep` has no GMX equivalent: mail stays in the inbox unless a rule moves it",
                );
            }
            other => return at(c.pos, format!("`{other}` is not supported by GMX filters")),
        };
        Ok(Action::Known(known))
    }

    fn expr(&self, t: &Test) -> Res<Expr> {
        let bare = || {
            if t.args.is_empty() && t.tests.is_empty() {
                Ok(())
            } else {
                at(t.pos, format!("`{}` takes nothing", t.name))
            }
        };
        match t.name.as_str() {
            "true" => bare().map(|()| Expr::True),
            "false" => bare().map(|()| Expr::False),
            "not" => match (t.args.as_slice(), t.tests.as_slice()) {
                ([], [x]) => Ok(self.expr(x)?.not()),
                _ => at(t.pos, "`not` takes one test"),
            },
            "anyof" | "allof" => {
                if !t.args.is_empty() || t.tests.is_empty() {
                    return at(t.pos, format!("`{}` takes a list of tests", t.name));
                }
                let xs = t
                    .tests
                    .iter()
                    .map(|x| self.expr(x))
                    .collect::<Res<Vec<_>>>()?;
                Ok(if t.name == "anyof" {
                    Expr::Any(xs)
                } else {
                    Expr::All(xs)
                })
            }
            "header" | "address" => self.header(t),
            "size" => self.size(t),
            other => at(
                t.pos,
                format!("the `{other}` test is not supported by GMX filters"),
            ),
        }
    }

    fn size(&self, t: &Test) -> Res<Expr> {
        let (over, bytes) = match t.args.as_slice() {
            [Arg::Tag(tag, _), Arg::Number(n, _)] if tag == "over" => (true, *n),
            [Arg::Tag(tag, p), Arg::Number(n, _)] if tag == "under" => {
                if *n == 0 {
                    return at(*p, "`size :under 0` can never match");
                }
                (false, n - 1)
            }
            _ => return at(t.pos, "use `size :over <n>` or `size :under <n>`"),
        };
        Ok(Expr::Leaf(KnownCondition::SizeOver {
            inverted: !over,
            byte_size: bytes,
        }))
    }

    fn header(&self, t: &Test) -> Res<Expr> {
        #[derive(PartialEq)]
        enum Match {
            Is,
            Contains,
            Matches,
            List,
        }
        let address = t.name == "address";
        let mut how = Match::Is;
        let mut lists = Vec::new();
        let mut args = t.args.iter();
        while let Some(a) = args.next() {
            match a {
                Arg::Tag(tag, p) => match tag.as_str() {
                    "is" => how = Match::Is,
                    "contains" => how = Match::Contains,
                    "matches" => how = Match::Matches,
                    "list" => {
                        self.need("extlists", *p)?;
                        how = Match::List;
                    }
                    "comparator" => match args.next() {
                        Some(Arg::Strings(name, _)) if name == &["i;ascii-casemap"] => {}
                        _ => {
                            return at(
                                *p,
                                "GMX compares ignoring case; only `:comparator \"i;ascii-casemap\"` fits",
                            );
                        }
                    },
                    "all" if address => {}
                    "localpart" | "domain" | "user" | "detail" if address => {
                        return at(
                            *p,
                            format!("GMX matches whole addresses; `:{tag}` is not supported"),
                        );
                    }
                    _ => return at(*p, format!("`:{tag}` is not supported by GMX filters")),
                },
                Arg::Strings(s, p) => lists.push((s, *p)),
                Arg::Number(_, p) => return at(*p, "unexpected number"),
            }
        }
        let ([(names, names_at), (keys, keys_at)], []) = (lists.as_slice(), t.tests.as_slice())
        else {
            return at(
                t.pos,
                format!("`{}` takes header names and a key list", t.name),
            );
        };
        let mut names: Vec<String> = names.iter().map(|n| n.to_ascii_lowercase()).collect();
        names.sort();
        names.dedup();

        if how == Match::List {
            if names != ["from"] || !keys.iter().all(|k| k.starts_with(":addrbook")) {
                return at(
                    t.pos,
                    format!(
                        "GMX can only check the address book: `address :list \"from\" \"{ADDRESS_BOOK}\"`"
                    ),
                );
            }
            return Ok(Expr::Leaf(KnownCondition::AnyContact { inverted: false }));
        }
        if names.iter().any(|n| n == PRIORITY_HEADER) {
            if names.len() > 1 || how != Match::Is {
                return at(
                    *names_at,
                    format!("use `header :is \"{PRIORITY_HEADER}\" \"low|normal|high\"`"),
                );
            }
            let levels = keys
                .iter()
                .map(|k| {
                    let level = match k.to_ascii_lowercase().as_str() {
                        "low" => PriorityLevel::Low,
                        "normal" => PriorityLevel::Normal,
                        "high" => PriorityLevel::High,
                        _ => {
                            return at(
                                *keys_at,
                                format!("priority {k:?}: use low, normal or high"),
                            );
                        }
                    };
                    Ok(Expr::Leaf(KnownCondition::Priority {
                        inverted: false,
                        level,
                    }))
                })
                .collect::<Res<Vec<_>>>()?;
            return Ok(any(levels));
        }

        let cc = names.iter().any(|n| n == "cc");
        let mut fields = Vec::new();
        for n in &names {
            match n.as_str() {
                "from" => fields.push(Kind::From),
                "to" => fields.push(Kind::To),
                "subject" if !address => fields.push(Kind::Subject),
                "cc" if names.iter().any(|n| n == "to") => {}
                "cc" => {
                    return at(
                        *names_at,
                        "GMX checks Cc only together with To: use [\"to\", \"cc\"]",
                    );
                }
                other => {
                    return at(
                        *names_at,
                        format!("GMX filters check from, to, to+cc and subject, not {other:?}"),
                    );
                }
            }
        }
        let mut entries = Vec::new();
        for kind in fields {
            for key in keys.iter() {
                let (comparator, value) = match how {
                    Match::Is => (Comparator::Is, key.clone()),
                    Match::Contains => (Comparator::Contains, key.clone()),
                    Match::Matches => wildcard(key).or_else(|e| at(*keys_at, e))?,
                    Match::List => unreachable!("handled above"),
                };
                entries.push(Expr::Header(match kind {
                    Kind::From => KnownHeaderCondition::From {
                        comparator,
                        inverted: false,
                        value,
                    },
                    Kind::Subject => KnownHeaderCondition::Subject {
                        comparator,
                        inverted: false,
                        value,
                    },
                    Kind::To => KnownHeaderCondition::ToCc {
                        comparator,
                        inverted: false,
                        include_cc_header: cc.then_some(true),
                        value,
                    },
                }));
            }
        }
        Ok(any(entries))
    }
}

fn any(mut xs: Vec<Expr>) -> Expr {
    if xs.len() == 1 {
        xs.remove(0)
    } else {
        Expr::Any(xs)
    }
}

/// A `:matches` pattern as a GMX comparison: `*` only at the start and/or end.
fn wildcard(pattern: &str) -> Res<(Comparator, String)> {
    let (mut lead, mut trail) = (false, false);
    let mut literal = String::new();
    let mut chars = pattern.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' => literal.push(chars.next().unwrap_or('\\')),
            '*' if literal.is_empty() && !lead => lead = true,
            '*' if chars.peek().is_none() => trail = true,
            '*' | '?' => {
                return Err(format!(
                    "`:matches {pattern:?}`: GMX only supports `*` at the start and/or end (`\\\\*` is a literal star)"
                ));
            }
            c => literal.push(c),
        }
    }
    if literal.is_empty() {
        return Err(format!(
            "`:matches {pattern:?}` matches everything; use `true`"
        ));
    }
    let comparator = match (lead, trail) {
        (false, false) => Comparator::Is,
        (true, true) => Comparator::Contains,
        (false, true) => Comparator::StartsWith,
        (true, false) => Comparator::EndsWith,
    };
    Ok((comparator, literal))
}
