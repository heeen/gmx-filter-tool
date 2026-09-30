//! Sieve text to a generic command tree (RFC 5228 section 8); no meaning attached yet.

use std::fmt;

use pest::{Parser as _, iterators::Pair};

#[derive(pest_derive::Parser)]
#[grammar = "sieve/sieve.pest"]
struct SieveParser;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Pos {
    pub line: usize,
    pub col: usize,
}

impl fmt::Display for Pos {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "line {}:{}", self.line, self.col)
    }
}

fn pos(pair: &Pair<'_, Rule>) -> Pos {
    let (line, col) = pair.line_col();
    Pos { line, col }
}

#[derive(Debug, Clone)]
pub(super) enum Arg {
    Strings(Vec<String>, Pos),
    Number(u64, Pos),
    Tag(String, Pos),
}

impl Arg {
    pub fn pos(&self) -> Pos {
        match self {
            Self::Strings(_, p) | Self::Number(_, p) | Self::Tag(_, p) => *p,
        }
    }
}

#[derive(Debug, Clone)]
pub(super) struct Test {
    /// Lowercase: Sieve identifiers are case-insensitive.
    pub name: String,
    pub pos: Pos,
    pub args: Vec<Arg>,
    pub tests: Vec<Test>,
}

#[derive(Debug, Clone)]
pub(super) struct Command {
    pub name: String,
    pub pos: Pos,
    pub args: Vec<Arg>,
    pub tests: Vec<Test>,
    pub block: Option<Vec<Command>>,
    /// `#` comments between the previous command and this one, without the `#`.
    pub comments: Vec<String>,
}

pub(super) fn parse(text: &str) -> Result<Vec<Command>, String> {
    let file = SieveParser::parse(Rule::file, text)
        .map_err(|e| e.renamed_rules(rule_name).to_string())?
        .next()
        .expect("the file rule always yields one pair");
    commands(file)
}

fn rule_name(rule: &Rule) -> String {
    match rule {
        Rule::EOI => "end of file",
        Rule::command => "a command",
        Rule::block => "`{`",
        Rule::test | Rule::test_list => "a test",
        Rule::string_list | Rule::quoted | Rule::multi_line => "a string",
        Rule::number => "a number",
        Rule::tag => "a `:tag`",
        Rule::identifier => "a name",
        _ => return format!("{rule:?}"),
    }
    .to_owned()
}

fn commands(parent: Pair<'_, Rule>) -> Result<Vec<Command>, String> {
    let mut out = Vec::new();
    let mut comments = Vec::new();
    for pair in parent.into_inner() {
        match pair.as_rule() {
            Rule::COMMENT => {
                // pest runs COMMENT while skipping trivia, which yields no inner pairs
                if let Some(text) = pair.as_str().strip_prefix('#') {
                    comments.push(text.to_owned());
                }
            }
            Rule::command => {
                let mut cmd = command(pair)?;
                cmd.comments = std::mem::take(&mut comments);
                out.push(cmd);
            }
            _ => {}
        }
    }
    Ok(out)
}

fn command(pair: Pair<'_, Rule>) -> Result<Command, String> {
    let at = pos(&pair);
    let mut inner = pair.into_inner().filter(|p| p.as_rule() != Rule::COMMENT);
    let name = inner
        .next()
        .map(|p| p.as_str().to_ascii_lowercase())
        .unwrap_or_default();
    let mut cmd = Command {
        name,
        pos: at,
        args: Vec::new(),
        tests: Vec::new(),
        block: None,
        comments: Vec::new(),
    };
    for p in inner {
        match p.as_rule() {
            Rule::block => cmd.block = Some(commands(p)?),
            Rule::test => cmd.tests.push(test(p)?),
            Rule::test_list => cmd.tests = test_list(p)?,
            _ => cmd.args.push(argument(p)?),
        }
    }
    Ok(cmd)
}

fn test(pair: Pair<'_, Rule>) -> Result<Test, String> {
    let at = pos(&pair);
    let mut inner = pair.into_inner().filter(|p| p.as_rule() != Rule::COMMENT);
    let name = inner
        .next()
        .map(|p| p.as_str().to_ascii_lowercase())
        .unwrap_or_default();
    let mut t = Test {
        name,
        pos: at,
        args: Vec::new(),
        tests: Vec::new(),
    };
    for p in inner {
        match p.as_rule() {
            Rule::test => t.tests.push(test(p)?),
            Rule::test_list => t.tests = test_list(p)?,
            _ => t.args.push(argument(p)?),
        }
    }
    Ok(t)
}

fn test_list(pair: Pair<'_, Rule>) -> Result<Vec<Test>, String> {
    pair.into_inner()
        .filter(|p| p.as_rule() == Rule::test)
        .map(test)
        .collect()
}

fn argument(pair: Pair<'_, Rule>) -> Result<Arg, String> {
    let at = pos(&pair);
    Ok(match pair.as_rule() {
        Rule::string_list => Arg::Strings(
            pair.into_inner()
                .filter(|p| p.as_rule() != Rule::COMMENT)
                .map(string)
                .collect(),
            at,
        ),
        Rule::quoted | Rule::multi_line => Arg::Strings(vec![string(pair)], at),
        Rule::number => Arg::Number(
            number(pair.as_str()).ok_or_else(|| format!("{at}: number too large"))?,
            at,
        ),
        Rule::tag => Arg::Tag(
            pair.as_str().trim_start_matches(':').to_ascii_lowercase(),
            at,
        ),
        other => return Err(format!("{at}: unexpected {other:?}")),
    })
}

/// RFC 5228 2.4.1: a K, M or G suffix multiplies by 2^10, 2^20, 2^30.
fn number(s: &str) -> Option<u64> {
    let (digits, shift) = match s.chars().last()? {
        'k' | 'K' => (s.strip_suffix(['k', 'K'])?, 10),
        'm' | 'M' => (s.strip_suffix(['m', 'M'])?, 20),
        'g' | 'G' => (s.strip_suffix(['g', 'G'])?, 30),
        _ => (s, 0),
    };
    digits.parse::<u64>().ok()?.checked_mul(1 << shift)
}

fn string(pair: Pair<'_, Rule>) -> String {
    match pair.as_rule() {
        Rule::quoted => {
            let raw = pair.into_inner().next().map_or("", |p| p.as_str());
            let mut out = String::with_capacity(raw.len());
            let mut chars = raw.chars();
            while let Some(c) = chars.next() {
                // only \" and \\ are defined; any other escaped character stands for itself
                out.push(if c == '\\' {
                    chars.next().unwrap_or('\\')
                } else {
                    c
                });
            }
            out
        }
        _ => {
            let body = pair
                .into_inner()
                .find(|p| p.as_rule() == Rule::ml_body)
                .map_or("", |p| p.as_str());
            body.split_inclusive('\n')
                .map(|line| {
                    line.strip_prefix('.')
                        .filter(|l| l.starts_with('.'))
                        .unwrap_or(line)
                })
                .collect()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(arg: &Arg) -> &[String] {
        match arg {
            Arg::Strings(s, _) => s,
            other => panic!("not strings: {other:?}"),
        }
    }

    #[test]
    fn parses_commands_tests_and_comments() {
        let text = "require [\"fileinto\", \"copy\"];\n\
                    # rule:[News]\n# gmxf-id: 7\n\
                    IF anyof(header :contains \"from\" [\"a\\\"b\", \"c\\\\d\"], /* x */ not size :over 1K) {\n\
                    \tfileinto :copy \"INBOX/X\"; # trailing\n\
                    \tstop;\n}\n";
        let cmds = parse(text).unwrap();
        assert_eq!(cmds.len(), 2);
        assert_eq!(cmds[0].name, "require");
        assert_eq!(strings(&cmds[0].args[0]), ["fileinto", "copy"]);
        let rule = &cmds[1];
        assert_eq!(rule.name, "if");
        assert_eq!(rule.comments, [" rule:[News]", " gmxf-id: 7"]);
        assert_eq!(rule.pos, Pos { line: 4, col: 1 });
        let any = &rule.tests[0];
        assert_eq!(any.name, "anyof");
        assert_eq!(any.tests.len(), 2);
        assert_eq!(strings(&any.tests[0].args[2]), ["a\"b", "c\\d"]);
        let not = &any.tests[1];
        assert_eq!(
            (not.name.as_str(), not.tests[0].name.as_str()),
            ("not", "size")
        );
        assert!(matches!(not.tests[0].args[1], Arg::Number(1024, _)));
        let block = rule.block.as_ref().unwrap();
        assert!(matches!(&block[0].args[0], Arg::Tag(t, _) if t == "copy"));
        assert_eq!(block[1].name, "stop");
        assert_eq!(block[1].comments, [" trailing"]);
    }

    #[test]
    fn multi_line_strings_unstuff_dots() {
        let cmds = parse("notify text: # c\nline one\n..dot\n.\n;").unwrap();
        assert_eq!(strings(&cmds[0].args[0]), ["line one\n.dot\n"]);
    }

    #[test]
    fn syntax_errors_carry_a_position() {
        let err = parse("if true {\n  stop\n}").unwrap_err();
        assert!(err.contains("3:1"), "{err}");
        assert!(
            parse("size :over 99999999999G;")
                .unwrap_err()
                .contains("too large")
        );
    }
}
