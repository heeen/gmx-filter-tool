//! Experimental Sieve (RFC 5228) form of the rules file: the subset GMX can store (docs/sieve.md).

mod lower;
mod print;
mod syntax;

use crate::{
    DesiredRule, Error, HeaderCondition, KnownCondition, KnownHeaderCondition, Operator, Result,
};

pub use print::export_sieve;

/// Extensions a GMX rule can need; `require` of anything else is refused.
const EXTENSIONS: [&str; 6] = [
    "fileinto",
    "copy",
    "imap4flags",
    "enotify",
    "extlists",
    "comparator-i;ascii-casemap",
];
/// Stand-in header for GMX's priority condition, which has no Sieve test.
const PRIORITY_HEADER: &str = "x-gmxf-priority";
/// The RFC 6134 list name for "sender is in the address book".
const ADDRESS_BOOK: &str = ":addrbook:default";

/// The rules a Sieve file asks for, and remarks worth showing (e.g. which rules were split).
#[derive(Debug)]
pub struct SieveImport {
    pub rules: Vec<DesiredRule>,
    pub notes: Vec<String>,
}

/// Parses a Sieve rules file. With `split`, constructs GMX cannot store in one rule (nested `if`,
/// `elsif`/`else`, conditions nested too deep) become several rules; without it they are errors.
pub fn parse_sieve(text: &str, split: bool) -> Result<SieveImport> {
    let commands = syntax::parse(text).map_err(Error::Sieve)?;
    lower::lower(&commands, split).map_err(Error::Sieve)
}

/// The header field a `Multi*Comparator` group tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    From,
    To,
    Subject,
}

impl Kind {
    fn of(h: &KnownHeaderCondition) -> Self {
        match h {
            KnownHeaderCondition::From { .. } => Self::From,
            KnownHeaderCondition::ToCc { .. } => Self::To,
            KnownHeaderCondition::Subject { .. } => Self::Subject,
        }
    }
}

/// A `Multi*Comparator` condition with only known entries.
#[derive(Debug, Clone, PartialEq)]
struct Group {
    kind: Kind,
    op: Operator,
    inverted: bool,
    entries: Vec<KnownHeaderCondition>,
}

impl Group {
    fn of(c: &KnownCondition) -> Option<Self> {
        let (kind, op, inverted, entries) = match c {
            KnownCondition::MultiFromComparator {
                operator,
                inverted,
                header_comparator_conditions,
            } => (Kind::From, operator, inverted, header_comparator_conditions),
            KnownCondition::MultiToComparator {
                operator,
                inverted,
                header_comparator_conditions,
            } => (Kind::To, operator, inverted, header_comparator_conditions),
            KnownCondition::MultiSubjectComparator {
                operator,
                inverted,
                header_comparator_conditions,
            } => (
                Kind::Subject,
                operator,
                inverted,
                header_comparator_conditions,
            ),
            _ => return None,
        };
        let entries = entries
            .iter()
            .map(|h| match h {
                HeaderCondition::Known(k) if Kind::of(k) == kind => Some(k.clone()),
                _ => None,
            })
            .collect::<Option<Vec<_>>>()?;
        Some(Self {
            kind,
            op: op.clone(),
            inverted: *inverted,
            entries,
        })
    }

    fn into_condition(self) -> KnownCondition {
        let operator = self.op;
        let inverted = self.inverted;
        let header_comparator_conditions = self
            .entries
            .into_iter()
            .map(HeaderCondition::Known)
            .collect();
        match self.kind {
            Kind::From => KnownCondition::MultiFromComparator {
                operator,
                inverted,
                header_comparator_conditions,
            },
            Kind::To => KnownCondition::MultiToComparator {
                operator,
                inverted,
                header_comparator_conditions,
            },
            Kind::Subject => KnownCondition::MultiSubjectComparator {
                operator,
                inverted,
                header_comparator_conditions,
            },
        }
    }
}

fn entry_inverted(h: &mut KnownHeaderCondition) -> &mut bool {
    match h {
        KnownHeaderCondition::From { inverted, .. }
        | KnownHeaderCondition::Subject { inverted, .. }
        | KnownHeaderCondition::ToCc { inverted, .. } => inverted,
    }
}

/// The `inverted` flag of a size, priority or contact condition.
fn leaf_inverted(c: &mut KnownCondition) -> Option<&mut bool> {
    match c {
        KnownCondition::SizeOver { inverted, .. }
        | KnownCondition::Priority { inverted, .. }
        | KnownCondition::AnyContact { inverted } => Some(inverted),
        _ => None,
    }
}

#[cfg(test)]
mod tests;
