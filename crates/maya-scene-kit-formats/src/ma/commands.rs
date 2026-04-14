use crate::ma::error::MaParseError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ScalarTokenPolicy {
    Plain,
    Bool,
    Usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FlagDescriptor {
    pub(crate) name: &'static str,
    pub(crate) arity: usize,
    pub(crate) scalar_policy: ScalarTokenPolicy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FlagCommandKind {
    SetAttr,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Token {
    Bare(String),
    Quoted(String),
    Symbol(char),
}

pub fn tokenize_command(command: &str) -> Result<Vec<Token>, MaParseError> {
    let mut tokens = Vec::new();
    let mut chars = command.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch.is_whitespace() {
            continue;
        }

        match ch {
            ';' | '(' | ')' | '+' => tokens.push(Token::Symbol(ch)),
            '"' => {
                let mut value = String::new();
                let mut escaped = false;
                let mut closed = false;
                for next in chars.by_ref() {
                    if escaped {
                        match next {
                            'n' => value.push('\n'),
                            'r' => value.push('\r'),
                            't' => value.push('\t'),
                            '"' => value.push('"'),
                            '\\' => value.push('\\'),
                            other => {
                                value.push('\\');
                                value.push(other);
                            }
                        }
                        escaped = false;
                        continue;
                    }
                    if next == '\\' {
                        escaped = true;
                        continue;
                    }
                    if next == '"' {
                        closed = true;
                        break;
                    }
                    value.push(next);
                }
                if !closed {
                    return Err(MaParseError::Message(
                        "unterminated quoted string in Maya ASCII command".to_string(),
                    ));
                }
                tokens.push(Token::Quoted(value));
            }
            _ => {
                let mut value = String::from(ch);
                while let Some(&next) = chars.peek() {
                    if next == '+' && is_positive_exponent_continuation(&value, &chars) {
                        value.push(next);
                        chars.next();
                        continue;
                    }
                    if next.is_whitespace() || matches!(next, ';' | '(' | ')' | '+' | '"') {
                        break;
                    }
                    value.push(next);
                    chars.next();
                }
                tokens.push(Token::Bare(value));
            }
        }
    }

    Ok(tokens
        .into_iter()
        .filter(|token| !matches!(token, Token::Symbol(';')))
        .collect())
}

fn is_positive_exponent_continuation(
    current: &str,
    chars: &std::iter::Peekable<std::str::Chars<'_>>,
) -> bool {
    if !current.ends_with(['e', 'E']) {
        return false;
    }

    let mut lookahead = chars.clone();
    let _plus = lookahead.next();
    matches!(lookahead.peek(), Some(next) if next.is_ascii_digit())
}

pub fn token_text(token: &Token) -> Option<&str> {
    match token {
        Token::Bare(value) | Token::Quoted(value) => Some(value.as_str()),
        Token::Symbol(_) => None,
    }
}

pub fn bare_token(token: &Token) -> Option<&str> {
    match token {
        Token::Bare(value) => Some(value.as_str()),
        _ => None,
    }
}

const BOOL_FLAG: ScalarTokenPolicy = ScalarTokenPolicy::Bool;
const USIZE_FLAG: ScalarTokenPolicy = ScalarTokenPolicy::Usize;
const PLAIN_FLAG: ScalarTokenPolicy = ScalarTokenPolicy::Plain;
const SET_ATTR_FLAGS: &[FlagDescriptor] = &[
    FlagDescriptor {
        name: "-s",
        arity: 1,
        scalar_policy: USIZE_FLAG,
    },
    FlagDescriptor {
        name: "-ch",
        arity: 1,
        scalar_policy: USIZE_FLAG,
    },
    FlagDescriptor {
        name: "-l",
        arity: 1,
        scalar_policy: BOOL_FLAG,
    },
    FlagDescriptor {
        name: "-k",
        arity: 1,
        scalar_policy: BOOL_FLAG,
    },
    FlagDescriptor {
        name: "-type",
        arity: 1,
        scalar_policy: PLAIN_FLAG,
    },
];
// Runtime parser paths only need setAttr flag metadata. Other legacy command fallback
// lives in command-family owners such as `parse_references.rs`.
const fn command_flags(kind: FlagCommandKind) -> &'static [FlagDescriptor] {
    match kind {
        FlagCommandKind::SetAttr => SET_ATTR_FLAGS,
    }
}

pub(crate) fn command_flag_descriptor(
    kind: FlagCommandKind,
    flag_name: &str,
) -> Option<&'static FlagDescriptor> {
    command_flags(kind)
        .iter()
        .find(|flag| flag.name == flag_name)
}

#[cfg(test)]
mod tests {
    use super::{
        FlagCommandKind, ScalarTokenPolicy, Token, command_flag_descriptor, tokenize_command,
    };

    #[test]
    fn tokenizer_preserves_positive_exponent_numeric_tokens() {
        let tokens =
            tokenize_command("setAttr \".n[0]\" -type \"float3\" 1e+20 2 3;").expect("tokens");

        assert!(
            tokens
                .iter()
                .any(|token| token == &Token::Bare("1e+20".to_string()))
        );
        assert!(
            !tokens
                .iter()
                .any(|token| token == &Token::Bare("1e".to_string()))
        );
        assert!(!tokens.iter().any(|token| token == &Token::Symbol('+')));
    }

    #[test]
    fn setattr_flag_metadata_is_inspectable() {
        assert_eq!(
            command_flag_descriptor(FlagCommandKind::SetAttr, "-type")
                .expect("setAttr -type flag")
                .scalar_policy,
            ScalarTokenPolicy::Plain
        );
        assert_eq!(
            command_flag_descriptor(FlagCommandKind::SetAttr, "-s")
                .expect("setAttr -s flag")
                .arity,
            1
        );
    }
}
