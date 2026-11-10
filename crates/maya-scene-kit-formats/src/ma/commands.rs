use std::{collections::HashMap, sync::LazyLock};

use maya_mel::{
    maya::MayaCommandRegistry,
    sema::command_schema::{CommandRegistry, FlagArity},
};

use crate::ma::error::MaParseError;

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

pub(crate) fn setattr_flag_arity(flag: &str) -> Option<usize> {
    static FLAGS: LazyLock<HashMap<String, usize>> = LazyLock::new(|| {
        let registry = MayaCommandRegistry::new();
        let schema = registry.lookup("setAttr").expect("built-in setAttr schema");
        let mut flags = HashMap::new();
        for flag in schema.flags.iter() {
            let arity = match flag.arity_by_mode.create {
                FlagArity::None => 0,
                FlagArity::Exact(count) => usize::from(count),
                FlagArity::Range { max, .. } => usize::from(max),
            };
            flags.insert(flag.long_name.to_string(), arity);
            if let Some(short) = &flag.short_name {
                flags.insert(short.to_string(), arity);
            }
        }
        flags
    });
    FLAGS.get(flag.trim_start_matches('-')).copied()
}

#[cfg(test)]
mod tests {
    use super::{Token, setattr_flag_arity, tokenize_command};

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
        for flag in [
            "-type",
            "-typ",
            "-s",
            "-size",
            "-cb",
            "-channelBox",
            "-keyable",
            "-lock",
            "-capacityHint",
            "-caching",
        ] {
            assert_eq!(setattr_flag_arity(flag), Some(1), "{flag}");
        }
        for flag in ["-av", "-alteredValue", "-clamp"] {
            assert_eq!(setattr_flag_arity(flag), Some(0), "{flag}");
        }
    }
}
