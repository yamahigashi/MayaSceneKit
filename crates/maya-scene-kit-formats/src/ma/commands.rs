use std::{borrow::Cow, collections::HashMap, sync::LazyLock};

use maya_mel::{
    maya::MayaCommandRegistry,
    sema::command_schema::{CommandRegistry, FlagArity},
};

use crate::ma::{error::MaParseError, lexer::unescape_ma_string_literal};

pub(crate) static MAYA_COMMAND_REGISTRY: MayaCommandRegistry = MayaCommandRegistry::new();

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

#[derive(Clone, Copy)]
pub(crate) struct CreateNodeFlag {
    pub(crate) name: &'static str,
    pub(crate) arity: usize,
    pub(crate) allows_multiple: bool,
}

pub(crate) fn create_node_flag(flag: &str) -> Option<CreateNodeFlag> {
    static FLAGS: LazyLock<HashMap<&'static str, CreateNodeFlag>> = LazyLock::new(|| {
        let mut flags = HashMap::new();
        if let Some(schema) = MAYA_COMMAND_REGISTRY.lookup("createNode") {
            for flag in schema.flags.iter() {
                let arity = match flag.arity_by_mode.create {
                    FlagArity::None => 0,
                    FlagArity::Exact(count) => usize::from(count),
                    FlagArity::Range { .. } => continue,
                };
                let metadata = CreateNodeFlag {
                    name: flag.long_name.as_ref(),
                    arity,
                    allows_multiple: flag.allows_multiple,
                };
                flags.insert(flag.long_name.as_ref(), metadata);
                if let Some(short) = &flag.short_name {
                    flags.insert(short.as_ref(), metadata);
                }
            }
        }
        flags
    });
    FLAGS.get(flag.strip_prefix('-')?).copied()
}

pub(crate) fn is_file_command_callback_flag(flag: &[u8]) -> bool {
    static ALIASES: LazyLock<Vec<&'static str>> = LazyLock::new(|| {
        MAYA_COMMAND_REGISTRY
            .lookup("file")
            .and_then(|schema| {
                schema
                    .flags
                    .iter()
                    .find(|flag| flag.long_name.as_ref() == "command")
            })
            .map(|flag| {
                std::iter::once(flag.long_name.as_ref())
                    .chain(flag.short_name.as_deref())
                    .collect()
            })
            .unwrap_or_default()
    });
    flag.strip_prefix(b"-")
        .is_some_and(|name| ALIASES.iter().any(|alias| alias.as_bytes() == name))
}

fn command_flag_arities(command: &str) -> HashMap<String, FlagArity> {
    let mut flags = HashMap::new();
    if let Some(schema) = MAYA_COMMAND_REGISTRY.lookup(command) {
        for flag in schema.flags.iter() {
            flags.insert(flag.long_name.to_string(), flag.arity_by_mode.create);
            if let Some(short) = &flag.short_name {
                flags.insert(short.to_string(), flag.arity_by_mode.create);
            }
        }
    }
    flags
}

pub(crate) fn setattr_flag_arity(flag: &str) -> Option<usize> {
    static FLAGS: LazyLock<HashMap<String, FlagArity>> =
        LazyLock::new(|| command_flag_arities("setAttr"));
    match FLAGS.get(flag.trim_start_matches('-'))? {
        FlagArity::None => Some(0),
        FlagArity::Exact(count) => Some(usize::from(*count)),
        FlagArity::Range { max, .. } => Some(usize::from(*max)),
    }
}

pub(crate) fn connect_attr_flag_arity(flag: &str) -> Option<usize> {
    static FLAGS: LazyLock<HashMap<String, FlagArity>> =
        LazyLock::new(|| command_flag_arities("connectAttr"));
    match FLAGS.get(flag.trim_start_matches('-'))? {
        FlagArity::None => Some(0),
        FlagArity::Exact(count) => Some(usize::from(*count)),
        FlagArity::Range { .. } => None,
    }
}

pub(crate) fn unquoted_range_value(text: Cow<'_, str>) -> Cow<'_, str> {
    match text {
        Cow::Borrowed(text) => match string_literal_contents(text) {
            Some(contents) if contents.contains('\\') => {
                Cow::Owned(unescape_ma_string_literal(contents))
            }
            Some(contents) => Cow::Borrowed(contents),
            None => Cow::Borrowed(text),
        },
        Cow::Owned(text) => match string_literal_contents(&text) {
            Some(contents) => Cow::Owned(unescape_ma_string_literal(contents)),
            None => Cow::Owned(text),
        },
    }
}

pub(crate) fn string_literal_contents(text: &str) -> Option<&str> {
    text.strip_prefix('"')?.strip_suffix('"')
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
