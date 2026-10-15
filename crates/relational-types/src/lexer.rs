use crate::Error;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum TokenKind {
    Word(String),
    Quoted(String),
    String(String),
    Number(String),
    Binary(Vec<u8>),
    Symbol(char),
    Operator(String),
}
impl TokenKind {
    pub fn word_is(&self, word: &str) -> bool {
        matches!(self,Self::Word(value) if value.eq_ignore_ascii_case(word))
    }
    pub fn identifier(&self) -> Option<&str> {
        match self {
            Self::Word(s) | Self::Quoted(s) => Some(s),
            _ => None,
        }
    }
}
#[derive(Clone, Debug)]
pub(crate) struct Token {
    pub kind: TokenKind,
    pub start: usize,
    pub end: usize,
    pub line: usize,
}

pub(crate) fn lex(sql: &str) -> Result<Vec<Token>, Error> {
    let bytes = sql.as_bytes();
    let mut i = 0;
    let mut line = 1;
    let mut tokens = Vec::new();
    let mut parentheses = 0_usize;
    while i < bytes.len() {
        if i == 0 && sql.starts_with('\u{feff}') {
            i = 3;
            continue;
        }
        if bytes[i].is_ascii_whitespace() {
            if bytes[i] == b'\n' {
                line += 1;
            }
            i += 1;
            continue;
        }
        if bytes[i..].starts_with(b"--") {
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        if bytes[i..].starts_with(b"/*") {
            let mut depth = 1;
            i += 2;
            while i < bytes.len() && depth > 0 {
                if bytes[i..].starts_with(b"/*") {
                    depth += 1;
                    if depth > 128 {
                        return Err(Error::new(
                            "SQL comment nesting exceeds the 128-level budget",
                        ));
                    }
                    i += 2;
                } else if bytes[i..].starts_with(b"*/") {
                    depth -= 1;
                    i += 2;
                } else {
                    if bytes[i] == b'\n' {
                        line += 1;
                    }
                    i += 1;
                }
            }
            if depth != 0 {
                return Err(Error::new("unterminated SQL comment"));
            }
            continue;
        }
        let start = i;
        let token_line = line;
        let unicode_string = matches!(bytes[i], b'N' | b'n') && bytes.get(i + 1) == Some(&b'\'');
        let kind = if bytes[i] == b'\'' || unicode_string {
            if unicode_string {
                i += 1;
            }
            i += 1;
            let mut text = String::new();
            let mut part = i;
            let mut done = false;
            while i < bytes.len() {
                if bytes[i] == b'\'' {
                    text.push_str(&sql[part..i]);
                    if bytes.get(i + 1) == Some(&b'\'') {
                        text.push('\'');
                        i += 2;
                        part = i;
                    } else {
                        i += 1;
                        done = true;
                        break;
                    }
                } else {
                    if bytes[i] == b'\n' {
                        line += 1;
                    }
                    i += 1;
                }
            }
            if !done {
                return Err(Error::new("unterminated SQL string"));
            }
            TokenKind::String(text)
        } else if bytes[i] == b'"' || bytes[i] == b'[' {
            let end = if bytes[i] == b'[' { b']' } else { b'"' };
            i += 1;
            let mut text = String::new();
            let mut part = i;
            let mut done = false;
            while i < bytes.len() {
                if bytes[i] == end {
                    text.push_str(&sql[part..i]);
                    if bytes.get(i + 1) == Some(&end) {
                        text.push(end as char);
                        i += 2;
                        part = i;
                    } else {
                        i += 1;
                        done = true;
                        break;
                    }
                } else {
                    if bytes[i] == b'\n' {
                        line += 1;
                    }
                    i += 1;
                }
            }
            if !done {
                return Err(Error::new("unterminated quoted SQL identifier"));
            }
            TokenKind::Quoted(text)
        } else if bytes[i..].starts_with(b"0x") || bytes[i..].starts_with(b"0X") {
            i += 2;
            let hex_start = i;
            while i < bytes.len() && bytes[i].is_ascii_hexdigit() {
                i += 1;
            }
            let hex = &sql[hex_start..i];
            // SQL Server left-pads an odd leading hex digit (e.g. installation masks 0xf).
            let padded = if hex.len().is_multiple_of(2) {
                hex.to_owned()
            } else {
                format!("0{hex}")
            };
            let decoded = (0..padded.len())
                .step_by(2)
                .map(|j| {
                    u8::from_str_radix(&padded[j..j + 2], 16)
                        .map_err(|_| Error::new("invalid binary hex"))
                })
                .collect::<Result<Vec<_>, _>>()?;
            TokenKind::Binary(decoded)
        } else if bytes[i].is_ascii_digit()
            || (bytes[i] == b'.' && bytes.get(i + 1).is_some_and(u8::is_ascii_digit))
        {
            i += 1;
            while i < bytes.len() && (bytes[i].is_ascii_digit() || bytes[i] == b'.') {
                i += 1;
            }
            if matches!(bytes.get(i), Some(b'e' | b'E')) {
                i += 1;
                if matches!(bytes.get(i), Some(b'+' | b'-')) {
                    i += 1;
                }
                while i < bytes.len() && bytes[i].is_ascii_digit() {
                    i += 1;
                }
            }
            TokenKind::Number(sql[start..i].to_owned())
        } else if bytes[i].is_ascii_alphabetic()
            || matches!(bytes[i], b'_' | b'@' | b'#')
            || bytes[i] >= 128
        {
            i += 1;
            while i < bytes.len()
                && (bytes[i].is_ascii_alphanumeric()
                    || matches!(bytes[i], b'_' | b'@' | b'#' | b'$')
                    || bytes[i] >= 128)
            {
                i += 1;
            }
            TokenKind::Word(sql[start..i].to_owned())
        } else if matches!(bytes[i], b'=' | b'<' | b'>' | b'!') {
            i += 1;
            if matches!(bytes.get(i), Some(b'='))
                || (bytes[start] == b'<' && bytes.get(i) == Some(&b'>'))
            {
                i += 1;
            }
            TokenKind::Operator(sql[start..i].to_owned())
        } else {
            let ch = bytes[i] as char;
            i += 1;
            if !"(),;.*+-/%&|".contains(ch) {
                return Err(Error::new(format!(
                    "unsupported SQL character {ch:?} on line {line}"
                )));
            }
            TokenKind::Symbol(ch)
        };
        if kind == TokenKind::Symbol('(') {
            parentheses += 1;
            if parentheses > 128 {
                return Err(Error::new("SQL nesting exceeds the 128-level budget"));
            }
        }
        if kind == TokenKind::Symbol(')') {
            parentheses = parentheses
                .checked_sub(1)
                .ok_or_else(|| Error::new("unbalanced SQL closing parenthesis"))?;
        }
        if tokens.len() >= 1_000_000 {
            return Err(Error::new("SQL token count exceeds the planning budget"));
        }
        tokens.push(Token {
            kind,
            start,
            end: i,
            line: token_line,
        });
    }
    if parentheses != 0 {
        return Err(Error::new("unbalanced SQL opening parenthesis"));
    }
    Ok(tokens)
}

pub(crate) struct Parser<'a> {
    pub tokens: &'a [Token],
    pub position: usize,
}
impl<'a> Parser<'a> {
    pub fn new(tokens: &'a [Token]) -> Self {
        Self {
            tokens,
            position: 0,
        }
    }
    pub fn done(&self) -> bool {
        self.position == self.tokens.len()
    }
    pub fn peek(&self) -> Option<&TokenKind> {
        self.tokens.get(self.position).map(|t| &t.kind)
    }
    pub fn take(&mut self) -> Result<TokenKind, Error> {
        let value = self
            .peek()
            .cloned()
            .ok_or_else(|| Error::new("unexpected end of SQL"))?;
        self.position += 1;
        Ok(value)
    }
    pub fn eat_word(&mut self, word: &str) -> bool {
        if self.peek().is_some_and(|t| t.word_is(word)) {
            self.position += 1;
            true
        } else {
            false
        }
    }
    pub fn expect_word(&mut self, word: &str) -> Result<(), Error> {
        if self.eat_word(word) {
            Ok(())
        } else {
            Err(self.expected(word))
        }
    }
    pub fn eat_symbol(&mut self, symbol: char) -> bool {
        if self.peek() == Some(&TokenKind::Symbol(symbol)) {
            self.position += 1;
            true
        } else {
            false
        }
    }
    pub fn expect_symbol(&mut self, symbol: char) -> Result<(), Error> {
        if self.eat_symbol(symbol) {
            Ok(())
        } else {
            Err(self.expected(&symbol.to_string()))
        }
    }
    pub fn ident(&mut self) -> Result<String, Error> {
        self.take()?
            .identifier()
            .map(str::to_owned)
            .ok_or_else(|| self.expected("identifier"))
    }
    pub fn object_name(&mut self) -> Result<String, Error> {
        let first = self.ident()?;
        if !self.eat_symbol('.') {
            return Ok(first);
        }
        let second = self.ident()?;
        if self.eat_symbol('.') {
            return Err(Error::new("cross-database qualified names are unsupported"));
        }
        if !first.eq_ignore_ascii_case("dbo") {
            return Err(Error::new(format!(
                "unsupported schema {first:?}; expected dbo"
            )));
        }
        Ok(second)
    }
    pub fn number(&mut self) -> Result<String, Error> {
        let sign = if self.eat_symbol('-') {
            "-"
        } else {
            self.eat_symbol('+');
            ""
        };
        match self.take()? {
            TokenKind::Number(value) => Ok(format!("{sign}{value}")),
            _ => Err(self.expected("numeric literal")),
        }
    }
    pub fn literal(&mut self) -> Result<TokenKind, Error> {
        if self.peek() == Some(&TokenKind::Symbol('-'))
            || self.peek() == Some(&TokenKind::Symbol('+'))
        {
            return self.number().map(TokenKind::Number);
        }
        self.take()
    }
    pub fn expected(&self, description: &str) -> Error {
        Error::new(format!(
            "expected {description}, received {:?}",
            self.peek()
        ))
    }
    pub fn group(&mut self) -> Result<&'a [Token], Error> {
        self.expect_symbol('(')?;
        let start = self.position;
        let mut depth = 1;
        while let Some(token) = self.tokens.get(self.position) {
            self.position += 1;
            match token.kind {
                TokenKind::Symbol('(') => depth += 1,
                TokenKind::Symbol(')') => {
                    depth -= 1;
                    if depth == 0 {
                        return Ok(&self.tokens[start..self.position - 1]);
                    }
                }
                _ => {}
            }
        }
        Err(Error::new("unterminated parenthesized SQL expression"))
    }
}

pub(crate) fn split_commas(tokens: &[Token]) -> Vec<&[Token]> {
    let mut result = Vec::new();
    let mut start = 0;
    let mut depth = 0;
    for (i, token) in tokens.iter().enumerate() {
        match token.kind {
            TokenKind::Symbol('(') => depth += 1,
            TokenKind::Symbol(')') => depth -= 1,
            TokenKind::Symbol(',') if depth == 0 => {
                result.push(&tokens[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    result.push(&tokens[start..]);
    result
}

pub(crate) fn token_text(tokens: &[Token]) -> String {
    tokens
        .iter()
        .map(|t| match &t.kind {
            TokenKind::Word(s)
            | TokenKind::Quoted(s)
            | TokenKind::Number(s)
            | TokenKind::Operator(s) => s.clone(),
            TokenKind::String(s) => format!("'{}'", s.replace('\'', "''")),
            TokenKind::Binary(bytes) => format!(
                "0x{}",
                bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
            ),
            TokenKind::Symbol(c) => c.to_string(),
        })
        .collect::<Vec<_>>()
        .join(" ")
}
