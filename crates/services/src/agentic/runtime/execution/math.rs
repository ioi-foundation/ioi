use super::{ToolExecutionResult, ToolExecutor};
use ioi_types::app::agentic::AgentTool;

const MAX_EXPRESSION_LEN: usize = 512;

pub async fn handle(_exec: &ToolExecutor, tool: AgentTool) -> ToolExecutionResult {
    let AgentTool::MathEval { expression } = tool else {
        return ToolExecutionResult::failure(
            "ERROR_CLASS=ToolUnavailable math__eval received an unsupported payload.",
        );
    };

    match evaluate_expression(expression.trim()) {
        Ok(value) => {
            let rendered = render_numeric(value);
            ToolExecutionResult::success(format!("Math result: {}", rendered))
        }
        Err(err) => ToolExecutionResult::failure(format!("ERROR_CLASS=InvalidInput {}", err)),
    }
}

fn evaluate_expression(raw: &str) -> Result<f64, String> {
    if raw.is_empty() {
        return Err("math__eval requires a non-empty expression.".to_string());
    }
    if raw.len() > MAX_EXPRESSION_LEN {
        return Err(format!(
            "math__eval expression length exceeds {} characters.",
            MAX_EXPRESSION_LEN
        ));
    }

    let normalized = normalize_operators(raw);
    match parse_strict_expression(&normalized) {
        Ok(value) => Ok(value),
        Err(primary_err) => {
            if let Some(candidate) = extract_expression_candidate(&normalized) {
                let normalized_trimmed = normalized.trim();
                if candidate != normalized_trimmed {
                    if let Ok(value) = parse_strict_expression(&candidate) {
                        return Ok(value);
                    }
                }
            }
            Err(primary_err)
        }
    }
}

fn parse_strict_expression(input: &str) -> Result<f64, String> {
    let mut parser = ExpressionParser::new(input);
    let value = parser.parse_expression()?;
    parser.skip_whitespace();
    if !parser.is_eof() {
        return Err(format!(
            "Unexpected token '{}' at position {}.",
            parser.peek_char().unwrap_or('\0'),
            parser.pos
        ));
    }
    if !value.is_finite() {
        return Err("Expression result is non-finite.".to_string());
    }
    Ok(value)
}

fn extract_expression_candidate(input: &str) -> Option<String> {
    let mut candidate = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '0'..='9'
            | '+'
            | '-'
            | '*'
            | '/'
            | '%'
            | '^'
            | '('
            | ')'
            | '.'
            | 'x'
            | 'X'
            | 'e'
            | 'E' => candidate.push(ch),
            ',' => {}
            ch if ch.is_whitespace() => candidate.push(' '),
            _ => candidate.push(' '),
        }
    }

    let collapsed = candidate.split_whitespace().collect::<Vec<_>>().join(" ");
    if collapsed.is_empty() {
        return None;
    }

    let has_digit = collapsed.chars().any(|ch| ch.is_ascii_digit());
    let has_operator = collapsed.chars().any(|ch| {
        matches!(
            ch,
            '+' | '-' | '*' | '/' | '%' | '^' | 'x' | 'X' | '(' | ')'
        )
    });
    if !has_digit || !has_operator {
        return None;
    }
    Some(collapsed)
}

fn normalize_operators(raw: &str) -> String {
    raw.chars()
        .map(|ch| match ch {
            '×' | '∙' | '⋅' => '*',
            '÷' => '/',
            '−' | '–' | '—' => '-',
            _ => ch,
        })
        .collect()
}

fn render_numeric(value: f64) -> String {
    let rounded = value.round();
    if (value - rounded).abs() <= 1e-12 * rounded.abs().max(1.0) {
        return format!("{:.0}", rounded);
    }

    let mut rendered = format!("{:.15}", value);
    while rendered.contains('.') && rendered.ends_with('0') {
        rendered.pop();
    }
    if rendered.ends_with('.') {
        rendered.pop();
    }
    rendered
}

struct ExpressionParser<'a> {
    input: &'a str,
    pos: usize,
}

impl<'a> ExpressionParser<'a> {
    fn new(input: &'a str) -> Self {
        Self { input, pos: 0 }
    }

    fn parse_expression(&mut self) -> Result<f64, String> {
        self.parse_add_sub()
    }

    fn parse_add_sub(&mut self) -> Result<f64, String> {
        let mut value = self.parse_mul_div()?;
        loop {
            self.skip_whitespace();
            if self.consume_char('+') {
                value += self.parse_mul_div()?;
            } else if self.consume_char('-') {
                value -= self.parse_mul_div()?;
            } else {
                break;
            }
        }
        Ok(value)
    }

    fn parse_mul_div(&mut self) -> Result<f64, String> {
        let mut value = self.parse_power()?;
        loop {
            self.skip_whitespace();
            if self.consume_char('*') || self.consume_char('x') || self.consume_char('X') {
                value *= self.parse_power()?;
            } else if self.consume_char('/') {
                let rhs = self.parse_power()?;
                if rhs == 0.0 {
                    return Err("Division by zero is not allowed.".to_string());
                }
                value /= rhs;
            } else if self.consume_char('%') {
                let rhs = self.parse_power()?;
                if rhs == 0.0 {
                    return Err("Modulo by zero is not allowed.".to_string());
                }
                value %= rhs;
            } else {
                break;
            }
        }
        Ok(value)
    }

    fn parse_power(&mut self) -> Result<f64, String> {
        let base = self.parse_unary()?;
        self.skip_whitespace();
        if self.consume_char('^') {
            let exponent = self.parse_power()?;
            return Ok(base.powf(exponent));
        }
        Ok(base)
    }

    fn parse_unary(&mut self) -> Result<f64, String> {
        self.skip_whitespace();
        if self.consume_char('+') {
            return self.parse_unary();
        }
        if self.consume_char('-') {
            return Ok(-self.parse_unary()?);
        }
        self.parse_primary()
    }

    fn parse_primary(&mut self) -> Result<f64, String> {
        self.skip_whitespace();
        if self.consume_char('(') {
            let value = self.parse_expression()?;
            self.skip_whitespace();
            if !self.consume_char(')') {
                return Err("Unclosed '(' in expression.".to_string());
            }
            return Ok(value);
        }
        self.parse_number()
    }

    fn parse_number(&mut self) -> Result<f64, String> {
        self.skip_whitespace();
        let start = self.pos;
        let mut saw_digit = false;

        while let Some(ch) = self.peek_char() {
            if ch.is_ascii_digit() {
                saw_digit = true;
                self.advance_char();
            } else {
                break;
            }
        }

        if self.consume_char('.') {
            while let Some(ch) = self.peek_char() {
                if ch.is_ascii_digit() {
                    saw_digit = true;
                    self.advance_char();
                } else {
                    break;
                }
            }
        }

        if matches!(self.peek_char(), Some('e' | 'E')) {
            let exp_start = self.pos;
            self.advance_char();
            if matches!(self.peek_char(), Some('+' | '-')) {
                self.advance_char();
            }
            let mut exp_digits = 0usize;
            while let Some(ch) = self.peek_char() {
                if ch.is_ascii_digit() {
                    exp_digits += 1;
                    self.advance_char();
                } else {
                    break;
                }
            }
            if exp_digits == 0 {
                self.pos = exp_start;
            }
        }

        if !saw_digit {
            return Err(format!("Expected number at position {}.", start));
        }

        let literal = &self.input[start..self.pos];
        literal.parse::<f64>().map_err(|_| {
            format!(
                "Failed to parse numeric literal '{}' at position {}.",
                literal, start
            )
        })
    }

    fn skip_whitespace(&mut self) {
        while matches!(self.peek_char(), Some(ch) if ch.is_whitespace()) {
            self.advance_char();
        }
    }

    fn consume_char(&mut self, target: char) -> bool {
        if self.peek_char() == Some(target) {
            self.advance_char();
            true
        } else {
            false
        }
    }

    fn peek_char(&self) -> Option<char> {
        self.input[self.pos..].chars().next()
    }

    fn advance_char(&mut self) {
        if let Some(ch) = self.peek_char() {
            self.pos += ch.len_utf8();
        }
    }

    fn is_eof(&self) -> bool {
        self.pos >= self.input.len()
    }
}

#[cfg(test)]
mod tests {
    use super::{evaluate_expression, render_numeric};

    #[test]
    fn evaluates_basic_arithmetic() {
        let value = evaluate_expression("247 * 38").expect("expression should parse");
        assert_eq!(render_numeric(value), "9386");
    }

    #[test]
    fn respects_parentheses_and_precedence() {
        let value = evaluate_expression("(12 + 8) / 5").expect("expression should parse");
        assert_eq!(render_numeric(value), "4");
    }

    #[test]
    fn supports_unicode_math_operators() {
        let value = evaluate_expression("42 × 2 − 5").expect("expression should parse");
        assert_eq!(render_numeric(value), "79");
    }

    #[test]
    fn supports_natural_language_wrapped_expressions() {
        let value = evaluate_expression("What's 247 x 38?").expect("expression should parse");
        assert_eq!(render_numeric(value), "9386");
    }

    #[test]
    fn rejects_division_by_zero() {
        let err = evaluate_expression("5 / 0").expect_err("should reject divide-by-zero");
        assert!(err.contains("Division by zero"));
    }

    #[test]
    fn rejects_invalid_tokens() {
        let err = evaluate_expression("2 + apples").expect_err("should reject invalid token");
        assert!(err.contains("Expected number"));
    }
}
