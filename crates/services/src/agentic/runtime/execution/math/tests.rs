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
