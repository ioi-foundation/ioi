//! Constant-shape GF(2^8) helpers for byte-wise Shamir sharing.

/// Adds two field elements.
#[inline]
pub(super) fn add(left: u8, right: u8) -> u8 {
    left ^ right
}

/// Multiplies in the AES field `x^8 + x^4 + x^3 + x + 1`.
pub(super) fn mul(mut left: u8, mut right: u8) -> u8 {
    let mut result = 0u8;
    for _ in 0..8 {
        let mask = (right & 1).wrapping_neg();
        result ^= left & mask;
        let carry = left >> 7;
        left <<= 1;
        left ^= 0x1b & carry.wrapping_neg();
        right >>= 1;
    }
    result
}

fn pow(mut base: u8, mut exponent: u16) -> u8 {
    let mut result = 1u8;
    while exponent != 0 {
        let mask = (exponent & 1).wrapping_neg() as u8;
        let product = mul(result, base);
        result = (result & !mask) | (product & mask);
        base = mul(base, base);
        exponent >>= 1;
    }
    result
}

fn inverse(value: u8) -> Result<u8, String> {
    if value == 0 {
        return Err("cannot invert zero in GF(256)".into());
    }
    Ok(pow(value, 254))
}

pub(super) fn evaluate(coefficients: &[[u8; 32]], x: u8) -> [u8; 32] {
    let mut output = [0u8; 32];
    for coefficient in coefficients.iter().rev() {
        for (output_byte, coefficient_byte) in output.iter_mut().zip(coefficient.iter()) {
            *output_byte = add(mul(*output_byte, x), *coefficient_byte);
        }
    }
    output
}

/// Evaluates the unique degree-`points.len()-1` polynomial through `points`
/// at `x` using Lagrange interpolation.
pub(super) fn interpolate_at(points: &[(u8, [u8; 32])], x: u8) -> Result<[u8; 32], String> {
    if points.is_empty() {
        return Err("GF(256) interpolation needs at least one point".into());
    }
    let mut output = [0u8; 32];
    for (position, (x_i, y_i)) in points.iter().enumerate() {
        let mut numerator = 1u8;
        let mut denominator = 1u8;
        for (other_position, (x_j, _)) in points.iter().enumerate() {
            if position == other_position {
                continue;
            }
            if x_i == x_j {
                return Err("GF(256) interpolation contains a duplicate x-coordinate".into());
            }
            numerator = mul(numerator, add(x, *x_j));
            denominator = mul(denominator, add(*x_i, *x_j));
        }
        let basis = mul(numerator, inverse(denominator)?);
        for (output_byte, y_byte) in output.iter_mut().zip(y_i.iter()) {
            *output_byte ^= mul(*y_byte, basis);
        }
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interpolation_recovers_polynomial_at_every_point() {
        let coefficients = [[9u8; 32], [17u8; 32], [31u8; 32]];
        let points = (1..=3)
            .map(|x| (x, evaluate(&coefficients, x)))
            .collect::<Vec<_>>();
        assert_eq!(interpolate_at(&points, 0).unwrap(), coefficients[0]);
        for x in 1..=12 {
            assert_eq!(
                interpolate_at(&points, x).unwrap(),
                evaluate(&coefficients, x)
            );
        }
    }

    #[test]
    fn duplicate_coordinates_are_refused() {
        assert!(interpolate_at(&[(1, [1; 32]), (1, [2; 32])], 0).is_err());
    }
}
