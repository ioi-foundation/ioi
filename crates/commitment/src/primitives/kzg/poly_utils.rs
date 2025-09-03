// Path: crates/commitment/src/primitives/kzg/poly_utils.rs

//! Polynomial arithmetic utilities for the KZG scheme.
//!
//! This module provides helper functions for polynomial interpolation and division,
//! which are essential for constructing and proving KZG commitments. It operates
//! on polynomials whose coefficients are `Scalar`s from the `dcrypt` BLS12-31
//! implementation.

use dcrypt::algorithms::ec::bls12_381::Bls12_381Scalar as Scalar;
use std::ops::{Add, Mul, Sub};

/// A simple representation of a polynomial for utility functions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Polynomial {
    /// Coefficients in ascending order of degree, i.e., c_0, c_1, c_2, ...
    pub coeffs: Vec<Scalar>,
}

impl Polynomial {
    /// Creates a new polynomial with all-zero coefficients.
    pub fn zero(degree: usize) -> Self {
        Self {
            coeffs: vec![Scalar::zero(); degree + 1],
        }
    }

    /// Evaluates the polynomial at a given point `x` using Horner's method.
    pub fn eval(&self, x: &Scalar) -> Scalar {
        self.coeffs
            .iter()
            .rev()
            .fold(Scalar::zero(), |acc, coeff| acc * x + coeff)
    }
}

// Implement standard operations for cleaner code in interpolation/division.

impl<'b> Add<&'b Polynomial> for &Polynomial {
    type Output = Polynomial;
    fn add(self, rhs: &'b Polynomial) -> Polynomial {
        let max_len = self.coeffs.len().max(rhs.coeffs.len());
        let mut result_coeffs = Vec::with_capacity(max_len);
        // --- FIX for E0716: Create a longer-lived binding for the zero scalar ---
        let zero_scalar = Scalar::zero();
        for i in 0..max_len {
            let a = self.coeffs.get(i).unwrap_or(&zero_scalar);
            let b = rhs.coeffs.get(i).unwrap_or(&zero_scalar);
            result_coeffs.push(*a + *b);
        }
        Polynomial {
            coeffs: result_coeffs,
        }
    }
}

impl<'b> Sub<&'b Polynomial> for &Polynomial {
    type Output = Polynomial;
    fn sub(self, rhs: &'b Polynomial) -> Polynomial {
        let max_len = self.coeffs.len().max(rhs.coeffs.len());
        let mut result_coeffs = Vec::with_capacity(max_len);
        // --- FIX for E0716: Create a longer-lived binding for the zero scalar ---
        let zero_scalar = Scalar::zero();
        for i in 0..max_len {
            let a = self.coeffs.get(i).unwrap_or(&zero_scalar);
            let b = rhs.coeffs.get(i).unwrap_or(&zero_scalar);
            result_coeffs.push(*a - *b);
        }
        Polynomial {
            coeffs: result_coeffs,
        }
    }
}

impl<'b> Mul<&'b Polynomial> for &Polynomial {
    type Output = Polynomial;
    fn mul(self, rhs: &'b Polynomial) -> Polynomial {
        if self.coeffs.is_empty() || rhs.coeffs.is_empty() {
            return Polynomial { coeffs: vec![] };
        }
        let mut result = Polynomial::zero(self.coeffs.len() + rhs.coeffs.len() - 2);
        for (i, a) in self.coeffs.iter().enumerate() {
            for (j, b) in rhs.coeffs.iter().enumerate() {
                result.coeffs[i + j] += *a * *b;
            }
        }
        result
    }
}

/// Computes polynomial subtraction: `p(X) - y`.
pub fn poly_sub_scalar(poly: &Polynomial, y: Scalar) -> Polynomial {
    if poly.coeffs.is_empty() {
        return Polynomial { coeffs: vec![-y] };
    }
    let mut result = poly.clone();
    result.coeffs[0] -= y;
    result
}

/// Computes polynomial division `p(X) / (X - z)` using synthetic division.
/// Assumes that `p(z) == 0`, so the remainder is always zero.
pub fn poly_div_linear(poly: &Polynomial, z: Scalar) -> Result<Polynomial, String> {
    if poly.coeffs.is_empty() {
        return Ok(Polynomial { coeffs: vec![] });
    }
    let degree = poly.coeffs.len() - 1;
    if degree == 0 && poly.coeffs[0] == Scalar::zero() {
        return Ok(Polynomial { coeffs: vec![] });
    }
    let mut quotient_coeffs = vec![Scalar::zero(); degree];

    let mut last = Scalar::zero();
    for i in (0..=degree).rev() {
        let coeff = poly.coeffs[i] + last;
        if i > 0 {
            quotient_coeffs[i - 1] = coeff;
        } else {
            // The remainder should be zero
            // --- FIX for E0599: Compare with Scalar::zero() directly ---
            if coeff != Scalar::zero() {
                return Err("Polynomial division had a non-zero remainder.".into());
            }
        }
        last = coeff * z;
    }

    Ok(Polynomial {
        coeffs: quotient_coeffs,
    })
}
