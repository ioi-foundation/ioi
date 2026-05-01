#![allow(dead_code)]

use super::*;

include!("projection/anchors.rs");

include!("projection/compatibility.rs");

include!("projection/probe_terms.rs");

include!("projection/url_classification.rs");

#[cfg(test)]
#[path = "projection/tests.rs"]
mod tests;
