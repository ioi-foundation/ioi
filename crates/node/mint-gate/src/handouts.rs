//! THE HAND-OUT RECONCILE (BUILD-DELTA #36; Codex batch-3 r6 MAJOR 3): TESTS FIRST. This stub derives
//! no candidate; the tests in tests.rs state what the reconcile must find.

use proc_macro2::LineColumn;
use std::collections::{BTreeMap, BTreeSet};

pub const RETURN: &str = "return";
pub const MUT_PARAM: &str = "&mut parameter";
pub const NON_LOCAL: &str = "non-local write";
pub const CHANNEL: &str = "channel send";
pub const STATIC: &str = "static";
pub const CAPTURE: &str = "closure capture";
pub const UNANALYZED: &str = "unanalyzed item";

pub type Sinks = BTreeMap<&'static str, BTreeSet<usize>>;

pub fn analyze(_sig: &syn::Signature, _block: &syn::Block, _draws: &[LineColumn]) -> Sinks {
    Sinks::new()
}

pub fn item_sinks(_item: &str, _line: usize) -> Option<Sinks> {
    None
}

pub fn kinds(sinks: &Sinks) -> String {
    sinks.keys().copied().collect::<Vec<_>>().join(",")
}

pub fn render(_sinks: &Sinks) -> String {
    String::new()
}
