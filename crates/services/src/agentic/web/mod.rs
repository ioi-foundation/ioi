mod anchor_policy;
mod constants;
mod parsers;
mod readability;
mod search;
mod transport;
mod types;
mod urls;
mod util;

#[cfg(test)]
mod tests;

pub use readability::edge_web_read;
pub use search::edge_web_search;
pub use urls::{build_ddg_serp_url, build_default_search_url};
