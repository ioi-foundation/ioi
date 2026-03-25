mod browser_use_state;
mod element_click;
mod handler;
mod selector_click;
mod snapshot;
mod surface;
pub(crate) mod tree;

pub use handler::handle;
pub(super) use surface::{browser_surface_regions, is_probable_browser_window};

#[cfg(test)]
mod tests;
