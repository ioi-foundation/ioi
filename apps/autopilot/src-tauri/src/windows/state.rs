use once_cell::sync::Lazy;
use std::sync::Mutex;

use super::SpotlightLayout;

pub(super) static SPOTLIGHT_LAYOUT: Lazy<Mutex<SpotlightLayout>> =
    Lazy::new(|| Mutex::new(SpotlightLayout::default()));
