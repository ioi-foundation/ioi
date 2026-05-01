use super::*;

include!("browser_snapshot/actions.rs");
include!("browser_snapshot/parsing.rs");
include!("browser_snapshot/scroll_targets.rs");
include!("browser_snapshot/fragment_priority.rs");
include!("browser_snapshot/observation.rs");
include!("browser_snapshot/selection_state.rs");
include!("browser_snapshot/target_text.rs");
include!("browser_snapshot/navigation_transition.rs");
include!("browser_snapshot/snapshot_models.rs");
include!("browser_snapshot/visible_states.rs");
include!("browser_snapshot/text_controls.rs");
include!("browser_snapshot/autocomplete.rs");

#[cfg(test)]
#[path = "browser_snapshot/tests.rs"]
mod tests;
