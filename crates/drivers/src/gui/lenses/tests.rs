use super::LensRegistry;
use crate::gui::lenses::{auto::AutoLens, react::ReactLens};

#[test]
fn get_supports_legacy_react_lens_alias() {
    let mut registry = LensRegistry::new();
    registry.register(Box::new(ReactLens));
    registry.register(Box::new(AutoLens));

    let lens = registry.get("ReactLens").map(|lens| lens.name());
    assert_eq!(lens, Some("react_semantic"));
}

#[test]
fn get_supports_legacy_universal_lens_aliases() {
    let mut registry = LensRegistry::new();
    registry.register(Box::new(ReactLens));
    registry.register(Box::new(AutoLens));

    let auto_lens = registry.get("AutoLens").map(|lens| lens.name());
    assert_eq!(auto_lens, Some("universal_heuristic_v4"));

    let legacy_universal = registry
        .get("universal_heuristic_v3")
        .map(|lens| lens.name());
    assert_eq!(legacy_universal, Some("universal_heuristic_v4"));
}
