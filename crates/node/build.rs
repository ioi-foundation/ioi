// Path: crates/node/build.rs

fn main() {
    let features: Vec<String> = std::env::vars()
        .filter(|(key, _)| key.starts_with("CARGO_FEATURE_TREE_"))
        .map(|(key, _)| key)
        .collect();

    if features.len() > 1 {
        // The panic message will be displayed as a compile error.
        panic!(
            "Error: Please enable exactly one 'tree-*' feature for the depin-sdk-node crate. Found: {:?}",
            features
        );
    }
}
