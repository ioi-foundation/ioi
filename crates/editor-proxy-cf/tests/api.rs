//! T-API (DESIGN v2 (4)): the REVIEWED INTERFACES of the trusted crates, pinned. Any new public
//! item, impl, derive, cfg, macro, feature or dependency in `ioi-proxy-digest` or
//! `ioi-editor-proxy-ipc` changes a pin here and so needs review. This is an interface review
//! obligation, not a source census claiming exhaustive prevention of future Rust changes.
//!
//! `CF_API_OUT=<dir>` writes the current listings to <dir> instead of comparing (how the pins in
//! `api/` were produced).

use std::fs;
use std::path::{Path, PathBuf};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("the workspace root")
}

/// Every top-level src/*.rs of the crate (sorted by name; src/tests/ is the cfg(test) module), as
/// (file name, text).
fn crate_files(crate_dir: &str) -> Vec<(String, String)> {
    let src = root().join(crate_dir).join("src");
    let mut files: Vec<PathBuf> = fs::read_dir(&src)
        .expect("src")
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().map(|x| x == "rs").unwrap_or(false))
        .collect();
    files.sort();
    files
        .into_iter()
        .map(|file| {
            (
                file.file_name().unwrap().to_string_lossy().into_owned(),
                fs::read_to_string(&file).expect("source"),
            )
        })
        .collect()
}

/// The crate's interface listing.
fn interface(crate_dir: &str) -> String {
    interface_of(&crate_files(crate_dir))
}

/// The crate's interface lines: in every file, each trimmed line that starts a public item, an
/// impl, a derive, a cfg, a macro or an extern crate.
fn interface_of(files: &[(String, String)]) -> String {
    let mut out = String::new();
    for (name, text) in files {
        for line in text.lines() {
            let t = line.trim();
            let keep = (t.starts_with("pub ") && !t.starts_with("pub(crate)"))
                || t.starts_with("pub(in")
                || t.starts_with("impl")
                || t.starts_with("unsafe impl")
                || t.starts_with("#[derive")
                || t.starts_with("#[cfg")
                || t.starts_with("#![")
                || t.starts_with("macro_rules!")
                || t.starts_with("#[macro_export")
                || t.starts_with("extern crate")
                || t.starts_with("mod ")
                || t.starts_with("pub mod ");
            if keep {
                out.push_str(&format!("{}: {}\n", name, t));
            }
        }
    }
    out
}

fn check_pin(crate_dir: &str, pin: &str) {
    let current = interface(crate_dir);
    if let Ok(dir) = std::env::var("CF_API_OUT") {
        fs::create_dir_all(&dir).expect("api out");
        fs::write(Path::new(&dir).join(pin), &current).expect("api write");
        return;
    }
    let pinned = fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("api").join(pin))
        .unwrap_or_default();
    if current != pinned {
        let missing: Vec<&str> = pinned
            .lines()
            .filter(|l| !current.lines().any(|c| c == *l))
            .collect();
        let added: Vec<&str> = current
            .lines()
            .filter(|l| !pinned.lines().any(|p| p == *l))
            .collect();
        panic!(
            "T-API: the reviewed interface of {} changed (re-pin api/{} with CF_API_OUT after review)\n+ {}\n- {}",
            crate_dir,
            pin,
            added.join("\n+ "),
            missing.join("\n- ")
        );
    }
}

#[test]
fn t_api_the_outbound_digest_interface_is_pinned() {
    check_pin("crates/editor-proxy-digest", "ioi-proxy-digest.api");
}

#[test]
fn t_api_the_codec_interface_is_pinned() {
    check_pin("crates/editor-proxy-codec", "ioi-editor-proxy-ipc.api");
}

/// The crate's manifest text.
fn manifest_text(crate_dir: &str) -> String {
    fs::read_to_string(root().join(crate_dir).join("Cargo.toml")).expect("manifest")
}

/// The manifest's [dependencies] names and whether a [features] table exists.
fn manifest(crate_dir: &str) -> (Vec<String>, bool) {
    manifest_of(&manifest_text(crate_dir))
}

/// The [dependencies] names of a manifest text and whether a [features] table exists.
fn manifest_of(text: &str) -> (Vec<String>, bool) {
    let mut section = String::new();
    let mut deps = Vec::new();
    let mut features = false;
    for line in text.lines() {
        let t = line.trim();
        if t.starts_with('[') {
            section = t.to_string();
            if t.starts_with("[features") {
                features = true;
            }
            continue;
        }
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        if section == "[dependencies]"
            || section.starts_with("[target.")
            || section == "[build-dependencies]"
        {
            deps.push(format!(
                "{} {}",
                section,
                t.split('=').next().unwrap_or("").trim()
            ));
        }
    }
    (deps, features)
}

#[test]
fn t_api_no_features_and_exactly_the_reviewed_dependencies() {
    let (deps, features) = manifest("crates/editor-proxy-digest");
    assert!(!features, "T-API: ioi-proxy-digest has no cargo features");
    assert_eq!(
        deps,
        vec!["[dependencies] sha2".to_string()],
        "T-API: digest dependencies"
    );
    let (deps, features) = manifest("crates/editor-proxy-codec");
    assert!(
        !features,
        "T-API: ioi-editor-proxy-ipc has no cargo features (no feature exposes a test encoder)"
    );
    assert_eq!(
        deps,
        vec!["[dependencies] ioi-proxy-digest".to_string()],
        "T-API: codec dependencies"
    );
}

fn all_sources(crate_dir: &str) -> Vec<(String, String)> {
    fn walk(dir: &Path, out: &mut Vec<(String, String)>) {
        let mut entries: Vec<PathBuf> = fs::read_dir(dir)
            .expect("dir")
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .collect();
        entries.sort();
        for path in entries {
            if path.is_dir() {
                walk(&path, out);
            } else if path.extension().map(|x| x == "rs").unwrap_or(false) {
                out.push((
                    path.display().to_string(),
                    fs::read_to_string(&path).expect("source"),
                ));
            }
        }
    }
    let mut out = Vec::new();
    walk(&root().join(crate_dir).join("src"), &mut out);
    out
}

#[test]
fn t_api_production_forbids_unsafe_and_gates_test_code() {
    for crate_dir in ["crates/editor-proxy-digest", "crates/editor-proxy-codec"] {
        let lib = fs::read_to_string(root().join(crate_dir).join("src/lib.rs")).expect("lib.rs");
        assert!(
            lib.contains("\n#![forbid(unsafe_code)]\n"),
            "T-API: {} forbids unsafe code",
            crate_dir
        );
        assert!(
            lib.contains("\n#![no_std]\n"),
            "T-API: {} is no_std",
            crate_dir
        );
        for (path, text) in all_sources(crate_dir) {
            assert!(
                !text.contains("cfg(feature"),
                "T-API: {} uses a feature cfg",
                path
            );
            assert!(
                !text.contains("unsafe {") && !text.contains("unsafe fn"),
                "T-API: unsafe in {}",
                path
            );
            assert!(
                !text.contains("macro_export"),
                "T-API: an exported macro in {}",
                path
            );
        }
    }
    let lib =
        fs::read_to_string(root().join("crates/editor-proxy-codec/src/lib.rs")).expect("lib.rs");
    assert!(
        lib.contains("\n#[cfg(test)]\nmod tests;\n"),
        "T-API: the test-only encoder's module is cfg(test)"
    );
    assert!(
        lib.contains("#[cfg(any(test, fuzzing))]\npub mod fuzz_support;\n"),
        "T-API: the fuzz interpreter is cfg(test)/cfg(fuzzing) only"
    );
    // Every test_only_ item is behind a test/fuzzing cfg: a cfg'd impl block or its own cfg.
    for (path, text) in all_sources("crates/editor-proxy-codec") {
        if path.contains("/src/tests/") {
            continue;
        }
        let lines: Vec<&str> = text.lines().collect();
        let mut block_gated = false;
        for (i, line) in lines.iter().enumerate() {
            if line.starts_with("impl") {
                let mut j = i;
                block_gated = false;
                while j > 0 {
                    j -= 1;
                    let above = lines[j].trim();
                    if above.starts_with("///") {
                        continue;
                    }
                    block_gated = above == "#[cfg(any(test, fuzzing))]" || above == "#[cfg(test)]";
                    break;
                }
            } else if line.starts_with('}') {
                block_gated = false;
            }
            if line.contains("fn test_only_") {
                let own = lines[..i]
                    .iter()
                    .rev()
                    .map(|l| l.trim())
                    .find(|l| !l.starts_with("///"))
                    .map(|l| l == "#[cfg(test)]" || l == "#[cfg(any(test, fuzzing))]")
                    .unwrap_or(false);
                assert!(
                    block_gated || own,
                    "T-API: {}:{} test_only_ item is not cfg-gated",
                    path,
                    i + 1
                );
            }
        }
    }
}

// ---- the pins DETECT interface and dependency changes (Codex #85 U1 r1 MAJOR 3) ----------------
//
// Each test applies ONE textual change to a copy of a trusted crate's real source or manifest and
// requires the collector's listing to change (so the pin comparison above fails on it).

/// The crate's files with exactly one occurrence of `old` in `file` replaced by `new`.
fn edited(crate_dir: &str, file: &str, old: &str, new: &str) -> Vec<(String, String)> {
    let mut files = crate_files(crate_dir);
    let entry = files
        .iter_mut()
        .find(|(name, _)| name == file)
        .expect("SETUP: the file");
    assert_eq!(
        entry.1.matches(old).count(),
        1,
        "SETUP: the anchor occurs once"
    );
    entry.1 = entry.1.replacen(old, new, 1);
    files
}

/// The manifest text with exactly one occurrence of `old` replaced by `new`.
fn edited_manifest(crate_dir: &str, old: &str, new: &str) -> String {
    let text = manifest_text(crate_dir);
    assert_eq!(
        text.matches(old).count(),
        1,
        "SETUP: the anchor occurs once"
    );
    text.replacen(old, new, 1)
}

const CODEC: &str = "crates/editor-proxy-codec";
const DIGEST: &str = "crates/editor-proxy-digest";

#[test]
fn t_api_pin_detects_a_changed_argument_type() {
    let changed = edited(
        CODEC,
        "wire.rs",
        "        digests: &[Sha256Digest],\n    ) -> Result<OutboundAdmit, TooManyLeaseCandidates> {",
        "        digests: &[[u8; 32]],\n    ) -> Result<OutboundAdmit, TooManyLeaseCandidates> {",
    );
    assert_ne!(
        interface_of(&changed),
        interface(CODEC),
        "T-API: a changed argument type in a pinned multiline signature (OutboundAdmit::new) changes the listing"
    );
}

#[test]
fn t_api_pin_detects_an_added_enum_variant() {
    let changed = edited(
        CODEC,
        "refusal.rs",
        "    RateExceeded,\n}",
        "    RateExceeded,\n    /// Added.\n    Extra,\n}",
    );
    assert_ne!(
        interface_of(&changed),
        interface(CODEC),
        "T-API: an added variant of a public enum (IpcRefusal) changes the listing"
    );
}

#[test]
fn t_api_pin_detects_a_changed_trait_method() {
    let changed = edited(
        CODEC,
        "wire.rs",
        "    fn encode_frame(&self) -> Frame;",
        "    fn encode_frame(&self, extra: u8) -> Frame;",
    );
    assert_ne!(
        interface_of(&changed),
        interface(CODEC),
        "T-API: a changed method of a public trait (EncodeP2d) changes the listing"
    );
}

#[test]
fn t_api_pin_detects_a_changed_reexport_list() {
    let changed = edited(
        CODEC,
        "lib.rs",
        "    P2dRecv, MAX_FRAME,\n};",
        "    P2dRecv, MAX_FRAME, RECV_BUF_LEN,\n};",
    );
    assert_ne!(
        interface_of(&changed),
        interface(CODEC),
        "T-API: an added name in a multiline re-export (pub use wire::{{...}}) changes the listing"
    );
}

#[test]
fn t_api_pin_detects_a_changed_dependency_feature() {
    let changed = edited_manifest(
        CODEC,
        "ioi-proxy-digest = { path = \"../editor-proxy-digest\" }",
        "ioi-proxy-digest = { path = \"../editor-proxy-digest\", features = [\"std\"] }",
    );
    assert_ne!(
        manifest_of(&changed),
        manifest(CODEC),
        "T-API: an added dependency feature changes the pinned dependency specification"
    );
}

#[test]
fn t_api_pin_detects_a_changed_default_features_flag() {
    let changed = edited_manifest(
        DIGEST,
        "sha2 = { version = \"0.10\", default-features = false }",
        "sha2 = { version = \"0.10\" }",
    );
    assert_ne!(
        manifest_of(&changed),
        manifest(DIGEST),
        "T-API: dropping default-features = false changes the pinned dependency specification"
    );
}

#[test]
fn t_api_pin_reads_table_form_dependencies() {
    let same = edited_manifest(
        DIGEST,
        "[dependencies]\nsha2 = { version = \"0.10\", default-features = false }",
        "[dependencies.sha2]\nversion = \"0.10\"\ndefault-features = false",
    );
    assert_eq!(
        manifest_of(&same),
        manifest(DIGEST),
        "T-API: the same dependency written as a [dependencies.sha2] table has the same pinned specification"
    );
    let featured = edited_manifest(
        DIGEST,
        "[dependencies]\nsha2 = { version = \"0.10\", default-features = false }",
        "[dependencies.sha2]\nversion = \"0.10\"\ndefault-features = false\nfeatures = [\"asm\"]",
    );
    assert_ne!(
        manifest_of(&featured),
        manifest(DIGEST),
        "T-API: a feature added in a [dependencies.sha2] table changes the pinned specification"
    );
}
