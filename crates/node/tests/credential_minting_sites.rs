//! BUILD-DELTA #36, the class sweep: every site in crates/node and crates/services that MINTS a bearer
//! credential (a token a caller presents to prove authority) is registered here with its entropy source, and the
//! source text around it must show that source and no derivation from non-secret inputs. A credential-prefixed
//! literal that is not registered fails the test, so a new minting site must be added here, with its source,
//! before it can land. The check is textual: it proves what each site's source says, not what its runtime does.

use std::fs;
use std::path::{Path, PathBuf};

struct Site {
    file: &'static str,
    anchor: &'static str,
    /// Lines to read before and after the anchor.
    before: usize,
    after: usize,
    /// The entropy source the window must show.
    entropy: &'static str,
    note: &'static str,
}

const SITES: &[Site] = &[
    Site { file: "node/src/bin/hypervisor_daemon_routes/lifecycle_routes.rs", anchor: "pub(crate) fn gen_opaque", before: 0, after: 6, entropy: "uuid::Uuid::new_v4()", note: "bootstrap, session, SCIM and invite tokens: two UUIDv4 (OS RNG, 244 bits)" },
    Site { file: "node/src/bin/hypervisor_daemon_routes/lifecycle_routes.rs", anchor: "\"ioi_pat_{}{}\"", before: 2, after: 4, entropy: "uuid::Uuid::new_v4()", note: "API access tokens: two UUIDv4" },
    Site { file: "node/src/bin/hypervisor_daemon_routes/lifecycle_routes.rs", anchor: "pub(crate) fn random_token", before: 0, after: 8, entropy: "rand::thread_rng()", note: "OAuth state, nonce and PKCE verifier: the thread CSPRNG, seeded from the OS" },
    Site { file: "node/src/bin/hypervisor_daemon_routes/managed_runtime_routes.rs", anchor: "let token = uuid::Uuid::new_v4().to_string();", before: 0, after: 1, entropy: "uuid::Uuid::new_v4()", note: "managed backup export download token: UUIDv4 (122 bits), stored as a hash" },
    Site { file: "node/src/bin/hypervisor_daemon_routes/authority_routes.rs", anchor: "format!(\"ioi_lease_{}\"", before: 4, after: 0, entropy: "rand::rngs::OsRng.fill_bytes(&mut secret)", note: "env-ops capability lease bearer: 32 bytes from the OS RNG" },
    Site { file: "node/src/bin/hypervisor_daemon_routes/workload_effect_boundary.rs", anchor: "format!(\"wec_{}\"", before: 3, after: 0, entropy: "OsRng.fill_bytes(&mut random)", note: "workload effect capability token: 32 bytes from the OS RNG" },
    Site { file: "services/src/agentic/runtime/kernel/model_mount/capability_token_control.rs", anchor: "format!(\"ioi_mnt_{}\"", before: 8, after: 2, entropy: "OsRng.fill_bytes(&mut secret)", note: "model-mount capability token: 32 bytes from the OS RNG, id drawn separately" },
];

/// Literal prefixes that mark a minted credential in source. Any line holding one must belong to a registered site.
const PREFIXES: &[&str] = &["\"ioi_mnt_{", "\"ioi_pat_{", "\"ioi_lease_{", "\"wec_{", "\"ioi_sess_{", "\"ioi_bootstrap_{", "\"ioi_api_{"];

fn crates_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..")
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).into_iter().flatten().flatten() {
        let path = entry.path();
        if path.is_dir() {
            if path.file_name().is_some_and(|n| n == "tests" || n == "target") {
                continue;
            }
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

#[test]
fn every_registered_minting_site_shows_its_entropy_source_and_no_derivation() {
    for site in SITES {
        let text = fs::read_to_string(crates_dir().join(site.file)).unwrap_or_else(|e| panic!("{}: {e}", site.file));
        let lines: Vec<&str> = text.lines().collect();
        let at = lines
            .iter()
            .position(|line| line.contains(site.anchor))
            .unwrap_or_else(|| panic!("{}: anchor {:?} not found ({})", site.file, site.anchor, site.note));
        let window = lines[at.saturating_sub(site.before)..(at + 1 + site.after).min(lines.len())].join("\n");
        assert!(window.contains(site.entropy), "{}: {} — the window around {:?} must show {:?}\n{window}", site.file, site.note, site.anchor, site.entropy);
        for forbidden in ["hash_json(", "create_hash", "sha256_hex(&format!", "[..32]"] {
            assert!(!window.contains(forbidden), "{}: {} — the window shows a derivation ({forbidden:?})\n{window}", site.file, site.note);
        }
    }
}

#[test]
fn no_credential_prefixed_literal_is_unregistered() {
    let mut files = Vec::new();
    rust_files(&crates_dir().join("node/src"), &mut files);
    rust_files(&crates_dir().join("services/src"), &mut files);
    let mut unregistered = Vec::new();
    for file in files {
        let rel = file.strip_prefix(crates_dir()).unwrap().to_string_lossy().replace('\\', "/");
        let Ok(text) = fs::read_to_string(&file) else { continue };
        for (index, line) in text.lines().enumerate() {
            if PREFIXES.iter().any(|prefix| line.contains(prefix))
                && !SITES.iter().any(|site| site.file == rel && line.contains(site.anchor))
            {
                unregistered.push(format!("{rel}:{}: {}", index + 1, line.trim()));
            }
        }
    }
    assert!(unregistered.is_empty(), "credential minting sites not registered in SITES:\n{}", unregistered.join("\n"));
}
