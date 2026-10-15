//! THE COMPILE-FAIL BATTERY (DESIGN v2 (4); T-DIRECTION is cf16).
//!
//! 1. A nested `cargo build -p ioi-editor-proxy-cf --lib --message-format=json` (own target dir
//!    under CARGO_TARGET_TMPDIR, offline, locked) yields the PRODUCTION rlibs and their deps.
//! 2. cf00 (positive) must compile: otherwise every negative's evidence is invalid (SETUP_ERROR).
//! 3. Each NEGATIVE fixture is compiled by rustc against the production rlibs and must fail with
//!    ONLY its pinned diagnostic class, at its marked operation (`//~ <id>`). A fixture that
//!    COMPILES is an ASSERTION_FAIL (the restriction is missing); any other diagnostic, or a
//!    failure elsewhere than the marked line, is a SETUP_ERROR (invalid evidence, never a pass).
//! 4. Each CONTROL: for an API restriction, the defining crate copied with exactly ONE weakening
//!    must make the SAME fixture compile; for the premises cf08/cf09, the same fixture with one
//!    textual change must compile. A control that does not compile is an ASSERTION_FAIL.
//!
//! MUTANT MODE (the RED evidence for the battery): `CF_PRODUCTION_WEAKENING=<id>` builds the
//! defining crate WITH that fixture's weakening and uses it as "production" for every negative
//! (controls skipped). The battery must then FAIL, naming that fixture (and only fixtures the same
//! weakening also opens). The report's last line is `CF BATTERY FAILED: [...]` or `CF BATTERY OK`.

use serde_json::Value;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Krate {
    Digest,
    Codec,
}

#[derive(Clone, Copy)]
enum Edit {
    /// Replace the ONE occurrence of `anchor` (more or fewer is a SETUP_ERROR).
    Replace(&'static str, &'static str),
    /// Append an item at the end of the file.
    Append(&'static str),
}

#[derive(Clone, Copy)]
enum Control {
    /// The defining crate, with exactly this one edit to `file` (relative to its src/), makes the
    /// fixture compile.
    Weaken(Krate, &'static str, Edit),
    /// PREMISE: the same fixture with this one textual edit compiles.
    Premise(Edit),
}

struct Fixture {
    id: &'static str,
    file: &'static str,
    code: &'static str,
    control: Control,
}

const DIGEST_FIELD: Edit = Edit::Replace(
    "pub struct Sha256Digest([u8; 32]);",
    "pub struct Sha256Digest(pub [u8; 32]);",
);
const INBOUND_FIELD: Edit = Edit::Replace(
    "pub struct CompareOnlyDigest([u8; 32]);",
    "pub struct CompareOnlyDigest(pub [u8; 32]);",
);

const FIXTURES: &[Fixture] = &[
    Fixture {
        id: "cf01",
        file: "cf01_digest_tuple_construction.rs",
        code: "E0423",
        control: Control::Weaken(Krate::Digest, "lib.rs", DIGEST_FIELD),
    },
    Fixture {
        id: "cf02",
        file: "cf02_digest_from_array.rs",
        code: "E0277",
        control: Control::Weaken(
            Krate::Digest,
            "lib.rs",
            Edit::Append(
                "impl From<[u8; 32]> for Sha256Digest {\n    fn from(bytes: [u8; 32]) -> Sha256Digest {\n        Sha256Digest(bytes)\n    }\n}\n",
            ),
        ),
    },
    Fixture {
        id: "cf03",
        file: "cf03_digest_try_from_array.rs",
        code: "E0277",
        control: Control::Weaken(
            Krate::Digest,
            "lib.rs",
            Edit::Append(
                "impl TryFrom<[u8; 32]> for Sha256Digest {\n    type Error = core::convert::Infallible;\n    fn try_from(bytes: [u8; 32]) -> Result<Sha256Digest, Self::Error> {\n        Ok(Sha256Digest(bytes))\n    }\n}\n",
            ),
        ),
    },
    Fixture {
        id: "cf04",
        file: "cf04_digest_default.rs",
        code: "E0599",
        control: Control::Weaken(
            Krate::Digest,
            "lib.rs",
            Edit::Append(
                "impl Default for Sha256Digest {\n    fn default() -> Sha256Digest {\n        Sha256Digest([0u8; 32])\n    }\n}\n",
            ),
        ),
    },
    Fixture {
        id: "cf05",
        file: "cf05_digest_from_str.rs",
        code: "E0277",
        control: Control::Weaken(
            Krate::Digest,
            "lib.rs",
            Edit::Append(
                "impl core::str::FromStr for Sha256Digest {\n    type Err = ();\n    fn from_str(_text: &str) -> Result<Sha256Digest, ()> {\n        Ok(Sha256Digest([0u8; 32]))\n    }\n}\n",
            ),
        ),
    },
    Fixture {
        id: "cf06",
        file: "cf06_digest_deserialize.rs",
        code: "E0277",
        control: Control::Weaken(
            Krate::Digest,
            "lib.rs",
            Edit::Append(
                "impl<'de> serde::Deserialize<'de> for Sha256Digest {\n    fn deserialize<D: serde::Deserializer<'de>>(input: D) -> Result<Sha256Digest, D::Error> {\n        <[u8; 32] as serde::Deserialize<'de>>::deserialize(input).map(Sha256Digest)\n    }\n}\n",
            ),
        ),
    },
    Fixture {
        id: "cf07",
        file: "cf07_digest_field_access.rs",
        code: "E0616",
        control: Control::Weaken(Krate::Digest, "lib.rs", DIGEST_FIELD),
    },
    Fixture {
        id: "cf08",
        file: "cf08_premise_orphan_from.rs",
        code: "E0117",
        control: Control::Premise(Edit::Replace("for Sha256Digest {", "for LocalDigest {")),
    },
    Fixture {
        id: "cf09",
        file: "cf09_premise_forbid_unsafe.rs",
        code: "unsafe_code",
        control: Control::Premise(Edit::Replace("#![forbid(unsafe_code)]\n", "")),
    },
    Fixture {
        id: "cf10",
        file: "cf10_admit_from_raw_arrays.rs",
        code: "E0308",
        control: Control::Weaken(
            Krate::Codec,
            "wire.rs",
            Edit::Replace(
                "        digests: &[Sha256Digest],\n    ) -> Result<OutboundAdmit, TooManyLeaseCandidates> {\n        OutboundAdmit::build(purpose, digests.len(), |i| *digests[i].as_bytes())",
                "        digests: &[[u8; 32]],\n    ) -> Result<OutboundAdmit, TooManyLeaseCandidates> {\n        OutboundAdmit::build(purpose, digests.len(), |i| digests[i])",
            ),
        ),
    },
    Fixture {
        id: "cf11",
        file: "cf11_inbound_byte_accessor.rs",
        code: "E0599",
        control: Control::Weaken(
            Krate::Codec,
            "digest.rs",
            Edit::Replace(
                "impl CompareOnlyDigest {\n",
                "impl CompareOnlyDigest {\n    /// WEAKENING cf11.\n    pub fn as_bytes(&self) -> &[u8; 32] {\n        &self.0\n    }\n\n",
            ),
        ),
    },
    Fixture {
        id: "cf11b",
        file: "cf11b_inbound_field_access.rs",
        code: "E0616",
        control: Control::Weaken(Krate::Codec, "digest.rs", INBOUND_FIELD),
    },
    Fixture {
        id: "cf12",
        file: "cf12_inbound_debug.rs",
        code: "E0277",
        control: Control::Weaken(
            Krate::Codec,
            "digest.rs",
            Edit::Append(
                "impl core::fmt::Debug for CompareOnlyDigest {\n    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {\n        f.write_str(\"weakened\")\n    }\n}\n",
            ),
        ),
    },
    Fixture {
        id: "cf12b",
        file: "cf12b_inbound_display.rs",
        code: "E0277",
        control: Control::Weaken(
            Krate::Codec,
            "digest.rs",
            Edit::Append(
                "impl core::fmt::Display for CompareOnlyDigest {\n    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {\n        f.write_str(\"weakened\")\n    }\n}\n",
            ),
        ),
    },
    Fixture {
        id: "cf13",
        file: "cf13_inbound_serialize.rs",
        code: "E0277",
        control: Control::Weaken(
            Krate::Codec,
            "digest.rs",
            Edit::Append(
                "impl serde::Serialize for CompareOnlyDigest {\n    fn serialize<S: serde::Serializer>(&self, out: S) -> Result<S::Ok, S::Error> {\n        serde::Serialize::serialize(&self.0, out)\n    }\n}\n",
            ),
        ),
    },
    Fixture {
        id: "cf14",
        file: "cf14_inbound_tuple_construction.rs",
        code: "E0423",
        control: Control::Weaken(Krate::Codec, "digest.rs", INBOUND_FIELD),
    },
    Fixture {
        id: "cf15",
        file: "cf15_inbound_clone.rs",
        code: "E0308",
        control: Control::Weaken(
            Krate::Codec,
            "digest.rs",
            Edit::Append(
                "impl Clone for CompareOnlyDigest {\n    fn clone(&self) -> CompareOnlyDigest {\n        CompareOnlyDigest(self.0)\n    }\n}\n",
            ),
        ),
    },
    Fixture {
        id: "cf16",
        file: "cf16_encode_decoded_inbound.rs",
        code: "E0277",
        control: Control::Weaken(
            Krate::Codec,
            "wire.rs",
            Edit::Append(
                "impl sealed::Sealed for InboundP2d {}\n\nimpl EncodeP2d for InboundP2d {\n    fn encode_frame(&self) -> Frame {\n        Frame::start(KIND_READY).finish()\n    }\n}\n",
            ),
        ),
    },
    Fixture {
        id: "cf17",
        file: "cf17_inbound_private_constructor.rs",
        code: "E0624",
        control: Control::Weaken(
            Krate::Codec,
            "digest.rs",
            Edit::Replace(
                "    pub(crate) fn from_wire(bytes: [u8; 32]) -> CompareOnlyDigest {",
                "    /// WEAKENING cf17.\n    pub fn from_wire(bytes: [u8; 32]) -> CompareOnlyDigest {",
            ),
        ),
    },
    Fixture {
        id: "cf18a",
        file: "cf18a_inbound_from_array.rs",
        code: "E0277",
        control: Control::Weaken(
            Krate::Codec,
            "digest.rs",
            Edit::Append(
                "impl From<[u8; 32]> for CompareOnlyDigest {\n    fn from(bytes: [u8; 32]) -> CompareOnlyDigest {\n        CompareOnlyDigest(bytes)\n    }\n}\n",
            ),
        ),
    },
    Fixture {
        id: "cf18b",
        file: "cf18b_inbound_deserialize.rs",
        code: "E0277",
        control: Control::Weaken(
            Krate::Codec,
            "digest.rs",
            Edit::Append(
                "impl<'de> serde::Deserialize<'de> for CompareOnlyDigest {\n    fn deserialize<D: serde::Deserializer<'de>>(input: D) -> Result<CompareOnlyDigest, D::Error> {\n        <[u8; 32] as serde::Deserialize<'de>>::deserialize(input).map(CompareOnlyDigest)\n    }\n}\n",
            ),
        ),
    },
    Fixture {
        id: "cf19",
        file: "cf19_local_trait_private_field.rs",
        code: "E0616",
        control: Control::Weaken(Krate::Digest, "lib.rs", DIGEST_FIELD),
    },
    Fixture {
        id: "cf20",
        file: "cf20_local_macro_private_field.rs",
        code: "E0616",
        control: Control::Weaken(Krate::Codec, "digest.rs", INBOUND_FIELD),
    },
];

struct Env {
    root: PathBuf,
    out: PathBuf,
    deps: PathBuf,
    rlibs: BTreeMap<String, PathBuf>,
    rustc: String,
}

/// One diagnostic of level `error`: its code and the lines of its primary span and the macro
/// expansion sites above it.
struct Error {
    code: Option<String>,
    lines: Vec<u64>,
    message: String,
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("the workspace root")
}

fn nested_build() -> Env {
    let root = workspace_root();
    let base = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("cf-battery");
    let target = base.join("target");
    fs::create_dir_all(&base).expect("battery dir");
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let output = Command::new(cargo)
        .current_dir(&root)
        .args([
            "build",
            "--offline",
            "--locked",
            "-p",
            "ioi-editor-proxy-cf",
            "--lib",
        ])
        .arg("--message-format=json")
        .arg("--target-dir")
        .arg(&target)
        .env_remove("CARGO_TARGET_DIR")
        .env_remove("CARGO_BUILD_TARGET_DIR")
        .env_remove("CARGO_MAKEFLAGS")
        .env_remove("MAKEFLAGS")
        .env_remove("MFLAGS")
        .output()
        .expect("SETUP_ERROR: the nested cargo build did not start");
    assert!(
        output.status.success(),
        "SETUP_ERROR: the nested cargo build failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let mut rlibs = BTreeMap::new();
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        let Ok(message) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        if message["reason"] != "compiler-artifact" {
            continue;
        }
        let name = message["target"]["name"].as_str().unwrap_or("").to_string();
        if let Some(files) = message["filenames"].as_array() {
            for file in files.iter().filter_map(|f| f.as_str()) {
                if file.ends_with(".rlib") {
                    rlibs.insert(name.clone(), PathBuf::from(file));
                }
            }
        }
    }
    for needed in ["ioi_proxy_digest", "ioi_editor_proxy_ipc", "serde", "sha2"] {
        assert!(
            rlibs.contains_key(needed),
            "SETUP_ERROR: no {} rlib from the nested build",
            needed
        );
    }
    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".to_string());
    let version = Command::new(&rustc)
        .current_dir(&root)
        .arg("-V")
        .output()
        .expect("rustc -V");
    println!(
        "CF rustc: {}",
        String::from_utf8_lossy(&version.stdout).trim()
    );
    Env {
        root,
        out: base.join("out"),
        deps: target.join("debug").join("deps"),
        rlibs,
        rustc,
    }
}

impl Env {
    fn rlib(&self, name: &str) -> PathBuf {
        self.rlibs[name].clone()
    }

    /// rustc --emit=metadata of one crate root; the error diagnostics.
    fn compile(
        &self,
        name: &str,
        src: &Path,
        out_dir: &Path,
        externs: &[(&str, PathBuf)],
        cap_lints: bool,
    ) -> Vec<Error> {
        fs::create_dir_all(out_dir).expect("out dir");
        let mut command = Command::new(&self.rustc);
        command
            .current_dir(&self.root)
            .args([
                "--edition=2021",
                "--crate-type=lib",
                "--emit=metadata",
                "--error-format=json",
            ])
            .arg("--crate-name")
            .arg(name)
            .arg(src)
            .arg("-o")
            .arg(out_dir.join(format!("lib{}.rmeta", name)));
        // A TRANSITIVE dependency is found through the search path, not --extern: each extern's
        // own directory comes first (a weakened crate's rmeta), then the nested build's deps.
        for (_, path) in externs {
            if let Some(dir) = path.parent() {
                command
                    .arg("-L")
                    .arg(format!("dependency={}", dir.display()));
            }
        }
        command
            .arg("-L")
            .arg(format!("dependency={}", self.deps.display()));
        if cap_lints {
            command.arg("--cap-lints=warn");
        }
        for (crate_name, path) in externs {
            command
                .arg("--extern")
                .arg(format!("{}={}", crate_name, path.display()));
        }
        let output = command.output().expect("SETUP_ERROR: rustc did not start");
        let mut errors = Vec::new();
        for line in String::from_utf8_lossy(&output.stderr).lines() {
            let Ok(diag) = serde_json::from_str::<Value>(line) else {
                continue;
            };
            if diag["level"] != "error" {
                continue;
            }
            let message = diag["message"].as_str().unwrap_or("").to_string();
            if message.starts_with("aborting due to") {
                continue;
            }
            let code = diag["code"]["code"].as_str().map(|c| c.to_string());
            let mut lines = Vec::new();
            if let Some(spans) = diag["spans"].as_array() {
                for span in spans.iter().filter(|s| s["is_primary"] == true) {
                    let mut current = span;
                    loop {
                        if let Some(line) = current["line_start"].as_u64() {
                            lines.push(line);
                        }
                        if current["expansion"].is_null() {
                            break;
                        }
                        current = &current["expansion"]["span"];
                    }
                }
            }
            errors.push(Error {
                code,
                lines,
                message,
            });
        }
        if errors.is_empty() && !output.status.success() {
            errors.push(Error {
                code: None,
                lines: Vec::new(),
                message: format!("rustc failed without a JSON error: {:?}", output.status),
            });
        }
        errors
    }

    fn src_dir(&self, krate: Krate) -> PathBuf {
        self.root.join(match krate {
            Krate::Digest => "crates/editor-proxy-digest/src",
            Krate::Codec => "crates/editor-proxy-codec/src",
        })
    }

    /// Copies a crate's src/ (top-level .rs files and subdirectories) and applies one edit.
    fn weakened_copy(
        &self,
        tag: &str,
        krate: Krate,
        file: &str,
        edit: Edit,
    ) -> Result<PathBuf, String> {
        let dest = self.out.join(tag).join(format!("{:?}-src", krate));
        copy_dir(&self.src_dir(krate), &dest);
        let target = dest.join(file);
        let text = fs::read_to_string(&target).map_err(|e| format!("read {}: {}", file, e))?;
        let edited = apply(&text, edit).map_err(|e| format!("{} in {}", e, file))?;
        fs::write(&target, edited).expect("write the weakened file");
        Ok(dest.join("lib.rs"))
    }

    /// Builds the digest crate from `src` (rmeta).
    fn build_digest(&self, tag: &str, src: &Path) -> Result<PathBuf, String> {
        let out = self.out.join(tag).join("digest-out");
        let errors = self.compile(
            "ioi_proxy_digest",
            src,
            &out,
            &[("sha2", self.rlib("sha2")), ("serde", self.rlib("serde"))],
            true,
        );
        if !errors.is_empty() {
            return Err(format!(
                "the weakened digest crate does not build: {}",
                first(&errors)
            ));
        }
        Ok(out.join("libioi_proxy_digest.rmeta"))
    }

    /// Builds the codec crate from `src` against `digest` (rmeta).
    fn build_codec(&self, tag: &str, src: &Path, digest: PathBuf) -> Result<PathBuf, String> {
        let out = self.out.join(tag).join("codec-out");
        let errors = self.compile(
            "ioi_editor_proxy_ipc",
            src,
            &out,
            &[("ioi_proxy_digest", digest), ("serde", self.rlib("serde"))],
            true,
        );
        if !errors.is_empty() {
            return Err(format!(
                "the weakened codec crate does not build: {}",
                first(&errors)
            ));
        }
        Ok(out.join("libioi_editor_proxy_ipc.rmeta"))
    }
}

fn first(errors: &[Error]) -> String {
    errors
        .iter()
        .take(3)
        .map(|e| {
            format!(
                "[{}] {} (lines {:?})",
                e.code.clone().unwrap_or_default(),
                e.message,
                e.lines
            )
        })
        .collect::<Vec<_>>()
        .join("; ")
}

fn copy_dir(from: &Path, to: &Path) {
    fs::create_dir_all(to).expect("copy dir");
    for entry in fs::read_dir(from).expect("read src dir") {
        let entry = entry.expect("entry");
        let path = entry.path();
        let dest = to.join(entry.file_name());
        if path.is_dir() {
            copy_dir(&path, &dest);
        } else {
            fs::copy(&path, &dest).expect("copy file");
        }
    }
}

fn apply(text: &str, edit: Edit) -> Result<String, String> {
    match edit {
        Edit::Replace(anchor, with) => {
            let count = text.matches(anchor).count();
            if count != 1 {
                return Err(format!(
                    "SETUP_ERROR: anchor found {} times (needs exactly 1): {:?}",
                    count, anchor
                ));
            }
            Ok(text.replacen(anchor, with, 1))
        }
        Edit::Append(item) => Ok(format!("{}\n{}", text, item)),
    }
}

fn marker_line(text: &str, id: &str) -> Option<u64> {
    let marker = format!("//~ {}", id);
    let hits: Vec<u64> = text
        .lines()
        .enumerate()
        .filter(|(_, line)| line.trim_end().ends_with(&marker))
        .map(|(i, _)| i as u64 + 1)
        .collect();
    if hits.len() == 1 {
        Some(hits[0])
    } else {
        None
    }
}

/// The production (or, in mutant mode, weakened) externs a fixture links.
struct Externs {
    digest: PathBuf,
    codec: PathBuf,
}

impl Externs {
    fn list(&self, env: &Env) -> Vec<(&'static str, PathBuf)> {
        vec![
            ("ioi_proxy_digest", self.digest.clone()),
            ("ioi_editor_proxy_ipc", self.codec.clone()),
            ("serde", env.rlib("serde")),
        ]
    }
}

#[derive(Debug, PartialEq)]
enum Outcome {
    Pass,
    AssertionFail(String),
    SetupError(String),
}

fn judge_negative(fixture: &Fixture, errors: &[Error], marker: u64) -> Outcome {
    if errors.is_empty() {
        return Outcome::AssertionFail(
            "the negative COMPILED against production: the restriction is missing".to_string(),
        );
    }
    if let Some(other) = errors
        .iter()
        .find(|e| e.code.as_deref() != Some(fixture.code))
    {
        return Outcome::SetupError(format!(
            "an unrelated diagnostic (want only {}): {}",
            fixture.code,
            first(std::slice::from_ref(other))
        ));
    }
    if !errors.iter().any(|e| e.lines.contains(&marker)) {
        return Outcome::SetupError(format!(
            "{} raised elsewhere than the marked operation (line {}): {}",
            fixture.code,
            marker,
            first(errors)
        ));
    }
    Outcome::Pass
}

/// `real` = the unweakened production rlibs (cf00 validates the environment against them);
/// `production` = what the negatives link (the real rlibs, or in mutant mode the weakened ones).
fn run_battery(
    env: &Env,
    real: &Externs,
    production: &Externs,
    with_controls: bool,
) -> Vec<(String, &'static str, Outcome)> {
    let fixtures_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures");
    let mut results = Vec::new();
    // cf00: the positive control for the whole battery.
    let positive = fixtures_dir.join("cf00_positive.rs");
    let errors = env.compile(
        "cf00",
        &positive,
        &env.out.join("cf00"),
        &real.list(env),
        false,
    );
    if !errors.is_empty() {
        println!("CF cf00 POSITIVE SETUP_ERROR: {}", first(&errors));
        results.push((
            "cf00".to_string(),
            "POSITIVE",
            Outcome::SetupError(format!("cf00 does not compile: {}", first(&errors))),
        ));
        return results;
    }
    println!("CF cf00 POSITIVE Pass");
    results.push(("cf00".to_string(), "POSITIVE", Outcome::Pass));
    for fixture in FIXTURES {
        let path = fixtures_dir.join(fixture.file);
        let text = fs::read_to_string(&path).expect("fixture");
        let Some(marker) = marker_line(&text, fixture.id) else {
            results.push((
                fixture.id.to_string(),
                "NEGATIVE",
                Outcome::SetupError("no single marker".to_string()),
            ));
            continue;
        };
        let tag = format!("{}-neg", fixture.id);
        let errors = env.compile(
            fixture.id,
            &path,
            &env.out.join(&tag),
            &production.list(env),
            false,
        );
        let verdict = judge_negative(fixture, &errors, marker);
        println!(
            "CF {} NEGATIVE {:?} (want {} at line {}; got {})",
            fixture.id,
            verdict,
            fixture.code,
            marker,
            if errors.is_empty() {
                "no error".to_string()
            } else {
                first(&errors)
            }
        );
        results.push((fixture.id.to_string(), "NEGATIVE", verdict));
        if !with_controls {
            continue;
        }
        let tag = format!("{}-ctl", fixture.id);
        let control = match fixture.control {
            Control::Premise(edit) => match apply(&text, edit) {
                Err(e) => Outcome::SetupError(e),
                Ok(edited) => {
                    let dir = env.out.join(&tag);
                    fs::create_dir_all(&dir).expect("control dir");
                    let src = dir.join(fixture.file);
                    fs::write(&src, edited).expect("control fixture");
                    let errors = env.compile(fixture.id, &src, &dir, &production.list(env), false);
                    if errors.is_empty() {
                        Outcome::Pass
                    } else {
                        Outcome::AssertionFail(format!(
                            "the premise control does not compile: {}",
                            first(&errors)
                        ))
                    }
                }
            },
            Control::Weaken(krate, file, edit) => {
                let built =
                    env.weakened_copy(&tag, krate, file, edit)
                        .and_then(|src| match krate {
                            Krate::Digest => {
                                let digest = env.build_digest(&tag, &src)?;
                                let codec = env.build_codec(
                                    &tag,
                                    &env.src_dir(Krate::Codec).join("lib.rs"),
                                    digest.clone(),
                                )?;
                                Ok(Externs { digest, codec })
                            }
                            Krate::Codec => {
                                let codec =
                                    env.build_codec(&tag, &src, production.digest.clone())?;
                                Ok(Externs {
                                    digest: production.digest.clone(),
                                    codec,
                                })
                            }
                        });
                match built {
                    Err(e) => Outcome::SetupError(e),
                    Ok(weak) => {
                        let errors = env.compile(
                            fixture.id,
                            &path,
                            &env.out.join(&tag),
                            &weak.list(env),
                            false,
                        );
                        if errors.is_empty() {
                            Outcome::Pass
                        } else {
                            Outcome::AssertionFail(format!(
                                "the weakened crate still rejects the fixture: {}",
                                first(&errors)
                            ))
                        }
                    }
                }
            }
        };
        println!("CF {} CONTROL {:?}", fixture.id, control);
        results.push((fixture.id.to_string(), "CONTROL", control));
    }
    results
}

#[test]
fn compile_fail_battery() {
    let env = nested_build();
    let real = Externs {
        digest: env.rlib("ioi_proxy_digest"),
        codec: env.rlib("ioi_editor_proxy_ipc"),
    };
    let mut production = Externs {
        digest: real.digest.clone(),
        codec: real.codec.clone(),
    };
    let mutant = std::env::var("CF_PRODUCTION_WEAKENING").ok();
    if let Some(id) = &mutant {
        let fixture = FIXTURES
            .iter()
            .find(|f| f.id == id.as_str())
            .unwrap_or_else(|| panic!("SETUP_ERROR: no fixture {}", id));
        let Control::Weaken(krate, file, edit) = fixture.control else {
            panic!(
                "SETUP_ERROR: {} is a premise; it has no production weakening",
                id
            );
        };
        let tag = format!("mutant-{}", id);
        let src = env
            .weakened_copy(&tag, krate, file, edit)
            .expect("the mutant copy");
        production = match krate {
            Krate::Digest => {
                let digest = env.build_digest(&tag, &src).expect("the mutant digest");
                let codec = env
                    .build_codec(
                        &tag,
                        &env.src_dir(Krate::Codec).join("lib.rs"),
                        digest.clone(),
                    )
                    .expect("the codec over the mutant digest");
                Externs { digest, codec }
            }
            Krate::Codec => {
                let codec = env
                    .build_codec(&tag, &src, production.digest.clone())
                    .expect("the mutant codec");
                Externs {
                    digest: production.digest.clone(),
                    codec,
                }
            }
        };
        println!(
            "CF MUTANT MODE: production weakened by {}'s weakening ({:?} {})",
            id, krate, file
        );
    }
    let results = run_battery(&env, &real, &production, mutant.is_none());
    let setup: Vec<String> = results
        .iter()
        .filter(|(_, _, o)| matches!(o, Outcome::SetupError(_)))
        .map(|(id, part, _)| format!("{} {}", id, part))
        .collect();
    let failed: Vec<String> = results
        .iter()
        .filter(|(_, _, o)| matches!(o, Outcome::AssertionFail(_)))
        .map(|(id, part, _)| format!("{} {}", id, part))
        .collect();
    let passed = results
        .iter()
        .filter(|(_, _, o)| *o == Outcome::Pass)
        .count();
    println!(
        "CF SUMMARY: {} checks, {} PASS, {} ASSERTION_FAIL, {} SETUP_ERROR",
        results.len(),
        passed,
        failed.len(),
        setup.len()
    );
    if !setup.is_empty() {
        println!("CF BATTERY INVALID: SETUP_ERROR in [{}]", setup.join(", "));
        panic!(
            "CF BATTERY INVALID (setup errors are never evidence): [{}]",
            setup.join(", ")
        );
    }
    if !failed.is_empty() {
        println!("CF BATTERY FAILED: [{}]", failed.join(", "));
        panic!("CF BATTERY FAILED: [{}]", failed.join(", "));
    }
    let expected = if mutant.is_some() {
        1 + FIXTURES.len()
    } else {
        1 + 2 * FIXTURES.len()
    };
    assert_eq!(results.len(), expected, "every fixture ran");
    println!("CF BATTERY OK");
}
