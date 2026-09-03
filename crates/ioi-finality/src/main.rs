use ioi_finality::portable_assurance::{verify_portable_assurance_bytes, PortableAssuranceTrustV1};
use serde_json::Value;
use std::path::PathBuf;

fn main() {
    let mut args = std::env::args_os();
    let _program = args.next();
    let Some(path) = args.next().map(PathBuf::from) else {
        eprintln!(
            "usage: ioi-receipt-proof-verify <portable-assurance-v1.json> <external-trust-v1.json>"
        );
        std::process::exit(2);
    };
    let Some(trust_path) = args.next().map(PathBuf::from) else {
        eprintln!("an external trust-policy path is required");
        std::process::exit(2);
    };
    if args.next().is_some() {
        eprintln!("exactly one receipt and one external trust-policy path are required");
        std::process::exit(2);
    }
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("receipt proof refused: {error}");
            std::process::exit(1);
        }
    };
    let trust = std::fs::read(&trust_path)
        .map_err(|error| error.to_string())
        .and_then(|bytes| {
            let value =
                serde_json::from_slice::<Value>(&bytes).map_err(|error| error.to_string())?;
            let canonical = serde_jcs::to_vec(&value).map_err(|error| error.to_string())?;
            if canonical != bytes {
                return Err("trust policy is not canonical RFC 8785/JCS".into());
            }
            serde_json::from_value::<PortableAssuranceTrustV1>(value)
                .map_err(|error| error.to_string())
        });
    let trust = match trust {
        Ok(trust) => trust,
        Err(error) => {
            eprintln!("external trust policy refused: {error}");
            std::process::exit(1);
        }
    };
    let report = verify_portable_assurance_bytes(&bytes, &trust);
    println!(
        "{}",
        serde_json::to_string(&report).expect("verification report serializes")
    );
    if !report.accepted {
        std::process::exit(1);
    }
}
