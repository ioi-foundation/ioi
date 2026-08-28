use ioi_finality::verify_bundle;
use serde_json::Value;
use std::path::PathBuf;

fn main() {
    let mut args = std::env::args_os();
    let _program = args.next();
    let Some(path) = args.next().map(PathBuf::from) else {
        eprintln!("usage: ioi-receipt-proof-verify <receipt-proof-bundle-v2.json>");
        std::process::exit(2);
    };
    if args.next().is_some() {
        eprintln!("exactly one bundle path is required");
        std::process::exit(2);
    }
    let result = std::fs::read_to_string(&path)
        .map_err(|error| error.to_string())
        .and_then(|body| serde_json::from_str::<Value>(&body).map_err(|error| error.to_string()))
        .and_then(|bundle| verify_bundle(&bundle).map_err(|error| error.to_string()));
    match result {
        Ok(verified) => {
            println!(
                "{}",
                serde_json::to_string(&verified).expect("verified result serializes")
            );
        }
        Err(error) => {
            eprintln!("receipt proof refused: {error}");
            std::process::exit(1);
        }
    }
}
