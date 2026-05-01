fn main() {
    if let Err(error) = autopilot_lib::proofs::plugin::run_cli() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
