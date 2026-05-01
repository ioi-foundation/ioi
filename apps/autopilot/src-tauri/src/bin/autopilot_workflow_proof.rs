fn main() {
    if let Err(error) = autopilot_lib::proofs::workflow::run_cli() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
