fn main() {
    if let Err(error) = autopilot_lib::proofs::file_context::run_cli() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
