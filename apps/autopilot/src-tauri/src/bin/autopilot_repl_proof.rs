fn main() {
    if let Err(error) = autopilot_lib::proofs::repl::run_cli() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
