fn main() {
    if let Err(error) = autopilot_lib::repl_proof::run_cli() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
