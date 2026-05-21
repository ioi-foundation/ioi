fn main() {
    if let Err(error) = autopilot_lib::repl_cli::run_cli() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
