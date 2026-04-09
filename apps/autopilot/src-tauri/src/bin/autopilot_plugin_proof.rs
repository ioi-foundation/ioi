fn main() {
    if let Err(error) = autopilot_lib::plugin_proof::run_cli() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
