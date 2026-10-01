fn main() {
    match delegated_sudo::cli::run() {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            eprintln!("delegated-sudo: {error}");
            std::process::exit(1);
        }
    }
}
