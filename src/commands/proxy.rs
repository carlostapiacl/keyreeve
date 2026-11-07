use super::usage;
use keyreeve::proxy;
use std::path::Path;
use std::process::ExitCode;

pub fn run_proxy(args: &[String]) -> ExitCode {
    let [flag, folder] = args else {
        return usage();
    };
    if flag != "--run-dir" {
        return usage();
    }
    match proxy::serve_from_stdin(Path::new(folder)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("proxy: {error}");
            ExitCode::FAILURE
        }
    }
}
