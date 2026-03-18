//! AgentShield CLI — scan OpenClaw skills for security issues.

use std::path::Path;
use std::path::PathBuf;
use std::process;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        print_usage();
        process::exit(1);
    }

    match args[1].as_str() {
        "scan" => {
            if args.len() < 3 {
                eprintln!("Error: missing path argument");
                eprintln!("Usage: agentshield scan <path> [--format terminal|json|sarif]");
                process::exit(1);
            }
            let path = PathBuf::from(&args[2]);
            let format = parse_format(&args);
            run_scan(&path, &format);
        }
        "version" | "--version" | "-V" => {
            println!("agentshield {}", env!("CARGO_PKG_VERSION"));
        }
        "help" | "--help" | "-h" => {
            print_usage();
        }
        other => {
            eprintln!("Error: unknown command '{}'", other);
            print_usage();
            process::exit(1);
        }
    }
}

fn run_scan(path: &Path, format: &str) {
    match scanner_core::scan_skill(path) {
        Ok(report) => {
            let output = match format {
                "json" => report.to_json().unwrap_or_else(|e| {
                    eprintln!("Error formatting JSON: {}", e);
                    process::exit(1);
                }),
                "sarif" => report.to_sarif().unwrap_or_else(|e| {
                    eprintln!("Error formatting SARIF: {}", e);
                    process::exit(1);
                }),
                _ => report.to_terminal(),
            };
            print!("{}", output);

            // Exit with code 1 if high risk
            if report.score > 50 {
                process::exit(1);
            }
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            process::exit(2);
        }
    }
}

fn parse_format(args: &[String]) -> String {
    for (i, arg) in args.iter().enumerate() {
        if (arg == "--format" || arg == "-f") && i + 1 < args.len() {
            return args[i + 1].clone();
        }
    }
    "terminal".to_string()
}

fn print_usage() {
    println!(
        "AgentShield v{} — Security scanner for AI agent skills\n\
         \n\
         USAGE:\n\
         \x20   agentshield scan <path>        Scan a local skill directory\n\
         \x20   agentshield version            Show version\n\
         \x20   agentshield help               Show this help\n\
         \n\
         OPTIONS:\n\
         \x20   --format, -f <type>            Output format: terminal (default), json, sarif\n\
         \n\
         EXAMPLES:\n\
         \x20   agentshield scan ./my-skill/\n\
         \x20   agentshield scan ./my-skill/ --format json\n\
         \x20   agentshield scan ./my-skill/ -f sarif > report.sarif",
        env!("CARGO_PKG_VERSION")
    );
}
