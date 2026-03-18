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
        "check" => {
            if args.len() < 3 {
                eprintln!("Error: missing content argument");
                eprintln!("Usage: agentshield check --stdin");
                process::exit(1);
            }
            let format = parse_format(&args);
            let framework = parse_framework(&args);
            if args[2] == "--stdin" {
                run_check_stdin(&format, framework.as_deref());
            } else {
                let filepath = &args[2];
                let content = match std::fs::read_to_string(filepath) {
                    Ok(c) => c,
                    Err(e) => {
                        eprintln!("Error reading file: {}", e);
                        process::exit(2);
                    }
                };
                run_check_content(filepath, &content, &format, framework.as_deref());
            }
        }
        "rules" => {
            print_rules();
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
            print_report(&report, format);
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

fn run_check_stdin(format: &str, framework: Option<&str>) {
    use std::io::Read;
    let mut content = String::new();
    if let Err(e) = std::io::stdin().read_to_string(&mut content) {
        eprintln!("Error reading stdin: {}", e);
        process::exit(2);
    }
    run_check_content("stdin", &content, format, framework);
}

fn run_check_content(name: &str, content: &str, format: &str, framework: Option<&str>) {
    let fw = framework.and_then(parse_framework_enum);

    let result = if fw.is_some() || framework == Some("auto") {
        scanner_core::scan_framework_content(name, name, content, fw)
    } else {
        scanner_core::scan_skill_content(name, content)
    };

    match result {
        Ok(report) => {
            print_report(&report, format);
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

fn parse_framework_enum(s: &str) -> Option<scanner_core::frameworks::Framework> {
    match s {
        "langchain" => Some(scanner_core::frameworks::Framework::LangChain),
        "crewai" => Some(scanner_core::frameworks::Framework::CrewAI),
        "dify" => Some(scanner_core::frameworks::Framework::Dify),
        "openclaw" => Some(scanner_core::frameworks::Framework::OpenClaw),
        _ => None,
    }
}

fn parse_framework(args: &[String]) -> Option<String> {
    for (i, arg) in args.iter().enumerate() {
        if arg == "--framework" && i + 1 < args.len() {
            return Some(args[i + 1].clone());
        }
    }
    None
}

fn print_report(report: &scanner_core::report::ScanReport, format: &str) {
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
}

fn parse_format(args: &[String]) -> String {
    for (i, arg) in args.iter().enumerate() {
        if (arg == "--format" || arg == "-f") && i + 1 < args.len() {
            return args[i + 1].clone();
        }
    }
    "terminal".to_string()
}

fn print_rules() {
    println!("AgentShield Detection Rules");
    println!("═══════════════════════════════════════════════════════════════");
    println!();
    let header_id = "ID";
    let header_cat = "Category";
    let header_sev = "Severity";
    let header_desc = "Description";
    println!(
        "{:<8} {:<17} {:<10} {}",
        header_id, header_cat, header_sev, header_desc
    );
    let sep_id = "──────";
    let sep_cat = "───────────────";
    let sep_sev = "────────";
    let sep_desc = "───────────────────────────────";
    println!("{:<8} {:<17} {:<10} {}", sep_id, sep_cat, sep_sev, sep_desc);
    let rules = [
        (
            "SC-001",
            "Supply Chain",
            "CRITICAL",
            "Fake prerequisite installer",
        ),
        ("SC-002", "Supply Chain", "HIGH", "Typosquatting skill name"),
        (
            "CE-001",
            "Code Execution",
            "CRITICAL",
            "Pipe-to-interpreter (curl | bash)",
        ),
        (
            "CE-002",
            "Code Execution",
            "CRITICAL",
            "Reverse shell patterns",
        ),
        (
            "CE-003",
            "Code Execution",
            "HIGH",
            "Dynamic code evaluation (eval/exec)",
        ),
        (
            "CE-004",
            "Code Execution",
            "HIGH",
            "Download and execute pattern",
        ),
        (
            "DE-001",
            "Data Exfil",
            "HIGH",
            "Sensitive credential file access",
        ),
        (
            "DE-002",
            "Data Exfil",
            "HIGH",
            "Webhook exfiltration endpoints",
        ),
        (
            "DE-003",
            "Data Exfil",
            "HIGH",
            "Base64 encoding + network send",
        ),
        (
            "DE-004",
            "Data Exfil",
            "HIGH",
            "Environment variable harvesting",
        ),
        (
            "PI-001",
            "Prompt Injection",
            "HIGH",
            "Hidden instruction override",
        ),
        (
            "PI-002",
            "Prompt Injection",
            "HIGH",
            "Hidden Unicode / zero-width characters",
        ),
        ("BP-001", "Best Practice", "MEDIUM", "Unpinned dependencies"),
        (
            "SIG-001",
            "Signatures",
            "HIGH",
            "Known malware campaign name pattern",
        ),
        (
            "SIG-002",
            "Signatures",
            "CRITICAL",
            "Known malware distribution URL",
        ),
        (
            "SIG-003",
            "Signatures",
            "HIGH",
            "Known malicious publisher reference",
        ),
        (
            "SM-003",
            "Metadata",
            "MEDIUM",
            "Missing skill name in frontmatter",
        ),
        ("SM-004", "Metadata", "LOW", "Missing skill description"),
        ("SM-005", "Metadata", "INFO", "Missing version field"),
        (
            "SM-006",
            "Metadata",
            "MEDIUM",
            "Excessive env var requirements",
        ),
        (
            "SM-007",
            "Metadata",
            "MEDIUM",
            "Always-on skill (always: true)",
        ),
        (
            "BA-001",
            "Behavioral",
            "HIGH",
            "Credential access vs stated purpose mismatch",
        ),
        (
            "BA-002",
            "Behavioral",
            "MEDIUM",
            "Unusually many external URLs",
        ),
        (
            "BA-003",
            "Behavioral",
            "MEDIUM",
            "Minimal content with many permissions",
        ),
    ];

    for (id, cat, sev, desc) in &rules {
        println!("{:<8} {:<17} {:<10} {}", id, cat, sev, desc);
    }
    println!();
}

fn print_usage() {
    println!(
        "AgentShield v{} — Security scanner for AI agent skills\n\
         \n\
         USAGE:\n\
         \x20   agentshield scan <path>            Scan a local skill directory\n\
         \x20   agentshield check <file>           Scan a single SKILL.md file\n\
         \x20   agentshield check --stdin          Scan SKILL.md content from stdin\n\
         \x20   agentshield rules                  List all detection rules\n\
         \x20   agentshield version                Show version\n\
         \x20   agentshield help                   Show this help\n\
         \n\
         OPTIONS:\n\
         \x20   --format, -f <type>                Output format: terminal (default), json, sarif\n\
         \x20   --framework <type>                 Framework: openclaw (default), langchain, crewai, dify, auto\n\
         \n\
         EXAMPLES:\n\
         \x20   agentshield scan ./my-skill/\n\
         \x20   agentshield scan ./my-skill/ --format json\n\
         \x20   agentshield check SKILL.md\n\
         \x20   agentshield check tools.py --framework langchain\n\
         \x20   cat SKILL.md | agentshield check --stdin -f sarif\n\
         \n\
         EXIT CODES:\n\
         \x20   0   Clean or low risk (score <= 50)\n\
         \x20   1   High risk (score > 50)\n\
         \x20   2   Error (file not found, parse error, etc.)",
        env!("CARGO_PKG_VERSION")
    );
}
