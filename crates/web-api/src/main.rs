//! AgentShield Web API — HTTP server exposing scan_skill_content.
//!
//! Endpoints:
//!   POST /api/v1/scan       — scan SKILL.md content (JSON body)
//!   GET  /api/v1/rules      — list detection rules
//!   GET  /api/v1/health     — health check

use actix_cors::Cors;
use actix_web::{middleware, web, App, HttpResponse, HttpServer};
use serde::{Deserialize, Serialize};
use std::time::Instant;

#[derive(Deserialize)]
struct ScanRequest {
    /// Skill name (optional, used in report)
    name: Option<String>,
    /// Raw SKILL.md content
    content: String,
    /// Output format: "json" (default) or "sarif"
    format: Option<String>,
    /// Framework: "openclaw" (default), "langchain", "crewai", "dify", or "auto"
    framework: Option<String>,
    /// Filename hint for auto-detection (e.g. "tools.py", "agent.yaml")
    filename: Option<String>,
}

#[derive(Serialize)]
struct ScanResponse {
    skill_name: String,
    score: u32,
    risk_level: String,
    findings: Vec<FindingResponse>,
    breakdown: BreakdownResponse,
    scan_duration_ms: u128,
}

#[derive(Serialize)]
struct FindingResponse {
    rule_id: String,
    title: String,
    severity: String,
    description: String,
    evidence: String,
    line: Option<usize>,
    remediation: String,
}

#[derive(Serialize)]
struct BreakdownResponse {
    critical_count: usize,
    high_count: usize,
    medium_count: usize,
    low_count: usize,
    info_count: usize,
}

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    version: &'static str,
}

#[derive(Serialize)]
struct RuleInfo {
    id: &'static str,
    category: &'static str,
    severity: &'static str,
    description: &'static str,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

async fn scan_handler(body: web::Json<ScanRequest>) -> HttpResponse {
    let start = Instant::now();
    let name = body.name.as_deref().unwrap_or("unknown");
    let filename = body.filename.as_deref().unwrap_or("SKILL.md");

    let framework = match body.framework.as_deref() {
        Some("langchain") => Some(scanner_core::frameworks::Framework::LangChain),
        Some("crewai") => Some(scanner_core::frameworks::Framework::CrewAI),
        Some("dify") => Some(scanner_core::frameworks::Framework::Dify),
        Some("openclaw") => Some(scanner_core::frameworks::Framework::OpenClaw),
        _ => None, // auto-detect
    };

    let result = if framework.is_some() || body.framework.as_deref() == Some("auto") {
        scanner_core::scan_framework_content(name, filename, &body.content, framework)
    } else {
        scanner_core::scan_skill_content(name, &body.content)
    };

    match result {
        Ok(report) => {
            let format = body.format.as_deref().unwrap_or("json");

            if format == "sarif" {
                match report.to_sarif() {
                    Ok(sarif) => {
                        return HttpResponse::Ok()
                            .content_type("application/sarif+json")
                            .body(sarif);
                    }
                    Err(e) => {
                        return HttpResponse::InternalServerError().json(ErrorResponse {
                            error: e.to_string(),
                        });
                    }
                }
            }

            let response = ScanResponse {
                skill_name: report.skill_name,
                score: report.score,
                risk_level: format!("{:?}", report.risk_level),
                findings: report
                    .findings
                    .iter()
                    .map(|f| FindingResponse {
                        rule_id: f.rule_id.clone(),
                        title: f.title.clone(),
                        severity: format!("{:?}", f.severity),
                        description: f.description.clone(),
                        evidence: f.evidence.clone(),
                        line: f.line,
                        remediation: f.remediation.clone(),
                    })
                    .collect(),
                breakdown: BreakdownResponse {
                    critical_count: report.breakdown.critical_count,
                    high_count: report.breakdown.high_count,
                    medium_count: report.breakdown.medium_count,
                    low_count: report.breakdown.low_count,
                    info_count: report.breakdown.info_count,
                },
                scan_duration_ms: start.elapsed().as_millis(),
            };

            HttpResponse::Ok().json(response)
        }
        Err(e) => HttpResponse::BadRequest().json(ErrorResponse {
            error: e.to_string(),
        }),
    }
}

async fn health_handler() -> HttpResponse {
    HttpResponse::Ok().json(HealthResponse {
        status: "ok",
        version: env!("CARGO_PKG_VERSION"),
    })
}

async fn rules_handler() -> HttpResponse {
    let rules = vec![
        RuleInfo {
            id: "SC-001",
            category: "Supply Chain",
            severity: "Critical",
            description: "Fake prerequisite installer",
        },
        RuleInfo {
            id: "SC-002",
            category: "Supply Chain",
            severity: "High",
            description: "Typosquatting skill name",
        },
        RuleInfo {
            id: "CE-001",
            category: "Code Execution",
            severity: "Critical",
            description: "Pipe-to-interpreter (curl | bash)",
        },
        RuleInfo {
            id: "CE-002",
            category: "Code Execution",
            severity: "Critical",
            description: "Reverse shell patterns",
        },
        RuleInfo {
            id: "CE-003",
            category: "Code Execution",
            severity: "High",
            description: "Dynamic code evaluation (eval/exec)",
        },
        RuleInfo {
            id: "CE-004",
            category: "Code Execution",
            severity: "High",
            description: "Download and execute pattern",
        },
        RuleInfo {
            id: "DE-001",
            category: "Data Exfil",
            severity: "High",
            description: "Sensitive credential file access",
        },
        RuleInfo {
            id: "DE-002",
            category: "Data Exfil",
            severity: "High",
            description: "Webhook exfiltration endpoints",
        },
        RuleInfo {
            id: "DE-003",
            category: "Data Exfil",
            severity: "High",
            description: "Base64 encoding + network send",
        },
        RuleInfo {
            id: "DE-004",
            category: "Data Exfil",
            severity: "High",
            description: "Environment variable harvesting",
        },
        RuleInfo {
            id: "PI-001",
            category: "Prompt Injection",
            severity: "High",
            description: "Hidden instruction override",
        },
        RuleInfo {
            id: "PI-002",
            category: "Prompt Injection",
            severity: "High",
            description: "Hidden Unicode / zero-width characters",
        },
        RuleInfo {
            id: "BP-001",
            category: "Best Practice",
            severity: "Medium",
            description: "Unpinned dependencies",
        },
    ];
    HttpResponse::Ok().json(rules)
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let host = std::env::var("HOST").unwrap_or_else(|_| "0.0.0.0".to_string());
    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8080);

    eprintln!("AgentShield Web API v{}", env!("CARGO_PKG_VERSION"));
    eprintln!("Listening on {}:{}", host, port);

    HttpServer::new(|| {
        let cors = Cors::default()
            .allow_any_origin()
            .allow_any_method()
            .allow_any_header()
            .max_age(3600);

        App::new()
            .wrap(cors)
            .wrap(middleware::Compress::default())
            .service(
                web::scope("/api/v1")
                    .route("/scan", web::post().to(scan_handler))
                    .route("/rules", web::get().to(rules_handler))
                    .route("/health", web::get().to(health_handler)),
            )
    })
    .bind(format!("{}:{}", host, port))?
    .run()
    .await
}
