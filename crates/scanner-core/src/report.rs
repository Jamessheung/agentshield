//! Report generation — formats scan results for terminal, JSON, and SARIF output.

use crate::analyzers::{Finding, Severity};
use crate::scoring::{RiskLevel, ScoreBreakdown};
use serde::Serialize;

/// Complete scan report.
#[derive(Debug, Serialize)]
pub struct ScanReport {
    pub skill_name: String,
    pub score: u32,
    pub risk_level: RiskLevel,
    pub findings: Vec<Finding>,
    pub breakdown: ScoreBreakdown,
}

impl ScanReport {
    /// Format the report as a colored terminal string.
    pub fn to_terminal(&self) -> String {
        let mut out = String::new();

        out.push_str("\n  AgentShield Scan Report\n");
        out.push_str("  ───────────────────────────────────────\n");
        out.push_str(&format!("  Skill:       {}\n", self.skill_name));
        out.push_str(&format!(
            "  Risk Score:  {}/100 ({})\n",
            self.score, self.risk_level
        ));
        out.push('\n');

        if self.findings.is_empty() {
            out.push_str("  ✅ No security issues found.\n");
        } else {
            for finding in &self.findings {
                let icon = match finding.severity {
                    Severity::Critical => "⛔ CRITICAL",
                    Severity::High => "⚠  HIGH    ",
                    Severity::Medium => "⚠  MEDIUM  ",
                    Severity::Low => "ℹ  LOW     ",
                    Severity::Info => "ℹ  INFO    ",
                };
                out.push_str(&format!("  {} {}\n", icon, finding.title));
                if let Some(line) = finding.line {
                    out.push_str(&format!(
                        "             Line {}: {}\n",
                        line, finding.evidence
                    ));
                } else if !finding.evidence.is_empty() {
                    out.push_str(&format!("             {}\n", finding.evidence));
                }
                out.push('\n');
            }
        }

        // Verdict
        out.push_str("  ───────────────────────────────────────\n");
        let verdict = match self.risk_level {
            RiskLevel::Clean => "SAFE — No issues detected.",
            RiskLevel::Low => "LOW RISK — Minor issues found, review recommended.",
            RiskLevel::Medium => "MEDIUM RISK — Review before installing.",
            RiskLevel::High => "HIGH RISK — Do not install without careful review.",
            RiskLevel::Critical => "DO NOT INSTALL — Likely malicious.",
        };
        out.push_str(&format!("  Verdict: {}\n\n", verdict));

        out
    }

    /// Format the report as JSON.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Format the report as SARIF (Static Analysis Results Interchange Format).
    pub fn to_sarif(&self) -> Result<String, serde_json::Error> {
        let sarif = serde_json::json!({
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "AgentShield",
                        "version": env!("CARGO_PKG_VERSION"),
                        "informationUri": "https://github.com/agentshield/agentshield",
                        "rules": self.findings.iter().map(|f| {
                            serde_json::json!({
                                "id": f.rule_id,
                                "name": f.title,
                                "shortDescription": { "text": f.description },
                                "defaultConfiguration": {
                                    "level": match f.severity {
                                        Severity::Critical | Severity::High => "error",
                                        Severity::Medium => "warning",
                                        _ => "note",
                                    }
                                }
                            })
                        }).collect::<Vec<_>>()
                    }
                },
                "results": self.findings.iter().map(|f| {
                    let mut result = serde_json::json!({
                        "ruleId": f.rule_id,
                        "message": { "text": f.description },
                        "level": match f.severity {
                            Severity::Critical | Severity::High => "error",
                            Severity::Medium => "warning",
                            _ => "note",
                        },
                    });
                    if let Some(line) = f.line {
                        result["locations"] = serde_json::json!([{
                            "physicalLocation": {
                                "artifactLocation": { "uri": "SKILL.md" },
                                "region": { "startLine": line }
                            }
                        }]);
                    }
                    result
                }).collect::<Vec<_>>()
            }]
        });
        serde_json::to_string_pretty(&sarif)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_report() -> ScanReport {
        ScanReport {
            skill_name: "test-skill".to_string(),
            score: 45,
            risk_level: RiskLevel::Medium,
            findings: vec![Finding {
                rule_id: "CE-001".to_string(),
                title: "Pipe-to-interpreter pattern".to_string(),
                severity: Severity::Critical,
                description: "Downloads and pipes to bash.".to_string(),
                evidence: "curl ... | bash".to_string(),
                line: Some(10),
                remediation: "Download first, then inspect.".to_string(),
                references: vec![],
            }],
            breakdown: ScoreBreakdown {
                critical_count: 1,
                high_count: 0,
                medium_count: 0,
                low_count: 0,
                info_count: 0,
            },
        }
    }

    #[test]
    fn test_terminal_output() {
        let report = sample_report();
        let output = report.to_terminal();
        assert!(output.contains("test-skill"));
        assert!(output.contains("45/100"));
        assert!(output.contains("CRITICAL"));
    }

    #[test]
    fn test_json_output() {
        let report = sample_report();
        let json = report.to_json().unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["skill_name"], "test-skill");
        assert_eq!(parsed["score"], 45);
    }

    #[test]
    fn test_sarif_output() {
        let report = sample_report();
        let sarif = report.to_sarif().unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&sarif).unwrap();
        assert_eq!(parsed["version"], "2.1.0");
        assert!(!parsed["runs"][0]["results"].as_array().unwrap().is_empty());
    }
}
