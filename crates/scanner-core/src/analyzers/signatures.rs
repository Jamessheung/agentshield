//! Known malware signature matching from YAML database.
//! Matches skills against known malicious campaigns like ClawHavoc.

use super::{Analyzer, Finding, Severity};
use crate::ingester::ParsedSkill;

/// Known malicious publisher accounts.
const KNOWN_MALICIOUS_PUBLISHERS: &[&str] = &[
    "hightower6eu",
    "sakaen736jih",
];

/// Known malicious URL patterns.
const KNOWN_MALICIOUS_URL_PATTERNS: &[&str] = &[
    "raw.githubusercontent.com/hightower6eu/",
    "raw.githubusercontent.com/sakaen736jih/",
];

/// Known malicious skill name patterns (prefix matches).
const KNOWN_MALICIOUS_NAME_PREFIXES: &[&str] = &[
    "solana-wallet",
    "polymarket-",
    "youtube-summarize",
    "auto-updater",
];

/// Signature-based analyzer matching against known malware campaigns.
pub struct SignatureAnalyzer;

impl SignatureAnalyzer {
    pub fn new() -> Self {
        Self
    }
}

impl Analyzer for SignatureAnalyzer {
    fn name(&self) -> &str {
        "signatures"
    }

    fn analyze(&self, skill: &ParsedSkill) -> Vec<Finding> {
        let mut findings = Vec::new();
        let name_lower = skill.frontmatter.name.to_lowercase();

        // Check skill name against known malicious name patterns
        for prefix in KNOWN_MALICIOUS_NAME_PREFIXES {
            if name_lower.starts_with(prefix) {
                findings.push(Finding {
                    rule_id: "SIG-001".to_string(),
                    title: "Skill name matches known malware campaign pattern".to_string(),
                    severity: Severity::High,
                    description: format!(
                        "Skill name '{}' matches the pattern '{}*' associated with \
                         the ClawHavoc malware campaign.",
                        skill.frontmatter.name, prefix
                    ),
                    evidence: skill.frontmatter.name.clone(),
                    line: None,
                    remediation: "Verify the skill publisher and contents carefully before installing."
                        .to_string(),
                    references: vec![
                        "https://thehackernews.com/2026/02/researchers-find-341-malicious-clawhub.html"
                            .to_string(),
                    ],
                });
                break;
            }
        }

        // Check URLs against known malicious patterns
        for url in &skill.urls {
            for pattern in KNOWN_MALICIOUS_URL_PATTERNS {
                if url.url.contains(pattern) {
                    findings.push(Finding {
                        rule_id: "SIG-002".to_string(),
                        title: "URL matches known malware distribution source".to_string(),
                        severity: Severity::Critical,
                        description: format!(
                            "URL '{}' matches a known malicious distribution source \
                             from the ClawHavoc campaign.",
                            url.url
                        ),
                        evidence: url.url.clone(),
                        line: Some(url.line),
                        remediation: "Do not download or execute anything from this URL.".to_string(),
                        references: vec![
                            "https://thehackernews.com/2026/02/researchers-find-341-malicious-clawhub.html"
                                .to_string(),
                        ],
                    });
                    break;
                }
            }
        }

        // Check raw text for known publisher references
        let raw_lower = skill.raw_text.to_lowercase();
        for publisher in KNOWN_MALICIOUS_PUBLISHERS {
            if raw_lower.contains(publisher) {
                // Avoid duplicate if we already flagged the URL
                let already_flagged = findings.iter().any(|f| f.rule_id == "SIG-002");
                if !already_flagged {
                    findings.push(Finding {
                        rule_id: "SIG-003".to_string(),
                        title: "References known malicious publisher account".to_string(),
                        severity: Severity::High,
                        description: format!(
                            "Skill references the account '{}' which is associated with \
                             the ClawHavoc malware campaign.",
                            publisher
                        ),
                        evidence: publisher.to_string(),
                        line: None,
                        remediation: "Do not use skills from this publisher.".to_string(),
                        references: vec![
                            "https://thehackernews.com/2026/02/researchers-find-341-malicious-clawhub.html"
                                .to_string(),
                        ],
                    });
                }
                break;
            }
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ingester;

    fn scan(raw: &str) -> Vec<Finding> {
        let skill = ingester::parse_skill_content(raw).unwrap();
        SignatureAnalyzer::new().analyze(&skill)
    }

    #[test]
    fn test_detects_clawhavoc_name() {
        let findings = scan(
            "---\nname: solana-wallet-tracker\ndescription: Track wallets\nversion: \"1.0.0\"\n---\n# Test",
        );
        assert!(findings.iter().any(|f| f.rule_id == "SIG-001"));
    }

    #[test]
    fn test_detects_malicious_url() {
        let findings = scan(
            "---\nname: test\ndescription: Test\nversion: \"1.0.0\"\n---\n# Test\n\n\
             Download from https://raw.githubusercontent.com/hightower6eu/malware/main/install.sh",
        );
        assert!(findings.iter().any(|f| f.rule_id == "SIG-002"));
    }

    #[test]
    fn test_clean_skill_no_signatures() {
        let findings = scan(
            "---\nname: weather\ndescription: Weather lookup\nversion: \"1.0.0\"\n---\n# Weather\n\nGet weather data.",
        );
        assert!(findings.is_empty());
    }
}
