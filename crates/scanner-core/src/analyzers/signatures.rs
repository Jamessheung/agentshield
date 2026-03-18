//! Known malware signature matching and typosquatting detection.
//! Matches skills against known malicious campaigns like ClawHavoc,
//! and detects name similarities to popular skills (SC-002).

use super::{Analyzer, Finding, Severity};
use crate::ingester::ParsedSkill;

/// Known malicious publisher accounts.
const KNOWN_MALICIOUS_PUBLISHERS: &[&str] = &["hightower6eu", "sakaen736jih"];

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

/// Popular/legitimate skill names to check typosquatting against.
const POPULAR_SKILL_NAMES: &[&str] = &[
    "clawhub-cli",
    "openclaw-tools",
    "web-search",
    "code-review",
    "git-commit",
    "file-manager",
    "api-client",
    "docker-manager",
    "db-query",
    "slack-notify",
    "email-sender",
    "pdf-reader",
    "image-gen",
    "translate",
    "summarize",
    "calendar",
    "weather",
    "calculator",
    "note-taker",
    "task-manager",
];

/// Signature-based analyzer matching against known malware campaigns.
pub struct SignatureAnalyzer;

impl Default for SignatureAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

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

        // SIG-001: Check skill name against known malicious name patterns
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

        // SIG-002: Check URLs against known malicious patterns
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

        // SIG-003: Check raw text for known publisher references
        let raw_lower = skill.raw_text.to_lowercase();
        for publisher in KNOWN_MALICIOUS_PUBLISHERS {
            if raw_lower.contains(publisher) {
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

        // SC-002: Typosquatting detection using Levenshtein distance
        if !name_lower.is_empty() {
            for popular in POPULAR_SKILL_NAMES {
                // Skip exact match (that's the legitimate skill)
                if name_lower == *popular {
                    continue;
                }

                let distance = strsim::levenshtein(&name_lower, popular);

                // Flag if Levenshtein distance is 1-2 (very similar but not identical)
                if distance > 0 && distance <= 2 {
                    findings.push(Finding {
                        rule_id: "SC-002".to_string(),
                        title: "Possible typosquatting of popular skill name".to_string(),
                        severity: Severity::High,
                        description: format!(
                            "Skill name '{}' is very similar to the popular skill '{}' \
                             (edit distance: {}). This may be a typosquatting attempt.",
                            skill.frontmatter.name, popular, distance
                        ),
                        evidence: format!(
                            "'{}' vs '{}' (distance: {})",
                            skill.frontmatter.name, popular, distance
                        ),
                        line: None,
                        remediation: "Verify this is the intended skill. Check the publisher \
                                     identity and compare with the original."
                            .to_string(),
                        references: vec![],
                    });
                    break;
                }

                // Also check for common typosquat patterns: appending -pro, -free, -plus
                let suffixes = ["-pro", "-free", "-plus", "-official", "-latest"];
                for suffix in &suffixes {
                    if name_lower == format!("{}{}", popular, suffix) {
                        findings.push(Finding {
                            rule_id: "SC-002".to_string(),
                            title: "Possible typosquatting of popular skill name".to_string(),
                            severity: Severity::High,
                            description: format!(
                                "Skill name '{}' appends '{}' to the popular skill '{}'. \
                                 This is a common typosquatting technique.",
                                skill.frontmatter.name, suffix, popular
                            ),
                            evidence: format!(
                                "'{}' = '{}' + '{}'",
                                skill.frontmatter.name, popular, suffix
                            ),
                            line: None,
                            remediation: "Verify this is the intended skill. Check the publisher \
                                         identity and compare with the original."
                                .to_string(),
                            references: vec![],
                        });
                        break;
                    }
                }
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

    #[test]
    fn test_detects_typosquat_edit_distance() {
        // "clawhub-cIi" has edit distance 2 from "clawhub-cli" (l→I, i added)
        let findings =
            scan("---\nname: clawhub-clii\ndescription: CLI tool\nversion: \"1.0.0\"\n---\n# Test");
        assert!(
            findings.iter().any(|f| f.rule_id == "SC-002"),
            "Should detect typosquat of clawhub-cli, got: {:?}",
            findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_detects_typosquat_suffix() {
        let findings = scan(
            "---\nname: web-search-pro\ndescription: Search the web\nversion: \"1.0.0\"\n---\n# Test",
        );
        assert!(
            findings.iter().any(|f| f.rule_id == "SC-002"),
            "Should detect -pro suffix typosquat"
        );
    }

    #[test]
    fn test_no_typosquat_for_exact_name() {
        let findings =
            scan("---\nname: weather\ndescription: Weather\nversion: \"1.0.0\"\n---\n# Weather");
        assert!(
            !findings.iter().any(|f| f.rule_id == "SC-002"),
            "Exact popular name should not trigger SC-002"
        );
    }

    #[test]
    fn test_no_typosquat_for_dissimilar_name() {
        let findings = scan(
            "---\nname: my-awesome-tool\ndescription: A tool\nversion: \"1.0.0\"\n---\n# Test",
        );
        assert!(
            !findings.iter().any(|f| f.rule_id == "SC-002"),
            "Dissimilar name should not trigger SC-002"
        );
    }
}
