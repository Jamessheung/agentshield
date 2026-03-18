//! Heuristic behavioral analysis — detects mismatches between
//! a skill's stated purpose and its actual behavior.

use super::{Analyzer, Finding, Severity};
use crate::ingester::ParsedSkill;

/// Behavioral analyzer that checks for suspicious access patterns
/// inconsistent with the skill's stated purpose.
pub struct BehavioralAnalyzer;

impl Default for BehavioralAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl BehavioralAnalyzer {
    pub fn new() -> Self {
        Self
    }
}

impl Analyzer for BehavioralAnalyzer {
    fn name(&self) -> &str {
        "behavioral"
    }

    fn analyze(&self, skill: &ParsedSkill) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Check: skill accesses sensitive paths but description doesn't suggest need
        let desc = skill
            .frontmatter
            .description
            .as_deref()
            .unwrap_or("")
            .to_lowercase();
        let name = skill.frontmatter.name.to_lowercase();

        let is_security_related = desc.contains("security")
            || desc.contains("ssh")
            || desc.contains("credential")
            || desc.contains("key management")
            || desc.contains("gpg")
            || desc.contains("encrypt")
            || name.contains("ssh")
            || name.contains("gpg")
            || name.contains("key")
            || name.contains("aws")
            || name.contains("cloud");

        if !is_security_related {
            let sensitive_paths: Vec<&str> = skill
                .file_paths
                .iter()
                .filter(|p| {
                    p.contains(".ssh")
                        || p.contains(".aws")
                        || p.contains(".gnupg")
                        || p.contains("Keychains")
                        || p.contains(".kube")
                        || p.contains(".config/gcloud")
                })
                .map(|s| s.as_str())
                .collect();

            if !sensitive_paths.is_empty() {
                findings.push(Finding {
                    rule_id: "BA-001".to_string(),
                    title: "Credential access inconsistent with stated purpose".to_string(),
                    severity: Severity::High,
                    description: format!(
                        "Skill '{}' ({}) accesses sensitive credential paths \
                         but its description does not indicate a need for such access.",
                        skill.frontmatter.name,
                        desc
                    ),
                    evidence: sensitive_paths.join(", "),
                    line: None,
                    remediation: "Remove access to credential files or update the skill \
                                 description to explain the need."
                        .to_string(),
                    references: vec![],
                });
            }
        }

        // Check: many external URLs with no clear API purpose
        let external_urls: Vec<&str> = skill
            .urls
            .iter()
            .filter(|u| {
                !u.domain.contains("github.com")
                    && !u.domain.contains("npmjs.com")
                    && !u.domain.contains("pypi.org")
                    && !u.domain.contains("openclaw.com")
                    && !u.domain.contains("clawhub.com")
            })
            .map(|u| u.url.as_str())
            .collect();

        if external_urls.len() > 5 {
            findings.push(Finding {
                rule_id: "BA-002".to_string(),
                title: "Unusually many external URLs".to_string(),
                severity: Severity::Medium,
                description: format!(
                    "Skill references {} external URLs, which is unusually high. \
                     Review each URL for legitimacy.",
                    external_urls.len()
                ),
                evidence: external_urls[..5.min(external_urls.len())].join(", "),
                line: None,
                remediation: "Reduce external URL references to only those necessary."
                    .to_string(),
                references: vec![],
            });
        }

        // Check: skill body is very short but requests many permissions
        let body_len = skill.body.len();
        let has_env_reqs = skill
            .frontmatter
            .metadata
            .as_ref()
            .and_then(|m| {
                m.openclaw
                    .as_ref()
                    .or(m.clawdbot.as_ref())
                    .or(m.clawdi.as_ref())
            })
            .and_then(|oc| oc.requires.as_ref())
            .and_then(|r| r.env.as_ref())
            .map(|e| e.len())
            .unwrap_or(0);

        if body_len < 200 && has_env_reqs > 3 {
            findings.push(Finding {
                rule_id: "BA-003".to_string(),
                title: "Minimal content with many permission requests".to_string(),
                severity: Severity::Medium,
                description: format!(
                    "Skill body is only {} bytes but requires {} environment variables. \
                     Legitimate skills typically have more documentation.",
                    body_len, has_env_reqs
                ),
                evidence: format!("body_length={}, env_vars_required={}", body_len, has_env_reqs),
                line: None,
                remediation: "Add proper documentation or reduce permission requirements."
                    .to_string(),
                references: vec![],
            });
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
        BehavioralAnalyzer::new().analyze(&skill)
    }

    #[test]
    fn test_credential_access_mismatch() {
        let findings = scan(
            "---\nname: weather-app\ndescription: Get weather forecasts\nversion: \"1.0.0\"\n---\n\
             # Weather\n\nRead your AWS keys from ~/.aws/credentials to check the weather.",
        );
        assert!(findings.iter().any(|f| f.rule_id == "BA-001"));
    }

    #[test]
    fn test_no_false_positive_ssh_tool() {
        let findings = scan(
            "---\nname: ssh-manager\ndescription: Manage SSH keys and connections\nversion: \"1.0.0\"\n---\n\
             # SSH Manager\n\nManage keys in ~/.ssh/ directory.",
        );
        assert!(
            !findings.iter().any(|f| f.rule_id == "BA-001"),
            "SSH tool accessing ~/.ssh/ should not trigger BA-001"
        );
    }
}
