//! Frontmatter metadata analysis — checks for suspicious skill metadata,
//! excessive permissions, and missing required fields.

use super::{Analyzer, Finding, Severity};
use crate::ingester::ParsedSkill;

/// Analyzer for SKILL.md frontmatter metadata.
pub struct MetadataAnalyzer;

impl Default for MetadataAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl MetadataAnalyzer {
    pub fn new() -> Self {
        Self
    }
}

impl Analyzer for MetadataAnalyzer {
    fn name(&self) -> &str {
        "metadata"
    }

    fn analyze(&self, skill: &ParsedSkill) -> Vec<Finding> {
        let mut findings = Vec::new();
        let fm = &skill.frontmatter;

        // Check for missing name
        if fm.name.is_empty() {
            findings.push(Finding {
                rule_id: "SM-003".to_string(),
                title: "Missing skill name in frontmatter".to_string(),
                severity: Severity::Medium,
                description: "SKILL.md frontmatter does not have a name field. \
                             This makes it harder to identify and track the skill."
                    .to_string(),
                evidence: String::new(),
                line: Some(1),
                remediation: "Add a 'name' field to the YAML frontmatter.".to_string(),
                references: vec![],
            });
        }

        // Check for missing description
        if fm.description.is_none() || fm.description.as_deref() == Some("") {
            findings.push(Finding {
                rule_id: "SM-004".to_string(),
                title: "Missing skill description".to_string(),
                severity: Severity::Low,
                description: "SKILL.md has no description. Legitimate skills typically \
                             describe their purpose."
                    .to_string(),
                evidence: String::new(),
                line: Some(1),
                remediation: "Add a 'description' field to the YAML frontmatter.".to_string(),
                references: vec![],
            });
        }

        // Check for missing version
        if fm.version.is_none() {
            findings.push(Finding {
                rule_id: "SM-005".to_string(),
                title: "Missing version field".to_string(),
                severity: Severity::Info,
                description: "SKILL.md has no version field.".to_string(),
                evidence: String::new(),
                line: Some(1),
                remediation: "Add a 'version' field to the YAML frontmatter.".to_string(),
                references: vec![],
            });
        }

        // Check for excessive env requirements
        if let Some(ref metadata) = fm.metadata {
            let oc_meta = metadata
                .openclaw
                .as_ref()
                .or(metadata.clawdbot.as_ref())
                .or(metadata.clawdi.as_ref());

            if let Some(oc) = oc_meta {
                if let Some(ref requires) = oc.requires {
                    // Check for excessive env vars
                    if let Some(ref env_vars) = requires.env {
                        if env_vars.len() > 10 {
                            findings.push(Finding {
                                rule_id: "SM-006".to_string(),
                                title: "Excessive environment variable requirements".to_string(),
                                severity: Severity::Medium,
                                description: format!(
                                    "Skill requires {} environment variables. \
                                     This is unusually high and may indicate an attempt to \
                                     collect sensitive data.",
                                    env_vars.len()
                                ),
                                evidence: env_vars.join(", "),
                                line: None,
                                remediation: "Review whether all environment variables are necessary."
                                    .to_string(),
                                references: vec![],
                            });
                        }

                        // Check for sensitive-sounding env vars
                        for var in env_vars {
                            let upper = var.to_uppercase();
                            if upper.contains("SECRET") || upper.contains("PRIVATE_KEY")
                                || upper.contains("PASSWORD") || upper.contains("TOKEN")
                            {
                                // This is normal for API tokens, only flag if many
                                // We just note it as info
                            }
                        }
                    }
                }

                // Check for "always" flag — runs on every prompt
                if oc.always == Some(true) {
                    findings.push(Finding {
                        rule_id: "SM-007".to_string(),
                        title: "Skill runs on every prompt (always: true)".to_string(),
                        severity: Severity::Medium,
                        description: "Skill is set to always run, meaning it executes on every \
                                     user prompt. This could be used for persistent surveillance \
                                     or data collection."
                            .to_string(),
                        evidence: "always: true".to_string(),
                        line: None,
                        remediation: "Only set always: true if the skill genuinely needs to run \
                                     on every prompt."
                            .to_string(),
                        references: vec![],
                    });
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
        MetadataAnalyzer::new().analyze(&skill)
    }

    #[test]
    fn test_complete_metadata_no_warnings() {
        let findings = scan(
            "---\nname: weather\ndescription: Get weather data\nversion: \"1.0.0\"\n---\n# Weather",
        );
        assert!(
            findings.is_empty(),
            "Complete metadata should have no findings, got: {:?}",
            findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_missing_description() {
        let findings = scan("---\nname: weather\nversion: \"1.0.0\"\n---\n# Weather");
        assert!(findings.iter().any(|f| f.rule_id == "SM-004"));
    }

    #[test]
    fn test_always_true_flagged() {
        let findings = scan(
            "---\nname: spy\ndescription: Watches everything\nversion: \"1.0.0\"\nmetadata:\n  openclaw:\n    always: true\n---\n# Spy",
        );
        assert!(findings.iter().any(|f| f.rule_id == "SM-007"));
    }
}
