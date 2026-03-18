//! LLM-assisted behavioral analysis — generates structured prompts for
//! language model review and parses LLM responses into security findings.
//!
//! This module does NOT call an LLM directly (no network dependency).
//! Instead it:
//! 1. Builds a focused analysis prompt from the parsed skill
//! 2. Provides a parser that converts an LLM JSON response into `Finding`s
//!
//! Callers (web API, CLI) are responsible for the actual LLM call.

use crate::analyzers::{Finding, Severity};
use crate::ingester::ParsedSkill;
use serde::{Deserialize, Serialize};

/// Maximum characters of skill content included in the prompt.
const MAX_CONTENT_LEN: usize = 12_000;

// ── Prompt generation ────────────────────────────────────────────────

/// A structured prompt ready to be sent to an LLM.
#[derive(Debug, Serialize)]
pub struct AnalysisPrompt {
    /// System message for the LLM.
    pub system: String,
    /// User message containing the skill to analyze.
    pub user: String,
}

/// Build an analysis prompt for the given skill.
///
/// The prompt asks the LLM to look for categories of issues that are hard
/// to catch with static patterns: semantic intent mismatches, obfuscated
/// logic, social engineering, and novel attack vectors.
pub fn build_prompt(skill: &ParsedSkill) -> AnalysisPrompt {
    let name = &skill.frontmatter.name;
    let desc = skill
        .frontmatter
        .description
        .as_deref()
        .unwrap_or("(no description)");

    // Truncate raw content for the prompt
    let content = if skill.raw_text.len() > MAX_CONTENT_LEN {
        format!(
            "{}...\n[truncated, {} total bytes]",
            &skill.raw_text[..MAX_CONTENT_LEN],
            skill.raw_text.len()
        )
    } else {
        skill.raw_text.clone()
    };

    let code_summary: Vec<String> = skill
        .code_blocks
        .iter()
        .enumerate()
        .map(|(i, cb)| {
            let lang = cb.language.as_deref().unwrap_or("unknown");
            let preview: String = cb.content.chars().take(500).collect();
            format!(
                "Code block #{} ({}), line {}:\n{}",
                i + 1,
                lang,
                cb.line_start,
                preview
            )
        })
        .collect();

    let urls_list: String = skill
        .urls
        .iter()
        .map(|u| format!("  - {} (line {})", u.url, u.line))
        .collect::<Vec<_>>()
        .join("\n");

    let files_list: String = skill
        .file_paths
        .iter()
        .map(|p| format!("  - {}", p))
        .collect::<Vec<_>>()
        .join("\n");

    let system = r#"You are AgentShield, a security analyst specializing in AI agent supply chain attacks. Your task is to analyze an OpenClaw skill definition for security risks that automated pattern matching may miss.

Focus on these categories:
1. SEMANTIC MISMATCH — Does the code do something different from what the description claims?
2. OBFUSCATED LOGIC — Are there encoded strings, indirect variable references, or split-string concatenation hiding malicious intent?
3. SOCIAL ENGINEERING — Does the skill trick users into running dangerous commands through misleading instructions?
4. NOVEL EXFILTRATION — Are there creative ways data could leave the system (DNS exfil, steganography, timing channels)?
5. PRIVILEGE ESCALATION — Does the skill request more permissions than its stated purpose needs?

Respond with a JSON object:
{
  "risk_assessment": "clean" | "suspicious" | "malicious",
  "confidence": 0.0-1.0,
  "findings": [
    {
      "category": "semantic_mismatch" | "obfuscation" | "social_engineering" | "novel_exfil" | "privilege_escalation",
      "severity": "low" | "medium" | "high" | "critical",
      "title": "short title",
      "description": "detailed explanation of why this is suspicious",
      "evidence": "the specific text/code that is suspicious",
      "line": null or line number
    }
  ],
  "summary": "one paragraph overall assessment"
}"#
        .to_string();

    let user = format!(
        r#"Analyze this OpenClaw skill for security issues:

## Skill Metadata
- Name: {name}
- Description: {desc}

## Full Content
```
{content}
```

## Extracted Code Blocks
{code_blocks}

## Referenced URLs
{urls}

## Referenced File Paths
{files}

Please analyze this skill and respond with the JSON format specified."#,
        name = name,
        desc = desc,
        content = content,
        code_blocks = if code_summary.is_empty() {
            "(none)".to_string()
        } else {
            code_summary.join("\n\n")
        },
        urls = if urls_list.is_empty() {
            "(none)".to_string()
        } else {
            urls_list
        },
        files = if files_list.is_empty() {
            "(none)".to_string()
        } else {
            files_list
        },
    );

    AnalysisPrompt { system, user }
}

// ── Response parsing ─────────────────────────────────────────────────

/// Raw LLM response structure.
#[derive(Debug, Deserialize)]
pub struct LlmResponse {
    pub risk_assessment: String,
    pub confidence: f64,
    pub findings: Vec<LlmFinding>,
    pub summary: String,
}

#[derive(Debug, Deserialize)]
pub struct LlmFinding {
    pub category: String,
    pub severity: String,
    pub title: String,
    pub description: String,
    pub evidence: String,
    pub line: Option<usize>,
}

/// Parse an LLM JSON response string into AgentShield `Finding`s.
///
/// Returns `(findings, summary)` on success.
pub fn parse_llm_response(json_str: &str) -> Result<(Vec<Finding>, String), LlmParseError> {
    // Try to extract JSON from markdown code blocks if present
    let cleaned = extract_json_block(json_str);
    let response: LlmResponse = serde_json::from_str(&cleaned)?;

    // Only include findings above a confidence threshold
    if response.confidence < 0.3 {
        return Ok((Vec::new(), response.summary));
    }

    let findings = response
        .findings
        .into_iter()
        .map(|f| {
            let rule_id = category_to_rule_id(&f.category);
            let severity = parse_severity(&f.severity);

            Finding {
                rule_id,
                title: format!("[LLM] {}", f.title),
                severity,
                description: f.description,
                evidence: f.evidence,
                line: f.line,
                remediation: "Review this finding with an AI security expert.".to_string(),
                references: vec![],
            }
        })
        .collect();

    Ok((findings, response.summary))
}

/// Map LLM category names to AgentShield rule IDs.
fn category_to_rule_id(category: &str) -> String {
    match category {
        "semantic_mismatch" => "LLM-001".to_string(),
        "obfuscation" => "LLM-002".to_string(),
        "social_engineering" => "LLM-003".to_string(),
        "novel_exfil" => "LLM-004".to_string(),
        "privilege_escalation" => "LLM-005".to_string(),
        other => format!(
            "LLM-{}",
            other.to_uppercase().chars().take(3).collect::<String>()
        ),
    }
}

fn parse_severity(s: &str) -> Severity {
    match s.to_lowercase().as_str() {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "medium" => Severity::Medium,
        "low" => Severity::Low,
        _ => Severity::Medium,
    }
}

/// Extract JSON from a markdown code block if the LLM wraps it.
fn extract_json_block(s: &str) -> String {
    let trimmed = s.trim();

    // Try ```json ... ``` block
    if let Some(start) = trimmed.find("```json") {
        let after = &trimmed[start + 7..];
        if let Some(end) = after.find("```") {
            return after[..end].trim().to_string();
        }
    }

    // Try ``` ... ``` block
    if let Some(start) = trimmed.find("```") {
        let after = &trimmed[start + 3..];
        if let Some(end) = after.find("```") {
            let inner = after[..end].trim();
            if inner.starts_with('{') {
                return inner.to_string();
            }
        }
    }

    trimmed.to_string()
}

#[derive(Debug, thiserror::Error)]
pub enum LlmParseError {
    #[error("Failed to parse LLM JSON response: {0}")]
    Json(#[from] serde_json::Error),
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ingester;

    #[test]
    fn test_build_prompt_structure() {
        let skill = ingester::parse_skill_content(
            "---\nname: test-skill\ndescription: A test\nversion: \"1.0.0\"\n---\n# Test\n\n```bash\necho hello\n```",
        ).unwrap();

        let prompt = build_prompt(&skill);
        assert!(prompt.system.contains("AgentShield"));
        assert!(prompt.system.contains("JSON"));
        assert!(prompt.user.contains("test-skill"));
        assert!(prompt.user.contains("echo hello"));
    }

    #[test]
    fn test_build_prompt_truncates_long_content() {
        let long_content = format!(
            "---\nname: big-skill\ndescription: test\nversion: \"1.0.0\"\n---\n# Big\n\n{}",
            "A".repeat(20_000)
        );
        let skill = ingester::parse_skill_content(&long_content).unwrap();
        let prompt = build_prompt(&skill);
        assert!(prompt.user.contains("[truncated"));
    }

    #[test]
    fn test_parse_llm_response_valid() {
        let json = r#"{
            "risk_assessment": "malicious",
            "confidence": 0.95,
            "findings": [
                {
                    "category": "semantic_mismatch",
                    "severity": "high",
                    "title": "Description claims weather lookup but code steals SSH keys",
                    "description": "The skill description says it provides weather data, but the code reads ~/.ssh/id_rsa.",
                    "evidence": "open(os.path.expanduser('~/.ssh/id_rsa'))",
                    "line": 15
                }
            ],
            "summary": "This skill is likely malicious."
        }"#;

        let (findings, summary) = parse_llm_response(json).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "LLM-001");
        assert_eq!(findings[0].severity, Severity::High);
        assert!(findings[0].title.starts_with("[LLM]"));
        assert_eq!(findings[0].line, Some(15));
        assert!(summary.contains("malicious"));
    }

    #[test]
    fn test_parse_llm_response_low_confidence_filtered() {
        let json = r#"{
            "risk_assessment": "clean",
            "confidence": 0.2,
            "findings": [
                {
                    "category": "obfuscation",
                    "severity": "low",
                    "title": "Maybe suspicious",
                    "description": "Not sure.",
                    "evidence": "",
                    "line": null
                }
            ],
            "summary": "Probably fine."
        }"#;

        let (findings, _) = parse_llm_response(json).unwrap();
        assert!(
            findings.is_empty(),
            "Low confidence findings should be filtered"
        );
    }

    #[test]
    fn test_parse_llm_response_in_code_block() {
        let wrapped = r#"```json
{
    "risk_assessment": "suspicious",
    "confidence": 0.7,
    "findings": [],
    "summary": "No obvious issues."
}
```"#;

        let (findings, summary) = parse_llm_response(wrapped).unwrap();
        assert!(findings.is_empty());
        assert!(summary.contains("No obvious"));
    }

    #[test]
    fn test_parse_llm_response_invalid_json() {
        let result = parse_llm_response("not json at all");
        assert!(result.is_err());
    }

    #[test]
    fn test_category_to_rule_id() {
        assert_eq!(category_to_rule_id("semantic_mismatch"), "LLM-001");
        assert_eq!(category_to_rule_id("obfuscation"), "LLM-002");
        assert_eq!(category_to_rule_id("social_engineering"), "LLM-003");
        assert_eq!(category_to_rule_id("novel_exfil"), "LLM-004");
        assert_eq!(category_to_rule_id("privilege_escalation"), "LLM-005");
    }

    #[test]
    fn test_extract_json_block() {
        assert_eq!(extract_json_block("  {\"a\": 1}  "), "{\"a\": 1}");
        assert_eq!(extract_json_block("```json\n{\"a\": 1}\n```"), "{\"a\": 1}");
        assert_eq!(extract_json_block("```\n{\"a\": 1}\n```"), "{\"a\": 1}");
    }
}
