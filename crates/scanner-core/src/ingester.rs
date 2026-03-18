//! SKILL.md parser — extracts YAML frontmatter, markdown sections,
//! code blocks, URLs, and file paths from skill files.

use serde::Deserialize;
use std::path::Path;

/// Parsed YAML frontmatter from a SKILL.md file.
#[derive(Debug, Deserialize, Default, Clone)]
pub struct SkillFrontmatter {
    #[serde(default)]
    pub name: String,
    pub description: Option<String>,
    pub version: Option<String>,
    pub metadata: Option<SkillMetadata>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct SkillMetadata {
    pub openclaw: Option<OpenClawMeta>,
    pub clawdbot: Option<OpenClawMeta>,
    #[serde(rename = "clawdi")]
    pub clawdi: Option<OpenClawMeta>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct OpenClawMeta {
    pub requires: Option<RequiresMeta>,
    #[serde(rename = "primaryEnv")]
    pub primary_env: Option<String>,
    pub always: Option<bool>,
    pub emoji: Option<String>,
    pub install: Option<Vec<InstallSpec>>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct RequiresMeta {
    pub env: Option<Vec<String>>,
    pub bins: Option<Vec<String>>,
    #[serde(rename = "anyBins")]
    pub any_bins: Option<Vec<String>>,
    pub config: Option<Vec<String>>,
    pub os: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct InstallSpec {
    pub id: Option<String>,
    pub kind: Option<String>,
    pub formula: Option<String>,
    pub package: Option<String>,
    pub bins: Option<Vec<String>>,
    pub label: Option<String>,
}

/// Fully parsed skill with all extracted data.
#[derive(Debug)]
pub struct ParsedSkill {
    pub frontmatter: SkillFrontmatter,
    pub body: String,
    pub sections: Vec<MarkdownSection>,
    pub code_blocks: Vec<CodeBlock>,
    pub urls: Vec<ExtractedUrl>,
    pub file_paths: Vec<String>,
    pub raw_text: String,
    pub files: Vec<SkillFile>,
}

#[derive(Debug, Clone)]
pub struct MarkdownSection {
    pub title: String,
    pub level: u8,
    pub content: String,
    pub line_start: usize,
    pub line_end: usize,
}

#[derive(Debug, Clone)]
pub struct CodeBlock {
    pub language: Option<String>,
    pub content: String,
    pub line_start: usize,
}

#[derive(Debug, Clone)]
pub struct ExtractedUrl {
    pub url: String,
    pub domain: String,
    pub line: usize,
    pub context: String,
}

#[derive(Debug, Clone)]
pub struct SkillFile {
    pub path: String,
    pub content: String,
    pub size: usize,
}

#[derive(Debug, thiserror::Error)]
pub enum IngesterError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("YAML parse error: {0}")]
    Yaml(#[from] serde_yaml::Error),

    #[error("No SKILL.md found in directory")]
    NoSkillMd,

    #[error("Invalid frontmatter: {0}")]
    InvalidFrontmatter(String),
}

/// Parse a skill from a directory containing SKILL.md.
pub fn parse_skill(skill_dir: &Path) -> Result<ParsedSkill, IngesterError> {
    let skill_md_path = skill_dir.join("SKILL.md");
    if !skill_md_path.exists() {
        return Err(IngesterError::NoSkillMd);
    }
    let raw_text = std::fs::read_to_string(&skill_md_path)?;
    let files = collect_skill_files(skill_dir, &skill_md_path)?;

    let mut skill = parse_skill_content(&raw_text)?;
    skill.files = files;
    Ok(skill)
}

/// Parse a skill from raw SKILL.md content (no filesystem access).
pub fn parse_skill_content(raw_text: &str) -> Result<ParsedSkill, IngesterError> {
    let (frontmatter_str, body) = split_frontmatter(raw_text)?;
    let frontmatter: SkillFrontmatter = serde_yaml::from_str(&frontmatter_str)
        .unwrap_or_default();

    let sections = parse_sections(&body);
    let code_blocks = extract_code_blocks(&body);
    let urls = extract_urls(raw_text);
    let file_paths = extract_file_paths(raw_text);

    Ok(ParsedSkill {
        frontmatter,
        body,
        sections,
        code_blocks,
        urls,
        file_paths,
        raw_text: raw_text.to_string(),
        files: Vec::new(),
    })
}

/// Split YAML frontmatter from markdown body.
fn split_frontmatter(raw: &str) -> Result<(String, String), IngesterError> {
    let trimmed = raw.trim_start();
    if !trimmed.starts_with("---") {
        // No frontmatter — treat entire content as body
        return Ok((String::new(), raw.to_string()));
    }

    // Find the closing ---
    let after_first = &trimmed[3..];
    if let Some(end_pos) = after_first.find("\n---") {
        let fm = after_first[..end_pos].trim().to_string();
        let body_start = end_pos + 4; // skip "\n---"
        let body = if body_start < after_first.len() {
            after_first[body_start..].trim_start_matches('\n').to_string()
        } else {
            String::new()
        };
        Ok((fm, body))
    } else {
        Err(IngesterError::InvalidFrontmatter(
            "No closing --- found for frontmatter".to_string(),
        ))
    }
}

/// Parse markdown into sections by heading level.
/// Each heading starts a new section. Content runs until the next heading of any level.
fn parse_sections(body: &str) -> Vec<MarkdownSection> {
    let mut sections = Vec::new();
    let lines: Vec<&str> = body.lines().collect();

    // First pass: find all heading positions
    let mut headings: Vec<(usize, u8, String)> = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        if let Some((level, title)) = parse_heading(line) {
            headings.push((i, level, title.to_string()));
        }
    }

    // Second pass: extract content between headings
    for (idx, (line_idx, level, title)) in headings.iter().enumerate() {
        let content_start = line_idx + 1;
        let content_end = if idx + 1 < headings.len() {
            headings[idx + 1].0
        } else {
            lines.len()
        };

        let content = if content_start < content_end {
            lines[content_start..content_end].join("\n")
        } else {
            String::new()
        };

        sections.push(MarkdownSection {
            title: title.clone(),
            level: *level,
            content,
            line_start: line_idx + 1, // 1-indexed
            line_end: content_end,
        });
    }

    sections
}

/// Parse a markdown heading line, returning (level, title).
fn parse_heading(line: &str) -> Option<(u8, &str)> {
    let trimmed = line.trim();
    if !trimmed.starts_with('#') {
        return None;
    }
    let hashes = trimmed.bytes().take_while(|&b| b == b'#').count();
    if hashes > 6 || hashes == 0 {
        return None;
    }
    let rest = trimmed[hashes..].trim();
    if rest.is_empty() {
        return None;
    }
    Some((hashes as u8, rest))
}

/// Extract fenced code blocks from markdown.
fn extract_code_blocks(body: &str) -> Vec<CodeBlock> {
    let mut blocks = Vec::new();
    let lines: Vec<&str> = body.lines().collect();
    let mut i = 0;

    while i < lines.len() {
        let line = lines[i].trim();
        if line.starts_with("```") {
            let lang = line.trim_start_matches('`').trim();
            let language = if lang.is_empty() {
                None
            } else {
                Some(lang.to_string())
            };
            let line_start = i + 1; // 1-indexed

            let mut content_lines = Vec::new();
            i += 1;
            while i < lines.len() {
                if lines[i].trim().starts_with("```") {
                    break;
                }
                content_lines.push(lines[i]);
                i += 1;
            }

            blocks.push(CodeBlock {
                language,
                content: content_lines.join("\n"),
                line_start,
            });
        }
        i += 1;
    }

    blocks
}

/// Extract all URLs from text.
fn extract_urls(text: &str) -> Vec<ExtractedUrl> {
    let url_re = regex::Regex::new(
        r#"https?://[^\s)\]>"'`]+"#
    ).expect("valid regex");

    let mut urls = Vec::new();
    for (line_idx, line) in text.lines().enumerate() {
        for m in url_re.find_iter(line) {
            let url = m.as_str().trim_end_matches(|c: char| c == '.' || c == ',');
            let domain = extract_domain(url).unwrap_or_default();
            urls.push(ExtractedUrl {
                url: url.to_string(),
                domain,
                line: line_idx + 1,
                context: line.to_string(),
            });
        }
    }
    urls
}

/// Extract domain from a URL string.
fn extract_domain(url: &str) -> Option<String> {
    let without_scheme = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))?;
    let domain = without_scheme.split('/').next()?;
    let domain = domain.split(':').next()?;
    Some(domain.to_string())
}

/// Extract file paths referenced in text (e.g. ~/.ssh/, /etc/passwd).
fn extract_file_paths(text: &str) -> Vec<String> {
    let path_re = regex::Regex::new(
        r"(?:~/|/etc/|/tmp/|/var/|/usr/)[\w./\-]+"
    ).expect("valid regex");

    let mut paths = Vec::new();
    for m in path_re.find_iter(text) {
        paths.push(m.as_str().to_string());
    }
    paths.sort();
    paths.dedup();
    paths
}

/// Collect non-SKILL.md files from the skill directory.
fn collect_skill_files(skill_dir: &Path, skill_md_path: &Path) -> Result<Vec<SkillFile>, std::io::Error> {
    let mut files = Vec::new();
    if !skill_dir.is_dir() {
        return Ok(files);
    }

    for entry in std::fs::read_dir(skill_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path == skill_md_path || !path.is_file() {
            continue;
        }

        // Only read text files up to 1MB
        let metadata = std::fs::metadata(&path)?;
        if metadata.len() > 1_048_576 {
            continue;
        }

        if let Ok(content) = std::fs::read_to_string(&path) {
            let rel_path = path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();
            files.push(SkillFile {
                path: rel_path,
                content: content.clone(),
                size: content.len(),
            });
        }
    }

    Ok(files)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_frontmatter() {
        let input = "---\nname: test\nversion: \"1.0\"\n---\n# Hello\n\nBody text";
        let (fm, body) = split_frontmatter(input).unwrap();
        assert!(fm.contains("name: test"));
        assert!(body.contains("# Hello"));
        assert!(body.contains("Body text"));
    }

    #[test]
    fn test_split_no_frontmatter() {
        let input = "# Hello\n\nNo frontmatter here";
        let (fm, body) = split_frontmatter(input).unwrap();
        assert!(fm.is_empty());
        assert!(body.contains("# Hello"));
    }

    #[test]
    fn test_parse_sections() {
        let body = "# Title\n\nIntro text\n\n## Section A\n\nContent A\n\n## Section B\n\nContent B";
        let sections = parse_sections(body);
        assert_eq!(sections.len(), 3);
        assert_eq!(sections[0].title, "Title");
        assert_eq!(sections[0].level, 1);
        assert_eq!(sections[1].title, "Section A");
        assert_eq!(sections[2].title, "Section B");
    }

    #[test]
    fn test_extract_code_blocks() {
        let body = "Some text\n\n```bash\necho hello\ncurl example.com\n```\n\nMore text\n\n```python\nprint('hi')\n```";
        let blocks = extract_code_blocks(body);
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0].language.as_deref(), Some("bash"));
        assert!(blocks[0].content.contains("curl example.com"));
        assert_eq!(blocks[1].language.as_deref(), Some("python"));
    }

    #[test]
    fn test_extract_urls() {
        let text = "Visit https://example.com/path and http://test.org/page for details.";
        let urls = extract_urls(text);
        assert_eq!(urls.len(), 2);
        assert_eq!(urls[0].domain, "example.com");
        assert_eq!(urls[1].domain, "test.org");
    }

    #[test]
    fn test_extract_file_paths() {
        let text = "Access ~/.ssh/id_rsa and /etc/passwd for credentials";
        let paths = extract_file_paths(text);
        assert!(paths.iter().any(|p| p.contains(".ssh")));
        assert!(paths.iter().any(|p| p.contains("/etc/passwd")));
    }

    #[test]
    fn test_parse_full_skill() {
        let raw = r#"---
name: test-skill
description: A test skill
version: "1.0.0"
metadata:
  openclaw:
    requires:
      env:
        - API_KEY
      bins:
        - curl
---

# Test Skill

## Usage

Use this skill to test things.

```bash
echo "hello world"
```
"#;
        let skill = parse_skill_content(raw).unwrap();
        assert_eq!(skill.frontmatter.name, "test-skill");
        assert!(!skill.sections.is_empty());
        assert!(!skill.code_blocks.is_empty());
    }
}
