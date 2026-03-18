//! Analysis pipeline — runs all analyzers against a parsed skill
//! and collects security findings.

pub mod behavioral;
pub mod metadata;
pub mod pattern;
pub mod signatures;

use crate::ingester::ParsedSkill;
use serde::Serialize;

/// Severity levels for findings.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Info => write!(f, "INFO"),
            Severity::Low => write!(f, "LOW"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::High => write!(f, "HIGH"),
            Severity::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// A single security finding from an analyzer.
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub rule_id: String,
    pub title: String,
    pub severity: Severity,
    pub description: String,
    pub evidence: String,
    pub line: Option<usize>,
    pub remediation: String,
    pub references: Vec<String>,
}

/// Trait all analyzers implement.
pub trait Analyzer: Send + Sync {
    /// Name of this analyzer.
    fn name(&self) -> &str;
    /// Run analysis on a parsed skill and return findings.
    fn analyze(&self, skill: &ParsedSkill) -> Vec<Finding>;
}

/// Run all analyzers and collect findings, sorted by severity (critical first).
pub fn run_analysis(skill: &ParsedSkill) -> Vec<Finding> {
    let analyzers: Vec<Box<dyn Analyzer>> = vec![
        Box::new(pattern::PatternAnalyzer::new()),
        Box::new(metadata::MetadataAnalyzer::new()),
        Box::new(behavioral::BehavioralAnalyzer::new()),
        Box::new(signatures::SignatureAnalyzer::new()),
    ];

    let mut all_findings = Vec::new();
    for analyzer in &analyzers {
        let findings = analyzer.analyze(skill);
        all_findings.extend(findings);
    }

    // Deduplicate by rule_id + line (same rule on same line = duplicate)
    all_findings.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.rule_id.cmp(&b.rule_id))
    });
    all_findings.dedup_by(|a, b| a.rule_id == b.rule_id && a.line == b.line);

    all_findings
}
