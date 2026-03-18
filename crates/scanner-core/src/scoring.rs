//! Risk score calculation — aggregates findings into a 0-100 risk score.

use crate::analyzers::{Finding, Severity};
use serde::Serialize;

/// Aggregated scan score.
pub struct ScanScore {
    pub total: u32,
    pub category: RiskLevel,
    pub breakdown: ScoreBreakdown,
}

/// Risk level categories.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum RiskLevel {
    Clean,
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RiskLevel::Clean => write!(f, "CLEAN"),
            RiskLevel::Low => write!(f, "LOW"),
            RiskLevel::Medium => write!(f, "MEDIUM"),
            RiskLevel::High => write!(f, "HIGH"),
            RiskLevel::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// Breakdown of findings by severity.
#[derive(Debug, Clone, Serialize)]
pub struct ScoreBreakdown {
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub info_count: usize,
}

/// Calculate risk score from findings.
///
/// Scoring weights:
/// - Critical: 30 points each
/// - High: 15 points each
/// - Medium: 5 points each
/// - Low: 2 points each
/// - Info: 0 points
///
/// Score is capped at 100.
pub fn calculate_score(findings: &[Finding]) -> ScanScore {
    let mut score: u32 = 0;
    let mut critical_count = 0;
    let mut high_count = 0;
    let mut medium_count = 0;
    let mut low_count = 0;
    let mut info_count = 0;

    for finding in findings {
        match finding.severity {
            Severity::Critical => {
                score += 30;
                critical_count += 1;
            }
            Severity::High => {
                score += 15;
                high_count += 1;
            }
            Severity::Medium => {
                score += 5;
                medium_count += 1;
            }
            Severity::Low => {
                score += 2;
                low_count += 1;
            }
            Severity::Info => {
                info_count += 1;
            }
        }
    }

    score = score.min(100);

    let category = match score {
        0 => RiskLevel::Clean,
        1..=25 => RiskLevel::Low,
        26..=50 => RiskLevel::Medium,
        51..=75 => RiskLevel::High,
        _ => RiskLevel::Critical,
    };

    ScanScore {
        total: score,
        category,
        breakdown: ScoreBreakdown {
            critical_count,
            high_count,
            medium_count,
            low_count,
            info_count,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_finding(severity: Severity) -> Finding {
        Finding {
            rule_id: "TEST".to_string(),
            title: "Test".to_string(),
            severity,
            description: "Test".to_string(),
            evidence: "Test".to_string(),
            line: None,
            remediation: "Test".to_string(),
            references: vec![],
        }
    }

    #[test]
    fn test_clean_score() {
        let score = calculate_score(&[]);
        assert_eq!(score.total, 0);
        assert_eq!(score.category, RiskLevel::Clean);
    }

    #[test]
    fn test_critical_score() {
        let findings = vec![
            make_finding(Severity::Critical),
            make_finding(Severity::Critical),
            make_finding(Severity::High),
        ];
        let score = calculate_score(&findings);
        assert_eq!(score.total, 75);
        assert_eq!(score.category, RiskLevel::High);
    }

    #[test]
    fn test_score_caps_at_100() {
        let findings: Vec<Finding> = (0..10).map(|_| make_finding(Severity::Critical)).collect();
        let score = calculate_score(&findings);
        assert_eq!(score.total, 100);
        assert_eq!(score.category, RiskLevel::Critical);
    }

    #[test]
    fn test_low_score() {
        let findings = vec![make_finding(Severity::Low)];
        let score = calculate_score(&findings);
        assert_eq!(score.total, 2);
        assert_eq!(score.category, RiskLevel::Low);
    }

    #[test]
    fn test_info_no_score() {
        let findings = vec![make_finding(Severity::Info)];
        let score = calculate_score(&findings);
        assert_eq!(score.total, 0);
        assert_eq!(score.category, RiskLevel::Clean);
    }
}
