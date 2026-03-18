//! Signature database — loads threat intelligence from YAML files.
//!
//! YAML signature files are embedded at compile time so no runtime
//! filesystem access is needed, while keeping the YAML files as the
//! single source of truth for indicators of compromise.

use serde::Deserialize;

/// A malware campaign signature loaded from YAML.
#[derive(Debug, Deserialize)]
pub struct CampaignSignature {
    pub campaign: String,
    #[serde(default)]
    pub references: Vec<String>,
    pub indicators: CampaignIndicators,
}

#[derive(Debug, Deserialize)]
pub struct CampaignIndicators {
    #[serde(default)]
    pub publisher_accounts: Vec<String>,
    #[serde(default)]
    pub name_patterns: Vec<String>,
    #[serde(default)]
    pub url_patterns: Vec<String>,
}

/// A technique-based signature (data exfiltration, reverse shells).
#[derive(Debug, Deserialize)]
pub struct TechniqueSignature {
    pub category: String,
    pub severity: String,
    #[serde(default)]
    pub endpoints: Vec<EndpointIndicator>,
    #[serde(default)]
    pub patterns: Vec<PatternIndicator>,
    #[serde(default)]
    pub techniques: Vec<TechniqueIndicator>,
}

#[derive(Debug, Deserialize)]
pub struct EndpointIndicator {
    pub domain: String,
    #[serde(default)]
    pub description: String,
}

#[derive(Debug, Deserialize)]
pub struct PatternIndicator {
    pub name: String,
    pub regex: String,
    #[serde(default)]
    pub description: String,
}

#[derive(Debug, Deserialize)]
pub struct TechniqueIndicator {
    pub name: String,
    pub regex: String,
    #[serde(default)]
    pub description: String,
}

/// Aggregated signature database built from all YAML files.
pub struct SignatureDatabase {
    pub campaigns: Vec<CampaignSignature>,
    pub techniques: Vec<TechniqueSignature>,
}

// Embed YAML files at compile time
const CLAWHAVOC_YAML: &str = include_str!("../../../signatures/clawhavoc.yaml");
const AMOS_STEALER_YAML: &str = include_str!("../../../signatures/amos-stealer.yaml");
const DATA_EXFIL_YAML: &str = include_str!("../../../signatures/data-exfil.yaml");
const REVERSE_SHELLS_YAML: &str = include_str!("../../../signatures/reverse-shells.yaml");

impl SignatureDatabase {
    /// Load the signature database from embedded YAML files.
    pub fn load() -> Self {
        let mut campaigns = Vec::new();
        let mut techniques = Vec::new();

        // Load campaign signatures
        for yaml in [CLAWHAVOC_YAML, AMOS_STEALER_YAML] {
            if let Ok(sig) = serde_yaml::from_str::<CampaignSignature>(yaml) {
                campaigns.push(sig);
            }
        }

        // Load technique signatures
        for yaml in [DATA_EXFIL_YAML, REVERSE_SHELLS_YAML] {
            if let Ok(sig) = serde_yaml::from_str::<TechniqueSignature>(yaml) {
                techniques.push(sig);
            }
        }

        Self {
            campaigns,
            techniques,
        }
    }

    /// Get all malicious publisher accounts across all campaigns.
    pub fn malicious_publishers(&self) -> Vec<&str> {
        self.campaigns
            .iter()
            .flat_map(|c| c.indicators.publisher_accounts.iter().map(|s| s.as_str()))
            .collect()
    }

    /// Get all malicious URL patterns across all campaigns.
    pub fn malicious_url_patterns(&self) -> Vec<&str> {
        self.campaigns
            .iter()
            .flat_map(|c| c.indicators.url_patterns.iter().map(|s| s.as_str()))
            .collect()
    }

    /// Get all malicious name patterns across all campaigns.
    /// Strips glob wildcards to produce prefix strings.
    /// Patterns with leading wildcards (e.g. `*-pro`) are excluded as they
    /// represent suffix patterns handled separately by typosquatting detection.
    pub fn malicious_name_prefixes(&self) -> Vec<String> {
        self.campaigns
            .iter()
            .flat_map(|c| {
                c.indicators.name_patterns.iter().filter_map(|p| {
                    // Skip suffix patterns like "*-pro"
                    if p.starts_with('*') {
                        return None;
                    }
                    // Strip trailing glob wildcards: "solana-wallet*" -> "solana-wallet"
                    let prefix = p.trim_end_matches('*').to_string();
                    if prefix.is_empty() {
                        None
                    } else {
                        Some(prefix)
                    }
                })
            })
            .collect()
    }

    /// Get references for a given campaign name.
    pub fn campaign_references(&self, campaign: &str) -> Vec<String> {
        self.campaigns
            .iter()
            .find(|c| c.campaign.to_lowercase().contains(&campaign.to_lowercase()))
            .map(|c| c.references.clone())
            .unwrap_or_default()
    }

    /// Get all exfiltration endpoint domains.
    pub fn exfil_domains(&self) -> Vec<&str> {
        self.techniques
            .iter()
            .flat_map(|t| t.endpoints.iter().map(|e| e.domain.as_str()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_database() {
        let db = SignatureDatabase::load();
        assert!(
            !db.campaigns.is_empty(),
            "Should load at least one campaign"
        );
        assert!(
            !db.techniques.is_empty(),
            "Should load at least one technique"
        );
    }

    #[test]
    fn test_malicious_publishers() {
        let db = SignatureDatabase::load();
        let publishers = db.malicious_publishers();
        assert!(
            publishers.contains(&"hightower6eu"),
            "Should include ClawHavoc publisher"
        );
    }

    #[test]
    fn test_malicious_url_patterns() {
        let db = SignatureDatabase::load();
        let patterns = db.malicious_url_patterns();
        assert!(!patterns.is_empty(), "Should have at least one URL pattern");
    }

    #[test]
    fn test_name_prefixes_strip_globs() {
        let db = SignatureDatabase::load();
        let prefixes = db.malicious_name_prefixes();
        assert!(
            prefixes.iter().any(|p| p == "solana-wallet"),
            "Should strip glob from solana-wallet*"
        );
        // Should not contain raw glob characters
        for prefix in &prefixes {
            assert!(!prefix.contains('*'), "Prefix should not contain '*'");
        }
    }

    #[test]
    fn test_campaign_references() {
        let db = SignatureDatabase::load();
        let refs = db.campaign_references("ClawHavoc");
        assert!(!refs.is_empty(), "ClawHavoc should have references");
    }

    #[test]
    fn test_exfil_domains() {
        let db = SignatureDatabase::load();
        let domains = db.exfil_domains();
        assert!(
            domains.contains(&"webhook.site"),
            "Should include webhook.site"
        );
    }
}
