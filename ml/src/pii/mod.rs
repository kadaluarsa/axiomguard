//! Hybrid PII sanitizer — regex fast-path + optional NER deep-path.
//!
//! Regex layer handles structured PII (emails, SSN, credit cards, API keys).
//! NER layer (when models are available) handles context-aware detection.

use std::path::Path;

/// Types of personally identifiable information.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PiiType {
    CreditCard,
    Ssn,
    Email,
    Phone,
    IpAddress,
    ApiKey,
    Password,
    Token,
    SshKey,
    PrivateKey,
}

impl PiiType {
    pub fn as_str(&self) -> &'static str {
        match self {
            PiiType::CreditCard => "CREDIT_CARD",
            PiiType::Ssn => "SSN",
            PiiType::Email => "EMAIL",
            PiiType::Phone => "PHONE",
            PiiType::IpAddress => "IP_ADDRESS",
            PiiType::ApiKey => "API_KEY",
            PiiType::Password => "PASSWORD",
            PiiType::Token => "TOKEN",
            PiiType::SshKey => "SSH_KEY",
            PiiType::PrivateKey => "PRIVATE_KEY",
        }
    }

    pub fn placeholder(&self, id: usize) -> String {
        format!("__PII_{}_{}__", self.as_str(), id)
    }
}

/// A single PII finding with location and confidence.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PiiFinding {
    pub pii_type: PiiType,
    pub start: usize,
    pub end: usize,
    pub confidence: f32,
    pub matched_text: String,
}

/// Result of PII sanitization.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SanitizeResult {
    /// Text with PII replaced by placeholders.
    pub sanitized: String,
    /// All PII findings.
    pub findings: Vec<PiiFinding>,
    /// Risk score based on PII density (0.0 = clean, 1.0 = high density).
    pub risk_score: f32,
    /// Whether any PII was found.
    pub has_pii: bool,
}

/// Hybrid PII sanitizer with regex + optional NER.
pub struct HybridPiiSanitizer {
    regex_layer: RegexLayer,
    // NER layer will be added when Candle models are available
    // ner_layer: Option<NerLayer>,
}

mod regex_layer;

use regex_layer::RegexLayer;

impl HybridPiiSanitizer {
    /// Create a new sanitizer, loading NER model if available.
    pub fn new(_model_dir: &Path) -> anyhow::Result<Self> {
        // TODO: Load NER model from model_dir if present
        Ok(Self::new_regex_only())
    }

    /// Create with regex-only capabilities.
    pub fn new_regex_only() -> Self {
        Self {
            regex_layer: RegexLayer::new(),
        }
    }

    /// Sanitize text by detecting and replacing PII.
    pub fn sanitize(&self, text: &str) -> SanitizeResult {
        let findings = self.regex_layer.detect(text);

        // TODO: If regex finds nothing suspicious, optionally run NER
        // TODO: If regex finds potential PII, run NER for confirmation

        if findings.is_empty() {
            return SanitizeResult {
                sanitized: text.to_string(),
                findings: vec![],
                risk_score: 0.0,
                has_pii: false,
            };
        }

        let sanitized = self.redact_findings(text, &findings);
        let risk_score = self.compute_risk_score(text.len(), &findings);

        SanitizeResult {
            sanitized,
            findings,
            risk_score,
            has_pii: true,
        }
    }

    /// Detect PII without redacting.
    pub fn detect(&self, text: &str) -> Vec<PiiFinding> {
        self.regex_layer.detect(text)
    }

    /// Check if text contains any PII.
    pub fn contains_pii(&self, text: &str) -> bool {
        self.regex_layer.detect(text).iter().any(|f| f.confidence > 0.7)
    }

    fn redact_findings(&self, text: &str, findings: &[PiiFinding]) -> String {
        let mut result = String::with_capacity(text.len());
        let mut last_end = 0;

        for (id, finding) in findings.iter().enumerate() {
            if finding.start > last_end {
                result.push_str(&text[last_end..finding.start]);
            }
            result.push_str(&finding.pii_type.placeholder(id));
            last_end = finding.end;
        }

        if last_end < text.len() {
            result.push_str(&text[last_end..]);
        }

        result
    }

    fn compute_risk_score(&self, text_len: usize, findings: &[PiiFinding]) -> f32 {
        if text_len == 0 {
            return 0.0;
        }

        let pii_chars: usize = findings.iter().map(|f| f.end - f.start).sum();
        let density = pii_chars as f32 / text_len as f32;

        // Weight by finding severity
        let severity: f32 = findings
            .iter()
            .map(|f| match f.pii_type {
                PiiType::Ssn | PiiType::CreditCard | PiiType::PrivateKey | PiiType::SshKey => 1.0,
                PiiType::ApiKey | PiiType::Token | PiiType::Password => 0.8,
                PiiType::Email | PiiType::Phone => 0.5,
                PiiType::IpAddress => 0.3,
            })
            .sum::<f32>()
            / findings.len().max(1) as f32;

        (severity * 0.7 + density * 0.3).min(1.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_email_sanitization() {
        let sanitizer = HybridPiiSanitizer::new_regex_only();
        let result = sanitizer.sanitize("Contact john.doe@example.com for details");
        assert!(result.has_pii);
        assert!(result.sanitized.contains("__PII_EMAIL_"));
        assert!(!result.sanitized.contains("john.doe@example.com"));
    }

    #[test]
    fn test_api_key_sanitization() {
        let sanitizer = HybridPiiSanitizer::new_regex_only();
        let result = sanitizer.sanitize(r#"api_key = "sk-abc123def456ghi789jkl""#);
        assert!(result.has_pii);
        assert!(result.sanitized.contains("__PII_API_KEY_"));
    }

    #[test]
    fn test_credit_card_sanitization() {
        let sanitizer = HybridPiiSanitizer::new_regex_only();
        let result = sanitizer.sanitize("Card: 4532015112830366");
        assert!(result.has_pii);
        assert!(result.sanitized.contains("__PII_CREDIT_CARD_"));
    }

    #[test]
    fn test_ssn_sanitization() {
        let sanitizer = HybridPiiSanitizer::new_regex_only();
        let result = sanitizer.sanitize("SSN: 123-45-6789");
        assert!(result.has_pii);
        assert!(result.sanitized.contains("__PII_SSN_"));
    }

    #[test]
    fn test_no_pii() {
        let sanitizer = HybridPiiSanitizer::new_regex_only();
        let result = sanitizer.sanitize("Hello world, no sensitive data here");
        assert!(!result.has_pii);
        assert_eq!(result.sanitized, "Hello world, no sensitive data here");
        assert_eq!(result.risk_score, 0.0);
    }

    #[test]
    fn test_multiple_pii_types() {
        let sanitizer = HybridPiiSanitizer::new_regex_only();
        let result = sanitizer.sanitize(
            "Email: test@example.com, SSN: 123-45-6789, Card: 4532015112830366",
        );
        assert!(result.has_pii);
        assert!(result.findings.len() >= 3);
        assert!(result.risk_score > 0.0);
    }

    #[test]
    fn test_risk_score_increases_with_severity() {
        let sanitizer = HybridPiiSanitizer::new_regex_only();

        let low_risk = sanitizer.sanitize("IP: 192.168.1.1");
        let high_risk = sanitizer.sanitize("SSN: 123-45-6789, Card: 4532015112830366");

        assert!(high_risk.risk_score > low_risk.risk_score);
    }

    #[test]
    fn test_contains_pii() {
        let sanitizer = HybridPiiSanitizer::new_regex_only();
        assert!(sanitizer.contains_pii("test@example.com"));
        assert!(!sanitizer.contains_pii("no sensitive data"));
    }
}
