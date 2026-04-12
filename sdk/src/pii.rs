use std::collections::HashMap;

use once_cell::sync::Lazy;
use regex::Regex;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PiiType {
    CreditCard,
    Ssn,
    Email,
    Phone,
    IpAddress,
    ApiKey,
    Password,
    Token,
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
        }
    }

    pub fn redaction_label(&self) -> String {
        format!("[REDACTED-{}]", self.as_str())
    }
}

#[derive(Debug, Clone)]
pub struct PiiFinding {
    pub pii_type: PiiType,
    pub start: usize,
    pub end: usize,
    pub confidence: f32,
}

#[derive(Debug, Clone)]
pub struct PiiConfig {
    pub enabled: bool,
    pub redact_credit_cards: bool,
    pub redact_ssn: bool,
    pub redact_emails: bool,
    pub redact_phones: bool,
    pub redact_ip_addresses: bool,
    pub redact_api_keys: bool,
    pub redact_passwords: bool,
    pub redact_tokens: bool,
    pub custom_patterns: Vec<(String, String)>,
}

impl Default for PiiConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            redact_credit_cards: true,
            redact_ssn: true,
            redact_emails: true,
            redact_phones: true,
            redact_ip_addresses: false,
            redact_api_keys: true,
            redact_passwords: true,
            redact_tokens: true,
            custom_patterns: vec![],
        }
    }
}

pub struct PiiSanitizer {
    config: PiiConfig,
    patterns: Vec<(PiiType, Regex)>,
}

static CREDIT_CARD_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})\b").unwrap()
});

static SSN_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").unwrap());

static EMAIL_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}").unwrap());

static PHONE_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b").unwrap()
});

static IP_ADDRESS_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b").unwrap()
});

static API_KEY_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r##"(?i)(?:api[_-]?key|apikey|key)\s*[:=]\s*['"]?([a-zA-Z0-9_-]{16,})['"]?"##)
        .unwrap()
});

static PASSWORD_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r##"(?i)['"]?(password|passwd|pwd)['"]?\s*[:=]\s*['"]?([^\s,'"\}]{8,})"##).unwrap()
});

static TOKEN_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b(?:bearer\s+)?([a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{20,})\b")
        .unwrap()
});

impl PiiSanitizer {
    pub fn new(config: PiiConfig) -> Self {
        let mut patterns: Vec<(PiiType, Regex)> = vec![];

        if config.redact_credit_cards {
            patterns.push((PiiType::CreditCard, CREDIT_CARD_REGEX.clone()));
        }
        if config.redact_ssn {
            patterns.push((PiiType::Ssn, SSN_REGEX.clone()));
        }
        if config.redact_emails {
            patterns.push((PiiType::Email, EMAIL_REGEX.clone()));
        }
        if config.redact_phones {
            patterns.push((PiiType::Phone, PHONE_REGEX.clone()));
        }
        if config.redact_ip_addresses {
            patterns.push((PiiType::IpAddress, IP_ADDRESS_REGEX.clone()));
        }
        if config.redact_api_keys {
            patterns.push((PiiType::ApiKey, API_KEY_REGEX.clone()));
        }
        if config.redact_passwords {
            patterns.push((PiiType::Password, PASSWORD_REGEX.clone()));
        }
        if config.redact_tokens {
            patterns.push((PiiType::Token, TOKEN_REGEX.clone()));
        }

        Self { config, patterns }
    }

    pub fn default() -> Self {
        Self::new(PiiConfig::default())
    }

    pub fn detect(&self, content: &str) -> Vec<PiiFinding> {
        let mut findings = vec![];

        for (pii_type, regex) in &self.patterns {
            for mat in regex.find_iter(content) {
                findings.push(PiiFinding {
                    pii_type: *pii_type,
                    start: mat.start(),
                    end: mat.end(),
                    confidence: 0.95,
                });
            }
        }

        findings.sort_by_key(|f| f.start);
        findings
    }

    pub fn contains_pii(&self, content: &str) -> bool {
        !self.detect(content).is_empty()
    }

    pub fn redact(&self, content: &str) -> String {
        if !self.config.enabled {
            return content.to_string();
        }

        let findings = self.detect(content);
        if findings.is_empty() {
            return content.to_string();
        }

        let mut result = String::with_capacity(content.len());
        let mut last_end = 0;

        for finding in findings {
            result.push_str(&content[last_end..finding.start]);
            result.push_str(&finding.pii_type.redaction_label());
            last_end = finding.end;
        }

        result.push_str(&content[last_end..]);

        result
    }

    pub fn sanitize_for_storage(&self, content: &str, max_length: usize) -> String {
        let redacted = self.redact(content);

        if redacted.len() > max_length {
            format!(
                "{}...[TRUNCATED]",
                &redacted[..max_length.saturating_sub(15)]
            )
        } else {
            redacted
        }
    }

    pub fn get_stats(&self, content: &str) -> PiiStats {
        let findings = self.detect(content);

        let mut counts = HashMap::new();
        for finding in &findings {
            *counts.entry(finding.pii_type).or_insert(0) += 1;
        }

        PiiStats {
            total_findings: findings.len(),
            type_counts: counts,
            has_pii: !findings.is_empty(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct PiiStats {
    pub total_findings: usize,
    pub type_counts: HashMap<PiiType, usize>,
    pub has_pii: bool,
}

impl PiiStats {
    pub fn to_metric_labels(&self) -> Vec<(String, usize)> {
        self.type_counts
            .iter()
            .map(|(t, c)| (format!("pii_type={}", t.as_str()), *c))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_credit_card_redaction() {
        let sanitizer = PiiSanitizer::default();
        let content = "My card is 4532015112830366 and 5555555555554444";
        let redacted = sanitizer.redact(content);

        assert!(redacted.contains("[REDACTED-CREDIT_CARD]"));
        assert!(!redacted.contains("4532015112830366"));
        assert!(!redacted.contains("5555555555554444"));
    }

    #[test]
    fn test_ssn_redaction() {
        let sanitizer = PiiSanitizer::default();
        let content = "My SSN is 123-45-6789";
        let redacted = sanitizer.redact(content);

        assert!(redacted.contains("[REDACTED-SSN]"));
        assert!(!redacted.contains("123-45-6789"));
    }

    #[test]
    fn test_email_redaction() {
        let sanitizer = PiiSanitizer::default();
        let content = "Contact me at john.doe@example.com";
        let redacted = sanitizer.redact(content);

        assert!(redacted.contains("[REDACTED-EMAIL]"));
        assert!(!redacted.contains("john.doe@example.com"));
    }

    #[test]
    fn test_password_redaction() {
        let sanitizer = PiiSanitizer::default();
        let content = r#"{"password": "supersecret123", "user": "admin"}"#;
        let redacted = sanitizer.redact(content);

        assert!(redacted.contains("[REDACTED-PASSWORD]"));
        assert!(!redacted.contains("supersecret123"));
    }

    #[test]
    fn test_no_pii_unchanged() {
        let sanitizer = PiiSanitizer::default();
        let content = "Hello world, this is a test message";
        let redacted = sanitizer.redact(content);

        assert_eq!(redacted, content);
    }

    #[test]
    fn test_pii_detection() {
        let sanitizer = PiiSanitizer::default();

        assert!(sanitizer.contains_pii("My card is 4532015112830366"));
        assert!(sanitizer.contains_pii("Contact john@example.com"));
        assert!(!sanitizer.contains_pii("Hello world"));
    }

    #[test]
    fn test_truncate() {
        let sanitizer = PiiSanitizer::default();
        let content = "a".repeat(1000);
        let truncated = sanitizer.sanitize_for_storage(&content, 100);

        assert!(truncated.len() <= 100);
        assert!(truncated.contains("[TRUNCATED]"));
    }

    #[test]
    fn test_stats() {
        let sanitizer = PiiSanitizer::default();
        let content = "Card: 4532015112830366, Email: test@example.com, SSN: 123-45-6789";
        let stats = sanitizer.get_stats(content);

        assert!(stats.has_pii);
        assert_eq!(stats.total_findings, 3);
        assert!(stats.type_counts.contains_key(&PiiType::CreditCard));
        assert!(stats.type_counts.contains_key(&PiiType::Email));
        assert!(stats.type_counts.contains_key(&PiiType::Ssn));
    }
}
