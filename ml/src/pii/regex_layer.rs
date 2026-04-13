//! Regex-based PII detection layer.
//!
//! Lifted from `sdk/src/pii.rs` with additional patterns for SSH keys,
//! private keys, and common secret formats.

use std::sync::LazyLock;

use regex::Regex;

use super::{PiiFinding, PiiType};

/// Compiled regex patterns for PII detection.
pub struct RegexLayer {
    patterns: Vec<(PiiType, Regex, f32)>,
}

// Static regex patterns — compiled once, reused forever.
static CREDIT_CARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})\b").unwrap()
});

static SSN: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").unwrap());

static EMAIL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}").unwrap());

static PHONE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b").unwrap()
});

static IP_ADDRESS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b").unwrap()
});

static API_KEY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:api[_-]?key|apikey|api[_-]?secret)\s*[:=]\s*['"]?([a-zA-Z0-9_\-]{16,})['"]?"#).unwrap()
});

static PASSWORD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)['"]?(password|passwd|pwd|secret)['"]?\s*[:=]\s*['"]?([^\s,'"\}]{8,})"#).unwrap()
});

static TOKEN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:bearer\s+)?([a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{20,})\b").unwrap()
});

static SSH_KEY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----").unwrap()
});

static PRIVATE_KEY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:private[_-]?key|ssh[_-]?key|pem)\s*[:=]\s*['"]?(-----BEGIN|MH[a-zA-Z0-9+/]{40,}|MII[a-zA-Z0-9+/]{40,})"#).unwrap()
});

// Common secret patterns
static AWS_KEY: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}").unwrap());

static GITHUB_TOKEN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"gh[pousr]_[A-Za-z0-9_]{36,}").unwrap());

static GENERIC_SECRET: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:secret|token|credential|auth[_-]?token)\s*[:=]\s*['"]?([a-zA-Z0-9_\-./+]{20,})['"]?"#).unwrap()
});

impl RegexLayer {
    pub fn new() -> Self {
        Self {
            patterns: vec![
                (PiiType::CreditCard, CREDIT_CARD.clone(), 0.95),
                (PiiType::Ssn, SSN.clone(), 0.95),
                (PiiType::Email, EMAIL.clone(), 0.90),
                (PiiType::Phone, PHONE.clone(), 0.85),
                (PiiType::ApiKey, API_KEY.clone(), 0.90),
                (PiiType::ApiKey, AWS_KEY.clone(), 0.95),
                (PiiType::ApiKey, GITHUB_TOKEN.clone(), 0.95),
                (PiiType::ApiKey, GENERIC_SECRET.clone(), 0.80),
                (PiiType::Password, PASSWORD.clone(), 0.90),
                (PiiType::Token, TOKEN.clone(), 0.85),
                (PiiType::SshKey, SSH_KEY.clone(), 0.95),
                (PiiType::PrivateKey, PRIVATE_KEY.clone(), 0.85),
                (PiiType::IpAddress, IP_ADDRESS.clone(), 0.70),
            ],
        }
    }

    /// Detect all PII in the given text.
    pub fn detect(&self, content: &str) -> Vec<PiiFinding> {
        let mut findings = Vec::new();

        for (pii_type, regex, base_confidence) in &self.patterns {
            for mat in regex.find_iter(content) {
                findings.push(PiiFinding {
                    pii_type: *pii_type,
                    start: mat.start(),
                    end: mat.end(),
                    confidence: *base_confidence,
                    matched_text: mat.as_str().to_string(),
                });
            }
        }

        // Sort by position and remove overlapping matches (keep highest confidence)
        findings.sort_by(|a, b| a.start.cmp(&b.start).then(b.confidence.partial_cmp(&a.confidence).unwrap()));
        self.remove_overlaps(findings)
    }

    fn remove_overlaps(&self, mut findings: Vec<PiiFinding>) -> Vec<PiiFinding> {
        let mut result: Vec<PiiFinding> = Vec::new();

        while let Some(finding) = findings.pop() {
            let overlaps = result.iter().any(|existing| {
                finding.start < existing.end && finding.end > existing.start
            });
            if !overlaps {
                result.push(finding);
            }
        }

        result.sort_by_key(|f| f.start);
        result
    }
}
