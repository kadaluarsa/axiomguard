//! Fast regex-based injection pattern filter.
//!
//! Catches known attack patterns in <1ms. Serves as pre-filter for
//! optional ML classifier on ambiguous cases.

use std::sync::LazyLock;

use regex::Regex;

use super::InjectionCategory;

/// A single pattern match result.
pub struct PatternMatch {
    pub pattern_name: String,
    pub category: InjectionCategory,
    pub severity: f32,
}

// --- Prompt injection patterns ---
static IGNORE_INSTRUCTIONS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\bignore\b.{0,20}\b(?:all\s+)?(?:previous|prior|above|earlier|above)\b.{0,20}\binstructions?\b").unwrap()
});

static DISREGARD_RULES: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(?:disregard|forget|discard|drop)\b.{0,30}\b(?:all\s+)?(?:rules?|instructions?|guidelines?|constraints?|policies?)\b").unwrap()
});

static NEW_INSTRUCTIONS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(?:new|updated|real|actual)\s+instructions?\b.{0,20}\b(?:are|is|follow)\b").unwrap()
});

// --- System override patterns ---
static SYSTEM_PROMPT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\bsystem\s*prompt\b.{0,10}[:=]").unwrap()
});

static YOU_ARE_NOW: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\byou\s+are\s+now\b.{0,40}\b(?:unrestricted|uncensored|unfiltered|free|unlimited|jailbroken|DAN)\b").unwrap()
});

static ROLE_OVERRIDE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(?:pretend|act\s+as|roleplay|simulate)\s+you(?:'re| are)\b.{0,40}\b(?:unrestricted|uncensored|unfiltered|without\s+(?:any\s+)?(?:rules?|limits?|restrictions?))\b").unwrap()
});

// --- Jailbreak patterns ---
static BYPASS_SAFETY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\bbypass\b.{0,20}\b(?:safety|security|filter|guard|protection|restrictions?)\b").unwrap()
});

static JAILBREAK: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\bjailbreak\b").unwrap()
});

static OUT_OF_CHARACTER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(?:step\s+out\s+of|break\s+(?:your\s+)?(?:character|role))\b").unwrap()
});

// --- Data exfiltration patterns ---
static SEND_SECRETS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(?:send|transmit|export|exfiltrate|forward|email|post)\b.{0,30}\b(?:secrets?|credentials?|passwords?|tokens?|keys?|sensitive)\b").unwrap()
});

static EXTERNAL_SERVER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(?:send|transmit|forward|post)\b.{0,30}\b(?:to\s+)?(?:external|remote|third.?party|outside)\w*\b").unwrap()
});

/// Compiled pattern filter for fast injection pre-screening.
pub struct PatternFilter {
    patterns: Vec<(&'static str, &'static LazyLock<Regex>, InjectionCategory, f32)>,
}

impl PatternFilter {
    pub fn new() -> Self {
        let patterns: Vec<(&'static str, &'static LazyLock<Regex>, InjectionCategory, f32)> = vec![
            // Prompt injection
            ("ignore_instructions", &IGNORE_INSTRUCTIONS, InjectionCategory::PromptInjection, 0.9),
            ("disregard_rules", &DISREGARD_RULES, InjectionCategory::PromptInjection, 0.85),
            ("new_instructions", &NEW_INSTRUCTIONS, InjectionCategory::PromptInjection, 0.8),
            // System override
            ("system_prompt_leak", &SYSTEM_PROMPT, InjectionCategory::SystemOverride, 0.85),
            ("you_are_now", &YOU_ARE_NOW, InjectionCategory::SystemOverride, 0.9),
            ("role_override", &ROLE_OVERRIDE, InjectionCategory::SystemOverride, 0.8),
            // Jailbreak
            ("bypass_safety", &BYPASS_SAFETY, InjectionCategory::Jailbreak, 0.9),
            ("jailbreak", &JAILBREAK, InjectionCategory::Jailbreak, 0.85),
            ("out_of_character", &OUT_OF_CHARACTER, InjectionCategory::Jailbreak, 0.7),
            // Data exfiltration
            ("send_secrets", &SEND_SECRETS, InjectionCategory::DataExfiltration, 0.85),
            ("external_server", &EXTERNAL_SERVER, InjectionCategory::DataExfiltration, 0.75),
        ];

        Self { patterns }
    }

    /// Check text against all patterns. Returns matches in order found.
    pub fn check(&self, text: &str) -> Vec<PatternMatch> {
        let mut matches = Vec::new();

        for (name, regex, category, severity) in &self.patterns {
            if regex.is_match(text) {
                matches.push(PatternMatch {
                    pattern_name: (*name).to_string(),
                    category: *category,
                    severity: *severity,
                });
            }
        }

        matches
    }
}
