//! Smart routing between deterministic rules and AI classification
//!
//! This module provides multiple strategies for deciding when to use
//! deterministic rules vs AI classification.

use serde::{Deserialize, Serialize};
use std::time::Instant;

/// Routing mode for classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RoutingMode {
    /// Rules only - never use AI
    /// Use case: Strict compliance, zero AI cost
    RulesOnly,
    
    /// AI only - skip rules
    /// Use case: Complex semantic analysis where rules can't help
    AiOnly,
    
    /// Sequential: Rules first, AI if no match
    /// Use case: Fast path for known patterns, AI for unknown
    Sequential,
    
    /// Speculative: Run rules and AI in parallel, combine results
    /// Use case: Best accuracy, uses more resources
    Speculative,
    
    /// Smart: Route based on content complexity
    /// Use case: Automatic optimization
    Smart,

    /// Formal: Strict compliance with documented policies, combines rules and AI for audit trails
    /// Use case: Regulated environments requiring full audit records
    Formal,
}

impl Default for RoutingMode {
    fn default() -> Self {
        RoutingMode::Sequential
    }
}

impl RoutingMode {
    /// Parse from string
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "rules_only" | "rules-only" => Some(RoutingMode::RulesOnly),
            "ai_only" | "ai-only" => Some(RoutingMode::AiOnly),
            "sequential" => Some(RoutingMode::Sequential),
            "speculative" => Some(RoutingMode::Speculative),
            "smart" => Some(RoutingMode::Smart),
            "formal" => Some(RoutingMode::Formal),
            _ => None,
        }
    }
}

/// Result from deterministic rule evaluation
#[derive(Debug, Clone)]
pub struct RuleEvaluationResult {
    pub matched: bool,
    pub rule_id: Option<String>,
    pub rule_name: Option<String>,
    pub decision: Option<crate::DecisionType>,
    pub priority: Option<i32>,
    pub evaluation_time_ms: u64,
}

/// Result from AI classification
#[derive(Debug, Clone)]
pub struct AiEvaluationResult {
    pub risk_level: f32,
    pub category: String,
    pub confidence: f32,
    pub model: String,
    pub fallback_used: bool,
    pub evaluation_time_ms: u64,
}

/// Combined classification result
#[derive(Debug, Clone)]
pub struct ClassificationResult {
    pub decision: crate::DecisionType,
    pub confidence: f32,
    pub reason: String,
    pub matched_rules: Vec<String>,
    pub ai_insights: Option<AiInsights>,
    pub routing_mode: RoutingMode,
    pub rule_time_ms: u64,
    pub ai_time_ms: u64,
    pub total_time_ms: u64,
}

#[derive(Debug, Clone)]
pub struct AiInsights {
    pub risk_level: f32,
    pub category: String,
    pub anomalies: Vec<String>,
    pub recommendations: Vec<String>,
    pub model: String,
    pub fallback_used: bool,
}

/// Smart router that decides when to use rules vs AI
#[derive(Debug)]
pub struct ClassificationRouter {
    mode: RoutingMode,
    /// Threshold for smart routing - content length that triggers AI
    smart_content_length_threshold: usize,
    /// Threshold for smart routing - complexity score
    smart_complexity_threshold: f32,
    /// Maximum time to wait for AI in speculative mode
    speculative_timeout_ms: u64,
}

impl ClassificationRouter {
    pub fn new(mode: RoutingMode) -> Self {
        Self {
            mode,
            smart_content_length_threshold: 200,  // Characters
            smart_complexity_threshold: 0.6,
            speculative_timeout_ms: 50,  // Wait max 50ms for AI
        }
    }
    
    pub fn with_config(
        mut self,
        content_threshold: usize,
        complexity_threshold: f32,
        speculative_timeout: u64,
    ) -> Self {
        self.smart_content_length_threshold = content_threshold;
        self.smart_complexity_threshold = complexity_threshold;
        self.speculative_timeout_ms = speculative_timeout;
        self
    }
    
    /// Determine if AI should be used based on content analysis
    pub fn should_use_ai(&self, content: &str, rule_match: bool) -> bool {
        match self.mode {
            RoutingMode::RulesOnly => false,
            RoutingMode::AiOnly => true,
            RoutingMode::Sequential => !rule_match,  // Use AI if no rule matched
            RoutingMode::Speculative => true,  // Always use AI (parallel)
            RoutingMode::Smart => self.smart_routing_decision(content, rule_match),
            RoutingMode::Formal => true,
        }
    }
    
    /// Smart routing logic
    fn smart_routing_decision(&self, content: &str, rule_match: bool) -> bool {
        // If we have a deterministic BLOCK rule, don't waste AI time
        if rule_match {
            return false;
        }
        
        // Analyze content complexity
        let complexity_score = self.analyze_content_complexity(content);
        
        // Use AI if content is complex or long
        let length_factor = (content.len() as f32 / self.smart_content_length_threshold as f32).min(1.0);
        let should_use_ai = complexity_score > self.smart_complexity_threshold || length_factor > 0.8;
        
        tracing::debug!(
            complexity_score = %complexity_score,
            length_factor = %length_factor,
            should_use_ai = %should_use_ai,
            "Smart routing decision"
        );
        
        should_use_ai
    }
    
    /// Analyze content complexity (0.0 = simple, 1.0 = complex)
    fn analyze_content_complexity(&self, content: &str) -> f32 {
        let mut score: f32 = 0.0;
        let content_lower = content.to_lowercase();
        
        // Check for complex patterns that benefit from AI
        let complex_indicators = [
            ("suspicious", 0.3),
            ("fraud", 0.4),
            ("urgent", 0.2),
            ("verify", 0.2),
            ("account", 0.15),
            ("password", 0.3),
            ("click here", 0.25),
            ("limited time", 0.2),
            ("http", 0.1),
            ("free", 0.1),
        ];
        
        for (pattern, weight) in &complex_indicators {
            if content_lower.contains(pattern) {
                score += weight;
            }
        }
        
        // Penalize very short content (rules usually handle these)
        if content.len() < 50 {
            score -= 0.3;
        }
        
        // Bonus for mixed languages or special characters
        let special_chars = content.chars().filter(|c| !c.is_ascii_alphanumeric() && !c.is_whitespace()).count();
        if special_chars > 5 {
            score += 0.2;
        }
        
        score.clamp(0.0_f32, 1.0_f32)
    }
    
    /// Get the routing mode
    pub fn mode(&self) -> RoutingMode {
        self.mode
    }
    
    /// Set routing mode
    pub fn set_mode(&mut self, mode: RoutingMode) {
        self.mode = mode;
    }
}

/// Rule hint that can be embedded in JSONLogic to indicate routing preference
/// 
/// Example:
/// ```json
/// {
///   "and": [
///     {">": [{"var": "amount"}, 10000]},
///     {"__hint": "use_ai_for_verification"}
///   ]
/// }
/// ```
#[derive(Debug, Clone)]
pub enum RuleHint {
    /// Skip AI even if no other rules match
    SkipAi,
    /// Always use AI for this rule match
    UseAi,
    /// Use AI if confidence is low
    UseAiIfUncertain,
    /// Parallel execution with AI
    Parallel,
}

impl RuleHint {
    /// Parse from string in JSONLogic
    pub fn from_hint_value(value: &str) -> Option<Self> {
        match value {
            "skip_ai" | "skip-ai" => Some(RuleHint::SkipAi),
            "use_ai" | "use-ai" => Some(RuleHint::UseAi),
            "use_ai_if_uncertain" | "use-ai-if-uncertain" => Some(RuleHint::UseAiIfUncertain),
            "parallel" => Some(RuleHint::Parallel),
            _ => None,
        }
    }
}

/// Configuration per rule for routing behavior
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleRoutingConfig {
    /// If true, matching this rule skips AI (deterministic)
    pub skip_ai: bool,
    /// If true, this rule requires AI confirmation
    pub require_ai: bool,
    /// Minimum AI confidence required if require_ai is true
    pub min_ai_confidence: f32,
    /// If true, run AI in parallel with this rule
    pub parallel_ai: bool,
}

impl Default for RuleRoutingConfig {
    fn default() -> Self {
        Self {
            skip_ai: false,
            require_ai: false,
            min_ai_confidence: 0.7,
            parallel_ai: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_routing_mode_parsing() {
        assert_eq!(RoutingMode::from_str("rules_only"), Some(RoutingMode::RulesOnly));
        assert_eq!(RoutingMode::from_str("ai-only"), Some(RoutingMode::AiOnly));
        assert_eq!(RoutingMode::from_str("sequential"), Some(RoutingMode::Sequential));
        assert_eq!(RoutingMode::from_str("speculative"), Some(RoutingMode::Speculative));
        assert_eq!(RoutingMode::from_str("smart"), Some(RoutingMode::Smart));
        assert_eq!(RoutingMode::from_str("formal"), Some(RoutingMode::Formal));
        assert_eq!(RoutingMode::from_str("unknown"), None);
    }
    
    #[test]
    fn test_smart_routing_simple_content() {
        let router = ClassificationRouter::new(RoutingMode::Smart);
        
        // Simple, short content - should not use AI
        let simple = "Hello world";
        assert!(!router.should_use_ai(simple, false));
        
        // Content with suspicious keywords - should use AI
        let suspicious = "Click here to verify your account password urgently";
        assert!(router.should_use_ai(suspicious, false));
    }
    
    #[test]
    fn test_rules_only_mode() {
        let router = ClassificationRouter::new(RoutingMode::RulesOnly);
        assert!(!router.should_use_ai("any content", false));
        assert!(!router.should_use_ai("any content", true));
    }
    
    #[test]
    fn test_ai_only_mode() {
        let router = ClassificationRouter::new(RoutingMode::AiOnly);
        assert!(router.should_use_ai("any content", false));
        assert!(router.should_use_ai("any content", true));
    }
    
    #[test]
    fn test_sequential_mode() {
        let router = ClassificationRouter::new(RoutingMode::Sequential);
        
        // If rule matched, don't use AI
        assert!(!router.should_use_ai("content", true));
        
        // If no rule matched, use AI
        assert!(router.should_use_ai("content", false));
    }
    
    #[test]
    fn test_complexity_analysis() {
        let router = ClassificationRouter::new(RoutingMode::Smart);
        
        let simple_score = router.analyze_content_complexity("Hello");
        let complex_score = router.analyze_content_complexity(
            "URGENT: Verify your account immediately by clicking this fraud link"
        );
        
        assert!(simple_score < complex_score);
        assert!(simple_score < 0.5);
        assert!(complex_score > 0.5);
    }
}
