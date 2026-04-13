use crate::{DecisionResult, tool_parser::ToolCall};
use common::DecisionType;

/// Human-readable explanation of a classification decision
#[derive(Debug, Clone)]
pub struct DecisionExplanation {
    pub explanation: String,
    pub key_factors: Vec<String>,
    pub remediation: Vec<String>,
}

/// Generate an explanation for a decision result
pub fn explain_decision(
    decision: &DecisionResult,
    tool_calls: &[ToolCall],
    content_preview: &str,
) -> DecisionExplanation {
    let mut factors = Vec::new();
    let mut remediation = Vec::new();

    // Explain decision type
    let decision_text = match decision.decision {
        DecisionType::Allow => "allowed",
        DecisionType::Block => "blocked",
        DecisionType::Flag => "flagged for review",
        DecisionType::Handover => "handed over for human review",
        DecisionType::Review => "flagged for review",
    };

    // Build base explanation
    let mut explanation = format!(
        "This content was {} because {} ",
        decision_text,
        decision.reason
    );

    // Rule-based factors
    if !decision.matched_rules.is_empty() {
        factors.push(format!(
            "Matched security rules: {}",
            decision.matched_rules.join(", ")
        ));
        explanation.push_str(&format!(
            "Security rule(s) {} triggered. ",
            decision.matched_rules.join(", ")
        ));
    }

    // AI-based factors
    if let Some(ref insights) = decision.ai_insights {
        factors.push(format!(
            "AI detected category '{}' with risk level {:.0}%",
            insights.category,
            insights.risk_level * 100.0
        ));
        if !insights.anomalies.is_empty() {
            factors.push(format!(
                "Anomalies detected: {}",
                insights.anomalies.join("; ")
            ));
        }
        explanation.push_str(&format!(
            "AI analysis categorized this as '{}' with {:.0}% risk. ",
            insights.category,
            insights.risk_level * 100.0
        ));
        remediation.extend(insights.recommendations.clone());
    }

    // Tool call factors
    if !tool_calls.is_empty() {
        let high_risk_tools: Vec<_> = tool_calls.iter().filter(|t| t.risk_score > 0.7).collect();
        if !high_risk_tools.is_empty() {
            let tool_names: Vec<_> = high_risk_tools.iter().map(|t| t.tool_name.clone()).collect();
            factors.push(format!(
                "High-risk tool calls detected: {}",
                tool_names.join(", ")
            ));
            explanation.push_str(&format!(
                "High-risk tool invocation(s) detected: {}. ",
                tool_names.join(", ")
            ));
            for tool in &high_risk_tools {
                if let Some(ref target) = tool.target {
                    factors.push(format!(
                        "Tool '{}' targets {}",
                        tool.tool_name, target
                    ));
                }
            }
            remediation.push("Review tool call permissions before execution".to_string());
        } else {
            let tool_names: Vec<_> = tool_calls.iter().map(|t| t.tool_name.clone()).collect();
            factors.push(format!(
                "Tool calls detected: {}",
                tool_names.join(", ")
            ));
        }
    }

    // Timing factors
    if decision.processing_time_ms > 80 {
        factors.push(format!(
            "Processing took {}ms (near timeout)",
            decision.processing_time_ms
        ));
    }

    if decision.cached {
        factors.push("Result served from cache".to_string());
    }

    // Decision-specific remediation
    match decision.decision {
        DecisionType::Block => {
            if remediation.is_empty() {
                remediation.push("Review the content and adjust rules if this is a false positive".to_string());
            }
            remediation.push("Check security logs for related activity".to_string());
        }
        DecisionType::Handover => {
            remediation.push("A security operator should review this content manually".to_string());
        }
        DecisionType::Flag => {
            remediation.push("Consider reviewing this content within 24 hours".to_string());
        }
        _ => {}
    }

    // Content preview
    let preview = if content_preview.len() > 100 {
        &content_preview[..100]
    } else {
        content_preview
    };
    explanation.push_str(&format!("Content preview: '{}'", preview));

    DecisionExplanation {
        explanation,
        key_factors: factors,
        remediation,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AiInsights;

    #[test]
    fn test_explain_block_with_rules() {
        let decision = DecisionResult {
            decision: DecisionType::Block,
            confidence: 0.95,
            reason: "Rule match: suspicious content".to_string(),
            matched_rules: vec!["rule-1".to_string()],
            ai_insights: None,
            verification_result: None,
            z3_verified: false,
            processing_time_ms: 10,
            cached: false,
            rule_eval_time_ms: Some(5),
            ai_time_ms: None,
            tool_calls: vec![],
            explanation: None,
            pii_detected: false,
            injection_detected: false,
            injection_confidence: 0.0,
            ml_risk_score: 0.0,
        };
        let explanation = explain_decision(&decision, &[], "test content");
        assert!(explanation.explanation.contains("blocked"));
        assert_eq!(explanation.key_factors.len(), 1);
    }

    #[test]
    fn test_explain_with_tool_calls() {
        let decision = DecisionResult {
            decision: DecisionType::Flag,
            confidence: 0.8,
            reason: "AI classification".to_string(),
            matched_rules: vec![],
            ai_insights: Some(AiInsights {
                risk_level: 0.7,
                category: "suspicious".to_string(),
                anomalies: vec!["unusual request".to_string()],
                recommendations: vec!["review".to_string()],
                model: "test".to_string(),
                fallback_used: false,
            }),
            verification_result: None,
            z3_verified: false,
            processing_time_ms: 20,
            cached: false,
            rule_eval_time_ms: None,
            ai_time_ms: Some(15),
            tool_calls: vec![],
            explanation: None,
            pii_detected: false,
            injection_detected: false,
            injection_confidence: 0.0,
            ml_risk_score: 0.0,
        };
        let tools = vec![ToolCall {
            tool_name: "exec".to_string(),
            arguments_json: "{}".to_string(),
            target: Some("shell".to_string()),
            risk_score: 0.95,
        }];
        let explanation = explain_decision(&decision, &tools, "run cmd");
        assert!(explanation.explanation.contains("exec"));
        assert!(explanation.key_factors.iter().any(|f| f.contains("High-risk")));
    }
}
