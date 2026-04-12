use rmcp::model::{
    GetPromptResult, PromptMessage, PromptMessageRole,
};
use serde_json::Value;

pub fn security_review_prompt(
    args: Option<serde_json::Map<String, Value>>,
) -> Result<GetPromptResult, rmcp::ErrorData> {
    let args = args.unwrap_or_default();
    let decision = args
        .get("decision")
        .and_then(|v| v.as_str())
        .unwrap_or("UNKNOWN");
    let reason = args
        .get("reason")
        .and_then(|v| v.as_str())
        .unwrap_or("No reason provided");

    let text = format!(
        r#"You are a security analyst reviewing an AxiomGuard classification decision.

Decision: {}
Reason: {}

Please review this decision and provide:
1. Whether you agree with the decision and why
2. Any false positive indicators to check
3. Recommended next steps for the security team
4. Suggested rule tuning if this looks like a false positive
"#,
        decision, reason
    );

    Ok(GetPromptResult::new(vec![
        PromptMessage::new_text(PromptMessageRole::User, text),
    ]).with_description("Security review prompt for AxiomGuard decisions"))
}

pub fn incident_response_prompt(
    args: Option<serde_json::Map<String, Value>>,
) -> Result<GetPromptResult, rmcp::ErrorData> {
    let args = args.unwrap_or_default();
    let root_cause = args
        .get("root_cause")
        .and_then(|v| v.as_str())
        .unwrap_or("No root cause identified");
    let recommendations = args
        .get("recommendations")
        .and_then(|v| v.as_str())
        .unwrap_or("Review related events and adjust rules");

    let text = format!(
        r#"You are an incident responder reviewing an AxiomGuard root cause analysis.

Root Cause: {}
Recommendations: {}

Please draft an incident response plan including:
1. Immediate containment actions
2. Communication plan for stakeholders
3. Long-term preventive measures
4. Follow-up tasks and owners
"#,
        root_cause, recommendations
    );

    Ok(GetPromptResult::new(vec![
        PromptMessage::new_text(PromptMessageRole::User, text),
    ]).with_description("Incident response prompt for RCA results"))
}
