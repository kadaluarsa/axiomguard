use serde_json::Value;

/// Parsed tool call
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ToolCall {
    pub tool_name: String,
    pub arguments_json: String,
    pub target: Option<String>,
    pub risk_score: f32,
}

/// Parse tool calls from content
pub fn parse_tool_calls(content: &str) -> Vec<ToolCall> {
    let mut calls = Vec::new();

    // Try OpenAI tool_calls format
    calls.extend(parse_openai_tool_calls(content));

    // Try Anthropic tool_use format
    calls.extend(parse_anthropic_tool_use(content));

    // Try generic JSON function call format
    calls.extend(parse_generic_function_call(content));

    calls
}

fn parse_openai_tool_calls(content: &str) -> Vec<ToolCall> {
    let mut calls = Vec::new();

    // Look for "tool_calls" array in JSON
    if let Ok(value) = serde_json::from_str::<Value>(content) {
        if let Some(tool_calls) = value.get("tool_calls").and_then(|v| v.as_array()) {
            for tc in tool_calls {
                if let Some(function) = tc.get("function") {
                    let name = function.get("name").and_then(|v| v.as_str()).unwrap_or("unknown");
                    let args = function.get("arguments")
                        .map(|v| v.to_string())
                        .unwrap_or_else(|| "{}".to_string());
                    calls.push(build_tool_call(name, &args));
                }
            }
        }

        // Also check legacy "function_call" format
        if let Some(fc) = value.get("function_call") {
            let name = fc.get("name").and_then(|v| v.as_str()).unwrap_or("unknown");
            let args = fc.get("arguments")
                .map(|v| v.to_string())
                .unwrap_or_else(|| "{}".to_string());
            calls.push(build_tool_call(name, &args));
        }
    }

    calls
}

fn parse_anthropic_tool_use(content: &str) -> Vec<ToolCall> {
    let mut calls = Vec::new();

    if let Ok(value) = serde_json::from_str::<Value>(content) {
        // Anthropic content blocks
        if let Some(content_blocks) = value.get("content").and_then(|v| v.as_array()) {
            for block in content_blocks {
                if block.get("type").and_then(|v| v.as_str()) == Some("tool_use") {
                    let name = block.get("name").and_then(|v| v.as_str()).unwrap_or("unknown");
                    let args = block.get("input")
                        .map(|v| v.to_string())
                        .unwrap_or_else(|| "{}".to_string());
                    calls.push(build_tool_call(name, &args));
                }
            }
        }
    }

    calls
}

fn parse_generic_function_call(content: &str) -> Vec<ToolCall> {
    let mut calls = Vec::new();

    // Try to find JSON objects with a "function" or "action" field
    if let Ok(value) = serde_json::from_str::<Value>(content) {
        if let Some(obj) = value.as_object() {
            if obj.contains_key("function") || obj.contains_key("action") {
                let name = obj.get("function")
                    .or_else(|| obj.get("action"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                let args = if let Some(params) = obj.get("parameters").or_else(|| obj.get("args")) {
                    params.to_string()
                } else {
                    let mut filtered = obj.clone();
                    filtered.remove("function");
                    filtered.remove("action");
                    filtered.remove("name");
                    Value::Object(filtered).to_string()
                };
                calls.push(build_tool_call(name, &args));
            }
        }
    }

    calls
}

fn build_tool_call(name: &str, args: &str) -> ToolCall {
    let risk_score = score_tool_risk(name, args);
    let target = infer_target(name, args);

    ToolCall {
        tool_name: name.to_string(),
        arguments_json: args.to_string(),
        target,
        risk_score,
    }
}

fn score_tool_risk(name: &str, _args: &str) -> f32 {
    let name_lower = name.to_lowercase();

    // High-risk tools
    if name_lower.contains("exec")
        || name_lower.contains("shell")
        || name_lower.contains("run_command")
        || name_lower.contains("eval")
        || name_lower.contains("code_execution")
    {
        return 0.95;
    }

    // File system tools
    if name_lower.contains("write_file")
        || name_lower.contains("delete_file")
        || name_lower.contains("modify_file")
        || name_lower.contains("append_file")
        || name_lower.contains("create_directory")
    {
        return 0.85;
    }

    // Network/tools that can exfiltrate
    if name_lower.contains("fetch")
        || name_lower.contains("http_request")
        || name_lower.contains("send_email")
        || name_lower.contains("slack")
        || name_lower.contains("webhook")
    {
        return 0.75;
    }

    // Database/tools that can modify state
    if name_lower.contains("sql")
        || name_lower.contains("query")
        || name_lower.contains("insert")
        || name_lower.contains("update")
        || name_lower.contains("delete")
    {
        return 0.7;
    }

    // Read-only tools
    if name_lower.contains("read_file")
        || name_lower.contains("list_directory")
        || name_lower.contains("search")
        || name_lower.contains("get")
        || name_lower.contains("fetch")
    {
        return 0.4;
    }

    0.5
}

fn infer_target(name: &str, args: &str) -> Option<String> {
    if let Ok(value) = serde_json::from_str::<Value>(args) {
        // Common target fields
        for key in &["path", "file_path", "url", "endpoint", "table", "email", "channel"] {
            if let Some(v) = value.get(key).and_then(|v| v.as_str()) {
                return Some(v.to_string());
            }
        }
    }

    // Infer from tool name
    if name.to_lowercase().contains("file") {
        return Some("filesystem".to_string());
    }
    if name.to_lowercase().contains("sql") || name.to_lowercase().contains("db") {
        return Some("database".to_string());
    }
    if name.to_lowercase().contains("http") || name.to_lowercase().contains("web") {
        return Some("network".to_string());
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_openai_tool_calls() {
        let content = r#"{"tool_calls":[{"id":"1","type":"function","function":{"name":"write_file","arguments":{"path":"/etc/passwd","content":"root"}}}]}"#;
        let calls = parse_tool_calls(content);
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].tool_name, "write_file");
        assert!(calls[0].risk_score > 0.8);
    }

    #[test]
    fn test_parse_generic_function_call() {
        let content = r#"{"function":"exec","parameters":{"command":"rm -rf /"}}"#;
        let calls = parse_tool_calls(content);
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].tool_name, "exec");
        assert!(calls[0].risk_score > 0.9);
    }

    #[test]
    fn test_parse_no_tool_calls() {
        let content = "Hello, this is just a normal message";
        let calls = parse_tool_calls(content);
        assert!(calls.is_empty());
    }
}
