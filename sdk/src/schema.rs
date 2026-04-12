use once_cell::sync::Lazy;
use regex::Regex;
use serde_json::Value;

#[derive(Debug, Clone)]
pub struct SchemaRule {
    pub field: String,
    pub constraint: SchemaConstraint,
}

#[derive(Debug, Clone)]
pub enum SchemaType {
    String,
    Number,
    Boolean,
    Array,
    Object,
}

#[derive(Debug, Clone)]
pub enum SchemaConstraint {
    Type { expected: SchemaType },
    MaxLen(usize),
    Pattern(String),
    Enum(Vec<String>),
    Required,
}

#[derive(Debug, Clone)]
pub struct ValidationResult {
    pub is_valid: bool,
    pub violations: Vec<String>,
}

impl ValidationResult {
    fn valid() -> Self {
        Self {
            is_valid: true,
            violations: Vec::new(),
        }
    }

    fn invalid(violations: Vec<String>) -> Self {
        Self {
            is_valid: false,
            violations,
        }
    }
}

static DANGEROUS_EXEC_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    [
        r"(?i)\brm\s+-rf\b",
        r"(?i)\bsudo\b",
        r"(?i)\bmkfifo\b",
        r"/etc/passwd",
    ]
    .iter()
    .map(|p| Regex::new(p).unwrap())
    .collect()
});

static INTERNAL_IP_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"^https?://(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|127\.\d{1,3}\.\d{1,3}\.\d{1,3}|169\.254\.\d{1,3}\.\d{1,3})(:\d+)?(/.*)?$",
    )
    .unwrap()
});

static PATH_TRAVERSAL_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(r"\.\.").unwrap());

static SENSITIVE_PATH_PREFIXES: &[&str] = &["/etc/", "/root/", "/var/log/"];

pub fn validate_arguments(tool_name: &str, args: &Value) -> ValidationResult {
    match tool_name {
        "exec" => validate_exec(args),
        "file_write" | "write_file" => validate_file_write(args),
        "http_post" | "http_request" => validate_http(args),
        _ => ValidationResult::valid(),
    }
}

fn validate_exec(args: &Value) -> ValidationResult {
    let mut violations = Vec::new();

    let command = match args.get("command") {
        Some(Value::String(s)) => s.clone(),
        Some(_) => {
            violations.push("exec: 'command' must be a string".to_string());
            return ValidationResult::invalid(violations);
        }
        None => {
            violations.push("exec: 'command' is required".to_string());
            return ValidationResult::invalid(violations);
        }
    };

    if command.len() > 1000 {
        violations.push("exec: 'command' exceeds max length of 1000".to_string());
    }

    for pattern in DANGEROUS_EXEC_PATTERNS.iter() {
        if pattern.is_match(&command) {
            violations.push("exec: 'command' contains dangerous pattern".to_string());
            break;
        }
    }

    if violations.is_empty() {
        ValidationResult::valid()
    } else {
        ValidationResult::invalid(violations)
    }
}

fn validate_file_write(args: &Value) -> ValidationResult {
    let mut violations = Vec::new();

    let path = match args.get("path") {
        Some(Value::String(s)) => s.clone(),
        Some(_) => {
            violations.push("file_write: 'path' must be a string".to_string());
            return ValidationResult::invalid(violations);
        }
        None => {
            violations.push("file_write: 'path' is required".to_string());
            return ValidationResult::invalid(violations);
        }
    };

    if PATH_TRAVERSAL_REGEX.is_match(&path) {
        violations.push("file_write: 'path' contains path traversal (..)".to_string());
    }

    for prefix in SENSITIVE_PATH_PREFIXES {
        if path.starts_with(prefix) {
            violations.push(format!(
                "file_write: 'path' targets sensitive location ({})",
                prefix
            ));
        }
    }

    if violations.is_empty() {
        ValidationResult::valid()
    } else {
        ValidationResult::invalid(violations)
    }
}

fn validate_http(args: &Value) -> ValidationResult {
    let mut violations = Vec::new();

    let url = match args.get("url") {
        Some(Value::String(s)) => s.clone(),
        Some(_) => {
            violations.push("http_request: 'url' must be a string".to_string());
            return ValidationResult::invalid(violations);
        }
        None => {
            violations.push("http_request: 'url' is required".to_string());
            return ValidationResult::invalid(violations);
        }
    };

    if INTERNAL_IP_REGEX.is_match(&url) {
        violations.push("http_request: 'url' targets internal IP address".to_string());
    }

    if violations.is_empty() {
        ValidationResult::valid()
    } else {
        ValidationResult::invalid(violations)
    }
}

pub fn validate_schema(args: &Value, rules: &[SchemaRule]) -> ValidationResult {
    let mut violations = Vec::new();

    for rule in rules {
        let field_value = get_field(args, &rule.field);

        match &rule.constraint {
            SchemaConstraint::Required => {
                if field_value.is_none() {
                    violations.push(format!("field '{}' is required", rule.field));
                }
            }
            SchemaConstraint::Type { expected } => {
                if let Some(val) = &field_value {
                    if !type_matches(val, expected) {
                        violations.push(format!(
                            "field '{}' has wrong type, expected {:?}",
                            rule.field, expected
                        ));
                    }
                }
            }
            SchemaConstraint::MaxLen(max) => {
                if let Some(Value::String(s)) = &field_value {
                    if s.len() > *max {
                        violations.push(format!(
                            "field '{}' exceeds max length of {}",
                            rule.field, max
                        ));
                    }
                }
            }
            SchemaConstraint::Pattern(pattern) => {
                if let Some(Value::String(s)) = &field_value {
                    if let Ok(re) = Regex::new(pattern) {
                        if !re.is_match(s) {
                            violations.push(format!(
                                "field '{}' does not match pattern '{}'",
                                rule.field, pattern
                            ));
                        }
                    }
                }
            }
            SchemaConstraint::Enum(allowed) => {
                if let Some(Value::String(s)) = &field_value {
                    if !allowed.contains(s) {
                        violations.push(format!(
                            "field '{}' value '{}' not in allowed values",
                            rule.field, s
                        ));
                    }
                }
            }
        }
    }

    if violations.is_empty() {
        ValidationResult::valid()
    } else {
        ValidationResult::invalid(violations)
    }
}

fn get_field<'a>(value: &'a Value, path: &str) -> Option<Value> {
    let parts: Vec<&str> = path.split('.').collect();
    let mut current = value;

    for part in parts {
        match current {
            Value::Object(map) => {
                current = map.get(part)?;
            }
            Value::Array(arr) => {
                let idx: usize = part.parse().ok()?;
                current = arr.get(idx)?;
            }
            _ => return None,
        }
    }

    Some(current.clone())
}

fn type_matches(value: &Value, expected: &SchemaType) -> bool {
    matches!(
        (value, expected),
        (Value::String(_), SchemaType::String)
            | (Value::Number(_), SchemaType::Number)
            | (Value::Bool(_), SchemaType::Boolean)
            | (Value::Array(_), SchemaType::Array)
            | (Value::Object(_), SchemaType::Object)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_path_traversal_blocked() {
        let args = serde_json::json!({"path": "../../../etc/shadow"});
        let result = validate_arguments("file_write", &args);
        assert!(!result.is_valid);
        assert!(result.violations.iter().any(|v| v.contains("traversal")));
    }

    #[test]
    fn test_internal_ip_blocked() {
        let args = serde_json::json!({"url": "http://10.0.0.1/admin"});
        let result = validate_arguments("http_post", &args);
        assert!(!result.is_valid);
        assert!(result.violations.iter().any(|v| v.contains("internal")));
    }

    #[test]
    fn test_internal_ip_192_168_blocked() {
        let args = serde_json::json!({"url": "http://192.168.1.1/secret"});
        let result = validate_arguments("http_request", &args);
        assert!(!result.is_valid);
    }

    #[test]
    fn test_internal_ip_localhost_blocked() {
        let args = serde_json::json!({"url": "http://127.0.0.1:8080/metrics"});
        let result = validate_arguments("http_post", &args);
        assert!(!result.is_valid);
    }

    #[test]
    fn test_exec_dangerous_commands_blocked() {
        let args = serde_json::json!({"command": "rm -rf /"});
        let result = validate_arguments("exec", &args);
        assert!(!result.is_valid);

        let args2 = serde_json::json!({"command": "sudo bash"});
        let result2 = validate_arguments("exec", &args2);
        assert!(!result2.is_valid);

        let args3 = serde_json::json!({"command": "cat /etc/passwd"});
        let result3 = validate_arguments("exec", &args3);
        assert!(!result3.is_valid);
    }

    #[test]
    fn test_exec_valid_command_passes() {
        let args = serde_json::json!({"command": "ls -la"});
        let result = validate_arguments("exec", &args);
        assert!(result.is_valid);
    }

    #[test]
    fn test_file_write_valid_path_passes() {
        let args = serde_json::json!({"path": "/tmp/output.txt"});
        let result = validate_arguments("file_write", &args);
        assert!(result.is_valid);
    }

    #[test]
    fn test_http_valid_url_passes() {
        let args = serde_json::json!({"url": "https://api.example.com/data"});
        let result = validate_arguments("http_post", &args);
        assert!(result.is_valid);
    }

    #[test]
    fn test_unknown_tool_always_valid() {
        let args = serde_json::json!({"anything": "goes"});
        let result = validate_arguments("custom_tool", &args);
        assert!(result.is_valid);
    }

    #[test]
    fn test_exec_non_string_command_blocked() {
        let args = serde_json::json!({"command": 123});
        let result = validate_arguments("exec", &args);
        assert!(!result.is_valid);
    }

    #[test]
    fn test_exec_missing_command_blocked() {
        let args = serde_json::json!({});
        let result = validate_arguments("exec", &args);
        assert!(!result.is_valid);
    }

    #[test]
    fn test_sensitive_path_blocked() {
        let args = serde_json::json!({"path": "/etc/hosts"});
        let result = validate_arguments("file_write", &args);
        assert!(!result.is_valid);

        let args2 = serde_json::json!({"path": "/root/.ssh/authorized_keys"});
        let result2 = validate_arguments("write_file", &args2);
        assert!(!result2.is_valid);
    }

    #[test]
    fn test_schema_validate_required() {
        let rules = vec![SchemaRule {
            field: "name".to_string(),
            constraint: SchemaConstraint::Required,
        }];
        let args = serde_json::json!({"other": "value"});
        let result = validate_schema(&args, &rules);
        assert!(!result.is_valid);
    }

    #[test]
    fn test_schema_validate_type() {
        let rules = vec![SchemaRule {
            field: "count".to_string(),
            constraint: SchemaConstraint::Type {
                expected: SchemaType::Number,
            },
        }];
        let args = serde_json::json!({"count": "not a number"});
        let result = validate_schema(&args, &rules);
        assert!(!result.is_valid);

        let args2 = serde_json::json!({"count": 42});
        let result2 = validate_schema(&args2, &rules);
        assert!(result2.is_valid);
    }

    #[test]
    fn test_schema_validate_enum() {
        let rules = vec![SchemaRule {
            field: "action".to_string(),
            constraint: SchemaConstraint::Enum(vec!["read".to_string(), "write".to_string()]),
        }];
        let args = serde_json::json!({"action": "delete"});
        let result = validate_schema(&args, &rules);
        assert!(!result.is_valid);
    }
}
