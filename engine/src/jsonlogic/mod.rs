//! JSONLogic Engine for Deterministic Security Rule Evaluation
//!
//! JSONLogic is a declarative way to define logic rules using JSON.
//! This engine evaluates rules against event data with <1ms latency target.
//!
//! Reference: http://jsonlogic.com/

use std::cell::RefCell;

/// Maximum recursion depth to prevent stack overflow
const MAX_RECURSION_DEPTH: usize = 100;

thread_local! {
    /// Thread-local recursion depth counter
    static RECURSION_DEPTH: RefCell<usize> = RefCell::new(0);
}

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

pub mod operators;

use operators::*;

/// Get a value at a dot-separated path from JSON data
fn get_value_at_path(data: &Value, path: &str) -> Option<Value> {
    if path.is_empty() {
        return Some(data.clone());
    }
    
    let parts: Vec<&str> = path.split('.').collect();
    let mut current = data;
    
    for part in parts {
        match current {
            Value::Object(map) => {
                current = map.get(part)?;
            }
            Value::Array(arr) => {
                let index: usize = part.parse().ok()?;
                current = arr.get(index)?;
            }
            _ => return None,
        }
    }
    
    Some(current.clone())
}

/// A JSONLogic rule
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Rule {
    /// Operation with arguments (check first - operations are objects with specific keys)
    Operation(HashMap<String, Vec<Rule>>),
    /// Operation with single argument (for {"var": "field"} style)
    OperationSingle(HashMap<String, Rule>),
    /// Primitive value (string, number, bool, null, array)
    Primitive(Value),
}

/// JSONLogic evaluation engine
pub struct JsonLogicEngine {
    custom_operators: HashMap<String, Box<dyn Fn(&[Value], &Value) -> Result<Value, JsonLogicError> + Send + Sync>>,
}

impl Default for JsonLogicEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for JsonLogicEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JsonLogicEngine")
            .field("custom_operators_count", &self.custom_operators.len())
            .finish()
    }
}

/// Evaluation error
#[derive(Debug, Clone, thiserror::Error)]
pub enum JsonLogicError {
    #[error("Unknown operator: {0}")]
    UnknownOperator(String),
    #[error("Invalid arguments for operator {0}: {1}")]
    InvalidArguments(String, String),
    #[error("Type error: expected {expected}, got {actual}")]
    TypeError { expected: String, actual: String },
    #[error("Missing variable: {0}")]
    MissingVariable(String),
    #[error("Evaluation error: {0}")]
    EvaluationError(String),
    #[error("Maximum recursion depth exceeded ({0})")]
    MaxDepthExceeded(usize),
    #[error("Validation error: {0}")]
    Validation(String),
}

impl JsonLogicEngine {
    /// Create a new engine with standard operators
    pub fn new() -> Self {
        Self {
            custom_operators: HashMap::new(),
        }
    }
    
    /// Register a custom operator
    pub fn register_operator<F>(&mut self, name: impl Into<String>, func: F)
    where
        F: Fn(&[Value], &Value) -> Result<Value, JsonLogicError> + Send + Sync + 'static,
    {
        self.custom_operators.insert(name.into(), Box::new(func));
    }

    /// Validate that a JSONLogic rule is well-formed without evaluating it.
    /// Checks: operators are known, arg counts are correct, nesting depth is within limits.
    pub fn validate(&self, rule: &Value) -> Result<(), JsonLogicError> {
        self.validate_value(rule, 0)
    }

    fn validate_value(&self, value: &Value, depth: usize) -> Result<(), JsonLogicError> {
        if depth > MAX_RECURSION_DEPTH {
            return Err(JsonLogicError::Validation(format!("Rule exceeds max nesting depth of {}", MAX_RECURSION_DEPTH)));
        }

        match value {
            Value::Object(map) => {
                if map.is_empty() {
                    return Err(JsonLogicError::Validation("Empty JSON object is not a valid rule".to_string()));
                }
                if map.len() > 1 {
                    return Err(JsonLogicError::Validation(format!("Rule object must have exactly one operator, found {} keys", map.len())));
                }
                let (operator, args) = map.iter().next().unwrap();
                if !self.custom_operators.contains_key(operator) && !is_builtin_operator(operator) {
                    return Err(JsonLogicError::Validation(format!("Unknown operator: '{}'", operator)));
                }
                self.validate_operator_args(operator, args, depth)
            }
            Value::String(_) | Value::Number(_) | Value::Bool(_) => Ok(()), // Literals are valid
            Value::Array(arr) => {
                for item in arr {
                    self.validate_value(item, depth)?;
                }
                Ok(())
            }
            Value::Null => Ok(()),
        }
    }

    fn validate_operator_args(&self, operator: &str, args: &Value, depth: usize) -> Result<(), JsonLogicError> {
        // Binary comparison operators require exactly 2 args
        let binary_ops = ["==", "===", "!=", "!==", ">", ">=", "<", "<=", "starts_with", "ends_with", "in"];
        if binary_ops.contains(&operator) {
            if let Value::Array(arr) = args {
                if arr.len() != 2 {
                    return Err(JsonLogicError::Validation(format!("Operator '{}' requires exactly 2 arguments, found {}", operator, arr.len())));
                }
                for arg in arr {
                    self.validate_value(arg, depth + 1)?;
                }
            }
            return Ok(());
        }

        // Logical operators require array of conditions
        if operator == "and" || operator == "or" {
            if let Value::Array(arr) = args {
                if arr.is_empty() {
                    return Err(JsonLogicError::Validation(format!("Operator '{}' requires at least 1 argument", operator)));
                }
                for arg in arr {
                    self.validate_value(arg, depth + 1)?;
                }
            }
            return Ok(());
        }

        // Not requires 1 arg
        if operator == "!" {
            if let Value::Array(arr) = args {
                if arr.len() != 1 {
                    return Err(JsonLogicError::Validation(format!("Operator '!' requires exactly 1 argument, found {}", arr.len())));
                }
                self.validate_value(&arr[0], depth + 1)?;
            }
            return Ok(());
        }

        // Var requires 1-2 args
        if operator == "var" {
            if let Value::Array(arr) = args {
                if arr.is_empty() || arr.len() > 2 {
                    return Err(JsonLogicError::Validation(format!("Operator 'var' requires 1-2 arguments, found {}", arr.len())));
                }
            }
            return Ok(());
        }

        // If requires 2-3 args
        if operator == "if" || operator == "?:" {
            if let Value::Array(arr) = args {
                if arr.len() < 2 || arr.len() > 3 {
                    return Err(JsonLogicError::Validation(format!("Operator '{}' requires 2-3 arguments, found {}", operator, arr.len())));
                }
                for arg in arr {
                    self.validate_value(arg, depth + 1)?;
                }
            }
            return Ok(());
        }

        // Map/filter/reduce/all/none/some require exactly 2 args (array + rule)
        let array_ops = ["map", "filter", "reduce", "all", "none", "some"];
        if array_ops.contains(&operator) {
            if let Value::Array(arr) = args {
                if arr.len() != 2 {
                    return Err(JsonLogicError::Validation(format!("Operator '{}' requires exactly 2 arguments, found {}", operator, arr.len())));
                }
                self.validate_value(&arr[0], depth + 1)?;
                self.validate_value(&arr[1], depth + 1)?;
            }
            return Ok(());
        }

        // cat, merge can take any number of args — just validate each
        if let Value::Array(arr) = args {
            for arg in arr {
                self.validate_value(arg, depth + 1)?;
            }
        }
        Ok(())
    }

    /// Evaluate a rule against data
    /// 
    /// # Arguments
    /// * `rule` - The JSONLogic rule to evaluate
    /// * `data` - The data context (event data)
    /// 
    /// # Returns
    /// * `Ok(Value)` - The result of evaluation
    /// * `Err(JsonLogicError)` - If evaluation fails
    pub fn evaluate(&self, rule: &Rule, data: &Value) -> Result<Value, JsonLogicError> {
        // Use thread-local depth counter
        RECURSION_DEPTH.with(|depth| {
            let current = *depth.borrow();
            if current >= MAX_RECURSION_DEPTH {
                return Err(JsonLogicError::MaxDepthExceeded(MAX_RECURSION_DEPTH));
            }
            *depth.borrow_mut() = current + 1;
            
            let result = self.evaluate_internal(rule, data);
            
            *depth.borrow_mut() = current;
            result
        })
    }
    
    fn evaluate_internal(&self, rule: &Rule, data: &Value) -> Result<Value, JsonLogicError> {
        match rule {
            Rule::Primitive(value) => Ok(value.clone()),
            Rule::Operation(op_map) => {
                let (op, args) = op_map.iter().next()
                    .ok_or_else(|| JsonLogicError::EvaluationError("Empty operation".to_string()))?;
                self.evaluate_operation(op, args, data)
            }
            Rule::OperationSingle(op_map) => {
                let (op, arg) = op_map.iter().next()
                    .ok_or_else(|| JsonLogicError::EvaluationError("Empty operation".to_string()))?;
                self.evaluate_operation_single(op, arg, data)
            }
        }
    }
    
    /// Evaluate from JSON Value directly
    pub fn evaluate_json(&self, rule: &Value, data: &Value) -> Result<Value, JsonLogicError> {
        let rule: Rule = serde_json::from_value(rule.clone())
            .map_err(|e| JsonLogicError::EvaluationError(format!("Invalid rule: {}", e)))?;
        self.evaluate(&rule, data)
    }
    
    fn evaluate_operation(&self, op: &str, args: &[Rule], data: &Value) -> Result<Value, JsonLogicError> {
        match op {
            // Comparison operators
            "==" | "===" => self.eval_equality(args, data, true),
            "!=" | "!==" => self.eval_inequality(args, data, true),
            ">" => eval_greater_than(self.eval_args(args, data)?),
            ">=" => eval_greater_than_or_equal(self.eval_args(args, data)?),
            "<" => eval_less_than(self.eval_args(args, data)?),
            "<=" => eval_less_than_or_equal(self.eval_args(args, data)?),
            
            // Logical operators
            "and" => eval_and(self, args, data),
            "or" => eval_or(self, args, data),
            "!" | "not" => eval_not(self.eval_args(args, data)?),
            "!!" => eval_double_not(self.eval_args(args, data)?),
            
            // Array operators
            "in" => eval_in(self.eval_args(args, data)?),
            "cat" => eval_cat(self.eval_args(args, data)?),
            "missing" => eval_missing(self.eval_args(args, data)?, data),
            "missing_some" => eval_missing_some(self.eval_args(args, data)?, data),
            
            // Data access
            "var" => eval_var(args, data),
            "if" => eval_if(self, args, data),
            
            // String operators
            "startsWith" => eval_starts_with(self.eval_args(args, data)?),
            "endsWith" => eval_ends_with(self.eval_args(args, data)?),
            "contains" => eval_contains(self.eval_args(args, data)?),
            
            // Numeric operators
            "+" => eval_add(self.eval_args(args, data)?),
            "-" => eval_subtract(self.eval_args(args, data)?),
            "*" => eval_multiply(self.eval_args(args, data)?),
            "/" => eval_divide(self.eval_args(args, data)?),
            "min" => eval_min(self.eval_args(args, data)?),
            "max" => eval_max(self.eval_args(args, data)?),
            
            // Misc - these are recursive, depth is tracked via thread_local
            "merge" => eval_merge(self.eval_args(args, data)?),
            "map" => eval_map(self, args, data),
            "filter" => eval_filter(self, args, data),
            "reduce" => eval_reduce(self, args, data),
            "all" => eval_all(self, args, data),
            "none" => eval_none(self, args, data),
            "some" => eval_some(self, args, data),
            
            // Custom operators
            _ => {
                if let Some(func) = self.custom_operators.get(op) {
                    let args = self.eval_args(args, data)?;
                    func(&args, data)
                } else {
                    Err(JsonLogicError::UnknownOperator(op.to_string()))
                }
            }
        }
    }
    
    fn evaluate_operation_single(&self, op: &str, arg: &Rule, data: &Value) -> Result<Value, JsonLogicError> {
        // Convert single arg to array and call standard evaluation
        match op {
            "var" => {
                // var can take a single path or [path, default]
                let path = match arg {
                    Rule::Primitive(Value::String(s)) => s.clone(),
                    Rule::Primitive(Value::Number(n)) => n.to_string(),
                    Rule::Primitive(Value::Null) => return Ok(data.clone()),
                    _ => return Ok(Value::Null),
                };
                Ok(get_value_at_path(data, &path).unwrap_or(Value::Null))
            }
            _ => {
                // For other operators, wrap in array
                self.evaluate_operation(op, &[arg.clone()], data)
            }
        }
    }
    
    fn eval_args(&self, args: &[Rule], data: &Value) -> Result<Vec<Value>, JsonLogicError> {
        args.iter()
            .map(|arg| self.evaluate(arg, data))
            .collect()
    }
    
    fn eval_equality(&self, args: &[Rule], data: &Value, strict: bool) -> Result<Value, JsonLogicError> {
        if args.len() != 2 {
            return Err(JsonLogicError::InvalidArguments(
                "==".to_string(),
                "requires exactly 2 arguments".to_string(),
            ));
        }
        let a = self.evaluate(&args[0], data)?;
        let b = self.evaluate(&args[1], data)?;
        Ok(Value::Bool(jsonlogic_equals(&a, &b, strict)))
    }
    
    fn eval_inequality(&self, args: &[Rule], data: &Value, strict: bool) -> Result<Value, JsonLogicError> {
        let result = self.eval_equality(args, data, strict)?;
        Ok(Value::Bool(!result.as_bool().unwrap_or(false)))
    }
}

/// Check if an operator is a built-in JSONLogic operator
fn is_builtin_operator(op: &str) -> bool {
    matches!(op, "==" | "===" | "!=" | "!==" | ">" | ">=" | "<" | "<="
        | "and" | "or" | "!" | "!!" | "var" | "if" | "?:" | "in"
        | "cat" | "starts_with" | "ends_with" | "contains"
        | "+" | "-" | "*" | "/" | "min" | "max" | "merge"
        | "map" | "filter" | "reduce" | "all" | "none" | "some"
        | "missing" | "missing_some" | "not" | "startsWith" | "endsWith")
}

/// Check if two values are equal according to JSONLogic rules
fn jsonlogic_equals(a: &Value, b: &Value, strict: bool) -> bool {
    if strict {
        a == b
    } else {
        // Loose equality - type coercion
        match (a, b) {
            (Value::Null, Value::Null) => true,
            (Value::Bool(x), Value::Bool(y)) => x == y,
            (Value::Number(x), Value::Number(y)) => {
                let xf = x.as_f64().unwrap_or(0.0);
                let yf = y.as_f64().unwrap_or(0.0);
                (xf - yf).abs() < f64::EPSILON
            }
            (Value::String(x), Value::String(y)) => x == y,
            // Type coercion cases
            (Value::String(s), Value::Number(n)) | (Value::Number(n), Value::String(s)) => {
                if let Ok(num) = s.parse::<f64>() {
                    (num - n.as_f64().unwrap_or(0.0)).abs() < f64::EPSILON
                } else {
                    false
                }
            }
            (Value::Bool(b), Value::Number(n)) | (Value::Number(n), Value::Bool(b)) => {
                let bool_as_num = if *b { 1.0 } else { 0.0 };
                (bool_as_num - n.as_f64().unwrap_or(0.0)).abs() < f64::EPSILON
            }
            (Value::Array(a), Value::Array(b)) => a == b,
            (Value::Object(a), Value::Object(b)) => a == b,
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_equality() {
        let engine = JsonLogicEngine::new();
        
        let rule = serde_json::json!({
            "==": [{"var": "amount"}, 100]
        });
        
        let data = serde_json::json!({"amount": 100});
        let result = engine.evaluate_json(&rule, &data).unwrap();
        assert_eq!(result, Value::Bool(true));
        
        let data2 = serde_json::json!({"amount": 200});
        let result2 = engine.evaluate_json(&rule, &data2).unwrap();
        assert_eq!(result2, Value::Bool(false));
    }
    
    #[test]
    fn test_comparison() {
        let engine = JsonLogicEngine::new();
        
        let rule = serde_json::json!({
            ">": [{"var": "risk_score"}, 0.5]
        });
        
        let data = serde_json::json!({"risk_score": 0.8});
        let result = engine.evaluate_json(&rule, &data).unwrap();
        assert_eq!(result, Value::Bool(true));
    }
    
    #[test]
    fn test_logical_and() {
        let engine = JsonLogicEngine::new();
        
        let rule = serde_json::json!({
            "and": [
                {">": [{"var": "amount"}, 100]},
                {"<": [{"var": "amount"}, 1000]}
            ]
        });
        
        let data = serde_json::json!({"amount": 500});
        let result = engine.evaluate_json(&rule, &data).unwrap();
        assert_eq!(result, Value::Bool(true));
    }
    
    #[test]
    fn test_complex_security_rule() {
        let engine = JsonLogicEngine::new();
        
        // Rule: Block if (amount > 10000 AND user.risk_level > 0.8) OR source == "suspicious_ip"
        let rule = serde_json::json!({
            "or": [
                {
                    "and": [
                        {">": [{"var": "transaction.amount"}, 10000]},
                        {">": [{"var": "user.risk_level"}, 0.8]}
                    ]
                },
                {"==": [{"var": "source"}, "suspicious_ip"]}
            ]
        });
        
        let data = serde_json::json!({
            "transaction": {"amount": 15000},
            "user": {"risk_level": 0.9},
            "source": "normal"
        });
        
        let result = engine.evaluate_json(&rule, &data).unwrap();
        assert_eq!(result, Value::Bool(true));
    }
}

#[cfg(test)]
mod validate_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_validate_simple_rule() {
        let engine = JsonLogicEngine::new();
        assert!(engine.validate(&json!({"==": [{"var": "tool"}, "bash"]})).is_ok());
    }

    #[test]
    fn test_validate_compound_rule() {
        let engine = JsonLogicEngine::new();
        assert!(engine.validate(&json!({"and": [
            {"==": [{"var": "tool"}, "bash"]},
            {"contains": [{"var": "args"}, "rm"]}
        ]})).is_ok());
    }

    #[test]
    fn test_validate_unknown_operator() {
        let engine = JsonLogicEngine::new();
        let result = engine.validate(&json!({"unknown_op": [1, 2]}));
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Unknown operator"));
    }

    #[test]
    fn test_validate_empty_object() {
        let engine = JsonLogicEngine::new();
        let result = engine.validate(&json!({}));
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Empty JSON object"));
    }

    #[test]
    fn test_validate_binary_wrong_args() {
        let engine = JsonLogicEngine::new();
        let result = engine.validate(&json!({"==": [1]}));
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("exactly 2 arguments"));
    }

    #[test]
    fn test_validate_nested_rules() {
        let engine = JsonLogicEngine::new();
        assert!(engine.validate(&json!({"or": [
            {"==": [{"var": "tool"}, "bash"]},
            {"and": [
                {"==": [{"var": "tool"}, "exec"]},
                {"contains": [{"var": "args"}, "curl"]}
            ]}
        ]})).is_ok());
    }
}
