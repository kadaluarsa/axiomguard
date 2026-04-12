use std::cell::RefCell;
use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub mod operators;

use operators::*;

const MAX_RECURSION_DEPTH: usize = 100;

thread_local! {
    static RECURSION_DEPTH: RefCell<usize> = RefCell::new(0);
}

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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Rule {
    Operation(HashMap<String, Vec<Rule>>),
    OperationSingle(HashMap<String, Rule>),
    Primitive(Value),
}

#[derive(Debug, Clone)]
pub enum JsonLogicError {
    UnknownOperator(String),
    InvalidArguments(String, String),
    TypeError { expected: String, actual: String },
    MissingVariable(String),
    EvaluationError(String),
    MaxDepthExceeded(usize),
}

impl fmt::Display for JsonLogicError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            JsonLogicError::UnknownOperator(op) => write!(f, "Unknown operator: {}", op),
            JsonLogicError::InvalidArguments(op, msg) => {
                write!(f, "Invalid arguments for operator {}: {}", op, msg)
            }
            JsonLogicError::TypeError { expected, actual } => {
                write!(f, "Type error: expected {}, got {}", expected, actual)
            }
            JsonLogicError::MissingVariable(var) => write!(f, "Missing variable: {}", var),
            JsonLogicError::EvaluationError(msg) => write!(f, "Evaluation error: {}", msg),
            JsonLogicError::MaxDepthExceeded(depth) => {
                write!(f, "Maximum recursion depth exceeded ({})", depth)
            }
        }
    }
}

impl std::error::Error for JsonLogicError {}

pub struct JsonLogicEngine {
    custom_operators: HashMap<
        String,
        Box<dyn Fn(&[Value], &Value) -> Result<Value, JsonLogicError> + Send + Sync>,
    >,
}

impl Default for JsonLogicEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for JsonLogicEngine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JsonLogicEngine")
            .field("custom_operators_count", &self.custom_operators.len())
            .finish()
    }
}

impl JsonLogicEngine {
    pub fn new() -> Self {
        Self {
            custom_operators: HashMap::new(),
        }
    }

    pub fn register_operator<F>(&mut self, name: impl Into<String>, func: F)
    where
        F: Fn(&[Value], &Value) -> Result<Value, JsonLogicError> + Send + Sync + 'static,
    {
        self.custom_operators.insert(name.into(), Box::new(func));
    }

    pub fn precompile(rule: &Value) -> Result<Rule, JsonLogicError> {
        serde_json::from_value(rule.clone())
            .map_err(|e| JsonLogicError::EvaluationError(format!("Invalid rule: {}", e)))
    }

    pub fn evaluate(&self, rule: &Rule, data: &Value) -> Result<Value, JsonLogicError> {
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
                let (op, args) = op_map.iter().next().ok_or_else(|| {
                    JsonLogicError::EvaluationError("Empty operation".to_string())
                })?;
                self.evaluate_operation(op, args, data)
            }
            Rule::OperationSingle(op_map) => {
                let (op, arg) = op_map.iter().next().ok_or_else(|| {
                    JsonLogicError::EvaluationError("Empty operation".to_string())
                })?;
                self.evaluate_operation_single(op, arg, data)
            }
        }
    }

    pub fn evaluate_json(&self, rule: &Value, data: &Value) -> Result<Value, JsonLogicError> {
        let compiled = Self::precompile(rule)?;
        self.evaluate(&compiled, data)
    }

    fn evaluate_operation(
        &self,
        op: &str,
        args: &[Rule],
        data: &Value,
    ) -> Result<Value, JsonLogicError> {
        match op {
            "==" | "===" => self.eval_equality(args, data, true),
            "!=" | "!==" => self.eval_inequality(args, data, true),
            ">" => eval_greater_than(self.eval_args(args, data)?),
            ">=" => eval_greater_than_or_equal(self.eval_args(args, data)?),
            "<" => eval_less_than(self.eval_args(args, data)?),
            "<=" => eval_less_than_or_equal(self.eval_args(args, data)?),

            "and" => eval_and(self, args, data),
            "or" => eval_or(self, args, data),
            "!" | "not" => eval_not(self.eval_args(args, data)?),
            "!!" => eval_double_not(self.eval_args(args, data)?),

            "in" => eval_in(self.eval_args(args, data)?),
            "cat" => eval_cat(self.eval_args(args, data)?),
            "missing" => eval_missing(self.eval_args(args, data)?, data),
            "missing_some" => eval_missing_some(self.eval_args(args, data)?, data),

            "var" => eval_var(args, data),
            "if" => eval_if(self, args, data),

            "startsWith" => eval_starts_with(self.eval_args(args, data)?),
            "endsWith" => eval_ends_with(self.eval_args(args, data)?),
            "contains" => eval_contains(self.eval_args(args, data)?),

            "+" => eval_add(self.eval_args(args, data)?),
            "-" => eval_subtract(self.eval_args(args, data)?),
            "*" => eval_multiply(self.eval_args(args, data)?),
            "/" => eval_divide(self.eval_args(args, data)?),
            "min" => eval_min(self.eval_args(args, data)?),
            "max" => eval_max(self.eval_args(args, data)?),

            "merge" => eval_merge(self.eval_args(args, data)?),
            "map" => eval_map(self, args, data),
            "filter" => eval_filter(self, args, data),
            "reduce" => eval_reduce(self, args, data),
            "all" => eval_all(self, args, data),
            "none" => eval_none(self, args, data),
            "some" => eval_some(self, args, data),

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

    fn evaluate_operation_single(
        &self,
        op: &str,
        arg: &Rule,
        data: &Value,
    ) -> Result<Value, JsonLogicError> {
        match op {
            "var" => {
                let path = match arg {
                    Rule::Primitive(Value::String(s)) => s.clone(),
                    Rule::Primitive(Value::Number(n)) => n.to_string(),
                    Rule::Primitive(Value::Null) => return Ok(data.clone()),
                    _ => return Ok(Value::Null),
                };
                Ok(get_value_at_path(data, &path).unwrap_or(Value::Null))
            }
            _ => self.evaluate_operation(op, &[arg.clone()], data),
        }
    }

    fn eval_args(&self, args: &[Rule], data: &Value) -> Result<Vec<Value>, JsonLogicError> {
        args.iter().map(|arg| self.evaluate(arg, data)).collect()
    }

    fn eval_equality(
        &self,
        args: &[Rule],
        data: &Value,
        strict: bool,
    ) -> Result<Value, JsonLogicError> {
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

    fn eval_inequality(
        &self,
        args: &[Rule],
        data: &Value,
        strict: bool,
    ) -> Result<Value, JsonLogicError> {
        let result = self.eval_equality(args, data, strict)?;
        Ok(Value::Bool(!result.as_bool().unwrap_or(false)))
    }
}

fn jsonlogic_equals(a: &Value, b: &Value, strict: bool) -> bool {
    if strict {
        a == b
    } else {
        match (a, b) {
            (Value::Null, Value::Null) => true,
            (Value::Bool(x), Value::Bool(y)) => x == y,
            (Value::Number(x), Value::Number(y)) => {
                let xf = x.as_f64().unwrap_or(0.0);
                let yf = y.as_f64().unwrap_or(0.0);
                (xf - yf).abs() < f64::EPSILON
            }
            (Value::String(x), Value::String(y)) => x == y,
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

    #[test]
    fn test_precompile() {
        let engine = JsonLogicEngine::new();

        let rule_json = serde_json::json!({
            ">": [{"var": "amount"}, 100]
        });

        let compiled = JsonLogicEngine::precompile(&rule_json).unwrap();

        let data1 = serde_json::json!({"amount": 200});
        let result1 = engine.evaluate(&compiled, &data1).unwrap();
        assert_eq!(result1, Value::Bool(true));

        let data2 = serde_json::json!({"amount": 50});
        let result2 = engine.evaluate(&compiled, &data2).unwrap();
        assert_eq!(result2, Value::Bool(false));
    }

    #[test]
    fn test_precompile_reuse() {
        let engine = JsonLogicEngine::new();

        let rule_json = serde_json::json!({
            "==": [{"var": "status"}, "active"]
        });

        let compiled = JsonLogicEngine::precompile(&rule_json).unwrap();

        let results: Vec<_> = [0, 1, 2, 3, 4]
            .iter()
            .map(|i| {
                let data =
                    serde_json::json!({"status": if i % 2 == 0 { "active" } else { "inactive" }});
                engine.evaluate(&compiled, &data).unwrap()
            })
            .collect();

        assert_eq!(results[0], Value::Bool(true));
        assert_eq!(results[1], Value::Bool(false));
        assert_eq!(results[2], Value::Bool(true));
        assert_eq!(results[3], Value::Bool(false));
        assert_eq!(results[4], Value::Bool(true));
    }
}
