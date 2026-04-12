use super::{JsonLogicEngine, JsonLogicError, Rule};
use serde_json::Value;

pub fn eval_greater_than(args: Vec<Value>) -> Result<Value, JsonLogicError> {
    if args.len() != 2 {
        return Err(JsonLogicError::InvalidArguments(
            ">".to_string(),
            "requires exactly 2 arguments".to_string(),
        ));
    }

    let a = to_number(&args[0])?;
    let b = to_number(&args[1])?;
    Ok(Value::Bool(a > b))
}

pub fn eval_greater_than_or_equal(args: Vec<Value>) -> Result<Value, JsonLogicError> {
    if args.len() != 2 {
        return Err(JsonLogicError::InvalidArguments(
            ">=".to_string(),
            "requires exactly 2 arguments".to_string(),
        ));
    }

    let a = to_number(&args[0])?;
    let b = to_number(&args[1])?;
    Ok(Value::Bool(a >= b))
}

pub fn eval_less_than(args: Vec<Value>) -> Result<Value, JsonLogicError> {
    if args.len() != 2 {
        return Err(JsonLogicError::InvalidArguments(
            "<".to_string(),
            "requires exactly 2 arguments".to_string(),
        ));
    }

    let a = to_number(&args[0])?;
    let b = to_number(&args[1])?;
    Ok(Value::Bool(a < b))
}

pub fn eval_less_than_or_equal(args: Vec<Value>) -> Result<Value, JsonLogicError> {
    if args.len() != 2 {
        return Err(JsonLogicError::InvalidArguments(
            "<=".to_string(),
            "requires exactly 2 arguments".to_string(),
        ));
    }

    let a = to_number(&args[0])?;
    let b = to_number(&args[1])?;
    Ok(Value::Bool(a <= b))
}

pub fn eval_and(
    engine: &JsonLogicEngine,
    args: &[Rule],
    data: &Value,
) -> Result<Value, JsonLogicError> {
    for arg in args {
        let result = engine.evaluate(arg, data)?;
        if !is_truthy(&result) {
            return Ok(Value::Bool(false));
        }
    }
    Ok(Value::Bool(true))
}

pub fn eval_or(
    engine: &JsonLogicEngine,
    args: &[Rule],
    data: &Value,
) -> Result<Value, JsonLogicError> {
    for arg in args {
        let result = engine.evaluate(arg, data)?;
        if is_truthy(&result) {
            return Ok(Value::Bool(true));
        }
    }
    Ok(Value::Bool(false))
}

pub fn eval_not(args: Vec<Value>) -> Result<Value, JsonLogicError> {
    if args.is_empty() {
        return Ok(Value::Bool(true));
    }
    Ok(Value::Bool(!is_truthy(&args[0])))
}

pub fn eval_double_not(args: Vec<Value>) -> Result<Value, JsonLogicError> {
    if args.is_empty() {
        return Ok(Value::Bool(false));
    }
    Ok(Value::Bool(is_truthy(&args[0])))
}

pub fn eval_in(args: Vec<Value>) -> Result<Value, JsonLogicError> {
    if args.len() != 2 {
        return Err(JsonLogicError::InvalidArguments(
            "in".to_string(),
            "requires exactly 2 arguments".to_string(),
        ));
    }

    let needle = &args[0];
    let haystack = &args[1];

    match haystack {
        Value::Array(arr) => Ok(Value::Bool(arr.contains(needle))),
        Value::String(s) => {
            if let Value::String(needle_str) = needle {
                Ok(Value::Bool(s.contains(needle_str)))
            } else {
                Ok(Value::Bool(false))
            }
        }
        _ => Ok(Value::Bool(false)),
    }
}

pub fn eval_cat(args: Vec<Value>) -> Result<Value, JsonLogicError> {
    let mut result = String::new();
    for arg in args {
        match arg {
            Value::String(s) => result.push_str(&s),
            Value::Number(n) => result.push_str(&n.to_string()),
            Value::Bool(b) => result.push_str(&b.to_string()),
            Value::Null => result.push_str("null"),
            _ => {}
        }
    }
    Ok(Value::String(result))
}

pub fn eval_missing(args: Vec<Value>, data: &Value) -> Result<Value, JsonLogicError> {
    let mut missing = Vec::new();

    for arg in args {
        if let Value::String(key) = arg {
            if get_value_at_path(data, &key).is_none() {
                missing.push(Value::String(key));
            }
        }
    }

    Ok(Value::Array(missing))
}

pub fn eval_missing_some(args: Vec<Value>, data: &Value) -> Result<Value, JsonLogicError> {
    if args.len() < 2 {
        return Ok(Value::Array(vec![]));
    }

    let min_required = args[0].as_u64().unwrap_or(0) as usize;
    let keys: Vec<String> = args[1..]
        .iter()
        .filter_map(|v| v.as_str().map(String::from))
        .collect();

    let found: Vec<_> = keys
        .iter()
        .filter(|key| get_value_at_path(data, key).is_some())
        .collect();

    if found.len() >= min_required {
        Ok(Value::Array(vec![]))
    } else {
        let missing: Vec<Value> = keys
            .iter()
            .filter(|key| get_value_at_path(data, key).is_none())
            .map(|key| Value::String(key.clone()))
            .collect();
        Ok(Value::Array(missing))
    }
}

pub fn eval_var(args: &[Rule], data: &Value) -> Result<Value, JsonLogicError> {
    if args.is_empty() {
        return Ok(data.clone());
    }

    let path = match &args[0] {
        Rule::Primitive(Value::String(s)) => s.clone(),
        Rule::Primitive(Value::Number(n)) => n.to_string(),
        Rule::Primitive(Value::Null) => return Ok(data.clone()),
        _ => {
            return Ok(Value::Null);
        }
    };

    let default = if args.len() > 1 {
        match &args[1] {
            Rule::Primitive(v) => v.clone(),
            _ => Value::Null,
        }
    } else {
        Value::Null
    };

    Ok(get_value_at_path(data, &path).unwrap_or(default))
}

pub fn eval_if(
    engine: &JsonLogicEngine,
    args: &[Rule],
    data: &Value,
) -> Result<Value, JsonLogicError> {
    if args.is_empty() {
        return Ok(Value::Null);
    }

    let condition = engine.evaluate(&args[0], data)?;

    if is_truthy(&condition) {
        if args.len() > 1 {
            engine.evaluate(&args[1], data)
        } else {
            Ok(condition)
        }
    } else {
        if args.len() > 2 {
            engine.evaluate(&args[2], data)
        } else {
            Ok(Value::Null)
        }
    }
}

pub fn eval_starts_with(args: Vec<Value>) -> Result<Value, JsonLogicError> {
    if args.len() != 2 {
        return Err(JsonLogicError::InvalidArguments(
            "startsWith".to_string(),
            "requires exactly 2 arguments".to_string(),
        ));
    }

    let string = args[0].as_str().unwrap_or("");
    let prefix = args[1].as_str().unwrap_or("");
    Ok(Value::Bool(string.starts_with(prefix)))
}

pub fn eval_ends_with(args: Vec<Value>) -> Result<Value, JsonLogicError> {
    if args.len() != 2 {
        return Err(JsonLogicError::InvalidArguments(
            "endsWith".to_string(),
            "requires exactly 2 arguments".to_string(),
        ));
    }

    let string = args[0].as_str().unwrap_or("");
    let suffix = args[1].as_str().unwrap_or("");
    Ok(Value::Bool(string.ends_with(suffix)))
}

pub fn eval_contains(args: Vec<Value>) -> Result<Value, JsonLogicError> {
    if args.len() != 2 {
        return Err(JsonLogicError::InvalidArguments(
            "contains".to_string(),
            "requires exactly 2 arguments".to_string(),
        ));
    }

    let string = args[0].as_str().unwrap_or("");
    let substring = args[1].as_str().unwrap_or("");
    Ok(Value::Bool(string.contains(substring)))
}

pub fn eval_add(args: Vec<Value>) -> Result<Value, JsonLogicError> {
    let mut sum = 0.0;
    for arg in args {
        sum += to_number(&arg)?;
    }
    Ok(Value::Number(
        serde_json::Number::from_f64(sum).unwrap_or(serde_json::Number::from(0)),
    ))
}

pub fn eval_subtract(args: Vec<Value>) -> Result<Value, JsonLogicError> {
    if args.is_empty() {
        return Ok(Value::Number(serde_json::Number::from(0)));
    }

    let first = to_number(&args[0])?;

    if args.len() == 1 {
        return Ok(Value::Number(
            serde_json::Number::from_f64(-first).unwrap_or(serde_json::Number::from(0)),
        ));
    }

    let mut result = first;
    for arg in &args[1..] {
        result -= to_number(arg)?;
    }

    Ok(Value::Number(
        serde_json::Number::from_f64(result).unwrap_or(serde_json::Number::from(0)),
    ))
}

pub fn eval_multiply(args: Vec<Value>) -> Result<Value, JsonLogicError> {
    let mut product = 1.0;
    for arg in args {
        product *= to_number(&arg)?;
    }
    Ok(Value::Number(
        serde_json::Number::from_f64(product).unwrap_or(serde_json::Number::from(0)),
    ))
}

pub fn eval_divide(args: Vec<Value>) -> Result<Value, JsonLogicError> {
    if args.len() != 2 {
        return Err(JsonLogicError::InvalidArguments(
            "/".to_string(),
            "requires exactly 2 arguments".to_string(),
        ));
    }

    let a = to_number(&args[0])?;
    let b = to_number(&args[1])?;

    if b == 0.0 {
        return Ok(Value::Null);
    }

    Ok(Value::Number(
        serde_json::Number::from_f64(a / b).unwrap_or(serde_json::Number::from(0)),
    ))
}

pub fn eval_min(args: Vec<Value>) -> Result<Value, JsonLogicError> {
    if args.is_empty() {
        return Ok(Value::Null);
    }

    let min = args
        .iter()
        .map(|v| to_number(v))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .fold(f64::INFINITY, f64::min);

    Ok(Value::Number(
        serde_json::Number::from_f64(min).unwrap_or(serde_json::Number::from(0)),
    ))
}

pub fn eval_max(args: Vec<Value>) -> Result<Value, JsonLogicError> {
    if args.is_empty() {
        return Ok(Value::Null);
    }

    let max = args
        .iter()
        .map(|v| to_number(v))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .fold(f64::NEG_INFINITY, f64::max);

    Ok(Value::Number(
        serde_json::Number::from_f64(max).unwrap_or(serde_json::Number::from(0)),
    ))
}

pub fn eval_merge(args: Vec<Value>) -> Result<Value, JsonLogicError> {
    let mut result = Vec::new();

    for arg in args {
        match arg {
            Value::Array(arr) => result.extend(arr),
            other => result.push(other),
        }
    }

    Ok(Value::Array(result))
}

pub fn eval_map(
    engine: &JsonLogicEngine,
    args: &[Rule],
    data: &Value,
) -> Result<Value, JsonLogicError> {
    if args.len() < 2 {
        return Ok(Value::Array(vec![]));
    }

    let arr = engine.evaluate(&args[0], data)?;
    let Value::Array(items) = arr else {
        return Ok(Value::Array(vec![]));
    };

    let mapper = &args[1];

    let result: Result<Vec<_>, _> = items
        .iter()
        .map(|item| engine.evaluate(mapper, item))
        .collect();

    Ok(Value::Array(result?))
}

pub fn eval_filter(
    engine: &JsonLogicEngine,
    args: &[Rule],
    data: &Value,
) -> Result<Value, JsonLogicError> {
    if args.len() < 2 {
        return Ok(Value::Array(vec![]));
    }

    let arr = engine.evaluate(&args[0], data)?;
    let Value::Array(items) = arr else {
        return Ok(Value::Array(vec![]));
    };

    let condition = &args[1];

    let mut result = Vec::new();
    for item in items {
        if is_truthy(&engine.evaluate(condition, &item)?) {
            result.push(item);
        }
    }

    Ok(Value::Array(result))
}

pub fn eval_reduce(
    engine: &JsonLogicEngine,
    args: &[Rule],
    data: &Value,
) -> Result<Value, JsonLogicError> {
    if args.len() < 2 {
        return Ok(Value::Null);
    }

    let arr = engine.evaluate(&args[0], data)?;
    let Value::Array(items) = arr else {
        return Ok(Value::Null);
    };

    let reducer = &args[1];
    let initial = if args.len() > 2 {
        engine.evaluate(&args[2], data)?
    } else {
        Value::Null
    };

    let mut accumulator = initial;
    for (index, current) in items.iter().enumerate() {
        let context = serde_json::json!({
            "current": current,
            "accumulator": accumulator,
            "index": index,
        });
        accumulator = engine.evaluate(reducer, &context)?;
    }

    Ok(accumulator)
}

pub fn eval_all(
    engine: &JsonLogicEngine,
    args: &[Rule],
    data: &Value,
) -> Result<Value, JsonLogicError> {
    if args.len() < 2 {
        return Ok(Value::Bool(false));
    }

    let arr = engine.evaluate(&args[0], data)?;
    let Value::Array(items) = arr else {
        return Ok(Value::Bool(false));
    };

    if items.is_empty() {
        return Ok(Value::Bool(false));
    }

    let condition = &args[1];

    for item in items {
        if !is_truthy(&engine.evaluate(condition, &item)?) {
            return Ok(Value::Bool(false));
        }
    }

    Ok(Value::Bool(true))
}

pub fn eval_none(
    engine: &JsonLogicEngine,
    args: &[Rule],
    data: &Value,
) -> Result<Value, JsonLogicError> {
    if args.len() < 2 {
        return Ok(Value::Bool(true));
    }

    let arr = engine.evaluate(&args[0], data)?;
    let Value::Array(items) = arr else {
        return Ok(Value::Bool(true));
    };

    let condition = &args[1];

    for item in items {
        if is_truthy(&engine.evaluate(condition, &item)?) {
            return Ok(Value::Bool(false));
        }
    }

    Ok(Value::Bool(true))
}

pub fn eval_some(
    engine: &JsonLogicEngine,
    args: &[Rule],
    data: &Value,
) -> Result<Value, JsonLogicError> {
    if args.len() < 2 {
        return Ok(Value::Bool(false));
    }

    let arr = engine.evaluate(&args[0], data)?;
    let Value::Array(items) = arr else {
        return Ok(Value::Bool(false));
    };

    if items.is_empty() {
        return Ok(Value::Bool(false));
    }

    let condition = &args[1];

    for item in items {
        if is_truthy(&engine.evaluate(condition, &item)?) {
            return Ok(Value::Bool(true));
        }
    }

    Ok(Value::Bool(false))
}

pub fn is_truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().map(|f| f != 0.0).unwrap_or(false),
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    }
}

fn to_number(value: &Value) -> Result<f64, JsonLogicError> {
    match value {
        Value::Number(n) => n.as_f64().ok_or_else(|| JsonLogicError::TypeError {
            expected: "number".to_string(),
            actual: "invalid number".to_string(),
        }),
        Value::String(s) => s.parse().map_err(|_| JsonLogicError::TypeError {
            expected: "number".to_string(),
            actual: format!("string '{}': not parseable as number", s),
        }),
        Value::Bool(true) => Ok(1.0),
        Value::Bool(false) => Ok(0.0),
        Value::Null => Ok(0.0),
        _ => Err(JsonLogicError::TypeError {
            expected: "number".to_string(),
            actual: format!("{}", value),
        }),
    }
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
