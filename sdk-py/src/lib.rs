use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

#[pyfunction]
fn compute_hash(json_str: &str) -> PyResult<String> {
    let val: serde_json::Value = serde_json::from_str(json_str)
        .map_err(|e| PyValueError::new_err(format!("invalid JSON: {}", e)))?;
    Ok(ag_tool_common::compute_args_hash(&val))
}

#[pyfunction]
fn verify_token(token_str: &str, verifying_key_hex: &str) -> PyResult<PyClaims> {
    let vk = ag_tool_common::parse_verifying_key(verifying_key_hex)
        .map_err(|e| PyValueError::new_err(e.to_string()))?;
    let claims = ag_tool_common::verify_token(token_str, &vk)
        .map_err(|e| PyValueError::new_err(e.to_string()))?;
    Ok(PyClaims {
        tool: claims.tool,
        args_hash: claims.args_hash,
        session_id: claims.session_id,
        tenant_id: claims.tenant_id,
        agent_id: claims.agent_id,
        decision: claims.decision,
        iat: claims.iat,
        exp: claims.exp,
        jti: claims.jti,
        risk_score: claims.risk_score,
    })
}

#[pyfunction]
#[pyo3(signature = (token_str, verifying_key_hex, expected_tool=None, expected_agent_id=None, expected_args_json=None, max_risk=None))]
fn verify_token_with_checks(
    token_str: &str,
    verifying_key_hex: &str,
    expected_tool: Option<&str>,
    expected_agent_id: Option<&str>,
    expected_args_json: Option<&str>,
    max_risk: Option<f64>,
) -> PyResult<PyVerifyResult> {
    let vk = ag_tool_common::parse_verifying_key(verifying_key_hex)
        .map_err(|e| PyValueError::new_err(e.to_string()))?;
    let claims = ag_tool_common::verify_token(token_str, &vk)
        .map_err(|e| PyValueError::new_err(e.to_string()))?;

    if let Some(tool) = expected_tool {
        if let Err(e) = ag_tool_common::verify_tool(&claims, tool) {
            return Ok(PyVerifyResult {
                valid: false,
                claims: Some(PyClaims::from_claims(&claims)),
                error: Some(e.to_string()),
            });
        }
    }

    if let Some(aid) = expected_agent_id {
        if let Err(e) = ag_tool_common::verify_agent_id(&claims, aid) {
            return Ok(PyVerifyResult {
                valid: false,
                claims: Some(PyClaims::from_claims(&claims)),
                error: Some(e.to_string()),
            });
        }
    }

    if let Some(args_json) = expected_args_json {
        let val: serde_json::Value = serde_json::from_str(args_json)
            .map_err(|e| PyValueError::new_err(format!("invalid args JSON: {}", e)))?;
        if let Err(e) = ag_tool_common::verify_args_hash(&claims, &val) {
            return Ok(PyVerifyResult {
                valid: false,
                claims: Some(PyClaims::from_claims(&claims)),
                error: Some(e.to_string()),
            });
        }
    }

    if let Some(max) = max_risk {
        if let Err(e) = ag_tool_common::verify_risk_below(&claims, max as f32) {
            return Ok(PyVerifyResult {
                valid: false,
                claims: Some(PyClaims::from_claims(&claims)),
                error: Some(e.to_string()),
            });
        }
    }

    if let Err(e) = ag_tool_common::verify_decision_allow(&claims) {
        return Ok(PyVerifyResult {
            valid: false,
            claims: Some(PyClaims::from_claims(&claims)),
            error: Some(e.to_string()),
        });
    }

    Ok(PyVerifyResult {
        valid: true,
        claims: Some(PyClaims::from_claims(&claims)),
        error: None,
    })
}

#[pyclass(frozen)]
#[derive(Clone)]
struct PyClaims {
    #[pyo3(get)]
    tool: String,
    #[pyo3(get)]
    args_hash: String,
    #[pyo3(get)]
    session_id: String,
    #[pyo3(get)]
    tenant_id: String,
    #[pyo3(get)]
    agent_id: String,
    #[pyo3(get)]
    decision: String,
    #[pyo3(get)]
    iat: i64,
    #[pyo3(get)]
    exp: i64,
    #[pyo3(get)]
    jti: String,
    #[pyo3(get)]
    risk_score: f32,
}

impl PyClaims {
    fn from_claims(c: &ag_tool_common::TokenClaims) -> Self {
        Self {
            tool: c.tool.clone(),
            args_hash: c.args_hash.clone(),
            session_id: c.session_id.clone(),
            tenant_id: c.tenant_id.clone(),
            agent_id: c.agent_id.clone(),
            decision: c.decision.clone(),
            iat: c.iat,
            exp: c.exp,
            jti: c.jti.clone(),
            risk_score: c.risk_score,
        }
    }
}

#[pymethods]
impl PyClaims {
    fn __repr__(&self) -> String {
        format!(
            "Claims(tool='{}', agent_id='{}', decision='{}')",
            self.tool, self.agent_id, self.decision
        )
    }
}

#[pyclass(frozen)]
struct PyVerifyResult {
    #[pyo3(get)]
    valid: bool,
    #[pyo3(get)]
    claims: Option<PyClaims>,
    #[pyo3(get)]
    error: Option<String>,
}

#[pymethods]
impl PyVerifyResult {
    fn __bool__(&self) -> bool {
        self.valid
    }

    fn __repr__(&self) -> String {
        if self.valid {
            "VerifyResult(valid=True)".to_string()
        } else {
            format!(
                "VerifyResult(valid=False, error='{}')",
                self.error.as_deref().unwrap_or("unknown")
            )
        }
    }
}

#[pymodule]
fn _axiomguard_core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(compute_hash, m)?)?;
    m.add_function(wrap_pyfunction!(verify_token, m)?)?;
    m.add_function(wrap_pyfunction!(verify_token_with_checks, m)?)?;
    m.add_class::<PyClaims>()?;
    m.add_class::<PyVerifyResult>()?;
    Ok(())
}
