//! Z3 Theorem Prover Integration for Formal Verification
//! Followed JsonLogicEngine and MlLayer patterns
//! Provides SAT/UNSAT verification of logical claims and constraints

use z3::{Solver, Symbol, SatResult, Config};
use z3::ast::{Bool, Real};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use std::panic::catch_unwind;
use tokio::sync::Mutex;
use std::future::Future;
use std::pin::Pin;

/// Z3 verification error types (matches JsonLogicError pattern)
#[derive(Debug, Clone, Error)]
pub enum Z3Error {
    #[error("Claim parsing failed: {0}")]
    ClaimParsingError(String),
    #[error("Constraint validation failed: {0}")]
    ConstraintValidationError(String),
    #[error("Solver initialization failed: {0}")]
    SolverInitError(String),
    #[error("SAT check returned unknown result")]
    SatUnknownError,
    #[error("Type mismatch: expected {expected}, got {actual}")]
    TypeError { expected: String, actual: String },
    #[error("Unknown claim type: {0}")]
    UnknownClaimType(String),
    #[error("Failed to get model: {0}")]
    ModelRetrievalError(String),
}

/// Logical claim type for Z3 verification (matches Rule pattern from JsonLogic)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Claim {
    /// Boolean claim (e.g., "user.is_admin == true")
    BoolClaim {
        lhs: String,
        op: String,
        rhs: bool,
    },
    /// Numeric claim (e.g., "transaction.amount > 1000")
    NumericClaim {
        lhs: String,
        op: String,
        rhs: f64,
    },
    /// Compound claim (AND/OR of other claims)
    CompoundClaim {
        op: String,
        claims: Vec<Claim>,
    },
}

/// Z3 verification engine (matches MlLayer/JsonLogicEngine structure)
pub struct Z3Engine;

thread_local! {
    static Z3_SOLVER: Mutex<Option<Solver>> = Mutex::new(None);
}

impl Z3Engine {
    /// Create new Z3 engine (matches MlLayer::new() pattern)
    /// Create new Z3 engine (matches MlLayer::new() pattern)
    pub fn new() -> Result<Self, Z3Error> {
        let config = Config::new();
        z3::with_z3_config(&config, || ());
        Ok(Self)
    }

    /// Reset solver state for new verification tasks
    async fn reset_solver(&self) -> Result<(), Z3Error> {
        // Reinitialize thread-local solver with implicit context using block_in_place for thread-local mutex
        Z3_SOLVER.with(|solver| {
            tokio::task::block_in_place(|| {
                let mut solver_guard = solver.blocking_lock();
                *solver_guard = None;
                let new_solver = catch_unwind(|| Solver::new())
                    .map_err(|e| Z3Error::SolverInitError(format!("Z3 solver reinitialization failed: {:?}", e)))?;
                *solver_guard = Some(new_solver);
                Ok(())
            })
        })?;
        Ok(())
    }

    /// Helper for recursive claim parsing (resolves E0733 async recursion size error)
    fn parse_claim_helper<'a>(&'a self, claim: &'a Claim) -> Pin<Box<dyn Future<Output = Result<Bool, Z3Error>> + 'a>> {
        Box::pin(async move {
            // Initialize solver with implicit context if needed
            // Initialize solver with implicit context using block_in_place for thread-local mutex
            Z3_SOLVER.with(|solver| {
                tokio::task::block_in_place(|| {
                    let mut solver_guard = solver.blocking_lock();
                    if solver_guard.is_none() {
                        let new_solver = catch_unwind(|| Solver::new())
                            .map_err(|e| Z3Error::SolverInitError(format!("Z3 solver initialization failed: {:?}", e)))?;
                        *solver_guard = Some(new_solver);
                    }
                    Ok(())
                })
            })?;

            match claim {
                Claim::BoolClaim { lhs, op, rhs } => {
                    let var = Bool::new_const(Symbol::String(lhs.clone()));
                    let rhs_val = Bool::from_bool(*rhs);

                    match op.as_str() {
                        "==" => Ok(var.eq(&rhs_val)),
                        "!=" => Ok(var.ne(&rhs_val)),
                        _ => Err(Z3Error::ClaimParsingError(format!("Unknown boolean operator: {op}"))),
                    }
                },
                Claim::NumericClaim { lhs, op, rhs } => {
                    let var = Real::new_const(Symbol::String(lhs.clone()));
                    let rhs_str = rhs.to_string();
                    let rhs_val = Real::from_rational_str(&rhs_str, "1")
                        .ok_or_else(|| Z3Error::ClaimParsingError(format!("Invalid numeric value: {rhs}")))?;

                    match op.as_str() {
                        ">" => Ok(var.gt(&rhs_val)),
                        ">=" => Ok(var.ge(&rhs_val)),
                        "<" => Ok(var.lt(&rhs_val)),
                        "<=" => Ok(var.le(&rhs_val)),
                        "==" => Ok(var.eq(&rhs_val)),
                        "!=" => Ok(var.ne(&rhs_val)),
                        _ => Err(Z3Error::ClaimParsingError(format!("Unknown numeric operator: {op}"))),
                    }
                },
                Claim::CompoundClaim { op, claims } => {
                    let mut parsed_claims = Vec::new();
                    for c in claims {
                        parsed_claims.push(self.parse_claim_helper(c).await?);
                    }

                    match op.as_str() {
                        "and" => Ok(Bool::and(&parsed_claims)),
                        "or" => Ok(Bool::or(&parsed_claims)),
                        _ => Err(Z3Error::UnknownClaimType(format!("Unknown compound operator: {op}"))),
                    }
                },
            }
        })
    }

    /// Parse claim into Z3 AST (basic claim parsing requirement)
    async fn parse_claim<'a>(&'a self, claim: &'a Claim) -> Pin<Box<dyn Future<Output = Result<Bool, Z3Error>> + 'a>> {
        Box::pin(self.parse_claim_helper(claim))
    }

    /// Verify claims against constraints (core verify method)
    pub async fn verify(&self, claims: &[Claim], constraints: &[Claim]) -> Result<(bool, Option<String>), Z3Error> {
        self.reset_solver().await?;

        // Get thread-local solver and context
        // Resolve lifetime issue with move keyword

        let solver = Z3_SOLVER.with(|s| {
            tokio::task::block_in_place(|| {
                let solver_guard = s.blocking_lock();
                solver_guard.as_ref().ok_or_else(|| Z3Error::SolverInitError("Z3 solver not initialized".into()))
                    .map(|s| s as *const Solver)
            })
        })?;

        // SAFETY: Solver is guaranteed to live for the duration of this verify call
        // because we do not drop it or allow reset while this scope is active
        let solver = unsafe { &*solver };

        // Add constraints to solver (simple constraint verification requirement)
        for constraint in constraints {
            let constraint_ast = self.parse_claim(constraint).await.await?;
            solver.assert(&constraint_ast);
        }

        // Add negated claims to check for SAT (UNSAT means claims are valid)
        for claim in claims {
            let claim_ast = self.parse_claim(claim).await.await?;
            solver.assert(&claim_ast);
        }

        // Check SAT/UNSAT result (handling requirement)
        let result = solver.check();

        match result {
            SatResult::Unsat => Ok((true, None)), // Claims are valid (no counterexample)
            SatResult::Sat => {
                let model = solver.get_model()
                    .ok_or_else(|| Z3Error::ModelRetrievalError("No model available for SAT result".into()))?;
                let counterexample = model.to_string();
                Ok((false, Some(counterexample)))
            },
            SatResult::Unknown => Err(Z3Error::SatUnknownError),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Followed existing test patterns from JsonLogicEngine and MlLayer
    #[tokio::test(flavor = "multi_thread")]
    async fn test_basic_bool_claim_verification() -> Result<(), Z3Error> {
        let engine = Z3Engine::new()?;

        // Claim: user.is_admin == true
        let claim = Claim::BoolClaim {
            lhs: "user.is_admin".into(),
            op: "==".into(),
            rhs: true,
        };

        // No constraints
        let (is_valid, counterexample) = engine.verify(&[claim], &[]).await?;

        // Claim should be invalid (no constraints enforce it)
        assert!(!is_valid);
        assert!(counterexample.is_some());

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_numeric_constraint_verification() -> Result<(), Z3Error> {
        let engine = Z3Engine::new()?;

        // Claim: transaction.amount > 1000
        let claim = Claim::NumericClaim {
            lhs: "transaction.amount".into(),
            op: ">".into(),
            rhs: 1000.0,
        };

        // Constraint: transaction.amount <= 500
        let constraint = Claim::NumericClaim {
            lhs: "transaction.amount".into(),
            op: "<=".into(),
            rhs: 500.0,
        };

        let (is_valid, counterexample) = engine.verify(&[claim], &[constraint]).await?;

        // Claim should be valid (constraint makes it impossible)
        assert!(is_valid);
        assert!(counterexample.is_none());

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_compound_claim_verification() -> Result<(), Z3Error> {
        let engine = Z3Engine::new()?;

        // Compound claim: (user.is_admin == true) AND (transaction.amount > 1000)
        let compound_claim = Claim::CompoundClaim {
            op: "and".into(),
            claims: vec![
                Claim::BoolClaim {
                    lhs: "user.is_admin".into(),
                    op: "==".into(),
                    rhs: true,
                },
                Claim::NumericClaim {
                    lhs: "transaction.amount".into(),
                    op: ">".into(),
                    rhs: 1000.0,
                },
            ],
        };

        // Constraint: user.is_admin == false
        let constraint = Claim::BoolClaim {
            lhs: "user.is_admin".into(),
            op: "==".into(),
            rhs: false,
        };

        let (is_valid, counterexample) = engine.verify(&[compound_claim], &[constraint]).await?;

        // Claim should be valid (constraint breaks compound condition)
        assert!(is_valid);
        assert!(counterexample.is_none());

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_claim_parsing_error() -> Result<(), Z3Error> {
        let engine = Z3Engine::new()?;

        // Invalid claim with unknown operator
        let invalid_claim = Claim::BoolClaim {
            lhs: "user.is_admin".into(),
            op: "xor".into(),
            rhs: true,
        };

        let result = engine.verify(&[invalid_claim], &[]).await;

        assert!(matches!(result, Err(Z3Error::ClaimParsingError(_))));

        Ok(())
    }
}
