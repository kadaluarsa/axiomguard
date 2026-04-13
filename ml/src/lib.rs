//! AxiomGuard ML — AI/ML capabilities for agent security.
//!
//! Three core capabilities:
//! - **PII sanitization** — hybrid regex + NER detection and redaction
//! - **Prompt injection detection** — regex pre-filter + classifier
//! - **Semantic risk scoring** — embedding-based tool argument analysis
//!
//! All capabilities degrade gracefully: regex-only → regex+ML → full ML.

pub mod embedding;
pub mod injection;
pub mod pii;

use std::path::Path;

/// Top-level ML engine combining all capabilities.
pub struct AxiomGuardML {
    pii: pii::HybridPiiSanitizer,
    injection: injection::InjectionDetector,
    embedding: embedding::EmbeddingEngine,
}

/// Result of a full ML assessment on a tool call.
#[derive(Debug, Clone, serde::Serialize)]
pub struct MlAssessment {
    pub pii: pii::SanitizeResult,
    pub injection: injection::InjectionResult,
    pub semantic_risk: f32,
}

impl AxiomGuardML {
    /// Create a new ML engine, loading models from the given directory.
    /// Models are optional — gracefully degrades to regex-only if missing.
    pub fn new(model_dir: &Path) -> anyhow::Result<Self> {
        Ok(Self {
            pii: pii::HybridPiiSanitizer::new(model_dir)?,
            injection: injection::InjectionDetector::new(model_dir)?,
            embedding: embedding::EmbeddingEngine::new(model_dir)?,
        })
    }

    /// Create with regex-only capabilities (no model downloads required).
    pub fn new_regex_only() -> Self {
        Self {
            pii: pii::HybridPiiSanitizer::new_regex_only(),
            injection: injection::InjectionDetector::new_regex_only(),
            embedding: embedding::EmbeddingEngine::new_regex_only(),
        }
    }

    /// Sanitize PII from text.
    pub fn sanitize_pii(&self, text: &str) -> pii::SanitizeResult {
        self.pii.sanitize(text)
    }

    /// Detect prompt injection attempts.
    pub fn detect_injection(&self, text: &str) -> injection::InjectionResult {
        self.injection.detect(text)
    }

    /// Score semantic risk of a tool call.
    pub fn score_semantic_risk(&self, tool: &str, args: &str, context: &[&str]) -> f32 {
        self.embedding.score(tool, args, context)
    }

    /// Run a full ML assessment on a tool call.
    pub fn assess(&self, tool: &str, args: &str, context: &[&str]) -> MlAssessment {
        MlAssessment {
            pii: self.sanitize_pii(args),
            injection: self.detect_injection(args),
            semantic_risk: self.score_semantic_risk(tool, args, context),
        }
    }
}
