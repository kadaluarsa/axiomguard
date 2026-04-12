//! Server-Sent Events handling
//! 
//! This module provides utilities for managing SSE connections
//! from clients to the AxiomGuard Shield service.

use axum::response::sse::Event;
use serde::Serialize;
use std::convert::Infallible;

/// SSE event types
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type")]
pub enum SseEvent {
    #[serde(rename = "classification")]
    Classification {
        session_id: String,
        decision: String,
        confidence: f32,
        reason: String,
    },
    #[serde(rename = "heartbeat")]
    Heartbeat {
        timestamp: i64,
    },
    #[serde(rename = "error")]
    Error {
        message: String,
        code: u16,
    },
}

impl SseEvent {
    /// Convert to axum SSE Event
    pub fn to_event(&self) -> Result<Event, Infallible> {
        let data = serde_json::to_string(self).unwrap_or_default();
        
        let event_type = match self {
            SseEvent::Classification { .. } => "classification",
            SseEvent::Heartbeat { .. } => "heartbeat",
            SseEvent::Error { .. } => "error",
        };
        
        Ok(Event::default()
            .event(event_type)
            .data(data))
    }
}

/// Create a heartbeat event
pub fn heartbeat() -> SseEvent {
    SseEvent::Heartbeat {
        timestamp: chrono::Utc::now().timestamp(),
    }
}

/// Create a classification event
pub fn classification(
    session_id: impl Into<String>,
    decision: impl Into<String>,
    confidence: f32,
    reason: impl Into<String>,
) -> SseEvent {
    SseEvent::Classification {
        session_id: session_id.into(),
        decision: decision.into(),
        confidence,
        reason: reason.into(),
    }
}

/// Create an error event
pub fn error(message: impl Into<String>, code: u16) -> SseEvent {
    SseEvent::Error {
        message: message.into(),
        code,
    }
}
