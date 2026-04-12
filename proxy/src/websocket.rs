//! WebSocket handling
//!
//! This module provides utilities for managing WebSocket connections
//! from clients to the AxiomGuard Shield service.

use serde::{Deserialize, Serialize};

/// WebSocket message types from client
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type")]
pub enum WsRequest {
    #[serde(rename = "classify")]
    Classify {
        session_id: String,
        content: String,
        #[serde(default)]
        metadata: serde_json::Value,
    },
    #[serde(rename = "ping")]
    Ping {
        timestamp: i64,
    },
    #[serde(rename = "subscribe")]
    Subscribe {
        session_id: String,
    },
}

/// WebSocket message types to client
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type")]
pub enum WsResponse {
    #[serde(rename = "classification")]
    Classification {
        session_id: String,
        decision: String,
        confidence: f32,
        reason: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        matched_rules: Option<Vec<String>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        ai_insights: Option<serde_json::Value>,
        processing_time_ms: u64,
    },
    #[serde(rename = "pong")]
    Pong {
        timestamp: i64,
        server_time: i64,
    },
    #[serde(rename = "error")]
    Error {
        message: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        code: Option<u16>,
    },
    #[serde(rename = "subscribed")]
    Subscribed {
        session_id: String,
    },
}

/// Session state for WebSocket connections
#[derive(Debug, Clone)]
pub struct WsSession {
    pub session_id: Option<String>,
    pub subscribed: bool,
    pub message_count: u64,
    pub connected_at: chrono::DateTime<chrono::Utc>,
}

impl WsSession {
    pub fn new() -> Self {
        Self {
            session_id: None,
            subscribed: false,
            message_count: 0,
            connected_at: chrono::Utc::now(),
        }
    }
    
    pub fn subscribe(&mut self, session_id: String) {
        self.session_id = Some(session_id);
        self.subscribed = true;
    }
}

impl Default for WsSession {
    fn default() -> Self {
        Self::new()
    }
}
