use crate::types::{DecisionType, GuardResult};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;
use uuid::Uuid;

#[derive(Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub event_id: String,
    pub timestamp: DateTime<Utc>,
    pub tenant_id: String,
    pub agent_id: String,
    pub session_id: Option<String>,
    pub tool_name: String,
    pub decision: DecisionType,
    pub risk_score: f32,
    pub processing_time_us: u64,
    pub reason: String,
    pub matched_rules: Vec<String>,
}

pub struct AuditBuffer {
    events: Mutex<Vec<AuditEvent>>,
    max_batch_size: usize,
    max_buffer_size: usize,
    wal_path: Option<PathBuf>,
}

impl AuditBuffer {
    pub fn new() -> Self {
        Self {
            events: Mutex::new(Vec::new()),
            max_batch_size: 50,
            max_buffer_size: 10000,
            wal_path: None,
        }
    }

    pub fn new_with_wal(path: impl AsRef<std::path::Path>) -> Self {
        Self {
            events: Mutex::new(Vec::new()),
            max_batch_size: 50,
            max_buffer_size: 10000,
            wal_path: Some(path.as_ref().to_path_buf()),
        }
    }

    pub fn record(&self, event: AuditEvent) {
        if let Some(ref path) = self.wal_path {
            match serde_json::to_vec(&event) {
                Ok(bytes) => {
                    if let Err(e) = OpenOptions::new()
                        .append(true)
                        .create(true)
                        .open(path)
                        .and_then(|mut file| {
                            file.write_all(&bytes)?;
                            file.write_all(b"\n")?;
                            file.flush()?;
                            Ok(())
                        })
                    {
                        tracing::warn!("audit wal write failed: {}", e);
                    }
                }
                Err(e) => {
                    tracing::warn!("audit wal serialization failed: {}", e);
                }
            }
        }

        let mut events = self.events.lock().unwrap();
        if events.len() >= self.max_buffer_size {
            events.remove(0);
        }
        events.push(event);
    }

    pub fn flush(&self) -> Vec<AuditEvent> {
        let mut events = self.events.lock().unwrap();
        let drained = std::mem::take(&mut *events);

        if let Some(ref path) = self.wal_path {
            if let Err(e) = OpenOptions::new()
                .write(true)
                .truncate(true)
                .create(true)
                .open(path)
                .and_then(|_| Ok(()))
            {
                tracing::warn!("audit wal truncate failed: {}", e);
            }
        }

        drained
    }

    pub fn recover_wal(path: impl AsRef<std::path::Path>) -> Result<Vec<AuditEvent>, String> {
        let path = path.as_ref();
        if !path.exists() {
            return Ok(Vec::new());
        }

        let data = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
        let mut events = Vec::new();
        for line in data.lines() {
            if line.is_empty() {
                continue;
            }
            match serde_json::from_str::<AuditEvent>(line) {
                Ok(event) => events.push(event),
                Err(e) => {
                    tracing::warn!("audit wal recovery parse failed for line: {}", e);
                }
            }
        }
        Ok(events)
    }

    pub fn len(&self) -> usize {
        self.events.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.events.lock().unwrap().is_empty()
    }
}

pub struct AuditEventContext {
    pub tenant_id: String,
    pub agent_id: String,
    pub session_id: Option<String>,
    pub tool_name: String,
}

impl AuditEvent {
    pub fn from_guard_result(result: &GuardResult, ctx: &AuditEventContext) -> Self {
        Self {
            event_id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            tenant_id: ctx.tenant_id.clone(),
            agent_id: ctx.agent_id.clone(),
            session_id: ctx.session_id.clone(),
            tool_name: ctx.tool_name.clone(),
            decision: result.decision,
            risk_score: result.risk_score,
            processing_time_us: result.processing_time_us,
            reason: result.reason.clone(),
            matched_rules: result.matched_rules.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn make_event(id: &str) -> AuditEvent {
        AuditEvent {
            event_id: id.to_string(),
            timestamp: Utc::now(),
            tenant_id: "tenant".into(),
            agent_id: "agent".into(),
            session_id: None,
            tool_name: "exec".into(),
            decision: DecisionType::Allow,
            risk_score: 0.1,
            processing_time_us: 100,
            reason: "test".into(),
            matched_rules: vec![],
        }
    }

    #[test]
    fn events_are_recorded() {
        let buffer = AuditBuffer::new();
        buffer.record(make_event("1"));
        buffer.record(make_event("2"));
        assert_eq!(buffer.len(), 2);
        assert!(!buffer.is_empty());
    }

    #[test]
    fn flush_drains_buffer() {
        let buffer = AuditBuffer::new();
        buffer.record(make_event("1"));
        buffer.record(make_event("2"));

        let events = buffer.flush();
        assert_eq!(events.len(), 2);
        assert!(buffer.is_empty());
    }

    #[test]
    fn buffer_overflow_drops_oldest() {
        let buffer = AuditBuffer::new();
        for i in 0..10001 {
            buffer.record(make_event(&i.to_string()));
        }
        assert_eq!(buffer.len(), buffer.max_buffer_size);

        let events = buffer.flush();
        assert_eq!(events[0].event_id, "1");
        assert_eq!(events.last().unwrap().event_id, "10000");
    }

    #[test]
    fn wal_write_and_recover_and_flush() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("axiomguard_audit_wal_{}.jsonl", Uuid::new_v4()));

        let buffer = AuditBuffer::new_with_wal(&path);
        buffer.record(make_event("ev1"));
        buffer.record(make_event("ev2"));

        let recovered = AuditBuffer::recover_wal(&path).unwrap();
        assert_eq!(recovered.len(), 2);
        assert_eq!(recovered[0].event_id, "ev1");
        assert_eq!(recovered[1].event_id, "ev2");

        let flushed = buffer.flush();
        assert_eq!(flushed.len(), 2);
        assert!(buffer.is_empty());

        let post_flush = AuditBuffer::recover_wal(&path).unwrap();
        assert!(post_flush.is_empty());

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn recover_missing_file_returns_empty_vec() {
        let path = std::env::temp_dir().join("axiomguard_nonexistent_wal.jsonl");
        let recovered = AuditBuffer::recover_wal(&path).unwrap();
        assert!(recovered.is_empty());
    }
}
