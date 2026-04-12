pub mod audit {
    include!(concat!(env!("OUT_DIR"), "/audit.rs"));
}

pub mod shield {
    include!(concat!(env!("OUT_DIR"), "/shield.rs"));
}

pub mod conversions {
    use crate::audit;
    use chrono::{DateTime, Utc};
    use common;
    use prost_types::{Struct, Timestamp, Value};
    use std::collections::BTreeMap;
    use uuid::Uuid;

    // Convert common types to protobuf types
    pub fn audit_event_to_proto(event: &common::AuditEvent) -> audit::SubmitEventRequest {
        audit::SubmitEventRequest {
            source: event.source.clone(),
            event_type: event.event_type.clone(),
            data: Some(serde_json_to_struct(event.data.clone())),
            timestamp: Some(timestamp_to_proto(event.timestamp)),
        }
    }

    pub fn audit_decision_to_proto(decision: &common::AuditDecision) -> audit::GetDecisionResponse {
        audit::GetDecisionResponse {
            event_id: decision.event_id.to_string(),
            decision: match decision.decision {
                common::DecisionType::Allow => audit::DecisionType::Allow,
                common::DecisionType::Block => audit::DecisionType::Block,
                common::DecisionType::Flag => audit::DecisionType::Flag,
                common::DecisionType::Review => audit::DecisionType::Review,
                common::DecisionType::Handover => audit::DecisionType::Review, // Map Handover to Review for audit
            } as i32,
            confidence: decision.confidence,
            rules_matched: decision.rules_matched.clone(),
            ai_insights: decision.ai_insights.clone().unwrap_or_default(),
            processing_time_ms: decision.processing_time_ms,
            timestamp: Some(timestamp_to_proto(decision.timestamp)),
        }
    }

    pub fn audit_rule_to_proto(rule: &common::AuditRule) -> audit::AuditRule {
        audit::AuditRule {
            id: rule.id.clone(),
            name: rule.name.clone(),
            description: rule.description.clone(),
            conditions: rule
                .conditions
                .iter()
                .map(rule_condition_to_proto)
                .collect(),
            decision: match rule.decision {
                common::DecisionType::Allow => audit::DecisionType::Allow,
                common::DecisionType::Block => audit::DecisionType::Block,
                common::DecisionType::Flag => audit::DecisionType::Flag,
                common::DecisionType::Review => audit::DecisionType::Review,
                common::DecisionType::Handover => audit::DecisionType::Review,
            } as i32,
            priority: rule.priority,
            enabled: rule.enabled,
        }
    }

    pub fn rule_condition_to_proto(condition: &common::RuleCondition) -> audit::RuleCondition {
        audit::RuleCondition {
            field: condition.field.clone(),
            operator: match condition.operator {
                common::ConditionOperator::Equals => audit::ConditionOperator::Equals,
                common::ConditionOperator::NotEquals => audit::ConditionOperator::NotEquals,
                common::ConditionOperator::GreaterThan => audit::ConditionOperator::GreaterThan,
                common::ConditionOperator::LessThan => audit::ConditionOperator::LessThan,
                common::ConditionOperator::Contains => audit::ConditionOperator::Contains,
                common::ConditionOperator::NotContains => audit::ConditionOperator::NotContains,
                common::ConditionOperator::RegexMatch => audit::ConditionOperator::RegexMatch,
                common::ConditionOperator::In => audit::ConditionOperator::In,
                common::ConditionOperator::NotIn => audit::ConditionOperator::NotIn,
            } as i32,
            value: Some(serde_json_to_value(condition.value.clone())),
        }
    }

    pub fn audit_metrics_to_proto(metrics: &common::AuditMetrics) -> audit::AuditMetrics {
        audit::AuditMetrics {
            total_events: metrics.total_events,
            processed_events: metrics.processed_events,
            blocked_events: metrics.blocked_events,
            flagged_events: metrics.flagged_events,
            avg_processing_time_ms: metrics.avg_processing_time_ms,
            errors: metrics.errors,
            rule_evaluation_time_ms: 0.0,
            ai_processing_time_ms: 0.0,
        }
    }

    // Convert protobuf types to common types
    pub fn proto_to_audit_event(request: &audit::SubmitEventRequest) -> common::AuditEvent {
        common::AuditEvent {
            id: Uuid::new_v4(),
            source: request.source.clone(),
            event_type: request.event_type.clone(),
            data: request
                .data
                .clone()
                .map(struct_to_serde_json)
                .unwrap_or(serde_json::Value::Null),
            timestamp: request
                .timestamp
                .as_ref()
                .map(proto_to_timestamp)
                .unwrap_or(Utc::now()),
        }
    }

    pub fn proto_to_audit_decision(response: &audit::GetDecisionResponse) -> common::AuditDecision {
        common::AuditDecision {
            event_id: Uuid::parse_str(&response.event_id).unwrap_or(Uuid::new_v4()),
            decision: match response.decision {
                0 => common::DecisionType::Allow,
                1 => common::DecisionType::Block,
                2 => common::DecisionType::Flag,
                3 => common::DecisionType::Review,
                _ => common::DecisionType::Review,
            },
            confidence: response.confidence,
            rules_matched: response.rules_matched.clone(),
            ai_insights: if response.ai_insights.is_empty() {
                None
            } else {
                Some(response.ai_insights.clone())
            },
            processing_time_ms: response.processing_time_ms,
            timestamp: response
                .timestamp
                .as_ref()
                .map(proto_to_timestamp)
                .unwrap_or(Utc::now()),
        }
    }

    pub fn proto_to_audit_rule(rule: &audit::AuditRule) -> common::AuditRule {
        common::AuditRule {
            id: rule.id.clone(),
            name: rule.name.clone(),
            description: rule.description.clone(),
            conditions: rule
                .conditions
                .iter()
                .map(proto_to_rule_condition)
                .collect(),
            decision: match rule.decision {
                0 => common::DecisionType::Allow,
                1 => common::DecisionType::Block,
                2 => common::DecisionType::Flag,
                3 => common::DecisionType::Review,
                _ => common::DecisionType::Review,
            },
            priority: rule.priority,
            enabled: rule.enabled,
        }
    }

    pub fn proto_to_rule_condition(condition: &audit::RuleCondition) -> common::RuleCondition {
        common::RuleCondition {
            field: condition.field.clone(),
            operator: match condition.operator {
                0 => common::ConditionOperator::Equals,
                1 => common::ConditionOperator::NotEquals,
                2 => common::ConditionOperator::GreaterThan,
                3 => common::ConditionOperator::LessThan,
                4 => common::ConditionOperator::Contains,
                5 => common::ConditionOperator::NotContains,
                6 => common::ConditionOperator::RegexMatch,
                7 => common::ConditionOperator::In,
                8 => common::ConditionOperator::NotIn,
                _ => common::ConditionOperator::Equals,
            },
            value: condition
                .value
                .clone()
                .map(value_to_serde_json)
                .unwrap_or(serde_json::Value::Null),
        }
    }

    pub fn proto_to_audit_metrics(metrics: &audit::AuditMetrics) -> common::AuditMetrics {
        common::AuditMetrics {
            total_events: metrics.total_events,
            processed_events: metrics.processed_events,
            blocked_events: metrics.blocked_events,
            flagged_events: metrics.flagged_events,
            avg_processing_time_ms: metrics.avg_processing_time_ms,
            errors: metrics.errors,
        }
    }

    // Helper conversions
    fn timestamp_to_proto(dt: DateTime<Utc>) -> Timestamp {
        Timestamp {
            seconds: dt.timestamp(),
            nanos: dt.timestamp_subsec_nanos() as i32,
        }
    }

    fn proto_to_timestamp(ts: &Timestamp) -> DateTime<Utc> {
        DateTime::from_timestamp(ts.seconds, ts.nanos as u32).unwrap_or(Utc::now())
    }

    fn serde_json_to_struct(value: serde_json::Value) -> Struct {
        let mut fields = BTreeMap::new();

        if let serde_json::Value::Object(map) = value {
            for (key, val) in map {
                fields.insert(key, serde_json_to_value(val));
            }
        }

        Struct { fields }
    }

    fn struct_to_serde_json(struct_val: Struct) -> serde_json::Value {
        let mut map = serde_json::Map::new();

        for (key, val) in struct_val.fields {
            map.insert(key, value_to_serde_json(val));
        }

        serde_json::Value::Object(map)
    }

    fn serde_json_to_value(value: serde_json::Value) -> Value {
        use prost_types::value::Kind;

        let kind = match value {
            serde_json::Value::Null => Kind::NullValue(0),
            serde_json::Value::Bool(b) => Kind::BoolValue(b),
            serde_json::Value::Number(n) => {
                if n.is_i64() {
                    Kind::NumberValue(n.as_i64().unwrap() as f64)
                } else if n.is_u64() {
                    Kind::NumberValue(n.as_u64().unwrap() as f64)
                } else {
                    Kind::NumberValue(n.as_f64().unwrap())
                }
            }
            serde_json::Value::String(s) => Kind::StringValue(s),
            serde_json::Value::Array(arr) => Kind::ListValue(prost_types::ListValue {
                values: arr.into_iter().map(serde_json_to_value).collect(),
            }),
            serde_json::Value::Object(map) => {
                let mut fields = BTreeMap::new();
                for (key, val) in map {
                    fields.insert(key, serde_json_to_value(val));
                }
                Kind::StructValue(Struct { fields })
            }
        };

        Value { kind: Some(kind) }
    }

    fn value_to_serde_json(value: Value) -> serde_json::Value {
        use prost_types::value::Kind;

        match value.kind {
            Some(Kind::NullValue(_)) => serde_json::Value::Null,
            Some(Kind::NumberValue(n)) => serde_json::Value::Number(
                serde_json::Number::from_f64(n).unwrap_or(serde_json::Number::from(0)),
            ),
            Some(Kind::StringValue(s)) => serde_json::Value::String(s),
            Some(Kind::BoolValue(b)) => serde_json::Value::Bool(b),
            Some(Kind::StructValue(s)) => struct_to_serde_json(s),
            Some(Kind::ListValue(l)) => {
                serde_json::Value::Array(l.values.into_iter().map(value_to_serde_json).collect())
            }
            None => serde_json::Value::Null,
        }
    }
}
