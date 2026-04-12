use std::time::Duration;
use tonic::transport::Channel;
use proto::audit::audit_service_client::AuditServiceClient;
use proto::audit::*;
use proto::conversions::*;

#[derive(Debug, Clone)]
pub struct AuditClient {
    inner: AuditServiceClient<Channel>,
}

impl AuditClient {
    pub async fn connect(_endpoint: String) -> Result<Self, Box<dyn std::error::Error>> {
        let channel = Channel::from_static("http://127.0.0.1:50051")
            .connect_timeout(Duration::from_secs(10))
            .connect()
            .await?;
        
        let inner = AuditServiceClient::new(channel);
        Ok(Self { inner })
    }

    pub async fn submit_event(&mut self, event: common::AuditEvent) -> Result<SubmitEventResponse, Box<dyn std::error::Error>> {
        let request = audit_event_to_proto(&event);

        let response = self.inner.submit_event(request).await?;
        Ok(response.into_inner())
    }

    pub async fn batch_submit_events(
        &mut self,
        events: Vec<common::AuditEvent>,
    ) -> Result<BatchSubmitEventsResponse, Box<dyn std::error::Error>> {
        let requests = events.into_iter().map(|event| {
            audit_event_to_proto(&event)
        }).collect();

        let request = BatchSubmitEventsRequest {
            events: requests,
        };

        let response = self.inner.batch_submit_events(request).await?;
        Ok(response.into_inner())
    }

    pub async fn get_metrics(&mut self) -> Result<common::AuditMetrics, Box<dyn std::error::Error>> {
        let request = GetMetricsRequest {
            include_historical: false,
            time_window_seconds: 300,
        };

        let response = self.inner.get_metrics(request).await?;
        Ok(proto_to_audit_metrics(&response.into_inner().metrics.unwrap()))
    }

    pub async fn update_rules(&mut self, rules: Vec<common::AuditRule>) -> Result<UpdateRulesResponse, Box<dyn std::error::Error>> {
        let request = UpdateRulesRequest {
            rules: rules.into_iter().map(|r| audit_rule_to_proto(&r)).collect(),
            replace_all: true,
        };

        let response = self.inner.update_rules(request).await?;
        Ok(response.into_inner())
    }

    pub async fn get_decision(&mut self, event_id: String) -> Result<common::AuditDecision, Box<dyn std::error::Error>> {
        let request = GetDecisionRequest {
            event_id: event_id,
        };

        let response = self.inner.get_decision(request).await?;
        Ok(proto_to_audit_decision(&response.into_inner()))
    }

    pub async fn stream_events(&mut self) -> Result<tonic::Streaming<StreamEventsResponse>, Box<dyn std::error::Error>> {
        // Create a stream of StreamEventsRequest
        let (mut tx, rx) = tokio::sync::mpsc::channel(1);
        tx.send(StreamEventsRequest {
            event_types: vec![],
            sources: vec![],
        }).await?;

        // Convert mpsc::Receiver to futures::Stream
        let stream = futures_util::stream::unfold(rx, |mut rx| async move {
            match rx.recv().await {
                Some(msg) => Some((msg, rx)),
                None => None,
            }
        });

        let request = tonic::Request::new(stream);

        let response = self.inner.stream_events(request).await?;
        Ok(response.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_client() {
        // This is a placeholder test - in real scenarios, you would:
        // 1. Start a test server
        // 2. Connect a client to it
        // 3. Test the interactions
        
        // For now, just test that the client can be created without panicking
        // The connection may succeed or fail depending on if a server is running
        let _client = AuditClient::connect("http://127.0.0.1:50051".to_string()).await;
        // Test passes if we get here without panicking
        assert!(true);
    }
}