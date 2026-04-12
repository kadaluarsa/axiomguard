use clap::Parser;
use client::AuditClient;
use common::*;
use chrono::Utc;
use uuid::Uuid;
use tracing::Level;
use tracing_subscriber::fmt;
use futures_util::stream::StreamExt;

#[derive(Parser)]
#[command(name = "axiomguard-cli")]
#[command(about = "CLI client for AxiomGuard audit service")]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Server address
    #[arg(long, default_value = "http://127.0.0.1:50051")]
    server: String,

    /// Log level (trace, debug, info, warn, error)
    #[arg(long, default_value = "info")]
    log_level: String,
}

#[derive(clap::Subcommand)]
enum Commands {
    /// Submit an audit event
    Submit {
        /// Event source
        #[arg(long)]
        source: String,
        
        /// Event type
        #[arg(long)]
        event_type: String,
        
        /// Event data (JSON string)
        #[arg(long)]
        data: String,
    },

    /// Get metrics
    Metrics,

    /// Update audit rules
    UpdateRules {
        /// Rules file path
        #[arg(long)]
        rules_file: String,
    },

    /// Run benchmark
    Benchmark {
        /// Number of events to send
        #[arg(long, default_value = "1000")]
        count: usize,
    },

    /// Get decision for an event
    GetDecision {
        /// Event ID
        #[arg(long)]
        event_id: String,
    },

    /// Stream events and decisions
    StreamEvents,
}

async fn run_command(cli: &Cli, client: &mut AuditClient) -> Result<(), Box<dyn std::error::Error>> {
    match &cli.command {
        Commands::Submit { source, event_type, data } => {
            let parsed_data: serde_json::Value = serde_json::from_str(data)?;
            
            let event = AuditEvent {
                id: Uuid::new_v4(),
                timestamp: Utc::now(),
                source: source.clone(),
                event_type: event_type.clone(),
                data: parsed_data,
            };

            let response = client.submit_event(event).await?;
            println!("Event submitted successfully");
            println!("Event ID: {}", response.event_id);
            println!("Accepted: {}", response.accepted);
            println!("Message: {}", response.message);
        }

        Commands::Metrics => {
            let metrics = client.get_metrics().await?;
            println!("=== Audit Service Metrics ===");
            println!("Total Events: {}", metrics.total_events);
            println!("Processed Events: {}", metrics.processed_events);
            println!("Blocked Events: {}", metrics.blocked_events);
            println!("Flagged Events: {}", metrics.flagged_events);
            println!("Average Processing Time: {:.2}ms", metrics.avg_processing_time_ms);
            println!("Errors: {}", metrics.errors);
        }

        Commands::UpdateRules { rules_file } => {
            let rules_content = std::fs::read_to_string(rules_file)?;
            let rules: Vec<AuditRule> = serde_json::from_str(&rules_content)?;
            
            let response = client.update_rules(rules).await?;
            println!("Rules updated successfully");
            println!("Updated Rules: {}", response.updated_rules);
            println!("Total Rules: {}", response.total_rules);
            println!("Message: {}", response.message);
        }

        Commands::GetDecision { event_id } => {
            let decision = client.get_decision(event_id.clone()).await?;
            println!("=== Audit Decision ===");
            println!("Event ID: {}", decision.event_id);
            println!("Decision: {:?}", decision.decision);
            println!("Confidence: {:.2}", decision.confidence);
            println!("Rules Matched: {}", decision.rules_matched.join(", "));
            println!("Processing Time: {}ms", decision.processing_time_ms);
            println!("Timestamp: {}", decision.timestamp);
        }

        Commands::StreamEvents => {
            println!("Streaming events and decisions from audit service...");
            println!("Press Ctrl+C to stop streaming");

            let mut stream = client.stream_events().await?;
            
            while let Some(response) = stream.next().await {
                match response {
                    Ok(msg) => {
                        println!("=== Received Message ===");
                        println!("Type: {:?}", msg.payload);
                        println!("");
                    }
                    Err(e) => {
                        println!("Error streaming events: {}", e);
                        break;
                    }
                }
            }
        }

        Commands::Benchmark { count } => {
            let start_time = std::time::Instant::now();
            
            println!("Sending {} events to audit service...", count);
            
            let mut events = Vec::with_capacity(*count);
            for i in 0..*count {
                let event = AuditEvent {
                    id: Uuid::new_v4(),
                    timestamp: Utc::now(),
                    source: "benchmark".to_string(),
                    event_type: "performance_test".to_string(),
                    data: serde_json::json!({
                        "test_id": i,
                        "test": i as f64,
                        "timestamp": Utc::now().to_rfc3339(),
                        "metadata": {
                            "user_id": format!("user_{}", i % 100),
                            "region": match i % 3 {
                        0 => "us-east-1",
                        1 => "eu-west-1",
                        2 => "ap-southeast-1",
                        _ => "us-east-1",
                    },
                            "priority": i % 5
                        }
                    }),
                };
                
                events.push(event);
            }
            
            let response = client.batch_submit_events(events).await?;
            let duration = start_time.elapsed().as_secs_f64();
            
            println!("=== Benchmark Results ===");
            println!("Total Events Sent: {}", response.total_events);
            println!("Accepted Events: {}", response.accepted_events);
            println!("Failed Events: {}", response.failed_events);
            println!("Time Taken: {:.2} seconds", duration);
            println!("Throughput: {:.2} events/second", response.accepted_events as f64 / duration);
        }
    }

    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        let cli = Cli::parse();

    // Initialize logging
    let level = match cli.log_level.as_str() {
        "trace" => Level::TRACE,
        "debug" => Level::DEBUG,
        "info" => Level::INFO,
        "warn" => Level::WARN,
        "error" => Level::ERROR,
        _ => Level::INFO,
    };

    fmt()
        .with_max_level(level)
        .init();

    // Connect to the audit service
    println!("Connecting to audit service at: {}", cli.server);
    let mut client = AuditClient::connect(cli.server.clone()).await?;

    // Run the command
        run_command(&cli, &mut client).await?;

        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_cli() {
        use clap::CommandFactory;
        Cli::command().debug_assert()
    }
}