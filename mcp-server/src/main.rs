use clap::Parser;
use rmcp::ServiceExt;
use tracing::{info, warn};

mod config;
mod metrics;
mod prompts;
mod server;
mod tools;

use config::{McpConfig, TransportType};
use server::AxiomGuardMcpServer;

#[derive(Parser)]
#[command(name = "axiomguard-mcp")]
#[command(about = "AxiomGuard MCP Server - Model Context Protocol edge service")]
struct Cli {
    /// Transport type: stdio or sse
    #[arg(long, value_enum, default_value = "stdio")]
    transport: TransportType,

    /// Bind address for SSE transport
    #[arg(long, default_value = "0.0.0.0:8081")]
    bind_address: String,

    /// Configuration file path
    #[arg(long, default_value = "config.toml")]
    config: String,

    /// Shield gRPC endpoint
    #[arg(long)]
    shield_endpoint: Option<String>,

    /// Log level
    #[arg(long, default_value = "info")]
    log_level: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    // Initialize logging
    let level = match cli.log_level.as_str() {
        "trace" => tracing::Level::TRACE,
        "debug" => tracing::Level::DEBUG,
        "info" => tracing::Level::INFO,
        "warn" => tracing::Level::WARN,
        "error" => tracing::Level::ERROR,
        _ => tracing::Level::INFO,
    };
    tracing_subscriber::fmt().with_max_level(level).init();

    // Initialize telemetry
    common::telemetry::init_tracer("axiomguard-mcp");

    // Load configuration
    let mut config = match McpConfig::from_file(&cli.config) {
        Ok(cfg) => {
            info!("Loaded configuration from {}", cli.config);
            cfg
        }
        Err(e) => {
            warn!(error = %e, "Failed to load config file, using environment defaults");
            McpConfig::from_env()
        }
    };

    // CLI overrides
    config.transport = cli.transport;
    config.bind_address = cli.bind_address;
    if let Some(endpoint) = cli.shield_endpoint {
        config.shield_endpoint = endpoint;
    }

    info!(
        transport = %config.transport,
        shield_endpoint = %config.shield_endpoint,
        "Starting AxiomGuard MCP Server"
    );

    match config.transport {
        TransportType::Stdio => run_stdio(config).await,
        TransportType::Sse => run_sse(config).await,
    }
}

async fn run_stdio(config: McpConfig) -> Result<(), Box<dyn std::error::Error>> {
    let server = AxiomGuardMcpServer::new(config).await?;
    let router = server.router();

    let transport = rmcp::transport::stdio();
    let service = router.serve(transport).await?;
    let quit_reason = service.waiting().await;
    info!(?quit_reason, "MCP stdio service ended");
    Ok(())
}

async fn run_sse(config: McpConfig) -> Result<(), Box<dyn std::error::Error>> {
    use rmcp::transport::{
        StreamableHttpServerConfig,
        streamable_http_server::{
            session::local::LocalSessionManager,
            tower::StreamableHttpService,
        },
    };
    use tokio_util::sync::CancellationToken;

    let bind_address = config.bind_address.clone();
    let server = AxiomGuardMcpServer::new(config).await?;

    let ct = CancellationToken::new();
    let service: StreamableHttpService<
        rmcp::handler::server::router::Router<AxiomGuardMcpServer>,
        LocalSessionManager,
    > = StreamableHttpService::new(
        move || Ok(server.clone().router()),
        Default::default(),
        StreamableHttpServerConfig::default()
            .with_cancellation_token(ct.child_token()),
    );

    let app = axum::Router::new()
        .nest_service("/mcp", service)
        .route("/health", axum::routing::get(health_handler))
        .route("/metrics", axum::routing::get(metrics_handler));

    let listener = tokio::net::TcpListener::bind(&bind_address).await?;
    info!(bind_address = %bind_address, "MCP SSE server listening");

    axum::serve(listener, app)
        .with_graceful_shutdown(async move { ct.cancelled_owned().await })
        .await?;

    Ok(())
}

async fn health_handler() -> impl axum::response::IntoResponse {
    axum::Json(serde_json::json!({
        "status": "healthy",
        "service": "axiomguard-mcp",
    }))
}

async fn metrics_handler() -> impl axum::response::IntoResponse {
    let encoder = prometheus::TextEncoder::new();
    let metric_families = common::metrics::REGISTRY.gather();
    let mut buf = String::new();
    if let Err(e) = encoder.encode_utf8(&metric_families, &mut buf) {
        return (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            [(axum::http::header::CONTENT_TYPE, "text/plain")],
            format!("Failed to encode metrics: {}", e),
        );
    }
    (
        axum::http::StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        buf,
    )
}
