use clap::Parser;
use service::run_shield_server;
use tracing::Level;
use tracing_subscriber::fmt;

#[derive(Parser)]
#[command(name = "axiomguard-shield")]
#[command(about = "AxiomGuard Shield - Real-time security classification service")]
struct Cli {
    /// Server address
    #[arg(long, default_value = "0.0.0.0:50051")]
    address: String,

    /// Metrics server address
    #[arg(long, default_value = "0.0.0.0:9090")]
    metrics_address: String,

    /// Log level (trace, debug, info, warn, error)
    #[arg(long, default_value = "info")]
    log_level: String,

    /// Configuration file path
    #[arg(long, default_value = "config.toml")]
    config: String,

    /// Precache embedding model and exit
    #[arg(long)]
    precache: bool,
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

        if cli.precache {
            tracing::info!("Precaching embedding model...");
            let _ = engine::init_text_embedding().await;
            tracing::info!("Precache complete.");
            return Ok(());
        }

        // Load configuration
        let config = match service::config::ServerConfig::from_file(&cli.config) {
            Ok(config) => {
                tracing::info!("Loaded configuration from {}", cli.config);
                config
            }
            Err(e) => {
                tracing::warn!(error = %e, "Failed to load config file, using default configuration");
                service::config::ServerConfig::default()
            }
        };

        // Start the shield service
        run_shield_server(&config).await?;

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
