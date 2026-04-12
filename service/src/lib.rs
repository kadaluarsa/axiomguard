pub mod auth;
pub mod config;
pub mod shield_service;

pub use shield_service::run_shield_server;

use std::net::SocketAddr;
use warp::Filter;
use prometheus::Encoder;

/// Run Prometheus metrics server
pub fn run_metrics_server(addr: SocketAddr) {
    tokio::spawn(async move {
        tracing::info!(address = %addr, "Starting Prometheus metrics server");
        
        let metrics_router = warp::path!("metrics")
            .and(warp::get())
            .map(|| {
                let encoder = prometheus::TextEncoder::new();
                let metric_families = common::metrics::REGISTRY.gather();
                let mut buf = String::new();
                if let Err(e) = encoder.encode_utf8(&metric_families, &mut buf) {
                    tracing::error!(error = %e, "Failed to encode metrics");
                    return Box::new(warp::reply::with_status(
                        format!("Failed to encode metrics: {}", e),
                        warp::http::StatusCode::INTERNAL_SERVER_ERROR,
                    )) as Box<dyn warp::Reply>;
                }
                
                Box::new(warp::reply::with_header(
                    buf,
                    "Content-Type",
                    "text/plain; version=0.0.4",
                )) as Box<dyn warp::Reply>
            });
        
        let _ = warp::serve(metrics_router).run(addr).await;
    });
}

/// TLS configuration
pub mod tls {
    use std::fs;

    #[derive(Debug, Clone)]
    pub struct TlsConfig {
        pub cert_pem: Vec<u8>,
        pub key_pem: Vec<u8>,
        pub ca_cert_pem: Option<Vec<u8>>,
    }

    impl TlsConfig {
        pub fn from_files(cert_path: &str, key_path: &str, ca_cert_path: Option<&str>) -> Result<Self, Box<dyn std::error::Error>> {
            let cert_pem = fs::read(cert_path)?;
            let key_pem = fs::read(key_path)?;
            
            let ca_cert_pem = match ca_cert_path {
                Some(path) => Some(fs::read(path)?),
                None => None,
            };

            Ok(Self {
                cert_pem,
                key_pem,
                ca_cert_pem,
            })
        }
    }
}
