use std::net::SocketAddr;
use warp::Filter;
use prometheus::Encoder;
use common::metrics::REGISTRY;

pub async fn start_metrics_server(addr: SocketAddr) {
    let metrics_route = warp::path!("metrics")
        .and_then(handle_metrics);

    tracing::info!("Starting metrics server on {}", addr);
    warp::serve(metrics_route).run(addr).await;
}

async fn handle_metrics() -> Result<impl warp::Reply, warp::Rejection> {
    let encoder = prometheus::TextEncoder::new();
    let mut buffer = Vec::new();

    match encoder.encode(&REGISTRY.gather(), &mut buffer) {
        Ok(_) => Ok(warp::reply::with_header(
            buffer,
            "Content-Type",
            encoder.format_type(),
        )),
        Err(e) => {
            tracing::error!("Failed to encode metrics: {}", e);
            Ok(warp::reply::with_header(
                Vec::new(),
                "Content-Type",
                encoder.format_type(),
            ))
        }
    }
}
