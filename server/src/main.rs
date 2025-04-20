use axum::{Extension, Router};
use sqlx::PgPool;
use std::net::SocketAddr;
use tower_http::trace::TraceLayer;
use tracing_subscriber::{filter::EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

mod db;
mod models;
mod routes;
mod utils;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Read database URL
    let database_url = std::env::var("DATABASE_URL")?;
    // Create connection pool
    let pool = PgPool::connect(&database_url).await?;
    // Run migrations
    sqlx::migrate!().run(&pool).await?;

    // Build application
    let app = Router::new()
        .merge(routes::users::router())
        .merge(routes::signatures::router())
        .layer(TraceLayer::new_for_http())
        .layer(Extension(pool));

    // Start server
    let addr = SocketAddr::from(([0, 0, 0, 0], 8080));
    tracing::info!("listening on {}", addr);
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await?;

    Ok(())
}
