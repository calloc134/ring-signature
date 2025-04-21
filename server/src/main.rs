use axum::{Extension, Router};
use shuttle_runtime::CustomError;
use sqlx::PgPool;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use tracing_subscriber::{filter::EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

mod db;
mod models;
mod routes;
mod utils;

// Shuttleでデプロイできるような実装に変更
#[shuttle_runtime::main]
async fn main(#[shuttle_shared_db::Postgres] pool: PgPool) -> shuttle_axum::ShuttleAxum {
    tracing_subscriber::registry()
        .with(EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    // マイグレーションを実行
    sqlx::migrate!()
        .run(&pool)
        .await
        .map_err(CustomError::new)?;

    let app = Router::new()
        .merge(routes::users::router())
        .merge(routes::signatures::router())
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
        .layer(Extension(pool));

    Ok(app.into())
}
