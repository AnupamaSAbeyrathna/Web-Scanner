mod model;
mod scanner;

use tower_http::cors::CorsLayer;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use model::{ScanJob, ScanStatus};
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

type Db = Arc<Mutex<HashMap<String, ScanJob>>>;

#[derive(Deserialize)]
struct StartScanRequest {
    target: String,
}

#[tokio::main]
async fn main() {
    let db: Db = Arc::new(Mutex::new(HashMap::new()));

    let cors = CorsLayer::new()
        .allow_origin(tower_http::cors::Any)
        .allow_methods([axum::http::Method::GET, axum::http::Method::POST])
        .allow_headers(tower_http::cors::Any);

    let app = Router::new()
        .route("/scan/start", post(start_scan))
        .route("/scan/:id", get(get_scan))
        .layer(cors)
        .with_state(db);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    println!("Coordinator listening on {}", listener.local_addr().unwrap());
    axum::serve(listener, app).await.unwrap();
}

async fn start_scan(State(db): State<Db>, Json(payload): Json<StartScanRequest>) -> impl IntoResponse {
    let id = Uuid::new_v4().to_string();
    
    let job = ScanJob {
        id: id.clone(),
        target: payload.target.clone(),
        status: ScanStatus::Running,
        findings: vec![],
    };

    {
        let mut lock = db.lock().unwrap();
        lock.insert(id.clone(), job);
    }

    // Spawn scanner in background
    let db_clone = db.clone();
    let scan_id = id.clone();
    let target = payload.target.clone();
    tokio::spawn(async move {
        scanner::run_scan(scan_id, target, db_clone).await;
    });

    (StatusCode::ACCEPTED, Json(serde_json::json!({ "id": id, "status": "Running" })))
}

async fn get_scan(State(db): State<Db>, Path(id): Path<String>) -> impl IntoResponse {
    let lock = db.lock().unwrap();
    if let Some(job) = lock.get(&id) {
        (StatusCode::OK, Json(job.clone())).into_response()
    } else {
        (StatusCode::NOT_FOUND, Json(serde_json::json!({ "error": "Not Found" }))).into_response()
    }
}
