use axum::{http::StatusCode, routing::get, Json, Router};
use serde_json::{json, Value};
use std::{collections::BTreeMap, env, fs, process::Command};
use tokio_postgres::NoTls;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Exercise the original application thread before Tokio creates workers.
    // Worker/descendant events alone must not make the capture gate pass.
    fs::write("/data/startup-marker.txt", "fixture-startup-marker\n")?;
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(serve())
}

async fn serve() -> Result<(), Box<dyn std::error::Error>> {
    let router = Router::new()
        .route("/health", get(|| async { Json(json!({"ok": true})) }))
        .route("/identity", get(identity))
        .route("/exercise", get(exercise));
    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await?;
    println!("fixture-listening pid={}", std::process::id());
    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown())
        .await?;
    println!("fixture-shutdown-complete");
    Ok(())
}

async fn identity() -> Result<Json<Value>, (StatusCode, String)> {
    let status = fs::read_to_string("/proc/self/status").map_err(internal_error)?;
    let fields: BTreeMap<&str, &str> = status
        .lines()
        .filter_map(|line| line.split_once(':').map(|(key, value)| (key, value.trim())))
        .collect();
    Ok(Json(json!({"pid": std::process::id(), "status": fields})))
}

async fn exercise() -> Result<Json<Value>, (StatusCode, String)> {
    let connection_string = env::var("DATABASE_URL").map_err(internal_error)?;
    let (client, connection) = tokio_postgres::connect(&connection_string, NoTls)
        .await
        .map_err(internal_error)?;
    tokio::spawn(async move {
        if let Err(error) = connection.await {
            eprintln!("fixture database connection: {error}");
        }
    });
    let row = client
        .query_one("SELECT $1::TEXT, 42::INTEGER", &[&"ebpf-alpha-fixture"])
        .await
        .map_err(internal_error)?;
    let database_marker: String = row.get(0);
    let answer: i32 = row.get(1);
    fs::write("/data/route-marker.txt", "fixture-route-marker\n").map_err(internal_error)?;
    let child_status = Command::new("/bin/sh")
        .args([
            "-c",
            "printf 'fixture-descendant-marker\\n' > /data/descendant-marker.txt",
        ])
        .status()
        .map_err(internal_error)?;
    if !child_status.success() {
        return Err(internal_error("fixture descendant failed"));
    }
    println!("fixture-stdout-marker");
    eprintln!("fixture-stderr-marker");
    Ok(Json(
        json!({"database_marker": database_marker, "answer": answer, "file_written": true, "descendant_finished": true}),
    ))
}

async fn shutdown() {
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("install fixture SIGTERM handler");
    terminate.recv().await;
    fs::write("/data/shutdown-marker.txt", "fixture-graceful-shutdown\n")
        .expect("retain graceful-shutdown marker");
}

fn internal_error(error: impl std::fmt::Display) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, error.to_string())
}
