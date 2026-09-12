// src/doh.rs
use crate::engine::{process_dns_wire, AppState};
use axum::{
    body::Bytes,
    extract::{Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use base64::prelude::*;
use serde::Deserialize;

#[derive(Deserialize)]
pub struct DohQuery {
    pub dns: Option<String>,
}

pub fn build_doh_router(state: AppState) -> Router {
    Router::new()
        .route("/dns-query", get(handle_doh_get).post(handle_doh_post))
        .route("/health", get(handle_health))
        .with_state(state)
}

async fn handle_doh_get(State(state): State<AppState>, Query(params): Query<DohQuery>) -> Response {
    let encoded = match params.dns {
        Some(d) => d,
        None => return (StatusCode::BAD_REQUEST, "Missing dns parameter").into_response(),
    };

    let raw_bytes = match decode_dns_param(&encoded) {
        Ok(b) => b,
        Err(_) => return (StatusCode::BAD_REQUEST, "Invalid base64url encoding").into_response(),
    };

    let resp_wire = process_dns_wire(&raw_bytes, &state, "DoH").await;
    make_dns_response(resp_wire)
}

async fn handle_doh_post(State(state): State<AppState>, body: Bytes) -> Response {
    if body.is_empty() {
        return (StatusCode::BAD_REQUEST, "Empty body").into_response();
    }
    let resp_wire = process_dns_wire(&body, &state, "DoH").await;
    make_dns_response(resp_wire)
}

async fn handle_health(State(state): State<AppState>) -> impl IntoResponse {
    let payload = serde_json::json!({
        "status": "healthy",
        "cached_records": state.cache.len(),
    });
    (StatusCode::OK, [(header::CONTENT_TYPE, "application/json")], payload.to_string())
}

fn decode_dns_param(input: &str) -> Result<Vec<u8>, base64::DecodeError> {
    let s = input.trim().replace('-', "+").replace('_', "/");
    let pad_len = (4 - (s.len() % 4)) % 4;
    let padded = format!("{}{}", s, "=".repeat(pad_len));
    BASE64_STANDARD.decode(padded)
}

fn make_dns_response(bytes: Vec<u8>) -> Response {
    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, "application/dns-message".parse().unwrap());
    headers.insert(header::CACHE_CONTROL, "no-cache".parse().unwrap());
    (StatusCode::OK, headers, bytes).into_response()
}
