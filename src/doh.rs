// src/doh.rs
use crate::engine::{process_dns_wire, AppState};
use axum::{
    body::Bytes,
    extract::{ConnectInfo, DefaultBodyLimit, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use base64::prelude::*;
use serde::Deserialize;
use std::net::{IpAddr, SocketAddr};

const MAX_DOH_PAYLOAD: usize = 4096;

#[derive(Deserialize)]
pub struct DohQuery {
    pub dns: Option<String>,
}

pub fn build_doh_router(state: AppState) -> Router {
    Router::new()
        .route(
            "/dns-query",
            get(handle_doh_get)
                .post(handle_doh_post)
                .options(handle_doh_options),
        )
        .route("/health", get(handle_health))
        .layer(DefaultBodyLimit::max(MAX_DOH_PAYLOAD))
        .with_state(state)
}

async fn handle_doh_options() -> Response {
    let mut headers = HeaderMap::new();
    headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*".parse().unwrap());
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_METHODS,
        "GET, POST, OPTIONS".parse().unwrap(),
    );
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_HEADERS,
        "content-type, accept".parse().unwrap(),
    );
    (StatusCode::OK, headers, ()).into_response()
}

async fn handle_doh_get(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(params): Query<DohQuery>,
) -> Response {
    let encoded = match params.dns {
        Some(d) => d,
        None => return (StatusCode::BAD_REQUEST, "Missing dns parameter").into_response(),
    };

    let raw_bytes = match decode_dns_param(&encoded) {
        Ok(b) => b,
        Err(_) => return (StatusCode::BAD_REQUEST, "Invalid base64url encoding").into_response(),
    };

    if raw_bytes.len() > MAX_DOH_PAYLOAD {
        return (StatusCode::PAYLOAD_TOO_LARGE, "Payload exceeds size limit").into_response();
    }

    let client_ip = extract_client_ip(&headers, &peer);
    let resp_wire = process_dns_wire(&raw_bytes, &state, "DoH", client_ip).await;
    make_dns_response(resp_wire)
}

async fn handle_doh_post(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if body.is_empty() {
        return (StatusCode::BAD_REQUEST, "Empty body").into_response();
    }

    if let Some(content_type) = headers.get(header::CONTENT_TYPE) {
        if let Ok(ct) = content_type.to_str() {
            if !ct.starts_with("application/dns-message") {
                return (StatusCode::UNSUPPORTED_MEDIA_TYPE, "Unsupported media type").into_response();
            }
        }
    }

    let client_ip = extract_client_ip(&headers, &peer);
    let resp_wire = process_dns_wire(&body, &state, "DoH", client_ip).await;
    make_dns_response(resp_wire)
}

async fn handle_health(State(state): State<AppState>) -> impl IntoResponse {
    let payload = serde_json::json!({
        "status": "healthy",
        "cached_records": state.cache.len(),
    });
    (StatusCode::OK, [(header::CONTENT_TYPE, "application/json")], payload.to_string())
}

/// Resolves the originating client IP.
/// Reverse proxy headers are only trusted if the connection originates from loopback (Nginx).
fn extract_client_ip(headers: &HeaderMap, peer: &SocketAddr) -> IpAddr {
    if peer.ip().is_loopback() {
        // 1. Cloudflare header
        if let Some(cf_ip) = headers.get("cf-connecting-ip").and_then(|v| v.to_str().ok()) {
            if let Ok(ip) = cf_ip.trim().parse::<IpAddr>() {
                return ip;
            }
        }

        // 2. Nginx X-Real-IP
        if let Some(real_ip) = headers.get("x-real-ip").and_then(|v| v.to_str().ok()) {
            if let Ok(ip) = real_ip.trim().parse::<IpAddr>() {
                return ip;
            }
        }

        // 3. X-Forwarded-For (client IP is leftmost entry)
        if let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
            if let Some(first) = xff.split(',').next() {
                if let Ok(ip) = first.trim().parse::<IpAddr>() {
                    return ip;
                }
            }
        }
    }

    peer.ip()
}

fn decode_dns_param(input: &str) -> Result<Vec<u8>, base64::DecodeError> {
    let s = input.trim().replace('-', "+").replace('_', "/");
    let pad_len = (4 - (s.len() % 4)) % 4;
    let padded = format!("{}{}", s, "=".repeat(pad_len));
    BASE64_STANDARD.decode(padded)
}

fn make_dns_response(bytes: Vec<u8>) -> Response {
    if bytes.is_empty() {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, "application/dns-message".parse().unwrap());
    headers.insert(header::CACHE_CONTROL, "no-cache".parse().unwrap());
    headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*".parse().unwrap());
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_METHODS,
        "GET, POST, OPTIONS".parse().unwrap(),
    );
    (StatusCode::OK, headers, bytes).into_response()
}
