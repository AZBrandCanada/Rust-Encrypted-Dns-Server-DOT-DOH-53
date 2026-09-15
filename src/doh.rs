use crate::engine::{process_dns_query, AppState, ProcessOutcome};
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

/// RFC 8484 §4.1.1: DoH query using HTTP GET.
/// The DNS query is base64url encoded in the `dns` query parameter.
async fn handle_doh_get(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(params): Query<DohQuery>,
) -> Response {
    let encoded = match params.dns {
        Some(ref d) if !d.trim().is_empty() => d.trim(),
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                "Missing or empty 'dns' query parameter",
            )
                .into_response()
        }
    };

    let raw_bytes = match decode_dns_param(encoded) {
        Ok(b) if !b.is_empty() => b,
        Ok(_) => return (StatusCode::BAD_REQUEST, "Empty DNS query payload").into_response(),
        Err(_) => return (StatusCode::BAD_REQUEST, "Invalid base64url encoding").into_response(),
    };

    if raw_bytes.len() > MAX_DOH_PAYLOAD {
        return (StatusCode::PAYLOAD_TOO_LARGE, "DNS query exceeds size limit").into_response();
    }

    let client_ip = extract_client_ip(&headers, &peer);
    let outcome = process_dns_query(&raw_bytes, &state, "DoH", client_ip).await;
    handle_dns_outcome(outcome)
}

/// RFC 8484 §4.1.5: DoH query using HTTP POST.
/// The DNS query is contained in binary wire format in the HTTP body,
/// and the Content-Type header MUST be 'application/dns-message'.
async fn handle_doh_post(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if body.is_empty() {
        return (StatusCode::BAD_REQUEST, "Empty request body").into_response();
    }

    if body.len() > MAX_DOH_PAYLOAD {
        return (StatusCode::PAYLOAD_TOO_LARGE, "DNS query exceeds size limit").into_response();
    }

    // RFC 8484 §4.1: POST requires Content-Type: application/dns-message
    match headers.get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok()) {
        Some(ct) if ct.starts_with("application/dns-message") => {}
        _ => {
            return (
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "Content-Type must be application/dns-message",
            )
                .into_response()
        }
    }

    let client_ip = extract_client_ip(&headers, &peer);
    let outcome = process_dns_query(&body, &state, "DoH", client_ip).await;
    handle_dns_outcome(outcome)
}

/// Maps internal DNS engine outcomes to strict RFC 8484 HTTP responses.
fn handle_dns_outcome(outcome: ProcessOutcome) -> Response {
    match outcome {
        // RFC 8484 §4.2.1: Valid DNS messages (including SERVFAIL and truncated challenges)
        // are returned as HTTP 200 OK with Content-Type: application/dns-message.
        ProcessOutcome::Success(wire)
        | ProcessOutcome::ServFail(wire)
        | ProcessOutcome::Truncated(wire) => make_dns_response(wire),

        // Malformed or invalid DNS wire input returns HTTP 400 Bad Request.
        ProcessOutcome::Malformed => {
            (StatusCode::BAD_REQUEST, "Malformed or invalid DNS message").into_response()
        }

        // Rate-limited queries return HTTP 429 Too Many Requests.
        ProcessOutcome::Dropped => {
            (StatusCode::TOO_MANY_REQUESTS, "Rate limit exceeded").into_response()
        }
    }
}

async fn handle_health(State(state): State<AppState>) -> impl IntoResponse {
    let payload = serde_json::json!({
        "status": "healthy",
        "cached_records": state.cache.len(),
    });
    (StatusCode::OK, [(header::CONTENT_TYPE, "application/json")], payload.to_string())
}

/// Resolves the originating client IP.
/// Reverse proxy headers are only trusted if the connection originates from loopback (e.g. Nginx).
fn extract_client_ip(headers: &HeaderMap, peer: &SocketAddr) -> IpAddr {
    if peer.ip().is_loopback() {
        if let Some(cf_ip) = headers.get("cf-connecting-ip").and_then(|v| v.to_str().ok()) {
            if let Ok(ip) = cf_ip.trim().parse::<IpAddr>() {
                return ip;
            }
        }

        if let Some(real_ip) = headers.get("x-real-ip").and_then(|v| v.to_str().ok()) {
            if let Ok(ip) = real_ip.trim().parse::<IpAddr>() {
                return ip;
            }
        }

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

/// Decodes base64url encoded DNS query parameter (RFC 4648 §5).
/// Accepts unpadded (RFC 8484 compliant) and padded base64url inputs.
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
    headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*".parse().unwrap());
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_METHODS,
        "GET, POST, OPTIONS".parse().unwrap(),
    );
    (StatusCode::OK, headers, bytes).into_response()
}