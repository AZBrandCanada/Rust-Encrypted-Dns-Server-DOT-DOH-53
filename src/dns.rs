// src/dns.rs
use crate::engine::{process_dns_wire, AppState};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

pub async fn run_udp_listener(socket: Arc<UdpSocket>, state: AppState) {
    let mut buf = vec![0u8; 4096];
    loop {
        match socket.recv_from(&mut buf).await {
            Ok((len, peer)) => {
                let req_wire = buf[..len].to_vec();
                let socket_ref = socket.clone();
                let state_ref = state.clone();

                tokio::spawn(async move {
                    let resp = process_dns_wire(&req_wire, &state_ref, "UDP", peer.ip()).await;
                    if !resp.is_empty() {
                        let _ = socket_ref.send_to(&resp, peer).await;
                    }
                });
            }
            Err(e) => {
                tracing::warn!(error = %e, "[UDP] Error receiving packet");
            }
        }
    }
}

pub async fn run_tcp_listener(listener: TcpListener, state: AppState) {
    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                let _ = stream.set_nodelay(true);
                let state_ref = state.clone();
                tokio::spawn(async move {
                    handle_length_prefixed_stream(stream, state_ref, "TCP", peer.ip()).await;
                });
            }
            Err(e) => {
                tracing::warn!(error = %e, "[TCP] Error accepting connection");
            }
        }
    }
}

pub async fn handle_length_prefixed_stream<S>(
    mut stream: S,
    state: AppState,
    protocol: &'static str,
    client_ip: std::net::IpAddr,
) where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut len_buf = [0u8; 2];
    while stream.read_exact(&mut len_buf).await.is_ok() {
        let req_len = u16::from_be_bytes(len_buf) as usize;
        let mut req_buf = vec![0u8; req_len];
        if stream.read_exact(&mut req_buf).await.is_err() {
            break;
        }

        let resp_wire = process_dns_wire(&req_buf, &state, protocol, client_ip).await;
        if resp_wire.is_empty() {
            break;
        }

        let mut out = Vec::with_capacity(2 + resp_wire.len());
        out.extend_from_slice(&(resp_wire.len() as u16).to_be_bytes());
        out.extend_from_slice(&resp_wire);

        if stream.write_all(&out).await.is_err() || stream.flush().await.is_err() {
            break;
        }
    }
}
