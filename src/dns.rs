// src/dns.rs
use crate::engine::{process_dns_wire, AppState};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::Semaphore;
use tokio::time::timeout;

const IO_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_DNS_MSG_SIZE: usize = 4096;

pub async fn run_udp_listener(
    socket: Arc<UdpSocket>,
    state: AppState,
    concurrency_limit: Arc<Semaphore>,
) {
    let mut buf = vec![0u8; 4096];
    loop {
        match socket.recv_from(&mut buf).await {
            Ok((len, peer)) => {
                let req_wire = buf[..len].to_vec();
                let socket_ref = socket.clone();
                let state_ref = state.clone();

                if let Ok(permit) = concurrency_limit.clone().try_acquire_owned() {
                    tokio::spawn(async move {
                        let _permit = permit;
                        let resp = process_dns_wire(&req_wire, &state_ref, "UDP", peer.ip()).await;
                        if !resp.is_empty() {
                            let _ = socket_ref.send_to(&resp, peer).await;
                        }
                    });
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "[UDP] Error receiving packet");
            }
        }
    }
}

pub async fn run_tcp_listener(
    listener: TcpListener,
    state: AppState,
    concurrency_limit: Arc<Semaphore>,
) {
    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                let _ = stream.set_nodelay(true);
                let state_ref = state.clone();

                if let Ok(permit) = concurrency_limit.clone().try_acquire_owned() {
                    tokio::spawn(async move {
                        let _permit = permit;
                        handle_length_prefixed_stream(stream, state_ref, "TCP", peer.ip()).await;
                    });
                }
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
    loop {
        let read_len = timeout(IO_TIMEOUT, stream.read_exact(&mut len_buf)).await;
        if read_len.is_err() || read_len.unwrap().is_err() {
            break;
        }

        let req_len = u16::from_be_bytes(len_buf) as usize;
        if req_len == 0 || req_len > MAX_DNS_MSG_SIZE {
            break;
        }

        let mut req_buf = vec![0u8; req_len];
        if timeout(IO_TIMEOUT, stream.read_exact(&mut req_buf)).await.is_err() {
            break;
        }

        let resp_wire = process_dns_wire(&req_buf, &state, protocol, client_ip).await;
        if resp_wire.is_empty() {
            break;
        }

        let mut out = Vec::with_capacity(2 + resp_wire.len());
        out.extend_from_slice(&(resp_wire.len() as u16).to_be_bytes());
        out.extend_from_slice(&resp_wire);

        if timeout(IO_TIMEOUT, stream.write_all(&out)).await.is_err()
            || timeout(IO_TIMEOUT, stream.flush()).await.is_err()
        {
            break;
        }
    }
}
