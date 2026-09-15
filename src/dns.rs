use crate::engine::{process_dns_query, AppState, ProcessOutcome};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::Semaphore;
use tokio::time::timeout;

/// RFC 7766 §6.2.3: Idle timeout waiting for subsequent queries on an open connection.
const IDLE_TIMEOUT: Duration = Duration::from_secs(10);

/// Active I/O timeout for completing an in-progress frame read/write.
const IO_TIMEOUT: Duration = Duration::from_secs(5);

/// Maximum UDP datagram size (65,535 bytes).
/// Sizing the socket receive buffer to 64KB ensures the OS kernel never silently
/// truncates oversized incoming datagrams to a smaller user-space buffer.
const MAX_UDP_RECV_BUF: usize = 65535;

/// RFC 6891 §6.2.3: Standard maximum allowable UDP query payload size.
const MAX_UDP_QUERY_SIZE: usize = 4096;

/// RFC 7766 §8: The 2-byte length field permits messages up to 65,535 bytes (64 KB).
/// This is essential for post-quantum ML-DSA-44 and large DNSSEC key sets.
const MAX_TCP_MSG_SIZE: usize = 65535;

/// RFC 1035 §4.1.1: Minimum DNS message header size is 12 bytes.
const MIN_DNS_MSG_SIZE: usize = 12;

/// Spawns the UDP listener on port 53.
/// Handles UDP datagrams without establishing persistent state.
pub async fn run_udp_listener(
    socket: Arc<UdpSocket>,
    state: AppState,
    concurrency_limit: Arc<Semaphore>,
) {
    // 64 KB receive buffer guarantees the OS will never partially deliver/truncate
    // an incoming UDP datagram to fit into user-space.
    let mut buf = vec![0u8; MAX_UDP_RECV_BUF];
    loop {
        match socket.recv_from(&mut buf).await {
            Ok((len, peer)) => {
                // Reject undersized datagrams without processing
                if len < MIN_DNS_MSG_SIZE {
                    continue;
                }

                // If a datagram exceeds standard DNS UDP limits, reject it rather
                // than treating an oversized packet as valid.
                if len > MAX_UDP_QUERY_SIZE {
                    tracing::debug!(
                        len,
                        client = %peer.ip(),
                        "[UDP] Datagram exceeds maximum DNS UDP query size; dropping"
                    );
                    continue;
                }

                let req_wire = buf[..len].to_vec();
                let socket_ref = socket.clone();
                let state_ref = state.clone();

                if let Ok(permit) = concurrency_limit.clone().try_acquire_owned() {
                    tokio::spawn(async move {
                        let _permit = permit;
                        let outcome =
                            process_dns_query(&req_wire, &state_ref, "UDP", peer.ip()).await;

                        match outcome {
                            ProcessOutcome::Success(resp)
                            | ProcessOutcome::ServFail(resp)
                            | ProcessOutcome::Truncated(resp) => {
                                let _ = socket_ref.send_to(&resp, peer).await;
                            }
                            ProcessOutcome::Dropped | ProcessOutcome::Malformed => {
                                // Do not respond to malformed or rate-limited UDP packets
                                // to eliminate reflection and amplification vectors.
                            }
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

/// Spawns the TCP listener on port 53.
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

                match concurrency_limit.clone().try_acquire_owned() {
                    Ok(permit) => {
                        tokio::spawn(async move {
                            let _permit = permit;
                            handle_length_prefixed_stream(stream, state_ref, "TCP", peer.ip()).await;
                        });
                    }
                    Err(_) => {
                        tracing::warn!(
                            client = %peer.ip(),
                            "[TCP] Concurrency limit reached; dropping connection"
                        );
                    }
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "[TCP] Error accepting connection");
            }
        }
    }
}

/// Generic length-prefixed stream handler used by both plain TCP (port 53) and DoT (port 853).
///
/// Implements RFC 7766 connection reuse, pipelining, 16-bit framing, and idle disconnects.
pub async fn handle_length_prefixed_stream<S>(
    mut stream: S,
    state: AppState,
    protocol: &'static str,
    client_ip: IpAddr,
) where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut len_buf = [0u8; 2];
    loop {
        // 1. Read the 2-byte big-endian message length prefix with an idle timeout
        let read_len = timeout(IDLE_TIMEOUT, stream.read_exact(&mut len_buf)).await;
        let req_len = match read_len {
            Ok(Ok(2)) => u16::from_be_bytes(len_buf) as usize,
            _ => break, // Connection closed cleanly, unexpected EOF, or idle timeout expired
        };

        // RFC 7766 §8: Validate framing length.
        // Minimum DNS message is 12 bytes; maximum 16-bit frame size is 65,535 bytes.
        if !(MIN_DNS_MSG_SIZE..=MAX_TCP_MSG_SIZE).contains(&req_len) {
            tracing::debug!(
                protocol,
                client = %client_ip,
                len = req_len,
                "[{}] Invalid TCP frame length; closing stream",
                protocol
            );
            break;
        }

        // 2. Read the full DNS query payload with an active I/O timeout.
        // Verify both timer completion and underlying I/O success.
        let mut req_buf = vec![0u8; req_len];
        let read_payload = timeout(IO_TIMEOUT, stream.read_exact(&mut req_buf)).await;
        if !matches!(read_payload, Ok(Ok(_))) {
            break;
        }

        // 3. Process the query through the unified engine
        let outcome = process_dns_query(&req_buf, &state, protocol, client_ip).await;

        match outcome {
            ProcessOutcome::Success(resp_wire)
            | ProcessOutcome::ServFail(resp_wire)
            | ProcessOutcome::Truncated(resp_wire) => {
                if resp_wire.len() > MAX_TCP_MSG_SIZE {
                    tracing::error!(
                        protocol,
                        len = resp_wire.len(),
                        "[{}] Response exceeds 64KB TCP frame limit",
                        protocol
                    );
                    break;
                }

                let len_bytes = (resp_wire.len() as u16).to_be_bytes();
                let write_result = timeout(IO_TIMEOUT, async {
                    stream.write_all(&len_bytes).await?;
                    stream.write_all(&resp_wire).await?;
                    stream.flush().await?;
                    Ok::<(), std::io::Error>(())
                })
                .await;

                if !matches!(write_result, Ok(Ok(()))) {
                    break;
                }
            }
            ProcessOutcome::Dropped => {
                // RFC 7766 §6.2.1: If a query is dropped by rate limiting,
                // do NOT tear down the persistent connection; continue reading.
                continue;
            }
            ProcessOutcome::Malformed => {
                // Client transmitted an unparseable DNS wire buffer; close stream
                break;
            }
        }
    }
}