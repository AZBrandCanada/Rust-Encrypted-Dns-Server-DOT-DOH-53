use crate::dns::handle_length_prefixed_stream;
use crate::engine::AppState;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;

/// RFC 7858 §4.1: Bounded TLS handshake timeout to mitigate slowloris attacks.
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

/// Spawns the DNS-over-TLS (DoT) listener on port 853.
///
/// Operates as a transparent transport layer: accepts TLS connections, enforces
/// concurrency limits and handshake timeouts, and hands off the TLS stream to the
/// unified length-prefixed stream handler in `src/dns.rs`.
pub async fn run_dot_listener(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    state: AppState,
    concurrency_limit: Arc<Semaphore>,
) {
    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                // Disable Nagle's algorithm for low-latency DNS delivery
                let _ = stream.set_nodelay(true);

                let acceptor_ref = acceptor.clone();
                let state_ref = state.clone();

                match concurrency_limit.clone().try_acquire_owned() {
                    Ok(permit) => {
                        tokio::spawn(async move {
                            let _permit = permit;
                            match timeout(TLS_HANDSHAKE_TIMEOUT, acceptor_ref.accept(stream)).await
                            {
                                Ok(Ok(tls_stream)) => {
                                    // RFC 7858 §3.3: handle_length_prefixed_stream manages the
                                    // multi-query loop, 2-byte frame length, and idle timeouts.
                                    handle_length_prefixed_stream(
                                        tls_stream,
                                        state_ref,
                                        "DoT",
                                        peer.ip(),
                                    )
                                    .await;
                                }
                                Ok(Err(e)) => {
                                    tracing::debug!(
                                        client = %peer.ip(),
                                        error = %e,
                                        "[DoT] TLS handshake failed"
                                    );
                                }
                                Err(_) => {
                                    tracing::debug!(
                                        client = %peer.ip(),
                                        "[DoT] TLS handshake timed out"
                                    );
                                }
                            }
                        });
                    }
                    Err(_) => {
                        tracing::warn!(
                            client = %peer.ip(),
                            "[DoT] Concurrency limit reached; dropping incoming connection"
                        );
                    }
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "[DoT] Error accepting connection: {}", e);
            }
        }
    }
}
