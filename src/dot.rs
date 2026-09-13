// src/dot.rs
use crate::dns::handle_length_prefixed_stream;
use crate::engine::AppState;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;

const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

pub async fn run_dot_listener(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    state: AppState,
    concurrency_limit: Arc<Semaphore>,
) {
    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                let _ = stream.set_nodelay(true);
                let acceptor_ref = acceptor.clone();
                let state_ref = state.clone();

                if let Ok(permit) = concurrency_limit.clone().try_acquire_owned() {
                    tokio::spawn(async move {
                        let _permit = permit;
                        match timeout(TLS_HANDSHAKE_TIMEOUT, acceptor_ref.accept(stream)).await {
                            Ok(Ok(tls_stream)) => {
                                handle_length_prefixed_stream(tls_stream, state_ref, "DoT", peer.ip()).await;
                            }
                            Ok(Err(e)) => {
                                tracing::debug!(error = %e, "[DoT] TLS handshake failed");
                            }
                            Err(_) => {
                                tracing::debug!("[DoT] TLS handshake timed out");
                            }
                        }
                    });
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "[DoT] Error accepting connection");
            }
        }
    }
}
