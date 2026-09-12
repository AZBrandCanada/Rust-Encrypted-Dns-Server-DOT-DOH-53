// src/dot.rs
use crate::dns::handle_length_prefixed_stream;
use crate::engine::AppState;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

pub async fn run_dot_listener(listener: TcpListener, acceptor: TlsAcceptor, state: AppState) {
    loop {
        match listener.accept().await {
            Ok((stream, _peer)) => {
                let _ = stream.set_nodelay(true);
                let acceptor_ref = acceptor.clone();
                let state_ref = state.clone();

                tokio::spawn(async move {
                    match acceptor_ref.accept(stream).await {
                        Ok(tls_stream) => {
                            handle_length_prefixed_stream(tls_stream, state_ref, "DoT").await;
                        }
                        Err(e) => {
                            tracing::debug!(error = %e, "[DoT] TLS handshake failed");
                        }
                    }
                });
            }
            Err(e) => {
                tracing::warn!(error = %e, "[DoT] Error accepting TLS connection");
            }
        }
    }
}
