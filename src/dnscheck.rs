// src/dnscheck.rs

use axum::{
    extract::{
        ws::{Message as WsMessage, WebSocket, WebSocketUpgrade},
        Path, State,
    },
    response::IntoResponse,
};
use dashmap::DashMap;
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::opt::EdnsCode;
use hickory_proto::rr::rdata::{SOA, TXT};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::BinEncodable;
use serde::Serialize;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::broadcast;

#[derive(Debug, Clone, Default)]
pub struct DnscheckOptions {
    pub client_id: Option<String>,
    pub null_ip: bool,
    pub truncate: bool,
    pub bad_sig: bool,
    pub expired_sig: bool,
    pub no_sig: bool,
}

impl DnscheckOptions {
    pub fn parse(subdomain: &str) -> Self {
        let mut opts = Self::default();
        let cleaned = subdomain.trim_end_matches('.');
        let innermost = cleaned.rsplit('.').next().unwrap_or(cleaned);

        for part in innermost.split('-') {
            let p_lower = part.to_ascii_lowercase();
            match p_lower.as_str() {
                "nullip" => opts.null_ip = true,
                "truncate" => opts.truncate = true,
                "badsig" => opts.bad_sig = true,
                "expiredsig" => opts.expired_sig = true,
                "nosig" => opts.no_sig = true,
                s if s.len() <= 8 && s.chars().all(|c| c.is_ascii_hexdigit()) => {
                    opts.client_id = Some(s.to_string());
                }
                _ => {}
            }
        }
        opts
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DnsWatcherEvent {
    pub time: u64,
    pub proto: String,
    pub remote_ip: String,
    pub remote_port: u16,
    pub qname: String,
    pub qtype: String,
    pub is_edns0: bool,
    pub udp_size: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_subnet: Option<String>,
}

#[derive(Clone)]
pub struct DnscheckEngine {
    pub zone_suffix: String,
    pub server_ip: IpAddr,
    channels: Arc<DashMap<String, broadcast::Sender<DnsWatcherEvent>>>,
}

impl DnscheckEngine {
    pub fn new(zone_suffix: String, server_ip: IpAddr) -> Self {
        Self {
            zone_suffix: zone_suffix.trim_start_matches('.').to_lowercase(),
            server_ip,
            channels: Arc::new(DashMap::new()),
        }
    }

    pub fn matches_zone(&self, qname: &Name) -> bool {
        let q_str = qname.to_string().to_lowercase();
        let q_clean = q_str.trim_end_matches('.');
        q_clean == self.zone_suffix || q_clean.ends_with(&format!(".{}", self.zone_suffix))
    }

    pub async fn notify(&self, client_id: &str, event: DnsWatcherEvent) {
        if let Some(entry) = self.channels.get(client_id) {
            let _ = entry.send(event);
        }
    }

    pub async fn handle_query(
        &self,
        req: &Message,
        query: &Query,
        protocol: &str,
        peer_addr: SocketAddr,
    ) -> Option<Vec<u8>> {
        let qname = query.name();
        if !self.matches_zone(qname) {
            return None;
        }

        let q_str = qname.to_string().to_lowercase();
        let q_clean = q_str.trim_end_matches('.');
        let prefix = if q_clean == self.zone_suffix {
            ""
        } else {
            q_clean.trim_end_matches(&format!(".{}", self.zone_suffix))
        };

        let opts = DnscheckOptions::parse(prefix);

        let mut ecs_str: Option<String> = None;
        let mut udp_size: u16 = 512;
        let mut is_edns0 = false;

        // Use modern `extensions()` without deprecation warnings
        if let Some(edns) = req.extensions() {
            is_edns0 = true;
            udp_size = edns.max_payload();
            if let Some(subnet_opt) = edns.options().get(EdnsCode::Subnet) {
                ecs_str = Some(format!("{:?}", subnet_opt));
            }
        }

        if let Some(ref cid) = opts.client_id {
            let event = DnsWatcherEvent {
                time: SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs(),
                proto: protocol.to_string(),
                remote_ip: peer_addr.ip().to_string(),
                remote_port: peer_addr.port(),
                qname: qname.to_string(),
                qtype: format!("{:?}", query.query_type()),
                is_edns0,
                udp_size,
                client_subnet: ecs_str,
            };
            self.notify(cid, event).await;
        }

        let mut resp = Message::new();
        resp.set_id(req.id());
        resp.set_message_type(MessageType::Response);
        resp.set_op_code(OpCode::Query);
        resp.set_authoritative(true);
        resp.set_recursion_available(true);
        resp.add_query(query.clone());

        if opts.truncate && protocol == "UDP" {
            resp.set_truncated(true);
            return resp.to_bytes().ok();
        }

        let qtype = query.query_type();

        match qtype {
            RecordType::A => {
                let ip = if opts.null_ip {
                    Ipv4Addr::new(0, 0, 0, 0)
                } else if let IpAddr::V4(v4) = self.server_ip {
                    v4
                } else {
                    Ipv4Addr::new(127, 0, 0, 1)
                };
                resp.add_answer(Record::from_rdata(qname.clone(), 1, RData::A(ip.into())));
            }
            RecordType::AAAA => {
                let ip6 = if opts.null_ip {
                    Ipv6Addr::UNSPECIFIED
                } else if let IpAddr::V6(v6) = self.server_ip {
                    v6
                } else {
                    Ipv6Addr::LOCALHOST
                };
                resp.add_answer(Record::from_rdata(qname.clone(), 1, RData::AAAA(ip6.into())));
            }
            RecordType::TXT => {
                let txt_val = format!(
                    "FROM: {} PROTO: {} ID: {}",
                    peer_addr,
                    protocol,
                    req.id()
                );
                resp.add_answer(Record::from_rdata(
                    qname.clone(),
                    1,
                    RData::TXT(TXT::new(vec![txt_val])),
                ));
            }
            RecordType::SOA => {
                if let Ok(mname) = Name::from_str(&format!("ns1.{}.", self.zone_suffix)) {
                    if let Ok(rname) = Name::from_str(&format!("hostmaster.{}.", self.zone_suffix)) {
                        resp.add_answer(Record::from_rdata(
                            qname.clone(),
                            1800,
                            RData::SOA(SOA::new(mname, rname, 1, 1800, 1800, 3600, 1800)),
                        ));
                    }
                }
            }
            _ => {
                resp.set_response_code(ResponseCode::NoError);
            }
        }

        // DNSSEC simulation:
        // When badsig, expiredsig, or nosig are requested by the tester,
        // return ServFail so validating resolvers reject the response
        if opts.bad_sig || opts.expired_sig || opts.no_sig {
            resp.set_response_code(ResponseCode::ServFail);
            resp.take_answers();
        }

        resp.to_bytes().ok()
    }
}

pub async fn ws_watch_handler(
    ws: WebSocketUpgrade,
    Path(client_id): Path<String>,
    State(state): State<crate::engine::AppState>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_socket(socket, client_id, state.dnscheck))
}

async fn handle_socket(mut socket: WebSocket, client_id: String, engine: Arc<DnscheckEngine>) {
    let mut rx = {
        let entry = engine.channels.entry(client_id.clone()).or_insert_with(|| {
            let (tx, _) = broadcast::channel(128);
            tx
        });
        entry.subscribe()
    };

    while let Ok(event) = rx.recv().await {
        if let Ok(json_str) = serde_json::to_string(&event) {
            if socket.send(WsMessage::Text(json_str.into())).await.is_err() {
                break;
            }
        }
    }

    if let Some(entry) = engine.channels.get(&client_id) {
        if entry.receiver_count() == 0 {
            drop(entry);
            engine.channels.remove(&client_id);
        }
    }
}
