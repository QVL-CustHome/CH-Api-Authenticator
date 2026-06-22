use axum::http::HeaderMap;
use ipnet::IpNet;
use std::net::{IpAddr, SocketAddr};

pub const CLIENT_IP_HEADER: &str = "x-client-ip";

const DEFAULT_TRUSTED_PROXIES: &str = "127.0.0.1,::1";

#[derive(Debug, Clone)]
pub struct TrustedProxies {
    networks: Vec<IpNet>,
}

impl TrustedProxies {
    pub fn from_env() -> Self {
        let raw = std::env::var("AUTH_TRUSTED_PROXIES")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .unwrap_or_else(|| DEFAULT_TRUSTED_PROXIES.to_string());
        Self::parse(&raw)
    }

    pub fn parse(raw: &str) -> Self {
        let networks = raw
            .split(',')
            .filter_map(|entry| parse_network(entry.trim()))
            .collect();
        Self { networks }
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        self.networks.iter().any(|network| network.contains(&ip))
    }

    pub fn resolve(&self, peer: SocketAddr, headers: &HeaderMap) -> IpAddr {
        let peer_ip = peer.ip();
        if !self.contains(peer_ip) {
            return peer_ip;
        }
        forwarded_client_ip(headers).unwrap_or(peer_ip)
    }
}

fn parse_network(entry: &str) -> Option<IpNet> {
    if entry.is_empty() {
        return None;
    }
    if let Ok(network) = entry.parse::<IpNet>() {
        return Some(network);
    }
    entry.parse::<IpAddr>().map(IpNet::from).ok()
}

fn forwarded_client_ip(headers: &HeaderMap) -> Option<IpAddr> {
    headers
        .get(CLIENT_IP_HEADER)?
        .to_str()
        .ok()?
        .trim()
        .parse()
        .ok()
}
