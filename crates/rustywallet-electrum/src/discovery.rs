//! Server discovery via DNS seeds.
//!
//! This module provides functionality to discover Electrum servers
//! using DNS seed queries, similar to how Bitcoin nodes discover peers.

use std::net::{SocketAddr, ToSocketAddrs};
use std::time::Duration;

use crate::error::{ElectrumError, Result};
use crate::types::ClientConfig;

/// DNS seeds for discovering Electrum servers.
pub const DNS_SEEDS: &[&str] = &[
    // Bitcoin mainnet Electrum DNS seeds
    "electrum.blockstream.info",
    "electrum1.bluewallet.io",
    "electrum2.bluewallet.io",
    "bitcoin.aranguren.org",
    "electrum.bitaroo.net",
    "electrum.emzy.de",
    "electrum.hodlister.co",
];

/// Testnet DNS seeds.
pub const TESTNET_DNS_SEEDS: &[&str] = &[
    "electrum.blockstream.info",
    "testnet.aranguren.org",
];

/// Discovered server information.
#[derive(Debug, Clone)]
pub struct DiscoveredServer {
    /// Server hostname
    pub hostname: String,
    /// Resolved IP addresses
    pub addresses: Vec<SocketAddr>,
    /// SSL port (typically 50002)
    pub ssl_port: u16,
    /// TCP port (typically 50001)
    pub tcp_port: u16,
    /// Whether the server is reachable
    pub reachable: bool,
    /// Response time in milliseconds (if tested)
    pub latency_ms: Option<u64>,
}

impl DiscoveredServer {
    /// Create a new discovered server entry.
    pub fn new(hostname: impl Into<String>) -> Self {
        Self {
            hostname: hostname.into(),
            addresses: Vec::new(),
            ssl_port: 50002,
            tcp_port: 50001,
            reachable: false,
            latency_ms: None,
        }
    }

    /// Set custom ports.
    pub fn with_ports(mut self, ssl: u16, tcp: u16) -> Self {
        self.ssl_port = ssl;
        self.tcp_port = tcp;
        self
    }

    /// Get SSL address string.
    pub fn ssl_address(&self) -> String {
        format!("{}:{}", self.hostname, self.ssl_port)
    }

    /// Get TCP address string.
    pub fn tcp_address(&self) -> String {
        format!("{}:{}", self.hostname, self.tcp_port)
    }

    /// Convert to ClientConfig for SSL connection.
    pub fn to_ssl_config(&self) -> ClientConfig {
        ClientConfig::ssl(&self.hostname).with_port(self.ssl_port)
    }

    /// Convert to ClientConfig for TCP connection.
    pub fn to_tcp_config(&self) -> ClientConfig {
        ClientConfig::tcp(&self.hostname).with_port(self.tcp_port)
    }
}

/// Server discovery service.
#[derive(Debug, Clone)]
pub struct ServerDiscovery {
    seeds: Vec<String>,
    timeout: Duration,
    prefer_ssl: bool,
}

impl ServerDiscovery {
    /// Create a new discovery service with default mainnet seeds.
    pub fn new() -> Self {
        Self {
            seeds: DNS_SEEDS.iter().map(|s| s.to_string()).collect(),
            timeout: Duration::from_secs(5),
            prefer_ssl: true,
        }
    }

    /// Create a discovery service for testnet.
    pub fn testnet() -> Self {
        Self {
            seeds: TESTNET_DNS_SEEDS.iter().map(|s| s.to_string()).collect(),
            timeout: Duration::from_secs(5),
            prefer_ssl: true,
        }
    }

    /// Create with custom seeds.
    pub fn with_seeds(seeds: Vec<String>) -> Self {
        Self {
            seeds,
            timeout: Duration::from_secs(5),
            prefer_ssl: true,
        }
    }

    /// Set discovery timeout.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Set SSL preference.
    pub fn prefer_ssl(mut self, prefer: bool) -> Self {
        self.prefer_ssl = prefer;
        self
    }

    /// Add a custom seed.
    pub fn add_seed(&mut self, seed: impl Into<String>) {
        self.seeds.push(seed.into());
    }

    /// Discover servers by resolving DNS seeds.
    ///
    /// Returns a list of discovered servers with resolved addresses.
    pub fn discover(&self) -> Vec<DiscoveredServer> {
        let mut servers = Vec::new();

        for seed in &self.seeds {
            let mut server = DiscoveredServer::new(seed);
            
            // Special handling for known servers with non-standard ports
            if seed.contains("bluewallet") {
                server = server.with_ports(443, 50001);
            }

            // Resolve DNS
            let port = if self.prefer_ssl { server.ssl_port } else { server.tcp_port };
            let addr_str = format!("{}:{}", seed, port);
            
            if let Ok(addrs) = addr_str.to_socket_addrs() {
                server.addresses = addrs.collect();
                server.reachable = !server.addresses.is_empty();
            }

            servers.push(server);
        }

        servers
    }

    /// Discover and test servers for connectivity.
    ///
    /// This performs actual TCP connections to verify reachability.
    pub async fn discover_and_test(&self) -> Vec<DiscoveredServer> {
        let mut servers = self.discover();

        for server in &mut servers {
            if server.addresses.is_empty() {
                continue;
            }

            let port = if self.prefer_ssl { server.ssl_port } else { server.tcp_port };
            let addr = format!("{}:{}", server.hostname, port);

            let start = std::time::Instant::now();
            
            match tokio::time::timeout(
                self.timeout,
                tokio::net::TcpStream::connect(&addr),
            )
            .await
            {
                Ok(Ok(_)) => {
                    server.reachable = true;
                    server.latency_ms = Some(start.elapsed().as_millis() as u64);
                }
                _ => {
                    server.reachable = false;
                }
            }
        }

        servers
    }

    /// Get the best server based on latency.
    pub async fn best_server(&self) -> Result<DiscoveredServer> {
        let servers = self.discover_and_test().await;
        
        servers
            .into_iter()
            .filter(|s| s.reachable)
            .min_by_key(|s| s.latency_ms.unwrap_or(u64::MAX))
            .ok_or_else(|| ElectrumError::ConnectionFailed("No reachable servers found".into()))
    }

    /// Get all reachable servers sorted by latency.
    pub async fn reachable_servers(&self) -> Vec<DiscoveredServer> {
        let mut servers = self.discover_and_test().await;
        
        servers.retain(|s| s.reachable);
        servers.sort_by_key(|s| s.latency_ms.unwrap_or(u64::MAX));
        
        servers
    }

    /// Get a random reachable server.
    pub async fn random_server(&self) -> Result<DiscoveredServer> {
        use std::collections::hash_map::RandomState;
        use std::hash::{BuildHasher, Hasher};

        let servers = self.reachable_servers().await;
        
        if servers.is_empty() {
            return Err(ElectrumError::ConnectionFailed("No reachable servers found".into()));
        }

        // Simple random selection using hash
        let random = RandomState::new().build_hasher().finish() as usize;
        let index = random % servers.len();
        
        Ok(servers.into_iter().nth(index).unwrap())
    }
}

impl Default for ServerDiscovery {
    fn default() -> Self {
        Self::new()
    }
}

/// Hardcoded server list for fallback.
pub fn hardcoded_servers() -> Vec<DiscoveredServer> {
    vec![
        DiscoveredServer::new("electrum.blockstream.info").with_ports(50002, 50001),
        DiscoveredServer::new("electrum1.bluewallet.io").with_ports(443, 50001),
        DiscoveredServer::new("electrum2.bluewallet.io").with_ports(443, 50001),
        DiscoveredServer::new("bitcoin.aranguren.org").with_ports(50002, 50001),
        DiscoveredServer::new("electrum.bitaroo.net").with_ports(50002, 50001),
    ]
}

/// Get a default server configuration.
pub fn default_server() -> ClientConfig {
    ClientConfig::ssl("electrum.blockstream.info")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_discovered_server() {
        let server = DiscoveredServer::new("example.com");
        assert_eq!(server.ssl_address(), "example.com:50002");
        assert_eq!(server.tcp_address(), "example.com:50001");
    }

    #[test]
    fn test_custom_ports() {
        let server = DiscoveredServer::new("example.com").with_ports(443, 80);
        assert_eq!(server.ssl_address(), "example.com:443");
        assert_eq!(server.tcp_address(), "example.com:80");
    }

    #[test]
    fn test_discovery_seeds() {
        let discovery = ServerDiscovery::new();
        assert!(!discovery.seeds.is_empty());
    }

    #[test]
    fn test_hardcoded_servers() {
        let servers = hardcoded_servers();
        assert!(!servers.is_empty());
        assert!(servers.iter().any(|s| s.hostname.contains("blockstream")));
    }
}
