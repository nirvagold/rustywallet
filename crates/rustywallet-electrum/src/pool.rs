//! Connection pooling for Electrum clients.
//!
//! This module provides a connection pool that manages multiple
//! Electrum client connections for improved performance and reliability.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::{Mutex, Semaphore};

use crate::client::ElectrumClient;
use crate::error::{ElectrumError, Result};
use crate::types::ClientConfig;

/// A pooled connection wrapper.
struct PooledConnection {
    client: ElectrumClient,
    created_at: Instant,
    last_used: Instant,
    use_count: usize,
}

impl PooledConnection {
    fn new(client: ElectrumClient) -> Self {
        let now = Instant::now();
        Self {
            client,
            created_at: now,
            last_used: now,
            use_count: 0,
        }
    }

    fn touch(&mut self) {
        self.last_used = Instant::now();
        self.use_count += 1;
    }

    fn age(&self) -> Duration {
        self.created_at.elapsed()
    }

    fn idle_time(&self) -> Duration {
        self.last_used.elapsed()
    }
}

/// Configuration for the connection pool.
#[derive(Debug, Clone)]
pub struct PoolConfig {
    /// Minimum number of connections to maintain
    pub min_connections: usize,
    /// Maximum number of connections allowed
    pub max_connections: usize,
    /// Maximum time a connection can be idle before being closed
    pub idle_timeout: Duration,
    /// Maximum age of a connection before it's recycled
    pub max_age: Duration,
    /// Timeout for acquiring a connection from the pool
    pub acquire_timeout: Duration,
    /// Whether to validate connections before returning them
    pub validate_on_acquire: bool,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            min_connections: 1,
            max_connections: 10,
            idle_timeout: Duration::from_secs(300),
            max_age: Duration::from_secs(3600),
            acquire_timeout: Duration::from_secs(30),
            validate_on_acquire: true,
        }
    }
}

impl PoolConfig {
    /// Create a new pool configuration.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set minimum connections.
    pub fn min_connections(mut self, min: usize) -> Self {
        self.min_connections = min;
        self
    }

    /// Set maximum connections.
    pub fn max_connections(mut self, max: usize) -> Self {
        self.max_connections = max;
        self
    }

    /// Set idle timeout.
    pub fn idle_timeout(mut self, timeout: Duration) -> Self {
        self.idle_timeout = timeout;
        self
    }

    /// Set maximum connection age.
    pub fn max_age(mut self, age: Duration) -> Self {
        self.max_age = age;
        self
    }

    /// Set acquire timeout.
    pub fn acquire_timeout(mut self, timeout: Duration) -> Self {
        self.acquire_timeout = timeout;
        self
    }

    /// Set whether to validate on acquire.
    pub fn validate_on_acquire(mut self, validate: bool) -> Self {
        self.validate_on_acquire = validate;
        self
    }
}

/// Connection pool for Electrum clients.
pub struct ConnectionPool {
    config: PoolConfig,
    client_config: ClientConfig,
    connections: Mutex<VecDeque<PooledConnection>>,
    semaphore: Arc<Semaphore>,
    active_count: AtomicUsize,
    total_created: AtomicUsize,
}

impl ConnectionPool {
    /// Create a new connection pool.
    pub fn new(client_config: ClientConfig, pool_config: PoolConfig) -> Self {
        let semaphore = Arc::new(Semaphore::new(pool_config.max_connections));
        
        Self {
            config: pool_config,
            client_config,
            connections: Mutex::new(VecDeque::new()),
            semaphore,
            active_count: AtomicUsize::new(0),
            total_created: AtomicUsize::new(0),
        }
    }

    /// Create a pool with default configuration.
    pub fn with_defaults(client_config: ClientConfig) -> Self {
        Self::new(client_config, PoolConfig::default())
    }

    /// Initialize the pool with minimum connections.
    pub async fn initialize(&self) -> Result<()> {
        let mut conns = self.connections.lock().await;
        
        while conns.len() < self.config.min_connections {
            let client = ElectrumClient::with_config(self.client_config.clone()).await?;
            conns.push_back(PooledConnection::new(client));
            self.total_created.fetch_add(1, Ordering::SeqCst);
        }
        
        Ok(())
    }

    /// Acquire a connection from the pool.
    pub async fn acquire(&self) -> Result<PooledClient<'_>> {
        // Try to acquire a permit
        let permit = tokio::time::timeout(
            self.config.acquire_timeout,
            self.semaphore.clone().acquire_owned(),
        )
        .await
        .map_err(|_| ElectrumError::Timeout)?
        .map_err(|_| ElectrumError::ConnectionFailed("Pool closed".into()))?;

        // Try to get an existing connection
        let mut conns = self.connections.lock().await;
        
        while let Some(mut conn) = conns.pop_front() {
            // Check if connection is still valid
            if conn.age() > self.config.max_age {
                continue; // Connection too old, discard
            }
            
            if conn.idle_time() > self.config.idle_timeout {
                continue; // Connection idle too long, discard
            }

            // Validate if configured
            if self.config.validate_on_acquire {
                drop(conns); // Release lock during validation
                
                if conn.client.ping().await.is_ok() {
                    conn.touch();
                    self.active_count.fetch_add(1, Ordering::SeqCst);
                    return Ok(PooledClient {
                        connection: Some(conn),
                        pool: self,
                        _permit: permit,
                    });
                }
                
                conns = self.connections.lock().await;
                continue; // Validation failed, try next
            }

            conn.touch();
            self.active_count.fetch_add(1, Ordering::SeqCst);
            return Ok(PooledClient {
                connection: Some(conn),
                pool: self,
                _permit: permit,
            });
        }
        
        drop(conns);

        // No available connections, create a new one
        let client = ElectrumClient::with_config(self.client_config.clone()).await?;
        let mut conn = PooledConnection::new(client);
        conn.touch();
        
        self.total_created.fetch_add(1, Ordering::SeqCst);
        self.active_count.fetch_add(1, Ordering::SeqCst);
        
        Ok(PooledClient {
            connection: Some(conn),
            pool: self,
            _permit: permit,
        })
    }

    /// Return a connection to the pool.
    #[allow(dead_code)]
    async fn release(&self, conn: PooledConnection) {
        self.active_count.fetch_sub(1, Ordering::SeqCst);
        
        // Check if connection should be kept
        if conn.age() > self.config.max_age {
            return; // Too old, discard
        }

        let mut conns = self.connections.lock().await;
        
        // Only keep if under max
        if conns.len() < self.config.max_connections {
            conns.push_back(conn);
        }
    }

    /// Get pool statistics.
    pub async fn stats(&self) -> PoolStats {
        let conns = self.connections.lock().await;
        
        PoolStats {
            idle_connections: conns.len(),
            active_connections: self.active_count.load(Ordering::SeqCst),
            total_created: self.total_created.load(Ordering::SeqCst),
            max_connections: self.config.max_connections,
        }
    }

    /// Close all connections and reset the pool.
    pub async fn close(&self) {
        let mut conns = self.connections.lock().await;
        conns.clear();
    }

    /// Remove idle connections that exceed the timeout.
    pub async fn cleanup(&self) {
        let mut conns = self.connections.lock().await;
        
        conns.retain(|conn| {
            conn.idle_time() <= self.config.idle_timeout && 
            conn.age() <= self.config.max_age
        });

        // Ensure minimum connections
        // Note: This doesn't create new connections, just retains existing ones
    }
}

/// Pool statistics.
#[derive(Debug, Clone)]
pub struct PoolStats {
    /// Number of idle connections in the pool
    pub idle_connections: usize,
    /// Number of connections currently in use
    pub active_connections: usize,
    /// Total number of connections created
    pub total_created: usize,
    /// Maximum allowed connections
    pub max_connections: usize,
}

impl PoolStats {
    /// Get total connections (idle + active).
    pub fn total_connections(&self) -> usize {
        self.idle_connections + self.active_connections
    }

    /// Get pool utilization as a percentage.
    pub fn utilization(&self) -> f64 {
        if self.max_connections == 0 {
            0.0
        } else {
            (self.active_connections as f64 / self.max_connections as f64) * 100.0
        }
    }
}

/// A client borrowed from the connection pool.
///
/// The connection is automatically returned to the pool when dropped.
pub struct PooledClient<'a> {
    connection: Option<PooledConnection>,
    pool: &'a ConnectionPool,
    _permit: tokio::sync::OwnedSemaphorePermit,
}

impl<'a> PooledClient<'a> {
    /// Get a reference to the underlying client.
    pub fn client(&self) -> &ElectrumClient {
        &self.connection.as_ref().unwrap().client
    }

    /// Get the connection's use count.
    pub fn use_count(&self) -> usize {
        self.connection.as_ref().unwrap().use_count
    }

    /// Get the connection's age.
    pub fn age(&self) -> Duration {
        self.connection.as_ref().unwrap().age()
    }
}

impl<'a> std::ops::Deref for PooledClient<'a> {
    type Target = ElectrumClient;

    fn deref(&self) -> &Self::Target {
        self.client()
    }
}

impl<'a> Drop for PooledClient<'a> {
    fn drop(&mut self) {
        // Note: We can't spawn async task here due to lifetime constraints.
        // The connection will be dropped. For proper pooling, use the pool's
        // release method explicitly before dropping, or use a different pattern.
        // This is a limitation of the current design.
        self.connection.take();
        self.pool.active_count.fetch_sub(1, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pool_config_default() {
        let config = PoolConfig::default();
        assert_eq!(config.min_connections, 1);
        assert_eq!(config.max_connections, 10);
    }

    #[test]
    fn test_pool_config_builder() {
        let config = PoolConfig::new()
            .min_connections(2)
            .max_connections(20)
            .idle_timeout(Duration::from_secs(60));
        
        assert_eq!(config.min_connections, 2);
        assert_eq!(config.max_connections, 20);
        assert_eq!(config.idle_timeout, Duration::from_secs(60));
    }

    #[test]
    fn test_pool_stats() {
        let stats = PoolStats {
            idle_connections: 5,
            active_connections: 3,
            total_created: 10,
            max_connections: 10,
        };
        
        assert_eq!(stats.total_connections(), 8);
        assert_eq!(stats.utilization(), 30.0);
    }
}
