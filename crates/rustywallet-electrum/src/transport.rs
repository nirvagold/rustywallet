//! Transport layer for Electrum protocol communication.
//!
//! Handles TCP and TLS connections with JSON-RPC framing.

use std::sync::Arc;

use rustls::{
    client::{ServerCertVerified, ServerCertVerifier},
    Certificate, ClientConfig as RustlsConfig, OwnedTrustAnchor, RootCertStore, ServerName,
};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

use crate::error::{ElectrumError, Result};
use crate::types::ClientConfig;

/// Dummy certificate verifier that accepts any certificate (INSECURE).
struct NoVerifier;

impl ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &Certificate,
        _intermediates: &[Certificate],
        _server_name: &ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: std::time::SystemTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
}

/// JSON-RPC request structure.
#[derive(Debug, Serialize)]
pub struct JsonRpcRequest<'a> {
    /// JSON-RPC version (always "2.0")
    pub jsonrpc: &'static str,
    /// Request ID for matching responses
    pub id: u64,
    /// Method name to call
    pub method: &'a str,
    /// Method parameters
    pub params: Vec<serde_json::Value>,
}

impl<'a> JsonRpcRequest<'a> {
    /// Create a new JSON-RPC request.
    pub fn new(id: u64, method: &'a str, params: Vec<serde_json::Value>) -> Self {
        Self {
            jsonrpc: "2.0",
            id,
            method,
            params,
        }
    }
}

/// JSON-RPC response structure.
#[derive(Debug, Deserialize)]
pub struct JsonRpcResponse {
    /// JSON-RPC version
    pub jsonrpc: String,
    /// Response ID matching request
    pub id: Option<u64>,
    /// Result value (if successful)
    pub result: Option<serde_json::Value>,
    /// Error (if failed)
    pub error: Option<JsonRpcError>,
}

/// JSON-RPC error structure.
#[derive(Debug, Deserialize)]
pub struct JsonRpcError {
    /// Error code
    pub code: i32,
    /// Error message
    pub message: String,
}

/// Transport connection type.
enum Connection {
    Tcp(BufReader<TcpStream>),
    Tls(Box<BufReader<TlsStream<TcpStream>>>),
}

/// Transport layer for Electrum server communication.
pub struct Transport {
    connection: Mutex<Connection>,
    config: ClientConfig,
}

impl Transport {
    /// Create a new transport connection.
    pub async fn connect(config: ClientConfig) -> Result<Self> {
        let connection = if config.use_tls {
            Self::connect_tls(&config).await?
        } else {
            Self::connect_tcp(&config).await?
        };

        Ok(Self {
            connection: Mutex::new(connection),
            config,
        })
    }

    /// Connect via plain TCP.
    async fn connect_tcp(config: &ClientConfig) -> Result<Connection> {
        let addr = config.address();
        let stream = tokio::time::timeout(config.timeout, TcpStream::connect(&addr))
            .await
            .map_err(|_| ElectrumError::Timeout)?
            .map_err(|e| ElectrumError::ConnectionFailed(format!("{}: {}", addr, e)))?;

        stream.set_nodelay(true)?;
        Ok(Connection::Tcp(BufReader::new(stream)))
    }

    /// Connect via TLS/SSL.
    async fn connect_tls(config: &ClientConfig) -> Result<Connection> {
        let addr = config.address();

        // Create TCP connection first
        let stream = tokio::time::timeout(config.timeout, TcpStream::connect(&addr))
            .await
            .map_err(|_| ElectrumError::Timeout)?
            .map_err(|e| ElectrumError::ConnectionFailed(format!("{}: {}", addr, e)))?;

        stream.set_nodelay(true)?;

        // Setup TLS config
        let tls_config = if config.skip_tls_verify {
            // INSECURE: Skip certificate validation
            RustlsConfig::builder()
                .with_safe_defaults()
                .with_custom_certificate_verifier(Arc::new(NoVerifier))
                .with_no_client_auth()
        } else {
            // Normal: Use webpki roots for validation
            let mut root_store = RootCertStore::empty();
            root_store.add_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
                OwnedTrustAnchor::from_subject_spki_name_constraints(
                    ta.subject,
                    ta.spki,
                    ta.name_constraints,
                )
            }));

            RustlsConfig::builder()
                .with_safe_defaults()
                .with_root_certificates(root_store)
                .with_no_client_auth()
        };

        let connector = TlsConnector::from(Arc::new(tls_config));

        let server_name = ServerName::try_from(config.server.as_str())
            .map_err(|e| ElectrumError::TlsError(format!("Invalid server name: {}", e)))?;

        let tls_stream = tokio::time::timeout(config.timeout, connector.connect(server_name, stream))
            .await
            .map_err(|_| ElectrumError::Timeout)?
            .map_err(|e| ElectrumError::TlsError(e.to_string()))?;

        Ok(Connection::Tls(Box::new(BufReader::new(tls_stream))))
    }

    /// Send a JSON-RPC request and receive response.
    pub async fn request(
        &self,
        id: u64,
        method: &str,
        params: Vec<serde_json::Value>,
    ) -> Result<serde_json::Value> {
        let request = JsonRpcRequest::new(id, method, params);
        let request_json = serde_json::to_string(&request)?;

        let mut conn = self.connection.lock().await;

        // Send request with newline delimiter
        let request_line = format!("{}\n", request_json);

        match &mut *conn {
            Connection::Tcp(reader) => {
                reader.get_mut().write_all(request_line.as_bytes()).await?;
                reader.get_mut().flush().await?;
            }
            Connection::Tls(reader) => {
                reader.get_mut().write_all(request_line.as_bytes()).await?;
                reader.get_mut().flush().await?;
            }
        }

        // Read response line
        let mut response_line = String::new();

        let bytes_read = tokio::time::timeout(self.config.timeout, async {
            match &mut *conn {
                Connection::Tcp(reader) => reader.read_line(&mut response_line).await,
                Connection::Tls(reader) => reader.read_line(&mut response_line).await,
            }
        })
        .await
        .map_err(|_| ElectrumError::Timeout)??;

        if bytes_read == 0 {
            return Err(ElectrumError::Disconnected);
        }

        // Parse response
        let response: JsonRpcResponse = serde_json::from_str(&response_line)?;

        // Check for errors
        if let Some(error) = response.error {
            return Err(ElectrumError::ServerError {
                code: error.code,
                message: error.message,
            });
        }

        // Verify ID matches
        if let Some(resp_id) = response.id {
            if resp_id != id {
                return Err(ElectrumError::IdMismatch {
                    expected: id,
                    got: resp_id,
                });
            }
        }

        // Return result (null is valid for some methods like ping)
        Ok(response.result.unwrap_or(serde_json::Value::Null))
    }

    /// Send a batch of JSON-RPC requests.
    pub async fn batch_request(
        &self,
        requests: Vec<(u64, &str, Vec<serde_json::Value>)>,
    ) -> Result<Vec<serde_json::Value>> {
        if requests.is_empty() {
            return Ok(vec![]);
        }

        let batch: Vec<JsonRpcRequest> = requests
            .iter()
            .map(|(id, method, params)| JsonRpcRequest::new(*id, method, params.clone()))
            .collect();

        let request_json = serde_json::to_string(&batch)?;

        let mut conn = self.connection.lock().await;

        // Send batch request
        let request_line = format!("{}\n", request_json);

        match &mut *conn {
            Connection::Tcp(reader) => {
                reader.get_mut().write_all(request_line.as_bytes()).await?;
                reader.get_mut().flush().await?;
            }
            Connection::Tls(reader) => {
                reader.get_mut().write_all(request_line.as_bytes()).await?;
                reader.get_mut().flush().await?;
            }
        }

        // Read response
        let mut response_line = String::new();

        let bytes_read = tokio::time::timeout(self.config.timeout, async {
            match &mut *conn {
                Connection::Tcp(reader) => reader.read_line(&mut response_line).await,
                Connection::Tls(reader) => reader.read_line(&mut response_line).await,
            }
        })
        .await
        .map_err(|_| ElectrumError::Timeout)??;

        if bytes_read == 0 {
            return Err(ElectrumError::Disconnected);
        }

        // Parse batch response
        let responses: Vec<JsonRpcResponse> = serde_json::from_str(&response_line)?;

        // Extract results in order
        let mut results = Vec::with_capacity(responses.len());
        for response in responses {
            if let Some(error) = response.error {
                return Err(ElectrumError::ServerError {
                    code: error.code,
                    message: error.message,
                });
            }
            results.push(
                response
                    .result
                    .ok_or_else(|| ElectrumError::InvalidResponse("Missing result".into()))?,
            );
        }

        Ok(results)
    }

    /// Get the current configuration.
    pub fn config(&self) -> &ClientConfig {
        &self.config
    }
}
