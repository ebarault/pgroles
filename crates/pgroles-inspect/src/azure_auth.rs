//! Microsoft Entra tokens for Azure Database for PostgreSQL Flexible Server.
//! The projected AKS service account token is exchanged for a database token;
//! neither token is persisted in a Kubernetes Secret or PostgreSQL URL config.

use std::path::Path;
use std::time::{Duration, SystemTime};

use serde::Deserialize;
use thiserror::Error;

pub const POSTGRES_SCOPE: &str = "https://ossrdbms-aad.database.windows.net/.default";
const ASSERTION_TYPE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

#[derive(Debug, Error)]
pub enum AzureAuthError {
    #[error("missing Azure Workload Identity environment variable {0}")]
    MissingEnvironment(&'static str),
    #[error("invalid Azure tenant ID")]
    InvalidTenant,
    #[error("failed to read projected Azure federated token: {0}")]
    ReadAssertion(#[from] std::io::Error),
    #[error("Azure token request failed: {0}")]
    Request(#[from] reqwest::Error),
    #[error("Azure token endpoint returned HTTP {0}")]
    Rejected(u16),
    #[error("Azure token response has no usable access token or expiry")]
    InvalidResponse,
}

#[derive(Debug)]
pub struct AccessToken {
    pub value: String,
    pub expires_at: SystemTime,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    expires_in: u64,
}

/// Read the current projected assertion on every call so AKS rotation is used.
pub async fn fetch_workload_identity_token() -> Result<AccessToken, AzureAuthError> {
    let client_id = std::env::var("AZURE_CLIENT_ID")
        .map_err(|_| AzureAuthError::MissingEnvironment("AZURE_CLIENT_ID"))?;
    let tenant_id = std::env::var("AZURE_TENANT_ID")
        .map_err(|_| AzureAuthError::MissingEnvironment("AZURE_TENANT_ID"))?;
    let token_file = std::env::var("AZURE_FEDERATED_TOKEN_FILE")
        .map_err(|_| AzureAuthError::MissingEnvironment("AZURE_FEDERATED_TOKEN_FILE"))?;
    if tenant_id.is_empty()
        || !tenant_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
    {
        return Err(AzureAuthError::InvalidTenant);
    }
    let endpoint = format!("https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token");
    fetch_token(
        &reqwest::Client::new(),
        &endpoint,
        &client_id,
        Path::new(&token_file),
    )
    .await
}

async fn fetch_token(
    client: &reqwest::Client,
    endpoint: &str,
    client_id: &str,
    token_file: &Path,
) -> Result<AccessToken, AzureAuthError> {
    let assertion = tokio::fs::read_to_string(token_file).await?;
    if assertion.trim().is_empty() || client_id.trim().is_empty() {
        return Err(AzureAuthError::InvalidResponse);
    }
    let response = client
        .post(endpoint)
        .timeout(Duration::from_secs(10))
        .form(&[
            ("client_id", client_id),
            ("scope", POSTGRES_SCOPE),
            ("grant_type", "client_credentials"),
            ("client_assertion_type", ASSERTION_TYPE),
            ("client_assertion", assertion.trim()),
        ])
        .send()
        .await?;
    if !response.status().is_success() {
        return Err(AzureAuthError::Rejected(response.status().as_u16()));
    }
    let body: TokenResponse = response.json().await?;
    if body.access_token.trim().is_empty() || body.expires_in == 0 {
        return Err(AzureAuthError::InvalidResponse);
    }
    Ok(AccessToken {
        value: body.access_token,
        expires_at: SystemTime::now() + Duration::from_secs(body.expires_in),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn exchanges_projected_assertion() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}/token", listener.local_addr().unwrap());
        let token_file =
            std::env::temp_dir().join(format!("pgroles-azure-test-{}", std::process::id()));
        tokio::fs::write(&token_file, "projected-assertion")
            .await
            .unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            while !String::from_utf8_lossy(&request)
                .contains("client_assertion=projected-assertion")
            {
                let mut chunk = [0; 1024];
                let size = socket.read(&mut chunk).await.unwrap();
                assert!(size > 0 && request.len() < 4096);
                request.extend_from_slice(&chunk[..size]);
            }
            let request = String::from_utf8_lossy(&request);
            assert!(request.contains("client_assertion=projected-assertion"));
            assert!(request.contains("client_id=client-id"));
            let body = r#"{"access_token":"database-token","expires_in":3600}"#;
            socket.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes()).await.unwrap();
        });
        let result = fetch_token(&reqwest::Client::new(), &endpoint, "client-id", &token_file)
            .await
            .unwrap();
        assert_eq!(result.value, "database-token");
        assert!(result.expires_at > SystemTime::now() + Duration::from_secs(3500));
        server.await.unwrap();
        tokio::fs::remove_file(token_file).await.unwrap();
    }

    #[tokio::test]
    async fn reads_rotated_assertion_for_each_token_request() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}/token", listener.local_addr().unwrap());
        let token_file =
            std::env::temp_dir().join(format!("pgroles-azure-rotate-{}", std::process::id()));
        tokio::fs::write(&token_file, "first-assertion")
            .await
            .unwrap();
        let server = tokio::spawn(async move {
            for expected in ["first-assertion", "second-assertion"] {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                while !String::from_utf8_lossy(&request).contains(expected) {
                    let mut chunk = [0; 1024];
                    let size = socket.read(&mut chunk).await.unwrap();
                    assert!(size > 0 && request.len() < 4096);
                    request.extend_from_slice(&chunk[..size]);
                }
                let body = r#"{"access_token":"database-token","expires_in":3600}"#;
                socket.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes()).await.unwrap();
            }
        });
        let client = reqwest::Client::new();
        fetch_token(&client, &endpoint, "client-id", &token_file)
            .await
            .unwrap();
        tokio::fs::write(&token_file, "second-assertion")
            .await
            .unwrap();
        fetch_token(&client, &endpoint, "client-id", &token_file)
            .await
            .unwrap();
        server.await.unwrap();
        tokio::fs::remove_file(token_file).await.unwrap();
    }
}
