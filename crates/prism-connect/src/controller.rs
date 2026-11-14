//! Thin client for mihomo's external-controller REST API.

use std::time::{Duration, Instant};

use futures_util::StreamExt;
use serde_json::Value;

use crate::error::{Error, Result};

/// Never uses system/env proxies: the controller is local, and the system proxy may be us.
pub fn http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(30))
        .build()
        .expect("http client")
}

/// Same, without a total timeout, for long-lived streaming bodies.
pub fn stream_client() -> reqwest::Client {
    reqwest::Client::builder()
        .no_proxy()
        .build()
        .expect("stream client")
}

#[derive(Clone)]
pub struct Controller {
    http: reqwest::Client,
    base: String,
    secret: String,
}

impl Controller {
    pub fn new(http: reqwest::Client, port: u16, secret: String) -> Self {
        Self {
            http,
            base: format!("http://127.0.0.1:{port}"),
            secret,
        }
    }

    fn builder(&self, method: &str, path: &str) -> Result<reqwest::RequestBuilder> {
        if !path.starts_with('/') {
            return Err(Error::msg("controller path must start with '/'"));
        }
        let m = reqwest::Method::from_bytes(method.to_uppercase().as_bytes())
            .map_err(|e| Error::msg(e.to_string()))?;
        Ok(self
            .http
            .request(m, format!("{}{}", self.base, path))
            .bearer_auth(&self.secret))
    }

    pub async fn request(&self, method: &str, path: &str, body: Option<Value>) -> Result<Value> {
        let mut rb = self.builder(method, path)?;
        if let Some(b) = body {
            rb = rb.json(&b);
        }
        let resp = rb.send().await?;
        let status = resp.status();
        let text = resp.text().await?;
        if !status.is_success() {
            let msg = serde_json::from_str::<Value>(&text)
                .ok()
                .and_then(|v| v.get("message").and_then(Value::as_str).map(String::from))
                .unwrap_or(text);
            return Err(Error::msg(format!("{} {}", status.as_u16(), msg.trim())));
        }
        if text.trim().is_empty() {
            return Ok(Value::Null);
        }
        Ok(serde_json::from_str(&text).unwrap_or(Value::String(text)))
    }

    pub async fn ready(&self) -> bool {
        self.request("GET", "/version", None).await.is_ok()
    }

    pub async fn wait_ready(&self, total: Duration) -> bool {
        let start = Instant::now();
        while start.elapsed() < total {
            if self.ready().await {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(150)).await;
        }
        false
    }

    /// Follow a line-delimited streaming endpoint (`/traffic`, `/logs`).
    pub async fn stream(
        &self,
        client: &reqwest::Client,
        path: &str,
        mut on_line: impl FnMut(&str) + Send,
    ) -> Result<()> {
        let rb = client
            .get(format!("{}{}", self.base, path))
            .bearer_auth(&self.secret);
        let resp = rb.send().await?;
        if !resp.status().is_success() {
            return Err(Error::msg(format!("stream {path}: {}", resp.status())));
        }
        let mut stream = resp.bytes_stream();
        let mut buf: Vec<u8> = Vec::new();
        while let Some(chunk) = stream.next().await {
            buf.extend_from_slice(&chunk?);
            while let Some(i) = buf.iter().position(|b| *b == b'\n') {
                let line: Vec<u8> = buf.drain(..=i).collect();
                let s = String::from_utf8_lossy(&line);
                let s = s.trim();
                if !s.is_empty() {
                    on_line(s);
                }
            }
        }
        Ok(())
    }
}
