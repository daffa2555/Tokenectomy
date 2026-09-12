use crate::redact::redact_secrets;
use serde_json::Value;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

#[derive(Debug, Clone, Default)]
pub struct ProxySanitizeStats {
    pub raw_chars: usize,
    pub sanitized_chars: usize,
    pub secrets_redacted: usize,
}

/// Real-time thread-safe metrics collector for FinOps and token economics monitoring.
#[derive(Debug)]
pub struct ProxyMetrics {
    pub start_time: Instant,
    pub total_requests: AtomicU64,
    pub total_raw_chars: AtomicU64,
    pub total_sanitized_chars: AtomicU64,
    pub total_secrets_redacted: AtomicU64,
}

impl Default for ProxyMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl ProxyMetrics {
    pub fn new() -> Self {
        Self {
            start_time: Instant::now(),
            total_requests: AtomicU64::new(0),
            total_raw_chars: AtomicU64::new(0),
            total_sanitized_chars: AtomicU64::new(0),
            total_secrets_redacted: AtomicU64::new(0),
        }
    }

    pub fn record(&self, raw: usize, sanitized: usize, secrets: usize) {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        self.total_raw_chars.fetch_add(raw as u64, Ordering::Relaxed);
        self.total_sanitized_chars.fetch_add(sanitized as u64, Ordering::Relaxed);
        self.total_secrets_redacted.fetch_add(secrets as u64, Ordering::Relaxed);
    }

    pub fn record_request(&self) {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
    }

    pub fn to_json(&self) -> serde_json::Value {
        let raw_chars = self.total_raw_chars.load(Ordering::Relaxed);
        let sanitized_chars = self.total_sanitized_chars.load(Ordering::Relaxed);
        let requests = self.total_requests.load(Ordering::Relaxed);
        let secrets = self.total_secrets_redacted.load(Ordering::Relaxed);
        let uptime = self.start_time.elapsed().as_secs();

        let raw_tokens = raw_chars / 4;
        let sanitized_tokens = sanitized_chars / 4;
        let tokens_saved = raw_tokens.saturating_sub(sanitized_tokens);
        let saved_pct = if raw_chars > 0 {
            (raw_chars.saturating_sub(sanitized_chars) as f64 / raw_chars as f64) * 100.0
        } else {
            0.0
        };

        // Standard blended LLM input token pricing: ~$3.00 per 1M prompt tokens ($0.003/1K)
        let cost_saved_usd = (tokens_saved as f64 / 1_000_000.0) * 3.0;

        serde_json::json!({
            "status": "ok",
            "service": "tokenectomy-gateway",
            "version": env!("CARGO_PKG_VERSION"),
            "uptime_seconds": uptime,
            "total_requests": requests,
            "raw_characters": raw_chars,
            "sanitized_characters": sanitized_chars,
            "estimated_raw_tokens": raw_tokens,
            "estimated_sanitized_tokens": sanitized_tokens,
            "estimated_tokens_saved": tokens_saved,
            "reduction_percentage": (saved_pct * 10.0).round() / 10.0,
            "secrets_redacted": secrets,
            "estimated_cost_saved_usd": (cost_saved_usd * 1000.0).round() / 1000.0,
            "blended_rate_per_million": 3.00
        })
    }
}

/// Surgically cleans prompt payload: redacts secrets and strips framework dependency noise.
pub fn sanitize_prompt_payload(payload: &Value) -> (Value, ProxySanitizeStats) {
    let mut stats = ProxySanitizeStats::default();
    let mut modified = payload.clone();

    fn clean_string(text: &str, stats: &mut ProxySanitizeStats) -> String {
        stats.raw_chars += text.len();
        let redacted = redact_secrets(text);
        if redacted != text {
            stats.secrets_redacted += 1;
        }
        let final_content = crate::extractor::prune_framework_noise(&redacted);
        stats.sanitized_chars += final_content.len();
        final_content
    }

    // 1. Process "messages" array (OpenAI, Anthropic, Ollama chat completions)
    if let Some(messages) = modified.get_mut("messages").and_then(|m| m.as_array_mut()) {
        for msg in messages {
            if let Some(content) = msg.get_mut("content") {
                match content {
                    Value::String(s) => {
                        *s = clean_string(s, &mut stats);
                    }
                    Value::Array(parts) => {
                        for part in parts {
                            if let Some(text_val) = part.get_mut("text").and_then(|t| t.as_str()) {
                                let cleaned = clean_string(text_val, &mut stats);
                                part["text"] = Value::String(cleaned);
                            } else if let Some(content_val) = part.get_mut("content").and_then(|c| c.as_str()) {
                                let cleaned = clean_string(content_val, &mut stats);
                                part["content"] = Value::String(cleaned);
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    // 2. Process top-level "system" prompt (Anthropic Claude Messages API)
    if let Some(system) = modified.get_mut("system") {
        match system {
            Value::String(s) => {
                *s = clean_string(s, &mut stats);
            }
            Value::Array(parts) => {
                for part in parts {
                    if let Some(text_val) = part.get_mut("text").and_then(|t| t.as_str()) {
                        let cleaned = clean_string(text_val, &mut stats);
                        part["text"] = Value::String(cleaned);
                    }
                }
            }
            _ => {}
        }
    }

    // 3. Process top-level "prompt" (OpenAI Completions API, Ollama /api/generate)
    if let Some(prompt) = modified.get_mut("prompt") {
        if let Some(s) = prompt.as_str() {
            let cleaned = clean_string(s, &mut stats);
            *prompt = Value::String(cleaned);
        }
    }

    // 4. Process top-level "input" (OpenAI Embeddings / Transforms)
    if let Some(input) = modified.get_mut("input") {
        match input {
            Value::String(s) => {
                *s = clean_string(s, &mut stats);
            }
            Value::Array(items) => {
                for item in items {
                    if let Some(s) = item.as_str() {
                        let cleaned = clean_string(s, &mut stats);
                        *item = Value::String(cleaned);
                    }
                }
            }
            _ => {}
        }
    }

    (modified, stats)
}

pub const MAX_HEADER_SIZE: usize = 64 * 1024; // 64 KB
pub const MAX_BODY_SIZE: usize = 10 * 1024 * 1024; // 10 MB
pub const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
pub const UPSTREAM_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);
pub const MAX_CONCURRENT_CONNECTIONS: usize = 128;

/// Checks if a bind address is strictly local loopback (127.0.0.1, localhost, ::1).
pub fn is_loopback(bind_addr: &str) -> bool {
    let clean = bind_addr.trim();
    if clean == "localhost" || clean == "127.0.0.1" || clean == "::1" || clean == "[::1]" {
        return true;
    }
    if let Ok(ip) = clean.parse::<std::net::IpAddr>() {
        return ip.is_loopback();
    }
    if let Ok(addr) = clean.parse::<std::net::SocketAddr>() {
        return addr.ip().is_loopback();
    }
    if let Some((host, _)) = clean.rsplit_once(':') {
        let host_clean = host.trim_matches(|c| c == '[' || c == ']');
        if host_clean == "localhost" || host_clean == "127.0.0.1" || host_clean == "::1" {
            return true;
        }
        if let Ok(ip) = host_clean.parse::<std::net::IpAddr>() {
            return ip.is_loopback();
        }
    }
    false
}

/// Runs the AI Gateway Reverse Proxy on the specified bind address (default loopback).
pub async fn run_reverse_proxy(bind_addr: &str, upstream_url: &str) -> anyhow::Result<()> {
    run_reverse_proxy_configured(bind_addr, upstream_url, false, None).await
}

/// Runs the AI Gateway Reverse Proxy with explicit remote binding authorization and security limits.
pub async fn run_reverse_proxy_configured(
    bind_addr: &str,
    upstream_url: &str,
    allow_remote: bool,
    auth_token: Option<&str>,
) -> anyhow::Result<()> {
    let loopback = is_loopback(bind_addr);
    if !loopback {
        if !allow_remote {
            return Err(anyhow::anyhow!(
                "Security Violation: Binding to non-loopback address '{}' requires explicit '--allow-remote' flag.",
                bind_addr
            ));
        }
        if auth_token.is_none() || auth_token.map(|t| t.trim().is_empty()).unwrap_or(true) {
            return Err(anyhow::anyhow!(
                "Security Violation: Remote proxy mode on '{}' requires an authentication token via '--proxy-token' or 'TOKENECTOMY_PROXY_TOKEN'.",
                bind_addr
            ));
        }
    }

    let listener = TcpListener::bind(bind_addr).await?;
    let client = reqwest::Client::builder()
        .tcp_nodelay(true)
        .timeout(UPSTREAM_TIMEOUT)
        .build()?;
    let client = Arc::new(client);
    let upstream = Arc::new(upstream_url.trim_end_matches('/').to_string());
    let required_token = auth_token.map(|t| Arc::new(t.trim().to_string()));
    let semaphore = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_CONNECTIONS));
    let analyzer_state = Arc::new(crate::analyzer::AppState::new());
    let metrics = Arc::new(ProxyMetrics::new());

    println!("⚡ Tokenectomy AI Gateway Proxy active on http://{}", bind_addr);
    println!("📊 Real-Time FinOps Dashboard: http://{}/dashboard", bind_addr);
    println!("📈 Prometheus / JSON Metrics: http://{}/v1/metrics", bind_addr);
    println!("🔗 Forwarding to upstream: {}", upstream);
    if !loopback {
        println!("🔒 Remote mode ACTIVE (Protected with mandatory bearer authentication)");
    }
    println!("🛡️ Active filters: Zero-Leak Redaction + Polyglot Framework Surgery + AST Analyzer");

    loop {
        let (mut socket, peer_addr) = listener.accept().await?;
        let _ = socket.set_nodelay(true);
        let permit = match semaphore.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                log::warn!("Connection limit reached (max {}). Dropping {}", MAX_CONCURRENT_CONNECTIONS, peer_addr);
                let resp = "HTTP/1.1 503 Service Unavailable\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{\"error\":{\"message\":\"Proxy connection capacity saturated\",\"code\":503}}\r\n";
                let _ = socket.write_all(resp.as_bytes()).await;
                continue;
            }
        };

        let client_clone = Arc::clone(&client);
        let upstream_clone = Arc::clone(&upstream);
        let token_clone = required_token.clone();
        let analyzer_clone = Arc::clone(&analyzer_state);
        let metrics_clone = Arc::clone(&metrics);

        tokio::spawn(async move {
            let _permit = permit;
            let handler = async {
                let mut buf = vec![0u8; 16384];
                let mut total_read = 0;

                // Read HTTP request headers with MAX_HEADER_SIZE bound
                while total_read < MAX_HEADER_SIZE {
                    if buf.len() <= total_read {
                        buf.resize(buf.len() * 2, 0);
                    }
                    match socket.read(&mut buf[total_read..]).await {
                        Ok(0) => break,
                        Ok(n) => {
                            total_read += n;
                            if buf[..total_read].windows(4).any(|w| w == b"\r\n\r\n") {
                                break;
                            }
                        }
                        Err(e) => {
                            log::error!("Socket read error from {}: {}", peer_addr, e);
                            return;
                        }
                    }
                }

                if total_read == 0 {
                    return;
                }

                let req_str = String::from_utf8_lossy(&buf[..total_read]);
                let header_end = match req_str.find("\r\n\r\n") {
                    Some(idx) => idx,
                    None => {
                        let resp = "HTTP/1.1 431 Request Header Fields Too Large\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{\"error\":{\"message\":\"Headers exceed 64KB limit\",\"code\":431}}\r\n";
                        let _ = socket.write_all(resp.as_bytes()).await;
                        return;
                    }
                };

                let raw_headers = &req_str[..header_end];
                let body_start = header_end + 4;
                let mut lines = raw_headers.split("\r\n");
                let req_line = lines.next().unwrap_or("");
                let parts: Vec<&str> = req_line.split_whitespace().collect();

                if parts.len() < 2 {
                    return;
                }

                let method = parts[0];
                let full_path = parts[1];
                let (raw_path_no_query, _) = full_path.split_once('?').unwrap_or((full_path, ""));
                let path = if raw_path_no_query.len() > 1 && raw_path_no_query.ends_with('/') {
                    raw_path_no_query.trim_end_matches('/')
                } else {
                    raw_path_no_query
                };

                // Health check endpoint
                if path == "/health" || path == "/v1/health" {
                    let body = format!(
                        "{{\"status\":\"ok\",\"service\":\"tokenectomy-gateway\",\"version\":\"{}\"}}\r\n",
                        env!("CARGO_PKG_VERSION")
                    );
                    let resp = if method == "HEAD" {
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            body.len()
                        )
                    } else {
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        )
                    };
                    let _ = socket.write_all(resp.as_bytes()).await;
                    return;
                }

                // Prometheus / JSON Metrics API endpoint
                if path == "/v1/metrics" || path == "/metrics" {
                    let metrics_json = metrics_clone.to_json().to_string();
                    let resp = if method == "HEAD" {
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            metrics_json.len()
                        )
                    } else {
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            metrics_json.len(),
                            metrics_json
                        )
                    };
                    let _ = socket.write_all(resp.as_bytes()).await;
                    return;
                }

                // Embedded FinOps Dashboard UI
                if (method == "GET" || method == "HEAD") && (path == "/dashboard" || path == "/" || path == "/ui") {
                    let html = crate::dashboard::render_dashboard_html();
                    let resp = if method == "HEAD" {
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            html.len()
                        )
                    } else {
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            html.len(),
                            html
                        )
                    };
                    let _ = socket.write_all(resp.as_bytes()).await;
                    return;
                }

                // Extract Content-Length & Authorization, and collect client headers for upstream forwarding
                let mut content_length = 0;
                let mut client_auth = None;
                let mut forward_headers = Vec::new();

                for h in raw_headers.lines().skip(1) {
                    if let Some((k, v)) = h.split_once(':') {
                        let k_clean = k.trim();
                        let v_clean = v.trim();
                        let k_lower = k_clean.to_ascii_lowercase();

                        if k_lower == "content-length" {
                            content_length = v_clean.parse::<usize>().unwrap_or(0);
                        } else if k_lower == "authorization" {
                            client_auth = Some(v_clean.to_string());
                        } else if k_lower == "x-api-key" && client_auth.is_none() {
                            client_auth = Some(format!("Bearer {}", v_clean));
                        }

                        // RFC 7230 §6.1: Strip hop-by-hop headers and Host header
                        if k_lower != "content-length"
                            && k_lower != "connection"
                            && k_lower != "transfer-encoding"
                            && k_lower != "keep-alive"
                            && k_lower != "proxy-connection"
                            && k_lower != "upgrade"
                            && k_lower != "host"
                        {
                            forward_headers.push((k_clean.to_string(), v_clean.to_string()));
                        }
                    }
                }

                // Enforce authentication for remote mode
                if let Some(expected_token) = &token_clone {
                    let is_authed = match &client_auth {
                        Some(auth) => {
                            let token_part = auth.strip_prefix("Bearer ").unwrap_or(auth.as_str()).trim();
                            token_part == expected_token.as_str()
                        }
                        None => false,
                    };
                    if !is_authed {
                        let resp = "HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{\"error\":{\"message\":\"Unauthorized: Missing or invalid proxy authorization token\",\"code\":401}}\r\n";
                        let _ = socket.write_all(resp.as_bytes()).await;
                        return;
                    }
                }

                // Enforce MAX_BODY_SIZE
                if content_length > MAX_BODY_SIZE {
                    let resp = "HTTP/1.1 413 Payload Too Large\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{\"error\":{\"message\":\"Payload exceeds 10MB limit\",\"code\":413}}\r\n";
                    let _ = socket.write_all(resp.as_bytes()).await;
                    return;
                }

                // Read remaining body
                let mut body_bytes = buf[body_start..total_read].to_vec();
                while body_bytes.len() < content_length {
                    let to_read = (content_length - body_bytes.len()).min(16384);
                    let mut temp = vec![0u8; to_read];
                    match socket.read(&mut temp).await {
                        Ok(0) => break,
                        Ok(n) => body_bytes.extend_from_slice(&temp[..n]),
                        Err(_) => break,
                    }
                }

                // Handle /v1/analyze or /analyze directly on the gateway (#17, #18, #19, #20)
                if method == "POST" && (path == "/v1/analyze" || path == "/analyze") {
                    if let Ok(analyze_req) = serde_json::from_slice::<crate::analyzer::AnalyzeRequest>(&body_bytes) {
                        match crate::analyzer::analyze_source(&analyzer_clone, &analyze_req.language, &analyze_req.code) {
                            Ok(resp) => {
                                eprintln!(
                                    "⚡ [Proxy] /v1/analyze from {}: {} findings, {:.2}ms",
                                    peer_addr, resp.total_findings, resp.duration_ms
                                );
                                let res_json = serde_json::to_string(&resp).unwrap_or_default();
                                let resp_http = format!(
                                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                    res_json.len(),
                                    res_json
                                );
                                let _ = socket.write_all(resp_http.as_bytes()).await;
                                return;
                            }
                            Err(e) => {
                                let err_json = serde_json::json!({
                                    "version": "v1",
                                    "status": "error",
                                    "error": e
                                }).to_string();
                                let resp_http = format!(
                                    "HTTP/1.1 422 Unprocessable Entity\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                    err_json.len(),
                                    err_json
                                );
                                let _ = socket.write_all(resp_http.as_bytes()).await;
                                return;
                            }
                        }
                    } else {
                        let err_json = serde_json::json!({
                            "error": "Invalid JSON payload for /v1/analyze"
                        }).to_string();
                        let resp_http = format!(
                            "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            err_json.len(),
                            err_json
                        );
                        let _ = socket.write_all(resp_http.as_bytes()).await;
                        return;
                    }
                }

                // Process and sanitize body if JSON
                let mut final_body = body_bytes;
                if let Ok(json) = serde_json::from_slice::<Value>(&final_body) {
                    let (sanitized, stats) = sanitize_prompt_payload(&json);
                    metrics_clone.record(stats.raw_chars, stats.sanitized_chars, stats.secrets_redacted);
                    if stats.secrets_redacted > 0 || stats.raw_chars > stats.sanitized_chars {
                        let saved_pct = if stats.raw_chars > 0 {
                            (stats.raw_chars.saturating_sub(stats.sanitized_chars) as f64 / stats.raw_chars as f64) * 100.0
                        } else {
                            0.0
                        };
                        eprintln!(
                            "⚡ [Proxy] Sanitized request from {}: -{:.1}% noise cut, {} secrets redacted",
                            peer_addr, saved_pct, stats.secrets_redacted
                        );
                    }
                    if let Ok(new_bytes) = serde_json::to_vec(&sanitized) {
                        final_body = new_bytes;
                    }
                } else {
                    metrics_clone.record_request();
                }

                // Forward to upstream with complete query string preserved
                let target_url = format!("{}{}", upstream_clone, full_path);
                let mut req_builder = match method {
                    "POST" => client_clone.post(&target_url),
                    "GET" => client_clone.get(&target_url),
                    _ => client_clone.request(
                        reqwest::Method::from_bytes(method.as_bytes()).unwrap_or(reqwest::Method::GET),
                        &target_url,
                    ),
                };

                for (hk, hv) in forward_headers {
                    req_builder = req_builder.header(hk, hv);
                }

                if let Some(auth) = client_auth {
                    req_builder = req_builder.header("Authorization", auth);
                }
                req_builder = req_builder
                    .header("Content-Type", "application/json")
                    .body(final_body);

                match req_builder.send().await {
                    Ok(mut upstream_resp) => {
                        let status = upstream_resp.status();
                        let mut head = format!("HTTP/1.1 {} {}\r\n", status.as_u16(), status.canonical_reason().unwrap_or(""));
                        for (k, v) in upstream_resp.headers() {
                            let k_lower = k.as_str().to_ascii_lowercase();
                            // RFC 7230 §6.1: Strip hop-by-hop headers to prevent chunked framing mismatches
                            if k_lower == "transfer-encoding"
                                || k_lower == "connection"
                                || k_lower == "keep-alive"
                                || k_lower == "proxy-connection"
                                || k_lower == "upgrade"
                            {
                                continue;
                            }
                            head.push_str(&format!("{}: {}\r\n", k.as_str(), v.to_str().unwrap_or("")));
                        }
                        head.push_str("Connection: close\r\n\r\n");
                        let _ = socket.write_all(head.as_bytes()).await;

                        while let Ok(Some(chunk)) = upstream_resp.chunk().await {
                            if socket.write_all(&chunk).await.is_err() {
                                break;
                            }
                            let _ = socket.flush().await;
                        }
                        let _ = socket.flush().await;
                    }
                    Err(e) => {
                        let err_json = serde_json::json!({
                            "error": {
                                "message": format!("Tokenectomy Gateway: Failed to reach upstream: {}", e),
                                "type": "bad_gateway",
                                "code": 502
                            }
                        });
                        let resp = format!(
                            "HTTP/1.1 502 Bad Gateway\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{}\r\n",
                            err_json
                        );
                        let _ = socket.write_all(resp.as_bytes()).await;
                    }
                }
            };

            if let Err(_) = tokio::time::timeout(REQUEST_TIMEOUT, handler).await {
                log::warn!("Proxy connection from {} timed out after {}s", peer_addr, REQUEST_TIMEOUT.as_secs());
            }
        });
    }
}
