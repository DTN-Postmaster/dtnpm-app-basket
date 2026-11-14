//! Resource fetching (`http`/`https`, `gemini`, `file`, static mappings), SSRF / DNS-rebinding
//! protection, path-traversal checks, streaming size bounds, and bibliographic search/listing.

use crate::config::Config;
use anyhow::Result;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::error::Error as StdError;
use std::ffi::OsString;
use std::io::Read as _;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

/// TCP connect timeout for outbound HTTP(S) and Gemini requests.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Overall request timeout for outbound HTTP(S) and Gemini requests.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// Maximum Gemini response status header length including CRLF (`2 + 1 + 1024 = 1027` bytes).
pub const GEMINI_HEADER_MAX_BYTES: u64 = 1027;
/// Maximum compiled regex size (1 MiB) in `SEARCH` / `LIST`.
pub const REGEX_SIZE_LIMIT: usize = 1 << 20;
/// Maximum number of results returned by `perform_search`.
pub const MAX_SEARCH_RESULTS: usize = 100;

/// Custom error type used by [`SafeDnsResolver`] so SSRF rejections are preserved in error chains.
#[derive(Debug, Clone)]
pub struct SsrfDeniedError(pub String);

impl std::fmt::Display for SsrfDeniedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl StdError for SsrfDeniedError {}

/// Errors produced while validating or fetching a requested URI.
#[derive(Debug)]
pub enum FetchError {
    PayloadTooLarge,
    Forbidden(String),
    NotFound(String),
    Redirect(String),
    Other(String),
}

impl std::fmt::Display for FetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PayloadTooLarge => write!(f, "Payload too large"),
            Self::Forbidden(msg) => write!(f, "Access denied: {}", msg),
            Self::NotFound(msg) => write!(f, "Not found: {}", msg),
            Self::Redirect(target) => write!(f, "Redirect: {}", target),
            Self::Other(msg) => write!(f, "{}", msg),
        }
    }
}

impl StdError for FetchError {}

// Custom self-signed certificate verifier for opt-in insecure TLS mode.
#[derive(Debug)]
struct SelfSignedVerifier;

impl ServerCertVerifier for SelfSignedVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::ED448,
        ]
    }
}

/// Ensure a `rustls` process-level `CryptoProvider` is installed when both `aws-lc-rs`
/// and `ring` features exist in the workspace dependency graph.
fn ensure_rustls_provider() {
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    }
}

/// Build the `rustls` TLS connector for Gemini fetches.
pub fn build_tls_connector(insecure_tls: bool) -> Result<tokio_rustls::TlsConnector> {
    ensure_rustls_provider();
    let client_config = if insecure_tls {
        let mut config = ClientConfig::builder()
            .with_root_certificates(RootCertStore::empty())
            .with_no_client_auth();
        config
            .dangerous()
            .set_certificate_verifier(Arc::new(SelfSignedVerifier));
        config
    } else {
        let root_store = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth()
    };

    Ok(tokio_rustls::TlsConnector::from(Arc::new(client_config)))
}

/// Build a hardened `reqwest::Client` configured with timeouts and [`SafeDnsResolver`].
///
/// Uses `Policy::none()` so `fetch_resource` explicitly validates every redirect target
/// (including scheme restrictions and SSRF checks) before issuing the next hop.
pub fn build_http_client(insecure_tls: bool, allow_private_ips: bool) -> Result<reqwest::Client> {
    ensure_rustls_provider();
    let mut client_builder = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(REQUEST_TIMEOUT)
        .dns_resolver(Arc::new(SafeDnsResolver { allow_private_ips }));
    if insecure_tls {
        client_builder = client_builder
            .danger_accept_invalid_certs(true)
            .danger_accept_invalid_hostnames(true);
    }
    Ok(client_builder.build()?)
}

/// Check whether an IP address is a globally routable unicast address safe for outbound fetches.
///
/// Rejects loopback, unspecified, multicast, broadcast, private (RFC 1918), link-local
/// (169.254.0.0/16, fe80::/10), CGNAT (100.64.0.0/10), benchmarking (198.18.0.0/15, 2001:2::/48),
/// documentation ranges (TEST-NET-1/2/3, 2001:db8::/32, 3fff::/20), ULA (fc00::/7), site-local,
/// discard-only, reserved 240.0.0.0/4, and IPv4-mapped/compatible/translated/NAT64 addresses
/// wrapping unsafe IPv4 targets.
pub fn is_safe_ip(ip: IpAddr) -> bool {
    if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() {
        return false;
    }
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            // 0.0.0.0/8 ("this network")
            if octets[0] == 0 {
                return false;
            }
            // RFC 6598 CGNAT / Shared Address Space (100.64.0.0/10)
            if octets[0] == 100 && (octets[1] & 0b1100_0000) == 64 {
                return false;
            }
            // RFC 6890 IETF Protocol Assignments (192.0.0.0/24)
            if octets[0] == 192 && octets[1] == 0 && octets[2] == 0 {
                return false;
            }
            // RFC 2544 Benchmarking (198.18.0.0/15)
            if octets[0] == 198 && (octets[1] & 0xfe) == 18 {
                return false;
            }
            // Reserved / Future use (240.0.0.0/4, includes 255.255.255.255)
            if octets[0] >= 240 {
                return false;
            }
            !v4.is_private() && !v4.is_link_local() && !v4.is_broadcast() && !v4.is_documentation()
        }
        IpAddr::V6(v6) => {
            // IPv4-mapped IPv6 address (::ffff:x.x.x.x)
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_safe_ip(IpAddr::V4(v4));
            }
            let segs = v6.segments();
            // Deprecated IPv4-compatible IPv6 (::/96)
            if segs[..6] == [0, 0, 0, 0, 0, 0] {
                let v4 = Ipv4Addr::from(((segs[6] as u32) << 16) | (segs[7] as u32));
                return is_safe_ip(IpAddr::V4(v4));
            }
            // IPv4-translated IPv6 (::ffff:0:0:0/96)
            if segs[..6] == [0, 0, 0, 0, 0xffff, 0] {
                let v4 = Ipv4Addr::from(((segs[6] as u32) << 16) | (segs[7] as u32));
                return is_safe_ip(IpAddr::V4(v4));
            }
            // NAT64 well-known prefix (64:ff9b::/96)
            if segs[0] == 0x0064 && segs[1] == 0xff9b && segs[2..6] == [0, 0, 0, 0] {
                let v4 = Ipv4Addr::from(((segs[6] as u32) << 16) | (segs[7] as u32));
                return is_safe_ip(IpAddr::V4(v4));
            }
            // NAT64 local-use prefix (64:ff9b:1::/48)
            if segs[0] == 0x0064 && segs[1] == 0xff9b && segs[2] == 0x0001 {
                return false;
            }
            // Link-local (fe80::/10)
            let is_link_local = (segs[0] & 0xffc0) == 0xfe80;
            // Deprecated site-local (fec0::/10)
            let is_site_local = (segs[0] & 0xffc0) == 0xfec0;
            // Unique Local Address (fc00::/7)
            let is_unique_local = (segs[0] & 0xfe00) == 0xfc00;
            // Documentation (2001:db8::/32 and RFC 9637 3fff::/20)
            let is_doc = (segs[0] == 0x2001 && segs[1] == 0x0db8)
                || (segs[0] == 0x3fff && (segs[1] & 0xf000) == 0);
            // Benchmarking (2001:2::/48)
            let is_bench = segs[0] == 0x2001 && segs[1] == 0x0002 && segs[2] == 0;
            // Discard-only (100::/64)
            let is_discard = segs[0] == 0x0100 && segs[1] == 0 && segs[2] == 0 && segs[3] == 0;

            !is_link_local
                && !is_site_local
                && !is_unique_local
                && !is_doc
                && !is_bench
                && !is_discard
        }
    }
}

/// Validate a resolved address list against SSRF rules.
///
/// Rejects empty results and rejects immediately if `!allow_private_ips` and **any**
/// resolved address is unsafe (defeating dual-record DNS rebinding).
pub fn validate_resolved_addrs(
    addrs: Vec<SocketAddr>,
    allow_private_ips: bool,
) -> std::result::Result<Vec<SocketAddr>, SsrfDeniedError> {
    if addrs.is_empty() {
        return Err(SsrfDeniedError(
            "DNS resolution returned no addresses".to_string(),
        ));
    }
    if !allow_private_ips {
        for addr in &addrs {
            if !is_safe_ip(addr.ip()) {
                return Err(SsrfDeniedError(format!(
                    "Forbidden resolved IP address (SSRF protection): {}",
                    addr.ip()
                )));
            }
        }
    }
    Ok(addrs)
}

/// Resolve a hostname or IP literal and validate every returned address at connect time.
pub async fn resolve_and_validate_host(
    host: &str,
    port: u16,
    allow_private_ips: bool,
) -> std::result::Result<Vec<SocketAddr>, FetchError> {
    let host_clean = host.trim().trim_start_matches('[').trim_end_matches(']');
    if host_clean.is_empty() {
        return Err(FetchError::Forbidden("Empty host".to_string()));
    }

    if let Ok(ip) = host_clean.parse::<IpAddr>() {
        return validate_resolved_addrs(vec![SocketAddr::new(ip, port)], allow_private_ips)
            .map_err(|e| FetchError::Forbidden(e.0));
    }

    if !allow_private_ips && host_clean.eq_ignore_ascii_case("localhost") {
        return Err(FetchError::Forbidden(
            "Forbidden host (SSRF protection): localhost".to_string(),
        ));
    }

    let lookup_iter = tokio::net::lookup_host((host_clean, port))
        .await
        .map_err(|e| {
            FetchError::NotFound(format!("DNS resolution failed for {host_clean}: {e}"))
        })?;
    let addrs: Vec<SocketAddr> = lookup_iter.collect();
    validate_resolved_addrs(addrs, allow_private_ips).map_err(|e| FetchError::Forbidden(e.0))
}

/// Custom `reqwest::dns::Resolve` implementation that enforces `is_safe_ip` at connection time.
#[derive(Debug, Clone, Copy)]
pub struct SafeDnsResolver {
    /// When `true`, private/loopback/link-local IPs are permitted (explicit opt-in).
    pub allow_private_ips: bool,
}

impl reqwest::dns::Resolve for SafeDnsResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let host = name.as_str().to_string();
        let allow_private_ips = self.allow_private_ips;
        Box::pin(async move {
            let host_clean = host.trim().trim_start_matches('[').trim_end_matches(']');
            if host_clean.is_empty() {
                let err: Box<dyn StdError + Send + Sync> =
                    Box::new(SsrfDeniedError("Empty DNS hostname".to_string()));
                return Err(err);
            }
            if let Ok(ip) = host_clean.parse::<IpAddr>() {
                let validated =
                    validate_resolved_addrs(vec![SocketAddr::new(ip, 0)], allow_private_ips)
                        .map_err(|e| -> Box<dyn StdError + Send + Sync> { Box::new(e) })?;
                let addrs: reqwest::dns::Addrs = Box::new(validated.into_iter());
                return Ok(addrs);
            }
            if !allow_private_ips && host_clean.eq_ignore_ascii_case("localhost") {
                let err: Box<dyn StdError + Send + Sync> = Box::new(SsrfDeniedError(
                    "Forbidden host (SSRF protection): localhost".to_string(),
                ));
                return Err(err);
            }
            let lookup_iter = tokio::net::lookup_host((host_clean, 0))
                .await
                .map_err(|e| -> Box<dyn StdError + Send + Sync> { Box::new(e) })?;
            let addrs: Vec<SocketAddr> = lookup_iter.collect();
            let validated = validate_resolved_addrs(addrs, allow_private_ips)
                .map_err(|e| -> Box<dyn StdError + Send + Sync> { Box::new(e) })?;
            let iter: reqwest::dns::Addrs = Box::new(validated.into_iter());
            Ok(iter)
        })
    }
}

fn error_has_ssrf_forbidden(err: &(dyn StdError + 'static)) -> bool {
    let mut current: Option<&(dyn StdError + 'static)> = Some(err);
    while let Some(e) = current {
        if e.downcast_ref::<SsrfDeniedError>().is_some() {
            return true;
        }
        current = e.source();
    }
    false
}

/// Check if a hostname or IP literal resolves exclusively to safe addresses.
pub async fn is_safe_host(host: &str, port: u16, allow_private_ips: bool) -> bool {
    resolve_and_validate_host(host, port, allow_private_ips)
        .await
        .is_ok()
}

/// Validate a parsed HTTP(S) or Gemini URL against SSRF policy.
///
/// Always returns `false` for hostless URLs (`parsed.host_str()` is `None`).
pub async fn check_url_ssrf(parsed: &reqwest::Url, allow_private_ips: bool) -> bool {
    let Some(host) = parsed.host_str().filter(|h| !h.is_empty()) else {
        return false;
    };
    let port = parsed.port_or_known_default().unwrap_or_else(|| {
        if parsed.scheme() == "gemini" {
            1965
        } else {
            80
        }
    });
    is_safe_host(host, port, allow_private_ips).await
}

/// Parse a `gemini://` URL into `(unbracketed_host, port, canonical_url)`.
pub fn parse_gemini_url(url: &str) -> Result<(String, u16, String)> {
    let trimmed = url.trim();
    if !trimmed.starts_with("gemini://") {
        return Err(anyhow::anyhow!("URL does not start with gemini://"));
    }
    let parsed = reqwest::Url::parse(trimmed)?;
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(anyhow::anyhow!("Gemini URL must not contain userinfo"));
    }
    let host = parsed
        .host_str()
        .filter(|h| !h.is_empty())
        .ok_or_else(|| anyhow::anyhow!("Gemini URL is missing a host"))?;
    let host_unbracketed = host.trim_start_matches('[').trim_end_matches(']');
    let port = parsed.port().unwrap_or(1965);
    Ok((host_unbracketed.to_string(), port, trimmed.to_string()))
}

/// Read an async byte stream incrementally, aborting immediately if size exceeds `max_size`.
pub async fn read_async_bounded<R: AsyncRead + Unpin>(
    mut reader: R,
    max_size: u64,
) -> std::result::Result<Vec<u8>, FetchError> {
    let mut body = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        let n = reader
            .read(&mut chunk)
            .await
            .map_err(|e| FetchError::Other(e.to_string()))?;
        if n == 0 {
            break;
        }
        if (body.len() as u64).saturating_add(n as u64) > max_size {
            return Err(FetchError::PayloadTooLarge);
        }
        body.extend_from_slice(&chunk[..n]);
    }
    Ok(body)
}

async fn read_gemini_response<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    full_url: &str,
    max_size: u64,
) -> std::result::Result<(Vec<u8>, String), FetchError> {
    let request = format!("{}\r\n", full_url);
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|e| FetchError::NotFound(e.to_string()))?;
    stream
        .flush()
        .await
        .map_err(|e| FetchError::NotFound(e.to_string()))?;

    let mut reader = BufReader::new(stream);

    // Bound header reads to 1027 bytes so a peer omitting `\n` cannot exhaust memory.
    let mut header_bytes = Vec::new();
    let n = (&mut reader)
        .take(GEMINI_HEADER_MAX_BYTES)
        .read_until(b'\n', &mut header_bytes)
        .await
        .map_err(|e| FetchError::NotFound(e.to_string()))?;
    if n == 0 {
        return Err(FetchError::NotFound(
            "Connection closed before header received".to_string(),
        ));
    }
    if !header_bytes.ends_with(b"\n") {
        return Err(FetchError::Other(
            "Response header too long or truncated without newline".to_string(),
        ));
    }

    let header_str = String::from_utf8_lossy(&header_bytes);
    let header_str = header_str.trim_end_matches(&['\r', '\n'][..]);
    let parts: Vec<&str> = header_str.splitn(2, ' ').collect();
    if parts.is_empty() {
        return Err(FetchError::Other(
            "Invalid Gemini response header".to_string(),
        ));
    }
    let status_str = parts[0];
    let meta = if parts.len() > 1 { parts[1] } else { "" };

    if status_str.len() != 2 {
        return Err(FetchError::Other(format!(
            "Invalid Gemini status code: {}",
            status_str
        )));
    }
    let status_char = status_str
        .chars()
        .next()
        .ok_or_else(|| FetchError::Other("Empty Gemini status string".to_string()))?;

    match status_char {
        '2' => {
            let mime = if meta.is_empty() {
                "text/gemini; charset=utf-8".to_string()
            } else {
                meta.to_string()
            };
            let body = read_async_bounded(reader, max_size).await?;
            Ok((body, mime))
        }
        '3' => Err(FetchError::Redirect(meta.to_string())),
        _ => Err(FetchError::NotFound(format!(
            "Gemini error status {}: {}",
            status_str, meta
        ))),
    }
}

async fn connect_validated_addrs(addrs: &[SocketAddr]) -> std::io::Result<TcpStream> {
    let mut last_err = None;
    for addr in addrs {
        match TcpStream::connect(*addr).await {
            Ok(stream) => return Ok(stream),
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err
        .unwrap_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "No addresses")))
}

async fn fetch_gemini(
    url_str: &str,
    connector: &tokio_rustls::TlsConnector,
    allow_private_ips: bool,
    max_size: u64,
) -> std::result::Result<(Vec<u8>, String), FetchError> {
    let (host, port, full_url) =
        parse_gemini_url(url_str).map_err(|e| FetchError::Other(e.to_string()))?;

    // Pre-resolve and validate every IP once, then connect directly to the validated SocketAddr(s)
    // so TcpStream::connect never re-resolves DNS (defeating TOCTOU DNS rebinding).
    let addrs = resolve_and_validate_host(&host, port, allow_private_ips).await?;
    let server_name = ServerName::try_from(host.clone())
        .map_err(|_| FetchError::Other(format!("Invalid server name: {}", host)))?
        .to_owned();

    tokio::time::timeout(REQUEST_TIMEOUT, async {
        let tcp_stream = tokio::time::timeout(CONNECT_TIMEOUT, connect_validated_addrs(&addrs))
            .await
            .map_err(|_| FetchError::NotFound("Gemini TCP connect timed out".to_string()))?
            .map_err(|e| FetchError::NotFound(e.to_string()))?;

        let tls_stream = connector
            .connect(server_name, tcp_stream)
            .await
            .map_err(|e| FetchError::NotFound(e.to_string()))?;

        read_gemini_response(tls_stream, &full_url, max_size).await
    })
    .await
    .map_err(|_| FetchError::NotFound("Gemini request timed out".to_string()))?
}

fn canonicalize_target_safely(path: &Path) -> Option<PathBuf> {
    let normalized_input = if path.is_relative() {
        std::env::current_dir().ok()?.join(path)
    } else {
        path.to_path_buf()
    };

    if let Ok(canon) = normalized_input.canonicalize() {
        return Some(canon);
    }

    // If the target exists as a dangling/broken symlink, reject it.
    if std::fs::symlink_metadata(&normalized_input).is_ok() {
        return None;
    }

    let mut tail: Vec<OsString> = Vec::new();
    let mut current = normalized_input;
    loop {
        if current
            .components()
            .next_back()
            .is_some_and(|c| !matches!(c, Component::Normal(_)))
        {
            return None;
        }
        let name = current.file_name()?.to_os_string();
        tail.push(name);
        if !current.pop() {
            return None;
        }
        if let Ok(canon_ancestor) = current.canonicalize() {
            let mut joined = canon_ancestor;
            for component in tail.into_iter().rev() {
                joined.push(component);
            }
            return Some(joined);
        }
        if std::fs::symlink_metadata(&current).is_ok() {
            return None;
        }
    }
}

/// Resolve `path` safely inside one of `allowed_dirs`, preventing symlink escapes outside roots.
pub fn resolve_safe_file_path(path: &Path, allowed_dirs: &[PathBuf]) -> Option<PathBuf> {
    let canon_target = canonicalize_target_safely(path)?;
    for dir in allowed_dirs {
        let Ok(canon_root) = dir.canonicalize() else {
            continue;
        };
        if canon_target.starts_with(&canon_root) {
            return Some(canon_target);
        }
    }
    None
}

/// Check whether `path` falls strictly inside at least one canonicalized entry of `allowed_dirs`.
#[cfg_attr(not(test), allow(dead_code))]
pub fn check_file_path(path: &Path, allowed_dirs: &[PathBuf]) -> bool {
    resolve_safe_file_path(path, allowed_dirs).is_some()
}

/// Read a local regular file incrementally via `tokio::fs::File`, enforcing `max_size`.
pub async fn read_file_bounded(
    path: &Path,
    max_size: u64,
) -> std::result::Result<Vec<u8>, FetchError> {
    let mut file = tokio::fs::File::open(path)
        .await
        .map_err(|e| FetchError::NotFound(e.to_string()))?;
    let metadata = file
        .metadata()
        .await
        .map_err(|e| FetchError::NotFound(e.to_string()))?;
    if !metadata.is_file() {
        return Err(FetchError::Forbidden(format!(
            "Target is not a regular file: {}",
            path.display()
        )));
    }
    if metadata.len() > max_size {
        return Err(FetchError::PayloadTooLarge);
    }
    read_async_bounded(&mut file, max_size).await
}

pub fn guess_mime_type(path: &Path) -> &'static str {
    match path.extension().and_then(|s| s.to_str()) {
        Some("pdf") => "application/pdf",
        Some("txt") => "text/plain; charset=utf-8",
        Some("html") | Some("htm") => "text/html; charset=utf-8",
        Some("md") | Some("markdown") => "text/markdown; charset=utf-8",
        Some("png") => "image/png",
        Some("jpg") | Some("jpeg") => "image/jpeg",
        Some("gif") => "image/gif",
        Some("cbor") => "application/cbor",
        Some("xml") => "application/xml",
        Some("json") => "application/json",
        Some("toml") => "application/toml",
        Some("csv") => "text/csv; charset=utf-8",
        Some("zip") => "application/zip",
        _ => "application/octet-stream",
    }
}

async fn resolve_safe_redirect(
    current_uri: &str,
    location: &str,
    redirect_count: &mut u32,
    allow_private_ips: bool,
) -> std::result::Result<String, FetchError> {
    if *redirect_count >= 5 {
        return Err(FetchError::Other("Too many redirects".to_string()));
    }
    *redirect_count += 1;

    let base = reqwest::Url::parse(current_uri).map_err(|e| FetchError::Other(e.to_string()))?;
    let resolved = base
        .join(location.trim())
        .map_err(|e| FetchError::Other(e.to_string()))?;

    let scheme = resolved.scheme();
    if scheme != "http" && scheme != "https" && scheme != "gemini" {
        return Err(FetchError::Forbidden(format!(
            "Forbidden redirect scheme: {}",
            scheme
        )));
    }

    if !check_url_ssrf(&resolved, allow_private_ips).await {
        return Err(FetchError::Forbidden(format!(
            "Forbidden redirect host (SSRF protection): {}",
            resolved.host_str().unwrap_or("")
        )));
    }

    Ok(resolved.to_string())
}

/// Fetch a resource over HTTP(S), Gemini, `file://`, or static `config.mappings`,
/// enforcing SSRF protection, timeouts, redirect limits, and streaming byte caps.
pub async fn fetch_resource(
    uri: &str,
    client: &reqwest::Client,
    connector: &tokio_rustls::TlsConnector,
    config: &Config,
    max_size: u64,
) -> std::result::Result<(Vec<u8>, String), FetchError> {
    let allow_private_ips = config.security.allow_private_ips;
    let mut current_uri = uri.to_string();
    let mut redirect_count = 0;

    loop {
        if current_uri.starts_with("http://") || current_uri.starts_with("https://") {
            let url =
                reqwest::Url::parse(&current_uri).map_err(|e| FetchError::Other(e.to_string()))?;
            if !check_url_ssrf(&url, allow_private_ips).await {
                return Err(FetchError::Forbidden(format!(
                    "Forbidden host (SSRF protection): {}",
                    url.host_str().unwrap_or("")
                )));
            }

            let mut res = client.get(&current_uri).send().await.map_err(|e| {
                if error_has_ssrf_forbidden(&e) {
                    FetchError::Forbidden(format!(
                        "Forbidden host (SSRF protection): {}",
                        url.host_str().unwrap_or("")
                    ))
                } else {
                    FetchError::NotFound(e.to_string())
                }
            })?;

            let status = res.status();
            if status.is_success() {
                let mime = res
                    .headers()
                    .get(reqwest::header::CONTENT_TYPE)
                    .and_then(|h| h.to_str().ok())
                    .unwrap_or("application/octet-stream")
                    .to_string();

                if res.content_length().is_some_and(|len| len > max_size) {
                    return Err(FetchError::PayloadTooLarge);
                }

                let mut body = Vec::new();
                while let Some(chunk) = res
                    .chunk()
                    .await
                    .map_err(|e| FetchError::Other(e.to_string()))?
                {
                    if (body.len() as u64).saturating_add(chunk.len() as u64) > max_size {
                        return Err(FetchError::PayloadTooLarge);
                    }
                    body.extend_from_slice(&chunk);
                }
                return Ok((body, mime));
            } else if status.is_redirection() {
                let location = res
                    .headers()
                    .get(reqwest::header::LOCATION)
                    .and_then(|h| h.to_str().ok())
                    .ok_or_else(|| {
                        FetchError::Other("Redirect without Location header".to_string())
                    })?;
                current_uri = resolve_safe_redirect(
                    &current_uri,
                    location,
                    &mut redirect_count,
                    allow_private_ips,
                )
                .await?;
                continue;
            } else {
                return Err(FetchError::NotFound(format!("HTTP error: {}", status)));
            }
        } else if current_uri.starts_with("gemini://") {
            match fetch_gemini(&current_uri, connector, allow_private_ips, max_size).await {
                Ok(res) => return Ok(res),
                Err(FetchError::Redirect(redirect_meta)) => {
                    current_uri = resolve_safe_redirect(
                        &current_uri,
                        &redirect_meta,
                        &mut redirect_count,
                        allow_private_ips,
                    )
                    .await?;
                    continue;
                }
                Err(e) => return Err(e),
            }
        } else if let Some(file_path_str) = current_uri.strip_prefix("file://") {
            let path = PathBuf::from(file_path_str);
            let canonical =
                resolve_safe_file_path(&path, &config.allowed_dirs).ok_or_else(|| {
                    FetchError::Forbidden(format!(
                        "Access denied or file not allowed: {}",
                        file_path_str
                    ))
                })?;
            let bytes = read_file_bounded(&canonical, max_size).await?;
            let mime = guess_mime_type(&canonical).to_string();
            return Ok((bytes, mime));
        } else if let Some(mapped_path) = config.mappings.get(&current_uri) {
            let canonical = mapped_path
                .canonicalize()
                .map_err(|e| FetchError::NotFound(e.to_string()))?;
            let bytes = read_file_bounded(&canonical, max_size).await?;
            let mime = guess_mime_type(&canonical).to_string();
            return Ok((bytes, mime));
        } else {
            return Err(FetchError::NotFound(format!(
                "Unsupported URI scheme or mapping: {}",
                current_uri
            )));
        }
    }
}

/// Search `config.mappings` and `config.allowed_dirs` using a size-bounded regex,
/// returning at most [`MAX_SEARCH_RESULTS`] entries while preventing symlink traversal outside roots.
pub fn perform_search(query: &str, config: &Config) -> Vec<(String, PathBuf)> {
    let mut results = Vec::new();
    let re = match regex::RegexBuilder::new(query)
        .case_insensitive(true)
        .size_limit(REGEX_SIZE_LIMIT)
        .build()
    {
        Ok(r) => r,
        Err(_) => return results,
    };

    for (uri, path) in &config.mappings {
        if results.len() >= MAX_SEARCH_RESULTS {
            return results;
        }
        let filename = path.file_name().and_then(|f| f.to_str()).unwrap_or("");
        if re.is_match(uri) || re.is_match(filename) {
            results.push((uri.clone(), path.clone()));
        }
    }

    let mut visited_dirs: HashSet<PathBuf> = HashSet::new();
    for dir in &config.allowed_dirs {
        if results.len() >= MAX_SEARCH_RESULTS {
            break;
        }
        let Ok(canon_root) = dir.canonicalize() else {
            continue;
        };
        let mut dirs_to_visit = vec![(canon_root, 0)];
        while let Some((current_dir, depth)) = dirs_to_visit.pop() {
            if results.len() >= MAX_SEARCH_RESULTS {
                break;
            }
            if depth > config.max_search_depth || !visited_dirs.insert(current_dir.clone()) {
                continue;
            }
            let Ok(read_dir) = std::fs::read_dir(&current_dir) else {
                continue;
            };
            for entry in read_dir {
                if results.len() >= MAX_SEARCH_RESULTS {
                    break;
                }
                let Ok(entry) = entry else {
                    continue;
                };
                let path = entry.path();
                let Ok(symlink_meta) = std::fs::symlink_metadata(&path) else {
                    continue;
                };
                // Resolve symlinks safely and refuse any target outside allowed_dirs.
                let safe_path = if symlink_meta.file_type().is_symlink() {
                    let Some(resolved) = resolve_safe_file_path(&path, &config.allowed_dirs) else {
                        continue;
                    };
                    resolved
                } else {
                    path
                };
                let Ok(meta) = std::fs::metadata(&safe_path) else {
                    continue;
                };
                if meta.is_dir() {
                    let dir_name = safe_path.file_name().and_then(|f| f.to_str()).unwrap_or("");
                    if dir_name.starts_with('.')
                        || dir_name == "target"
                        || dir_name == "node_modules"
                    {
                        continue;
                    }
                    dirs_to_visit.push((safe_path, depth + 1));
                } else if meta.is_file() {
                    let filename = safe_path.file_name().and_then(|f| f.to_str()).unwrap_or("");
                    if re.is_match(filename) {
                        let uri = format!("file://{}", safe_path.to_string_lossy());
                        if !results.iter().any(|(u, _)| u == &uri) {
                            results.push((uri, safe_path));
                        }
                    }
                }
            }
        }
    }

    results
}

fn sha256_file_streaming(path: &Path) -> String {
    let Ok(mut file) = std::fs::File::open(path) else {
        return String::new();
    };
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];
    loop {
        match file.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => hasher.update(&buf[..n]),
            Err(_) => return String::new(),
        }
    }
    hex::encode(hasher.finalize())
}

/// Compile a `text/markdown` bibliographic index document for `LIST` / large `SEARCH` responses.
pub fn compile_list_document(query: &str, results: &[(String, PathBuf)]) -> String {
    let mut doc = format!("# Bibliographic Index: {}\n\n", query);
    for (uri, path) in results {
        let filename = path
            .file_name()
            .and_then(|f| f.to_str())
            .unwrap_or("Unknown");
        let metadata = path.metadata().ok();
        let size = metadata.as_ref().map(|m| m.len()).unwrap_or(0);
        let posix_date = metadata
            .as_ref()
            .and_then(|m| m.modified().ok())
            .and_then(|t| t.duration_since(std::time::SystemTime::UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let hash_hex = sha256_file_streaming(path);
        let mime = guess_mime_type(path);

        doc.push_str(&format!("### {}\n\n", filename));
        doc.push_str(&format!("- **Title**: {}\n", filename));
        doc.push_str("- **Author**: Local System Proxy\n");
        doc.push_str(&format!("- **MIME**: {}\n", mime));
        doc.push_str(&format!("- **Size**: {} bytes\n", size));
        doc.push_str(&format!("- **POSIX Date**: {}\n", posix_date));
        doc.push_str(&format!("- **SHA-256**: {}\n", hash_hex));
        doc.push_str(&format!("- **URI**: {}\n\n", uri));
    }
    doc
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::dns::Resolve;
    use std::str::FromStr;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    #[test]
    fn test_parse_gemini_url_valid_and_ipv6() {
        let url = "gemini://gemini.conman.org/test/path?query=1";
        let (host, port, full) = parse_gemini_url(url).unwrap();
        assert_eq!(host, "gemini.conman.org");
        assert_eq!(port, 1965);
        assert_eq!(full, "gemini://gemini.conman.org/test/path?query=1");

        let custom = "gemini://localhost:1966/path";
        let (host, port, full) = parse_gemini_url(custom).unwrap();
        assert_eq!(host, "localhost");
        assert_eq!(port, 1966);
        assert_eq!(full, "gemini://localhost:1966/path");

        let v6 = "gemini://[::1]:1967/v6";
        let (host, port, _) = parse_gemini_url(v6).unwrap();
        assert_eq!(host, "::1");
        assert_eq!(port, 1967);

        assert!(parse_gemini_url("gemini:///no-host").is_err());
    }

    #[test]
    fn test_check_file_path_and_symlink_escape() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let allowed_file = root.path().join("ok.txt");
        let outside_file = outside.path().join("secret.txt");
        std::fs::write(&allowed_file, b"ok").unwrap();
        std::fs::write(&outside_file, b"secret").unwrap();

        let allowed_dirs = vec![root.path().to_path_buf()];
        assert!(check_file_path(&allowed_file, &allowed_dirs));
        assert!(!check_file_path(&outside_file, &allowed_dirs));

        // Non-existent file inside allowed root is permitted by ancestor check; `..` escape is blocked.
        assert!(check_file_path(
            &root.path().join("future.txt"),
            &allowed_dirs
        ));
        assert!(!check_file_path(
            &root.path().join("nonexistent/../secret.txt"),
            &allowed_dirs
        ));

        #[cfg(unix)]
        {
            let link_file = root.path().join("escape_file");
            std::os::unix::fs::symlink(&outside_file, &link_file).unwrap();
            assert!(!check_file_path(&link_file, &allowed_dirs));

            let link_dir = root.path().join("escape_dir");
            std::os::unix::fs::symlink(outside.path(), &link_dir).unwrap();
            assert!(!check_file_path(
                &link_dir.join("secret.txt"),
                &allowed_dirs
            ));
            assert!(!check_file_path(
                &link_dir.join("nonexistent_inside_outside.txt"),
                &allowed_dirs
            ));

            let dangling = root.path().join("dangling");
            std::os::unix::fs::symlink(outside.path().join("missing"), &dangling).unwrap();
            assert!(!check_file_path(&dangling, &allowed_dirs));
        }
    }

    #[test]
    fn test_guess_mime_type() {
        assert_eq!(guess_mime_type(Path::new("test.pdf")), "application/pdf");
        assert_eq!(
            guess_mime_type(Path::new("test.md")),
            "text/markdown; charset=utf-8"
        );
        assert_eq!(
            guess_mime_type(Path::new("test.unknown")),
            "application/octet-stream"
        );
    }

    #[test]
    fn test_compile_list_document() {
        let temp = tempfile::tempdir().unwrap();
        let file1 = temp.path().join("guide.pdf");
        std::fs::write(&file1, b"pdf content").unwrap();

        let results = vec![("file:///path/guide.pdf".to_string(), file1)];
        let doc = compile_list_document("guide", &results);
        assert!(doc.contains("# Bibliographic Index: guide"));
        assert!(doc.contains("Title**: guide.pdf"));
        assert!(doc.contains("MIME**: application/pdf"));
    }

    #[test]
    fn test_is_safe_ip_extended_ranges() {
        // Blocked special-purpose IPv4
        for addr in [
            "127.0.0.1",
            "0.0.0.0",
            "0.1.2.3",
            "10.0.0.1",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "100.127.255.254",
            "192.0.0.1",
            "192.0.2.1",
            "198.18.0.1",
            "198.19.255.254",
            "198.51.100.1",
            "203.0.113.1",
            "224.0.0.1",
            "240.0.0.1",
            "255.255.255.255",
        ] {
            assert!(
                !is_safe_ip(addr.parse().unwrap()),
                "IPv4 {addr} must be blocked"
            );
        }

        // Blocked special-purpose IPv6
        for addr in [
            "::1",
            "::",
            "fe80::1",
            "fec0::1",
            "fc00::1",
            "fd12:3456:789a::1",
            "ff02::1",
            "2001:db8::1",
            "3fff::1",
            "2001:2::1",
            "100::1",
            "::ffff:127.0.0.1",
            "::ffff:192.168.1.1",
            "::ffff:100.64.0.1",
            "::127.0.0.1",
            "64:ff9b::10.0.0.1",
            "64:ff9b:1::1",
        ] {
            assert!(
                !is_safe_ip(addr.parse().unwrap()),
                "IPv6 {addr} must be blocked"
            );
        }

        // Public global addresses allowed
        assert!(is_safe_ip("8.8.8.8".parse().unwrap()));
        assert!(is_safe_ip("100.63.255.255".parse().unwrap()));
        assert!(is_safe_ip("100.128.0.1".parse().unwrap()));
        assert!(is_safe_ip("198.20.0.1".parse().unwrap()));
        assert!(is_safe_ip("2001:4860:4860::8888".parse().unwrap()));
        assert!(is_safe_ip("::ffff:8.8.8.8".parse().unwrap()));
    }

    #[tokio::test]
    async fn test_safe_dns_resolver_and_check_url_ssrf() {
        assert!(!is_safe_host("127.0.0.1", 80, false).await);
        assert!(!is_safe_host("[::ffff:127.0.0.1]", 80, false).await);
        assert!(is_safe_host("8.8.8.8", 80, false).await);
        assert!(!is_safe_host("localhost", 80, false).await);

        // Explicit opt-in allow_private_ips = true
        assert!(is_safe_host("127.0.0.1", 80, true).await);
        assert!(is_safe_host("localhost", 80, true).await);

        // Hostless URLs must be rejected regardless of allow_private_ips
        let hostless = reqwest::Url::parse("file:///etc/passwd").unwrap();
        assert!(!check_url_ssrf(&hostless, false).await);
        assert!(!check_url_ssrf(&hostless, true).await);

        // Dual-record DNS rebinding rejection: public IP + private IP -> rejected
        let dual_addrs = vec![
            "8.8.8.8:80".parse().unwrap(),
            "127.0.0.1:80".parse().unwrap(),
        ];
        assert!(validate_resolved_addrs(dual_addrs.clone(), false).is_err());
        assert!(validate_resolved_addrs(dual_addrs, true).is_ok());

        let dual_v6 = vec![
            "[2001:4860:4860::8888]:443".parse().unwrap(),
            "[fd00::1]:443".parse().unwrap(),
        ];
        assert!(validate_resolved_addrs(dual_v6, false).is_err());

        // SafeDnsResolver implements reqwest::dns::Resolve
        let strict_resolver = SafeDnsResolver {
            allow_private_ips: false,
        };
        let localhost_name = reqwest::dns::Name::from_str("localhost").unwrap();
        assert!(strict_resolver.resolve(localhost_name).await.is_err());

        let v4_loopback = reqwest::dns::Name::from_str("127.0.0.1").unwrap();
        assert!(strict_resolver.resolve(v4_loopback).await.is_err());

        let permissive_resolver = SafeDnsResolver {
            allow_private_ips: true,
        };
        let localhost_name_ok = reqwest::dns::Name::from_str("localhost").unwrap();
        let resolved: Vec<SocketAddr> = permissive_resolver
            .resolve(localhost_name_ok)
            .await
            .unwrap()
            .collect();
        assert!(!resolved.is_empty());
    }

    #[tokio::test]
    async fn test_streaming_size_caps_file_http_and_gemini() {
        // 1. File streaming size cap
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("payload.bin");
        std::fs::write(&file_path, vec![0xABu8; 4096]).unwrap();

        let client = build_http_client(false, true).unwrap();
        let connector = build_tls_connector(false).unwrap();
        let cfg = Config {
            allowed_dirs: vec![dir.path().to_path_buf()],
            security: crate::config::SecurityConfig {
                allow_private_ips: true,
                ..Default::default()
            },
            ..Default::default()
        };

        let file_uri = format!("file://{}", file_path.display());
        let err = fetch_resource(&file_uri, &client, &connector, &cfg, 1024)
            .await
            .unwrap_err();
        assert!(matches!(err, FetchError::PayloadTooLarge));

        let (ok_bytes, _) = fetch_resource(&file_uri, &client, &connector, &cfg, 4096)
            .await
            .unwrap();
        assert_eq!(ok_bytes.len(), 4096);

        // 2. HTTP chunked streaming cap without Content-Length + SSRF block when opt-in disabled
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let srv = tokio::spawn(async move {
            for _ in 0..2 {
                if let Ok((mut sock, _)) = listener.accept().await {
                    tokio::spawn(async move {
                        let mut req_buf = [0u8; 1024];
                        let _ = tokio::io::AsyncReadExt::read(&mut sock, &mut req_buf).await;
                        let body = "A".repeat(4096);
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n{body}"
                        );
                        let _ = sock.write_all(resp.as_bytes()).await;
                    });
                }
            }
        });

        let http_uri = format!("http://{addr}/stream");
        let err = fetch_resource(&http_uri, &client, &connector, &cfg, 1024)
            .await
            .unwrap_err();
        assert!(matches!(err, FetchError::PayloadTooLarge));

        let (ok_http, _) = fetch_resource(&http_uri, &client, &connector, &cfg, 8192)
            .await
            .unwrap();
        assert_eq!(ok_http.len(), 4096);

        // Verify default allow_private_ips = false rejects 127.0.0.1
        let strict_client = build_http_client(false, false).unwrap();
        let mut strict_cfg = cfg.clone();
        strict_cfg.security.allow_private_ips = false;
        let ssrf_err = fetch_resource(&http_uri, &strict_client, &connector, &strict_cfg, 8192)
            .await
            .unwrap_err();
        assert!(matches!(ssrf_err, FetchError::Forbidden(_)));
        srv.abort();

        // 3. Gemini header bound (> 1027 bytes without `\n`) and streaming body cap
        let (client_io, mut server_io) = tokio::io::duplex(4096);
        let writer = tokio::spawn(async move {
            let mut drain = [0u8; 256];
            let _ = tokio::io::AsyncReadExt::read(&mut server_io, &mut drain).await;
            let oversized_header = vec![b'X'; 2048];
            let _ = server_io.write_all(&oversized_header).await;
        });
        let res = read_gemini_response(client_io, "gemini://example.com/", 1024).await;
        assert!(res.is_err());
        writer.abort();

        let (client_io2, mut server_io2) = tokio::io::duplex(8192);
        let writer2 = tokio::spawn(async move {
            let mut drain = [0u8; 256];
            let _ = tokio::io::AsyncReadExt::read(&mut server_io2, &mut drain).await;
            let _ = server_io2.write_all(b"20 text/plain\r\n").await;
            let _ = server_io2.write_all(&vec![b'Z'; 2048]).await;
        });
        let res2 = read_gemini_response(client_io2, "gemini://example.com/", 1024).await;
        assert!(matches!(res2, Err(FetchError::PayloadTooLarge)));
        writer2.abort();
    }

    #[test]
    fn test_perform_search_limits_and_symlink_safety() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let outside_file = outside.path().join("match_secret.txt");
        std::fs::write(&outside_file, b"secret").unwrap();

        #[cfg(unix)]
        {
            let link = root.path().join("match_symlink.txt");
            std::os::unix::fs::symlink(&outside_file, &link).unwrap();
        }

        for i in 0..120 {
            let f = root.path().join(format!("match_doc_{i:03}.txt"));
            std::fs::write(&f, b"data").unwrap();
        }

        let cfg = Config {
            allowed_dirs: vec![root.path().to_path_buf()],
            ..Default::default()
        };

        let results = perform_search("match_", &cfg);
        assert_eq!(results.len(), MAX_SEARCH_RESULTS);
        assert!(results.iter().all(|(u, _)| !u.contains("symlink")));
        assert!(results.iter().all(|(u, _)| !u.contains("secret")));

        // Absurdly large regex rejected cleanly
        let huge_pattern = "a".repeat(500_000);
        assert!(perform_search(&huge_pattern, &cfg).is_empty());
    }

    #[tokio::test]
    async fn test_redirect_ssrf_blocking_and_gemini_ssrf() {
        let mut count = 0;
        // Redirect to file:// blocked
        let res =
            resolve_safe_redirect("https://8.8.8.8/", "file:///etc/passwd", &mut count, false)
                .await
                .unwrap_err();
        assert!(matches!(res, FetchError::Forbidden(_)));

        // Redirect to private IPv4 / IPv6 blocked when allow_private_ips = false
        let res = resolve_safe_redirect(
            "https://8.8.8.8/",
            "http://169.254.169.254/latest/meta-data/",
            &mut count,
            false,
        )
        .await
        .unwrap_err();
        assert!(matches!(res, FetchError::Forbidden(_)));

        let res = resolve_safe_redirect(
            "https://8.8.8.8/",
            "http://[::ffff:127.0.0.1]/admin",
            &mut count,
            false,
        )
        .await
        .unwrap_err();
        assert!(matches!(res, FetchError::Forbidden(_)));

        // Allowed when allow_private_ips = true
        let ok = resolve_safe_redirect(
            "https://8.8.8.8/",
            "http://127.0.0.1:8080/local",
            &mut count,
            true,
        )
        .await
        .unwrap();
        assert_eq!(ok, "http://127.0.0.1:8080/local");

        // Gemini SSRF blocked before connect when allow_private_ips = false
        let client = build_http_client(false, false).unwrap();
        let connector = build_tls_connector(false).unwrap();
        let cfg = Config::default();
        let gem_err = fetch_resource("gemini://127.0.0.1/secret", &client, &connector, &cfg, 1024)
            .await
            .unwrap_err();
        assert!(matches!(gem_err, FetchError::Forbidden(_)));
    }
}
