//! `dtnbasket` responder daemon entrypoint (RFC draft-f4jxq-dtn-basket-00).

mod config;
mod fetcher;
mod service;

use anyhow::Result;
use clap::Parser;
use dtnpm_app_basket::resolve_auth_token;
use dtnpm_core::cli_security::{KeyStore, VerifyPolicy, load_key};
use dtnpm_core::resolve_grpc_port;
use hardy_bpa::bpa::BpaRegistration;
use hardy_bpv7::eid::Service;
use std::path::PathBuf;
use std::sync::Arc;

use config::load_config;
use service::{BasketService, BasketServiceWrapper};

/// A Bundle Protocol 7 Basket Protocol Service for Delay Tolerant Networking interacting with Hardy.
/// Implements RFC draft-f4jxq-dtn-basket-00.
#[derive(Parser, Debug)]
#[command(author, version, about = "DTN Basket Protocol Responder Service", long_about = None)]
struct Args {
    /// Path to TOML configuration file
    #[arg(short, long)]
    config: Option<PathBuf>,

    /// Local gRPC port of Hardy BPA (default = 50051)
    #[arg(short, long)]
    port: Option<u16>,

    /// Use IPv6 for connecting to Hardy
    #[arg(short = '6', long)]
    ipv6: bool,

    /// Verbose output
    #[arg(short, long)]
    verbose: bool,

    /// Service endpoint to register (default = "dtnbasket")
    #[arg(short, long)]
    service: Option<String>,

    /// Path to keystore configuration file (defaults to ~/.config/dtn/keystore.toml)
    #[arg(long = "keystore")]
    keystore: Option<PathBuf>,

    /// Inline verification key material (string or hex)
    #[arg(long = "verify-key")]
    verify_key: Option<String>,

    /// Path to single verification key file
    #[arg(long = "verify-key-file")]
    verify_key_file: Option<String>,

    /// Verification policy for received bundles (strict, warn, or ignore) (default = "warn")
    #[arg(long = "verify-policy", default_value = "warn")]
    verify_policy: VerifyPolicy,

    /// Inline key material for response bundle signing (string or hex)
    #[arg(long = "sign-key")]
    sign_key: Option<String>,

    /// Path to file containing key material for response bundle signing
    #[arg(long = "sign-key-file")]
    sign_key_file: Option<String>,

    /// Security Source EID for BPSec BIB (defaults to bundle source EID)
    #[arg(long = "security-source")]
    security_source: Option<String>,

    /// Optional Bearer authentication token for protected gRPC BPA endpoints
    #[arg(long, env = "DTN_HDY_TOKEN")]
    token: Option<String>,

    /// Path to file containing Bearer authentication token for protected gRPC BPA endpoints
    #[arg(long = "token-file", env = "DTN_HDY_TOKEN_FILE")]
    token_file: Option<PathBuf>,

    /// Optional Unix Domain Socket path for connecting to a protected local BPA
    #[arg(long, env = "DTN_HDY_SOCKET")]
    socket: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Install default rustls crypto provider
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .ok();

    let args = Args::parse();

    let config = load_config(args.config, args.verbose)?;

    let localhost = if args.ipv6 { "[::1]" } else { "127.0.0.1" };
    let port_str = resolve_grpc_port(args.port.or(Some(config.bpa_grpc_port)));
    let grpc_addr = format!("http://{}:{}", localhost, port_str);

    if args.verbose {
        eprintln!("Connecting to Hardy BPA at {}", grpc_addr);
    }

    let mut keystore = KeyStore::load_default_or(args.keystore.as_deref())?;
    if args.verify_key.is_some() || args.verify_key_file.is_some() {
        let key_mat = load_key(args.verify_key.as_deref(), args.verify_key_file.as_deref())?;
        keystore.add_key("*", &key_mat.raw);
    }

    let resolved_token = resolve_auth_token(args.token.as_deref(), args.token_file.as_deref())?;
    let (remote_bpa, _grpc_guard) = dtnpm_core::create_remote_bpa(
        &grpc_addr,
        resolved_token.as_deref(),
        args.socket.as_deref(),
    )?;

    let service = BasketService::new(
        config.clone(),
        args.verbose,
        keystore,
        args.verify_policy,
        args.sign_key,
        args.sign_key_file,
        args.security_source,
    )?;

    let service_name_resolved = args.service.unwrap_or(config.service_name);
    let service_id = if let Ok(num) = service_name_resolved.parse::<u32>() {
        Service::Ipn(num)
    } else {
        Service::Dtn(service_name_resolved.into())
    };

    let wrapper = Arc::new(BasketServiceWrapper(service.clone()));

    let registered_eid = remote_bpa
        .register_service(service_id, wrapper.clone())
        .await
        .map_err(|e| anyhow::anyhow!("Service registration failed: {e}"))?;

    eprintln!("Listening for DTN Basket requests on: {}", registered_eid);

    tokio::signal::ctrl_c().await?;
    eprintln!("\nShutting down...");

    if let Some(sink) = service.sink.get() {
        sink.unregister().await;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cli_parses_token_file_flag() {
        let args = Args::try_parse_from(["dtnbasket", "--token-file", "/tmp/tok"]).unwrap();
        assert_eq!(args.token_file, Some(PathBuf::from("/tmp/tok")));
    }
}
