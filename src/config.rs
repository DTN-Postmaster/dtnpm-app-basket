//! Configuration schema and loader for the `dtnbasket` service.

use anyhow::{Context, Result};
use std::collections::HashMap;
use std::path::PathBuf;

/// Default maximum size (in octets) allowed for a single fetched item (50 MiB).
pub const DEFAULT_MAX_ITEM_SIZE: u64 = 50 * 1024 * 1024;
/// Default maximum cumulative bytes fetched across all items in a single basket request (100 MiB).
pub const DEFAULT_MAX_BUNDLE_SIZE: u64 = 100 * 1024 * 1024;

/// Security policy configuration for `dtnbasket`.
///
/// Both opt-ins default to `false` (fail-closed) and should only be set to `true`
/// in explicitly isolated development or pre-secured links.
#[derive(serde::Deserialize, Debug, Clone, Default)]
pub struct SecurityConfig {
    /// Allow HTTP(S)/Gemini fetches to loopback, private, link-local, or special-use IPs.
    #[serde(default)]
    pub allow_private_ips: bool,
    /// Allow `reply_to` EIDs whose node authority differs from `bundle.source`.
    #[serde(default)]
    pub allow_third_party_reply_to: bool,
}

/// Resource and bundle transfer limits configuration.
#[derive(serde::Deserialize, Debug, Clone)]
pub struct LimitsConfig {
    /// Maximum size in octets allowed for any single fetched item.
    #[serde(default = "default_max_item_size")]
    pub max_item_size: u64,
    /// Maximum cumulative octets fetched across all items in a single basket request.
    #[serde(default = "default_max_bundle_size")]
    pub max_bundle_size: u64,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_item_size: default_max_item_size(),
            max_bundle_size: default_max_bundle_size(),
        }
    }
}

/// Top-level `dtnbasket` responder configuration.
#[derive(serde::Deserialize, Debug, Clone)]
pub struct Config {
    /// Allow self-signed or unverified TLS certificates for HTTP(S) and Gemini.
    #[serde(default)]
    pub insecure_tls: bool,
    /// Local gRPC port of Hardy BPA.
    #[serde(default = "default_grpc_port")]
    pub bpa_grpc_port: u16,
    /// Service endpoint name registered with Hardy BPA.
    #[serde(default = "default_service_name")]
    pub service_name: String,
    /// Directories from which `file://` resources and `SEARCH`/`LIST` may read.
    #[serde(default)]
    pub allowed_dirs: Vec<PathBuf>,
    /// Static URN-to-filesystem mappings.
    #[serde(default)]
    pub mappings: HashMap<String, PathBuf>,
    /// Maximum directory traversal depth during `SEARCH`/`LIST`.
    #[serde(default = "default_search_depth")]
    pub max_search_depth: u32,
    /// SSRF and third-party reflection security toggles.
    #[serde(default)]
    pub security: SecurityConfig,
    /// Item and cumulative basket byte limits.
    #[serde(default)]
    pub limits: LimitsConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            insecure_tls: false,
            bpa_grpc_port: default_grpc_port(),
            service_name: default_service_name(),
            allowed_dirs: Vec::new(),
            mappings: HashMap::new(),
            max_search_depth: default_search_depth(),
            security: SecurityConfig::default(),
            limits: LimitsConfig::default(),
        }
    }
}

fn default_grpc_port() -> u16 {
    50051
}

fn default_service_name() -> String {
    "dtnbasket".to_string()
}

fn default_search_depth() -> u32 {
    3
}

fn default_max_item_size() -> u64 {
    DEFAULT_MAX_ITEM_SIZE
}

fn default_max_bundle_size() -> u64 {
    DEFAULT_MAX_BUNDLE_SIZE
}

/// Load `dtnbasket` configuration from an explicit path, `DTNBASKET_CONFIG`, or standard locations.
pub fn load_config(explicit_path: Option<PathBuf>, verbose: bool) -> Result<Config> {
    let mut config_file = None;
    let mut is_required = false;

    if let Some(path) = explicit_path {
        config_file = Some(path);
        is_required = true;
    } else if let Ok(env_val) = std::env::var("DTNBASKET_CONFIG") {
        config_file = Some(PathBuf::from(env_val));
        is_required = true;
    } else {
        let paths = [
            Some(PathBuf::from("./dtnbasket.toml")),
            directories::ProjectDirs::from("dtn", "", "dtnbasket")
                .map(|dirs| dirs.config_dir().join("dtnbasket.toml")),
            #[cfg(unix)]
            Some(PathBuf::from("/etc/dtn/dtnbasket.toml")),
        ];

        for path in paths.iter().flatten() {
            if path.exists() {
                config_file = Some(path.clone());
                break;
            }
        }
    }

    let builder = ::config::Config::builder();
    let builder = if let Some(ref file) = config_file {
        if verbose {
            eprintln!("Loading config from: {}", file.display());
        }
        builder.add_source(::config::File::from(file.clone()).required(is_required))
    } else {
        if verbose {
            eprintln!("No config file found, using default configuration");
        }
        return Ok(Config::default());
    };

    let mut config = match builder.build() {
        Ok(config_val) => match config_val.try_deserialize::<Config>() {
            Ok(cfg) => cfg,
            Err(e) => {
                if is_required {
                    return Err(e).context("Failed to deserialize required config file");
                }
                eprintln!("Warning: Failed to deserialize config: {e}. Using defaults.");
                Config::default()
            }
        },
        Err(e) => {
            if is_required {
                return Err(e).context("Failed to load required config file");
            }
            Config::default()
        }
    };

    // Resolve relative paths in allowed_dirs and canonicalize existing roots.
    let parent = config_file.as_ref().and_then(|p| p.parent());
    let mut canonical_dirs = Vec::new();
    for dir in &config.allowed_dirs {
        let abs_path = if dir.is_relative() {
            let mut resolved = None;
            if let Some(p) = parent {
                let p_join = p.join(dir);
                if p_join.exists() {
                    resolved = Some(p_join);
                }
            }
            if resolved.is_none() {
                resolved = std::env::current_dir()
                    .ok()
                    .map(|cwd| cwd.join(dir))
                    .filter(|p| p.exists());
            }
            resolved.unwrap_or_else(|| dir.clone())
        } else {
            dir.clone()
        };
        if let Ok(canon) = abs_path.canonicalize() {
            canonical_dirs.push(canon);
        } else {
            canonical_dirs.push(abs_path);
        }
    }
    config.allowed_dirs = canonical_dirs;

    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_deserialization_defaults_and_opt_ins() {
        let toml_str = r#"
            service_name = "dtnbasket_test"
            insecure_tls = true
            allowed_dirs = ["/tmp"]
            [mappings]
            "urn:dtn:test" = "/tmp/test.txt"
        "#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.service_name, "dtnbasket_test");
        assert!(config.insecure_tls);
        assert_eq!(config.allowed_dirs.len(), 1);
        assert_eq!(
            config
                .mappings
                .get("urn:dtn:test")
                .unwrap()
                .to_str()
                .unwrap(),
            "/tmp/test.txt"
        );
        // Security toggles must default to false (fail-closed)
        assert!(!config.security.allow_private_ips);
        assert!(!config.security.allow_third_party_reply_to);
        assert_eq!(config.limits.max_item_size, DEFAULT_MAX_ITEM_SIZE);
        assert_eq!(config.limits.max_bundle_size, DEFAULT_MAX_BUNDLE_SIZE);

        let opt_in_toml = r#"
            [security]
            allow_private_ips = true
            allow_third_party_reply_to = true

            [limits]
            max_item_size = 1024
            max_bundle_size = 4096
        "#;
        let opt_in: Config = toml::from_str(opt_in_toml).unwrap();
        assert!(opt_in.security.allow_private_ips);
        assert!(opt_in.security.allow_third_party_reply_to);
        assert_eq!(opt_in.limits.max_item_size, 1024);
        assert_eq!(opt_in.limits.max_bundle_size, 4096);
    }
}
