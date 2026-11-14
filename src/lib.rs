//! `dtnpm-app-basket`: Library target re-exporting DTN Basket Protocol primitives from `dtnpm-core`
//! and shared CLI helpers for `dtnbasket` and `dtnbasket-cli`.

use anyhow::{Context, Result, anyhow};
use std::path::Path;

pub use dtnpm_core::basket::*;

/// Resolve an optional gRPC Bearer authentication token from an inline value or a token file.
///
/// Trims surrounding whitespace/newlines and rejects empty token files or conflicting flags.
pub fn resolve_auth_token(
    token: Option<&str>,
    token_file: Option<&Path>,
) -> Result<Option<String>> {
    let normalized_inline = token.map(str::trim).filter(|s| !s.is_empty());
    match (normalized_inline, token_file) {
        (Some(_), Some(_)) => Err(anyhow!(
            "Cannot specify both --token (or DTN_HDY_TOKEN) and --token-file"
        )),
        (Some(inline), None) => Ok(Some(inline.to_string())),
        (None, Some(path)) => {
            let content = std::fs::read_to_string(path).with_context(|| {
                format!(
                    "Failed to read authentication token file {}",
                    path.display()
                )
            })?;
            let trimmed = content.trim();
            if trimmed.is_empty() {
                return Err(anyhow!(
                    "Authentication token file {} is empty",
                    path.display()
                ));
            }
            Ok(Some(trimmed.to_string()))
        }
        (None, None) => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_auth_token_inline_and_file() {
        assert_eq!(resolve_auth_token(None, None).unwrap(), None);
        assert_eq!(
            resolve_auth_token(Some("  my-token \n"), None).unwrap(),
            Some("my-token".to_string())
        );
        assert_eq!(resolve_auth_token(Some("   "), None).unwrap(), None);

        let dir = tempfile::tempdir().unwrap();
        let tok_path = dir.path().join("token.txt");
        std::fs::write(&tok_path, "file-secret-token\n").unwrap();
        assert_eq!(
            resolve_auth_token(None, Some(&tok_path)).unwrap(),
            Some("file-secret-token".to_string())
        );

        let empty_path = dir.path().join("empty.txt");
        std::fs::write(&empty_path, "   \n").unwrap();
        assert!(resolve_auth_token(None, Some(&empty_path)).is_err());

        assert!(resolve_auth_token(Some("inline"), Some(&tok_path)).is_err());
    }
}
