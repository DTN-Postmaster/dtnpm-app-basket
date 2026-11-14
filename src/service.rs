//! Hardy BPA service implementation for DTN Basket Protocol (`draft-f4jxq-dtn-basket-00`).

use crate::config::Config;
use crate::fetcher::{
    FetchError, build_http_client, build_tls_connector, compile_list_document, fetch_resource,
    guess_mime_type, perform_search, read_file_bounded, resolve_safe_file_path,
};
use anyhow::{Result, anyhow};
use bytes::Bytes;
use dtnpm_core::basket::*;
use dtnpm_core::cli_security::{KeyStore, VerifyPolicy, VerifyResult, verify_bundle};
use dtnpm_core::normalize_eid;
use hardy_bpa::async_trait;
use hardy_bpa::services::{Service as BpaService, ServiceSink};
use hardy_bpv7::builder::Builder;
use hardy_bpv7::creation_timestamp::CreationTimestamp;
use hardy_bpv7::eid::{Eid, NodeId};
use hardy_cbor::decode;
use hardy_cbor::encode::{self, Tagged};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::OnceCell;

const SEARCH_RESULT_INLINE_LIMIT: usize = 50;

struct OutboundRawBundle {
    bytes: Vec<u8>,
    hash: Vec<u8>,
    lifetime: u64,
}

struct ActiveTask {
    instance_id: u64,
    owner_node: Option<NodeId>,
    cancel_tx: tokio::sync::watch::Sender<bool>,
}

struct ActiveTaskGuard {
    active_tasks: Arc<Mutex<HashMap<String, Vec<ActiveTask>>>>,
    req_id: String,
    instance_id: u64,
}

impl Drop for ActiveTaskGuard {
    fn drop(&mut self) {
        let mut active = self
            .active_tasks
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(entries) = active.get_mut(&self.req_id) {
            entries.retain(|task| task.instance_id != self.instance_id);
            if entries.is_empty() {
                active.remove(&self.req_id);
            }
        }
    }
}

/// Validate `request.reply_to` against `bundle.source` unless third-party replies are opted in.
pub fn validate_reply_to(
    reply_to: Option<&str>,
    source: &Eid,
    allow_third_party_reply_to: bool,
) -> Result<Eid> {
    let Some(dest_str) = reply_to else {
        return Ok(source.clone());
    };

    let reply_eid = normalize_eid(dest_str)
        .parse::<Eid>()
        .map_err(|e| anyhow!("Invalid reply_to EID '{}': {}", dest_str, e))?;

    if matches!(reply_eid, Eid::Null | Eid::Unknown { .. }) {
        return Err(anyhow!(
            "reply_to EID '{}' has no routable endpoint authority",
            reply_eid
        ));
    }

    if allow_third_party_reply_to {
        return Ok(reply_eid);
    }

    let source_node = source
        .to_node_id()
        .map_err(|_| anyhow!("Source EID '{}' has no valid node authority", source))?;
    let reply_node = reply_eid
        .to_node_id()
        .map_err(|_| anyhow!("reply_to EID '{}' has no valid node authority", reply_eid))?;

    if reply_node != source_node {
        return Err(anyhow!(
            "Unauthorized third-party reply_to '{}' (node {}) for source '{}' (node {})",
            reply_eid,
            reply_node,
            source,
            source_node
        ));
    }

    Ok(reply_eid)
}

/// Compute the effective max fetch size for an item, capping `item.max_size` at
/// `config.limits.max_item_size` and bounding against the remaining `max_bundle_size` budget.
/// Returns `None` when the cumulative bundle budget is already exhausted.
fn effective_fetch_cap(
    item_max_size: Option<u64>,
    config: &Config,
    cumulative_bytes: u64,
) -> Option<u64> {
    if cumulative_bytes >= config.limits.max_bundle_size {
        return None;
    }
    let remaining_bundle = config.limits.max_bundle_size - cumulative_bytes;
    let capped_item = item_max_size
        .unwrap_or(config.limits.max_item_size)
        .min(config.limits.max_item_size);
    Some(capped_item.min(remaining_bundle))
}

fn bundle_budget_exceeded_response(item_idx: u64) -> ItemResponse {
    ItemResponse {
        item_idx,
        coap_status: coap_status::REQUEST_ENTITY_TOO_LARGE,
        metadata: None,
        diagnostic: Some("Basket cumulative bundle size limit exceeded".to_string()),
    }
}

fn sha256_digest(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

fn file_mtime_secs(path: &Path) -> Option<u64> {
    std::fs::metadata(path)
        .ok()
        .and_then(|m| m.modified().ok())
        .and_then(|t| t.duration_since(std::time::SystemTime::UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
}

/// Core DTN Basket service state implementing `GET`, `CHECK`, `SEARCH`, `CANCEL`, and `LIST`.
pub struct BasketService {
    pub local_eid: OnceCell<Eid>,
    pub sink: OnceCell<Box<dyn ServiceSink>>,
    config: Config,
    verbose: bool,
    client: reqwest::Client,
    tls_connector: tokio_rustls::TlsConnector,
    active_tasks: Arc<Mutex<HashMap<String, Vec<ActiveTask>>>>,
    next_task_id: AtomicU64,
    keystore: KeyStore,
    policy: VerifyPolicy,
    sign_key: Option<String>,
    sign_key_file: Option<String>,
    security_source: Option<String>,
}

impl BasketService {
    /// Construct a new [`BasketService`] configured with SSRF-safe HTTP/Gemini clients and limits.
    pub fn new(
        config: Config,
        verbose: bool,
        keystore: KeyStore,
        policy: VerifyPolicy,
        sign_key: Option<String>,
        sign_key_file: Option<String>,
        security_source: Option<String>,
    ) -> Result<Arc<Self>> {
        let client = build_http_client(config.insecure_tls, config.security.allow_private_ips)?;
        let tls_connector = build_tls_connector(config.insecure_tls)?;

        Ok(Arc::new(Self {
            local_eid: OnceCell::new(),
            sink: OnceCell::new(),
            config,
            verbose,
            client,
            tls_connector,
            active_tasks: Arc::new(Mutex::new(HashMap::new())),
            next_task_id: AtomicU64::new(1),
            keystore,
            policy,
            sign_key,
            sign_key_file,
            security_source,
        }))
    }

    /// Cancel an active request only if `requester` shares node authority with the original owner.
    pub fn cancel_request(&self, target_req_id: &str, requester: &Eid) -> (u8, String) {
        let Ok(requester_node) = requester.to_node_id() else {
            return (
                coap_status::FORBIDDEN,
                "Cancellation requires a valid source node EID".to_string(),
            );
        };

        let mut active = self
            .active_tasks
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        let Some(entries) = active.get_mut(target_req_id) else {
            return (
                coap_status::NOT_FOUND,
                format!("Request {} not found", target_req_id),
            );
        };

        let mut cancelled_any = false;
        let mut remaining = Vec::with_capacity(entries.len());
        for task in entries.drain(..) {
            if task.owner_node.as_ref() == Some(&requester_node) {
                let _ = task.cancel_tx.send(true);
                cancelled_any = true;
            } else {
                remaining.push(task);
            }
        }

        if remaining.is_empty() {
            active.remove(target_req_id);
        } else {
            *entries = remaining;
        }

        if cancelled_any {
            (
                coap_status::CHANGED,
                format!("Request {} successfully cancelled", target_req_id),
            )
        } else {
            (
                coap_status::FORBIDDEN,
                format!(
                    "Forbidden: request {} is owned by another node",
                    target_req_id
                ),
            )
        }
    }

    pub async fn process_request(self: Arc<Self>, source: Eid, payload: Vec<u8>) -> Result<()> {
        let request = match decode::parse::<BasketRequest>(&payload) {
            Ok(req) => req,
            Err(e) => {
                if self.verbose {
                    eprintln!("Failed to parse payload as BasketRequest: {}", e);
                }
                return Ok(());
            }
        };

        if self.verbose {
            eprintln!("Processing BasketRequest id: {}", request.req_id);
        }

        let reply_dest = validate_reply_to(
            request.reply_to.as_deref(),
            &source,
            self.config.security.allow_third_party_reply_to,
        )?;

        let default_lifetime = request.default_lifetime.unwrap_or(3600);

        let (cancel_tx, mut cancel_rx) = tokio::sync::watch::channel(false);
        let instance_id = self.next_task_id.fetch_add(1, Ordering::Relaxed);
        let owner_node = source.to_node_id().ok();
        {
            let mut active = self
                .active_tasks
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            active
                .entry(request.req_id.clone())
                .or_default()
                .push(ActiveTask {
                    instance_id,
                    owner_node,
                    cancel_tx,
                });
        }
        let _task_guard = ActiveTaskGuard {
            active_tasks: self.active_tasks.clone(),
            req_id: request.req_id.clone(),
            instance_id,
        };

        let mut item_responses = Vec::new();
        let mut raw_bundles_to_send = Vec::new();
        let mut cumulative_bytes: u64 = 0;

        for (idx, item) in request.items.iter().enumerate() {
            if *cancel_rx.borrow() {
                if self.verbose {
                    eprintln!(
                        "Request {} was cancelled, aborting remaining items.",
                        request.req_id
                    );
                }
                break;
            }

            let item_idx = idx as u64;

            match item.op {
                0 => {
                    match self
                        .handle_get(
                            item,
                            item_idx,
                            default_lifetime,
                            &mut cumulative_bytes,
                            &mut cancel_rx,
                        )
                        .await
                    {
                        Ok((item_resp, raw_data_opt)) => {
                            item_responses.push(item_resp);
                            if let Some(raw) = raw_data_opt {
                                raw_bundles_to_send.push(raw);
                            }
                        }
                        Err(e) => {
                            item_responses.push(ItemResponse {
                                item_idx,
                                coap_status: coap_status::INTERNAL_SERVER_ERROR,
                                metadata: None,
                                diagnostic: Some(e.to_string()),
                            });
                        }
                    }
                }
                1 => {
                    match self
                        .handle_check(item, item_idx, &mut cumulative_bytes, &mut cancel_rx)
                        .await
                    {
                        Ok(item_resp) => {
                            item_responses.push(item_resp);
                        }
                        Err(e) => {
                            item_responses.push(ItemResponse {
                                item_idx,
                                coap_status: coap_status::INTERNAL_SERVER_ERROR,
                                metadata: None,
                                diagnostic: Some(e.to_string()),
                            });
                        }
                    }
                }
                2 => {
                    match self
                        .handle_search(
                            item,
                            item_idx,
                            default_lifetime,
                            &mut cumulative_bytes,
                            &mut cancel_rx,
                        )
                        .await
                    {
                        Ok((mut resps, raws)) => {
                            item_responses.append(&mut resps);
                            raw_bundles_to_send.extend(raws);
                        }
                        Err(e) => {
                            item_responses.push(ItemResponse {
                                item_idx,
                                coap_status: coap_status::INTERNAL_SERVER_ERROR,
                                metadata: None,
                                diagnostic: Some(e.to_string()),
                            });
                        }
                    }
                }
                3 => {
                    let (status, diagnostic) = self.cancel_request(&item.uri, &source);
                    item_responses.push(ItemResponse {
                        item_idx,
                        coap_status: status,
                        metadata: None,
                        diagnostic: Some(diagnostic),
                    });
                }
                4 => {
                    match self
                        .handle_list(
                            item,
                            item_idx,
                            default_lifetime,
                            &mut cumulative_bytes,
                            &mut cancel_rx,
                        )
                        .await
                    {
                        Ok((item_resp, raw_data_opt)) => {
                            item_responses.push(item_resp);
                            if let Some(raw) = raw_data_opt {
                                raw_bundles_to_send.push(raw);
                            }
                        }
                        Err(e) => {
                            item_responses.push(ItemResponse {
                                item_idx,
                                coap_status: coap_status::INTERNAL_SERVER_ERROR,
                                metadata: None,
                                diagnostic: Some(e.to_string()),
                            });
                        }
                    }
                }
                _ => {
                    item_responses.push(ItemResponse {
                        item_idx,
                        coap_status: coap_status::NOT_FOUND,
                        metadata: None,
                        diagnostic: Some(format!("Unsupported operation: {}", item.op)),
                    });
                }
            }
        }

        // Send basket-response control bundle
        let response = BasketResponse {
            experiment_tag: request.experiment_tag,
            version: 1,
            req_id: request.req_id.clone(),
            items: item_responses,
        };

        let tagged_resp = Tagged::<44444, _>(&response);
        let (cbor_bytes, _) = encode::emit(&tagged_resp);

        let local_eid = self.local_eid.get().cloned().unwrap_or(Eid::Null);
        let sink = self
            .sink
            .get()
            .ok_or_else(|| anyhow!("Sink not registered"))?;

        let (control_bundle, control_bin) = Builder::new(local_eid.clone(), reply_dest.clone())
            .with_payload(cbor_bytes.into())
            .with_lifetime(std::time::Duration::from_secs(default_lifetime))
            .build(CreationTimestamp::now())
            .map_err(|e| anyhow!("Failed to build control bundle: {e}"))?;

        let (_, control_bin_signed) = self.maybe_sign(&control_bundle, control_bin.into_vec())?;
        sink.send(&mut Bytes::from(control_bin_signed)).await?;

        // Send raw content bundles
        for raw in raw_bundles_to_send {
            let (raw_bundle, raw_bin) = Builder::new(local_eid.clone(), reply_dest.clone())
                .with_payload(raw.bytes.into())
                .with_lifetime(std::time::Duration::from_secs(raw.lifetime))
                .build(CreationTimestamp::now())
                .map_err(|e| anyhow!("Failed to build raw content bundle: {e}"))?;

            let (_, raw_bin_signed) = self.maybe_sign(&raw_bundle, raw_bin.into_vec())?;

            if self.verbose {
                eprintln!(
                    "Sending raw bundle {} with hash {} and size {} bytes",
                    raw_bundle.primary.id.to_key(),
                    hex::encode(&raw.hash),
                    raw_bin_signed.len()
                );
            }
            sink.send(&mut Bytes::from(raw_bin_signed)).await?;
        }

        Ok(())
    }

    fn maybe_sign(
        &self,
        bundle: &hardy_bpv7::bundle::Bundle,
        binbundle: Vec<u8>,
    ) -> Result<(hardy_bpv7::bundle::Bundle, Vec<u8>)> {
        dtnpm_core::cli_security::maybe_sign_bundle(
            bundle.clone(),
            binbundle,
            self.sign_key.as_deref(),
            self.sign_key_file.as_deref(),
            self.security_source.as_deref(),
            self.verbose,
        )
    }

    async fn fetch_and_hash_item(
        &self,
        item: &RequestItem,
        item_idx: u64,
        cumulative_bytes: &mut u64,
        cancel_rx: &mut tokio::sync::watch::Receiver<bool>,
    ) -> Result<(ItemResponse, Option<(Vec<u8>, Vec<u8>)>)> {
        let Some(effective_max) =
            effective_fetch_cap(item.max_size, &self.config, *cumulative_bytes)
        else {
            return Ok((bundle_budget_exceeded_response(item_idx), None));
        };

        let fetch_fut = fetch_resource(
            &item.uri,
            &self.client,
            &self.tls_connector,
            &self.config,
            effective_max,
        );

        let fetch_res = tokio::select! {
            res = fetch_fut => res,
            _ = cancel_rx.changed() => {
                return Err(anyhow!("Operation cancelled"));
            }
        };

        let (body, mime) = match fetch_res {
            Ok(res) => res,
            Err(e) => {
                let status = match e {
                    FetchError::PayloadTooLarge => coap_status::REQUEST_ENTITY_TOO_LARGE,
                    FetchError::Forbidden(_) => coap_status::FORBIDDEN,
                    FetchError::NotFound(_) => coap_status::NOT_FOUND,
                    FetchError::Redirect(_) | FetchError::Other(_) => coap_status::NOT_FOUND,
                };

                return Ok((
                    ItemResponse {
                        item_idx,
                        coap_status: status,
                        metadata: None,
                        diagnostic: Some(e.to_string()),
                    },
                    None,
                ));
            }
        };

        *cumulative_bytes = cumulative_bytes.saturating_add(body.len() as u64);

        if let Some(formats) = item.accepted_formats.as_ref().filter(|f| !f.is_empty()) {
            let matches = formats
                .iter()
                .any(|f| if f == "*/*" { true } else { mime.contains(f) });
            if !matches {
                return Ok((
                    ItemResponse {
                        item_idx,
                        coap_status: coap_status::NOT_ACCEPTABLE,
                        metadata: None,
                        diagnostic: Some(format!("MIME type {} not accepted", mime)),
                    },
                    None,
                ));
            }
        }

        let hash = sha256_digest(&body);

        let last_modified = if let Some(path_str) = item.uri.strip_prefix("file://") {
            resolve_safe_file_path(Path::new(path_str), &self.config.allowed_dirs)
                .and_then(|canon| file_mtime_secs(&canon))
        } else if let Some(path) = self.config.mappings.get(&item.uri) {
            file_mtime_secs(path)
        } else {
            None
        };

        let metadata = ItemMetadata {
            hash: hash.clone(),
            size: Some(body.len() as u64),
            mime_type: Some(mime),
            uri: Some(item.uri.clone()),
            last_modified,
        };

        Ok((
            ItemResponse {
                item_idx,
                coap_status: coap_status::CONTENT,
                metadata: Some(metadata),
                diagnostic: None,
            },
            Some((body, hash)),
        ))
    }

    async fn handle_get(
        &self,
        item: &RequestItem,
        item_idx: u64,
        default_lifetime: u64,
        cumulative_bytes: &mut u64,
        cancel_rx: &mut tokio::sync::watch::Receiver<bool>,
    ) -> Result<(ItemResponse, Option<OutboundRawBundle>)> {
        let (item_resp, body_hash_opt) = self
            .fetch_and_hash_item(item, item_idx, cumulative_bytes, cancel_rx)
            .await?;
        let lifetime = item.lifetime_override.unwrap_or(default_lifetime);
        let bundle_to_send = body_hash_opt.map(|(bytes, hash)| OutboundRawBundle {
            bytes,
            hash,
            lifetime,
        });
        Ok((item_resp, bundle_to_send))
    }

    async fn handle_check(
        &self,
        item: &RequestItem,
        item_idx: u64,
        cumulative_bytes: &mut u64,
        cancel_rx: &mut tokio::sync::watch::Receiver<bool>,
    ) -> Result<ItemResponse> {
        let (item_resp, _) = self
            .fetch_and_hash_item(item, item_idx, cumulative_bytes, cancel_rx)
            .await?;
        Ok(item_resp)
    }

    fn build_list_bundle_response(
        &self,
        item: &RequestItem,
        item_idx: u64,
        default_lifetime: u64,
        doc_bytes: Vec<u8>,
        diagnostic: Option<String>,
        cumulative_bytes: &mut u64,
    ) -> (ItemResponse, Option<OutboundRawBundle>) {
        let doc_len = doc_bytes.len() as u64;
        let Some(effective_max) =
            effective_fetch_cap(item.max_size, &self.config, *cumulative_bytes)
        else {
            return (bundle_budget_exceeded_response(item_idx), None);
        };
        if doc_len > effective_max {
            return (
                ItemResponse {
                    item_idx,
                    coap_status: coap_status::REQUEST_ENTITY_TOO_LARGE,
                    metadata: None,
                    diagnostic: Some("Compiled index document exceeds max size limit".to_string()),
                },
                None,
            );
        }

        *cumulative_bytes = cumulative_bytes.saturating_add(doc_len);
        let hash = sha256_digest(&doc_bytes);
        let lifetime = item.lifetime_override.unwrap_or(default_lifetime);

        let metadata = ItemMetadata {
            hash: hash.clone(),
            size: Some(doc_len),
            mime_type: Some("text/markdown; charset=utf-8".to_string()),
            uri: Some(item.uri.clone()),
            last_modified: Some(
                std::time::SystemTime::now()
                    .duration_since(std::time::SystemTime::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
            ),
        };

        (
            ItemResponse {
                item_idx,
                coap_status: coap_status::CONTENT,
                metadata: Some(metadata),
                diagnostic,
            },
            Some(OutboundRawBundle {
                bytes: doc_bytes,
                hash,
                lifetime,
            }),
        )
    }

    async fn handle_search(
        &self,
        item: &RequestItem,
        item_idx: u64,
        default_lifetime: u64,
        cumulative_bytes: &mut u64,
        cancel_rx: &mut tokio::sync::watch::Receiver<bool>,
    ) -> Result<(Vec<ItemResponse>, Vec<OutboundRawBundle>)> {
        let query_clone = item.uri.clone();
        let config_clone = self.config.clone();
        let search_results =
            tokio::task::spawn_blocking(move || perform_search(&query_clone, &config_clone))
                .await?;

        let mut item_responses = Vec::new();
        let mut raw_bundles_to_send = Vec::new();

        let m = search_results.len();

        if m == 0 {
            item_responses.push(ItemResponse {
                item_idx,
                coap_status: coap_status::NOT_FOUND,
                metadata: None,
                diagnostic: Some("No matching resources found".to_string()),
            });
            return Ok((item_responses, raw_bundles_to_send));
        }

        if m > SEARCH_RESULT_INLINE_LIMIT {
            if self.verbose {
                eprintln!(
                    "Search found {} matches, exceeding {}. Returning LIST index document.",
                    m, SEARCH_RESULT_INLINE_LIMIT
                );
            }
            let query_clone = item.uri.clone();
            let results_clone = search_results.clone();
            let markdown_doc = tokio::task::spawn_blocking(move || {
                compile_list_document(&query_clone, &results_clone)
            })
            .await?;

            let (resp, raw_opt) = self.build_list_bundle_response(
                item,
                item_idx,
                default_lifetime,
                markdown_doc.into_bytes(),
                Some(format!(
                    "Result size exceeded {}, index document returned",
                    SEARCH_RESULT_INLINE_LIMIT
                )),
                cumulative_bytes,
            );
            item_responses.push(resp);
            if let Some(raw) = raw_opt {
                raw_bundles_to_send.push(raw);
            }
            return Ok((item_responses, raw_bundles_to_send));
        }

        for (uri, path) in search_results {
            if *cancel_rx.borrow() {
                break;
            }

            let Some(effective_max) =
                effective_fetch_cap(item.max_size, &self.config, *cumulative_bytes)
            else {
                item_responses.push(bundle_budget_exceeded_response(item_idx));
                continue;
            };

            let read_res = tokio::select! {
                res = read_file_bounded(&path, effective_max) => res,
                _ = cancel_rx.changed() => break,
            };

            let bytes = match read_res {
                Ok(b) => b,
                Err(FetchError::PayloadTooLarge) => {
                    item_responses.push(ItemResponse {
                        item_idx,
                        coap_status: coap_status::REQUEST_ENTITY_TOO_LARGE,
                        metadata: None,
                        diagnostic: Some(format!("Resource {} exceeds max size limit", uri)),
                    });
                    continue;
                }
                Err(_) => continue,
            };

            *cumulative_bytes = cumulative_bytes.saturating_add(bytes.len() as u64);
            let hash = sha256_digest(&bytes);

            let already_owned = item
                .have_hashes
                .as_ref()
                .is_some_and(|have| have.iter().any(|h| hash.starts_with(h)));

            let mime = guess_mime_type(&path).to_string();
            let last_modified = file_mtime_secs(&path);

            let metadata = ItemMetadata {
                hash: hash.clone(),
                size: Some(bytes.len() as u64),
                mime_type: Some(mime),
                uri: Some(uri),
                last_modified,
            };

            item_responses.push(ItemResponse {
                item_idx,
                coap_status: coap_status::CONTENT,
                metadata: Some(metadata),
                diagnostic: None,
            });

            if !already_owned {
                let lifetime = item.lifetime_override.unwrap_or(default_lifetime);
                raw_bundles_to_send.push(OutboundRawBundle {
                    bytes,
                    hash,
                    lifetime,
                });
            }
        }

        Ok((item_responses, raw_bundles_to_send))
    }

    async fn handle_list(
        &self,
        item: &RequestItem,
        item_idx: u64,
        default_lifetime: u64,
        cumulative_bytes: &mut u64,
        _cancel_rx: &mut tokio::sync::watch::Receiver<bool>,
    ) -> Result<(ItemResponse, Option<OutboundRawBundle>)> {
        let query_clone = item.uri.clone();
        let config_clone = self.config.clone();
        let search_results =
            tokio::task::spawn_blocking(move || perform_search(&query_clone, &config_clone))
                .await?;

        if search_results.is_empty() {
            return Ok((
                ItemResponse {
                    item_idx,
                    coap_status: coap_status::NOT_FOUND,
                    metadata: None,
                    diagnostic: Some("No matching resources found".to_string()),
                },
                None,
            ));
        }

        let query_clone = item.uri.clone();
        let results_clone = search_results.clone();
        let markdown_doc = tokio::task::spawn_blocking(move || {
            compile_list_document(&query_clone, &results_clone)
        })
        .await?;

        Ok(self.build_list_bundle_response(
            item,
            item_idx,
            default_lifetime,
            markdown_doc.into_bytes(),
            None,
            cumulative_bytes,
        ))
    }

    pub async fn on_register(&self, source: &Eid, sink: Box<dyn ServiceSink>) {
        if self.verbose {
            eprintln!(
                "Basket service registered successfully with EID: {}",
                source
            );
        }
        let _ = self.local_eid.set(source.clone());
        let _ = self.sink.set(sink);
    }

    pub async fn on_unregister(&self) {
        eprintln!("Error: Basket service unregistered (connection lost). Exiting.");
        std::process::exit(1);
    }

    pub async fn on_status_notify(
        &self,
        _bundle_id: &hardy_bpv7::bundle::Id,
        _from: &Eid,
        _kind: hardy_bpa::services::StatusNotify,
        _reason: hardy_bpv7::status_report::ReasonCode,
        _timestamp: Option<time::OffsetDateTime>,
    ) {
    }
}

/// Wrapper structure allowing `Arc<BasketService>` to implement Hardy `BpaService`.
pub struct BasketServiceWrapper(pub Arc<BasketService>);

#[async_trait]
impl BpaService for BasketServiceWrapper {
    async fn on_register(&self, source: &Eid, sink: Box<dyn ServiceSink>) {
        self.0.on_register(source, sink).await;
    }

    async fn on_unregister(&self) {
        self.0.on_unregister().await;
    }

    async fn on_deliver(
        &self,
        _id: &hardy_bpv7::bundle::Id,
        _expiry: time::OffsetDateTime,
        total_len: u64,
        stream: &mut dyn hardy_bpa::stream::Receiver<hardy_bpa::stream::Segment>,
    ) -> hardy_bpa::services::Result<()> {
        let data = hardy_bpa::stream::buffer_stream(stream, total_len).await?;
        let (source, payload) = match hardy_bpv7::parse::parse(data.clone()) {
            Ok(parsed) => {
                let payload_bytes = parsed
                    .bundle
                    .blocks
                    .get(&1)
                    .and_then(|b| b.payload(&parsed.data))
                    .map(|bytes| bytes.to_vec())
                    .unwrap_or_else(|| data.to_vec());
                (parsed.bundle.primary.id.source, payload_bytes)
            }
            Err(_) => (Eid::Null, data.to_vec()),
        };

        if self.0.policy != VerifyPolicy::Ignore {
            let res = verify_bundle(&data, &self.0.keystore);
            match res {
                VerifyResult::Valid => {
                    if self.0.verbose {
                        eprintln!("Signature verified successfully for source {}", source);
                    }
                }
                VerifyResult::Invalid(reason) => {
                    eprintln!(
                        "WARNING: Signature verification failed for {}: {}",
                        source, reason
                    );
                    if self.0.policy == VerifyPolicy::Strict {
                        eprintln!(
                            "Basket request bundle dropped due to strict verification policy."
                        );
                        return Ok(());
                    }
                }
                VerifyResult::Unsigned => {
                    if self.0.policy == VerifyPolicy::Strict {
                        eprintln!(
                            "WARNING: Unsigned basket request bundle received from {}. Dropped due to strict verification policy.",
                            source
                        );
                        return Ok(());
                    } else if self.0.verbose {
                        eprintln!("Received unsigned basket request bundle from {}", source);
                    }
                }
            }
        }

        let service = self.0.clone();
        tokio::spawn(async move {
            if let Err(e) = service.process_request(source, payload).await {
                eprintln!("Error processing request: {}", e);
            }
        });
        Ok(())
    }

    async fn on_status_notify(
        &self,
        bundle_id: &hardy_bpv7::bundle::Id,
        from: &Eid,
        kind: hardy_bpa::services::StatusNotify,
        reason: hardy_bpv7::status_report::ReasonCode,
        timestamp: Option<time::OffsetDateTime>,
    ) {
        self.0
            .on_status_notify(bundle_id, from, kind, reason, timestamp)
            .await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dtnpm_core::cli_security::{KeyStore, VerifyPolicy};
    use hardy_cbor::decode::FromCbor;
    use hardy_cbor::encode::{Encoder, Tagged, ToCbor};

    #[test]
    fn test_cbor_basket_request_roundtrip() {
        let req = BasketRequest {
            experiment_tag: Some(44444),
            version: 1,
            req_id: "req-123".to_string(),
            reply_to: Some("dtn://node2/incoming".to_string()),
            default_lifetime: Some(3600),
            items: vec![RequestItem {
                op: 0,
                uri: "https://example.com/file.bin".to_string(),
                max_size: Some(1024),
                accepted_formats: Some(vec!["application/octet-stream".to_string()]),
                have_hashes: Some(vec![vec![1, 2, 3, 4, 5, 6, 7, 8]]),
                if_modified_since: Some(123456789),
                lifetime_override: Some(600),
            }],
        };

        let mut encoder = Encoder::new();
        let tagged_req = Tagged::<44444, _>(&req);
        tagged_req.to_cbor(&mut encoder);
        let bytes = encoder.build();

        let (parsed_req, _shortest, _len) = BasketRequest::from_cbor(&bytes).unwrap();
        assert_eq!(parsed_req.version, 1);
        assert_eq!(parsed_req.req_id, "req-123");
        assert_eq!(parsed_req.reply_to.unwrap(), "dtn://node2/incoming");
        assert_eq!(parsed_req.default_lifetime.unwrap(), 3600);
        assert_eq!(parsed_req.items.len(), 1);
    }

    #[test]
    fn test_validate_reply_to_authority_and_opt_in() {
        let src_dtn: Eid = "dtn://alice/basket_client".parse().unwrap();
        let src_ipn: Eid = "ipn:42.1".parse().unwrap();

        // None defaults to source
        assert_eq!(validate_reply_to(None, &src_dtn, false).unwrap(), src_dtn);

        // Same authority (different service on same node) allowed
        let same_node = validate_reply_to(Some("dtn://alice/other_svc"), &src_dtn, false).unwrap();
        assert_eq!(same_node.to_string(), "dtn://alice/other_svc");

        let same_ipn = validate_reply_to(Some("ipn:42.99"), &src_ipn, false).unwrap();
        assert_eq!(same_ipn.to_string(), "ipn:42.99");

        // Different authority rejected by default
        assert!(validate_reply_to(Some("dtn://victim/flood"), &src_dtn, false).is_err());
        assert!(validate_reply_to(Some("ipn:99.1"), &src_ipn, false).is_err());
        assert!(validate_reply_to(Some("dtn:none"), &src_dtn, false).is_err());
        assert!(validate_reply_to(Some("not-an-eid"), &src_dtn, false).is_err());

        // Explicit opt-in allow_third_party_reply_to = true permits third-party EIDs
        let third_party = validate_reply_to(Some("dtn://relay/inbox"), &src_dtn, true).unwrap();
        assert_eq!(third_party.to_string(), "dtn://relay/inbox");
    }

    #[tokio::test]
    async fn test_cancel_ownership_and_not_found_diagnostic() {
        let svc = BasketService::new(
            Config::default(),
            false,
            KeyStore::empty(),
            VerifyPolicy::Ignore,
            None,
            None,
            None,
        )
        .unwrap();

        let alice: Eid = "dtn://alice/cli".parse().unwrap();
        let alice_other: Eid = "dtn://alice/admin".parse().unwrap();
        let mallory: Eid = "dtn://mallory/evil".parse().unwrap();

        // Missing request returns NOT_FOUND with accurate diagnostic (never "successfully cancelled")
        let (status_missing, diag_missing) = svc.cancel_request("req-missing", &alice);
        assert_eq!(status_missing, coap_status::NOT_FOUND);
        assert!(!diag_missing.contains("successfully cancelled"));
        assert!(diag_missing.contains("not found"));

        // Register an active task owned by alice
        let (tx, rx) = tokio::sync::watch::channel(false);
        {
            let mut active = svc.active_tasks.lock().unwrap();
            active.insert(
                "req-alice-1".to_string(),
                vec![ActiveTask {
                    instance_id: 1,
                    owner_node: alice.to_node_id().ok(),
                    cancel_tx: tx,
                }],
            );
        }

        // Mallory (another node) MUST NOT cancel alice's job
        let (status_mallory, diag_mallory) = svc.cancel_request("req-alice-1", &mallory);
        assert_eq!(status_mallory, coap_status::FORBIDDEN);
        assert!(diag_mallory.contains("another node"));
        assert!(!*rx.borrow());

        // Eid::Null MUST NOT cancel alice's job
        let (status_null, _) = svc.cancel_request("req-alice-1", &Eid::Null);
        assert_eq!(status_null, coap_status::FORBIDDEN);
        assert!(!*rx.borrow());

        // Alice's node CAN cancel alice's job
        let (status_ok, diag_ok) = svc.cancel_request("req-alice-1", &alice_other);
        assert_eq!(status_ok, coap_status::CHANGED);
        assert!(diag_ok.contains("successfully cancelled"));
        assert!(*rx.borrow());
    }

    #[tokio::test]
    async fn test_item_cap_and_cumulative_bundle_budget() {
        let dir = tempfile::tempdir().unwrap();
        let file1 = dir.path().join("a.bin");
        let file2 = dir.path().join("b.bin");
        std::fs::write(&file1, vec![1u8; 600]).unwrap();
        std::fs::write(&file2, vec![2u8; 500]).unwrap();

        let cfg = Config {
            allowed_dirs: vec![dir.path().to_path_buf()],
            limits: crate::config::LimitsConfig {
                max_item_size: 700,
                max_bundle_size: 1000,
            },
            ..Default::default()
        };

        let svc = BasketService::new(
            cfg,
            false,
            KeyStore::empty(),
            VerifyPolicy::Ignore,
            None,
            None,
            None,
        )
        .unwrap();

        let mut cumulative = 0u64;
        let (_tx, mut rx) = tokio::sync::watch::channel(false);

        // Item 1 requests 10_000 max_size, capped at config.limits.max_item_size (700) -> 600 fits
        let item1 = RequestItem {
            op: 0,
            uri: format!("file://{}", file1.display()),
            max_size: Some(10_000),
            accepted_formats: None,
            have_hashes: None,
            if_modified_since: None,
            lifetime_override: None,
        };
        let (resp1, bundle1) = svc
            .handle_get(&item1, 0, 3600, &mut cumulative, &mut rx)
            .await
            .unwrap();
        assert_eq!(resp1.coap_status, coap_status::CONTENT);
        assert!(bundle1.is_some());
        assert_eq!(cumulative, 600);

        // Item 2 is 500 bytes, exceeding remaining bundle budget (1000 - 600 = 400) -> 4.13
        let item2 = RequestItem {
            op: 0,
            uri: format!("file://{}", file2.display()),
            max_size: Some(700),
            accepted_formats: None,
            have_hashes: None,
            if_modified_since: None,
            lifetime_override: None,
        };
        let (resp2, bundle2) = svc
            .handle_get(&item2, 1, 3600, &mut cumulative, &mut rx)
            .await
            .unwrap();
        assert_eq!(resp2.coap_status, coap_status::REQUEST_ENTITY_TOO_LARGE);
        assert!(bundle2.is_none());
        assert_eq!(cumulative, 600);
    }
}
