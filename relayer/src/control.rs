//! Control-plane client: keeps the validator allowlist in sync with `flowra-control`.
//!
//! The relayer's allowlist used to be either the leader schedule or a static
//! `--allowed-validators` list. With `--control-url` it is instead the `allowed_validators`
//! list of the snapshot `flowra-control` serves for this component (the admin's validator
//! registry, filtered to this site). Same protocol the engine speaks:
//!
//!   boot     GET  {url}/v1/config/{component_id}          → snapshot, else disk cache
//!   runtime  GET  {url}/v1/config/{component_id}/watch    → SSE, full snapshot per change
//!   after    POST {url}/v1/config/{component_id}/ack      → {applied_version, applied_at}
//!
//! A validator removed from the registry is refused at the next challenge and its live packet
//! stream is closed on the next heartbeat tick (see `RelayerImpl::handle_heartbeat`). The last
//! applied list stays in force while the control plane is unreachable.

use std::{
    collections::HashSet,
    path::PathBuf,
    str::FromStr,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc, Arc, Mutex,
    },
    thread,
    time::Duration,
};

use arc_swap::ArcSwap;
use futures_util::StreamExt;
use log::*;
use serde::Deserialize;
use solana_pubkey::Pubkey;

use crate::auth_service::ValidatorAuther;

/// The subset of the control-plane snapshot the relayer uses. Unknown fields are ignored.
#[derive(Deserialize, Debug, Default)]
struct Snapshot {
    version: u64,
    #[serde(default)]
    allowed_validators: Vec<String>,
}

pub struct ControlClient {
    allowed: ArcSwap<HashSet<Pubkey>>,
    version: AtomicU64,
    connected: AtomicBool,
    origin: Mutex<String>,
}

impl ControlClient {
    /// Fetches the first snapshot (remote, else cache) and starts the watch thread. Returns
    /// once the allowlist is populated or, after `boot_timeout`, empty (refuse everyone until
    /// the control plane answers — never fail open).
    pub fn start(
        url: String,
        token: String,
        component_id: String,
        cache: Option<PathBuf>,
        exit: Arc<AtomicBool>,
    ) -> Arc<Self> {
        let client = Arc::new(Self {
            allowed: ArcSwap::from_pointee(HashSet::new()),
            version: AtomicU64::new(0),
            connected: AtomicBool::new(false),
            origin: Mutex::new("none".into()),
        });
        let (booted_tx, booted_rx) = mpsc::channel::<()>();
        let url = url.trim_end_matches('/').to_string();
        thread::Builder::new()
            .name("relayer-control".into())
            .spawn({
                let client = client.clone();
                move || {
                    let rt = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .expect("control runtime");
                    rt.block_on(async move {
                        let http = reqwest::Client::builder()
                            .connect_timeout(Duration::from_secs(5))
                            .build()
                            .expect("reqwest client");
                        let base = format!("{url}/v1/config/{component_id}");
                        // boot
                        match fetch(&http, &base, &token).await {
                            Ok(snap) => {
                                client.apply(&snap, &format!("{url} as {component_id}"));
                                write_cache(&cache, &snap);
                                ack(&http, &base, &token, snap.version).await;
                                client.connected.store(true, Ordering::Relaxed);
                            }
                            Err(e) => {
                                warn!("control: snapshot fetch failed ({e}); trying disk cache");
                                match read_cache(&cache) {
                                    Some(snap) => client.apply(&snap, &format!("cache {cache:?}")),
                                    None => warn!(
                                        "control: no cache either; refusing every validator until the control plane answers"
                                    ),
                                }
                            }
                        }
                        let _ = booted_tx.send(());
                        watch_loop(client, http, base, token, cache, exit).await;
                    });
                }
            })
            .expect("spawn control thread");
        // Give the boot fetch a bounded wait so a dead control plane can't hang startup.
        if booted_rx.recv_timeout(Duration::from_secs(15)).is_err() {
            warn!("control: boot did not finish in 15s; continuing with an empty allowlist");
        }
        client
    }

    fn apply(&self, snap: &Snapshot, origin: &str) {
        let set: HashSet<Pubkey> = snap
            .allowed_validators
            .iter()
            .filter_map(|s| match Pubkey::from_str(s) {
                Ok(p) => Some(p),
                Err(_) => {
                    warn!("control: ignoring malformed validator pubkey {s:?}");
                    None
                }
            })
            .collect();
        let was = self.version.swap(snap.version, Ordering::Relaxed);
        info!(
            "control: applied v{} (was v{was}; {} validators) from {origin}",
            snap.version,
            set.len()
        );
        self.allowed.store(Arc::new(set));
        *self.origin.lock().unwrap() = origin.to_string();
    }

    pub fn allowed(&self) -> Arc<HashSet<Pubkey>> {
        self.allowed.load_full()
    }

    pub fn version(&self) -> u64 {
        self.version.load(Ordering::Relaxed)
    }

    pub fn connected(&self) -> bool {
        self.connected.load(Ordering::Relaxed)
    }

    pub fn origin(&self) -> String {
        self.origin.lock().unwrap().clone()
    }
}

impl ValidatorAuther for ControlClient {
    fn is_authorized(&self, pubkey: &Pubkey) -> bool {
        self.allowed.load().contains(pubkey)
    }
}

async fn fetch(http: &reqwest::Client, base: &str, token: &str) -> Result<Snapshot, String> {
    let resp = http
        .get(base)
        .bearer_auth(token)
        .timeout(Duration::from_secs(10))
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !resp.status().is_success() {
        return Err(format!("HTTP {}", resp.status()));
    }
    resp.json::<Snapshot>().await.map_err(|e| e.to_string())
}

async fn ack(http: &reqwest::Client, base: &str, token: &str, version: u64) {
    let body = serde_json::json!({
        "applied_version": version,
        "applied_at": chrono::Utc::now().to_rfc3339(),
    });
    if let Err(e) = http
        .post(format!("{base}/ack"))
        .bearer_auth(token)
        .json(&body)
        .timeout(Duration::from_secs(10))
        .send()
        .await
    {
        warn!("control: ack v{version} failed: {e}");
    }
}

fn write_cache(cache: &Option<PathBuf>, snap: &Snapshot) {
    let Some(path) = cache else { return };
    let json = serde_json::json!({
        "version": snap.version,
        "allowed_validators": snap.allowed_validators,
    });
    let tmp = path.with_extension("tmp");
    let res = std::fs::write(&tmp, json.to_string()).and_then(|_| std::fs::rename(&tmp, path));
    if let Err(e) = res {
        warn!("control: could not write cache {path:?}: {e}");
    }
}

fn read_cache(cache: &Option<PathBuf>) -> Option<Snapshot> {
    let path = cache.as_ref()?;
    let bytes = std::fs::read(path).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// Minimal SSE consumer: `data:` lines carry one JSON snapshot each, blank line ends an
/// event, `:` lines are keepalives.
async fn watch_loop(
    client: Arc<ControlClient>,
    http: reqwest::Client,
    base: String,
    token: String,
    cache: Option<PathBuf>,
    exit: Arc<AtomicBool>,
) {
    let watch_url = format!("{base}/watch");
    let mut backoff = Duration::from_secs(1);
    while !exit.load(Ordering::Relaxed) {
        let resp = match http.get(&watch_url).bearer_auth(&token).send().await {
            Ok(r) if r.status().is_success() => r,
            Ok(r) => {
                warn!("control: watch HTTP {}; retrying in {backoff:?}", r.status());
                client.connected.store(false, Ordering::Relaxed);
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(Duration::from_secs(60));
                continue;
            }
            Err(e) => {
                warn!("control: watch connect failed ({e}); retrying in {backoff:?}");
                client.connected.store(false, Ordering::Relaxed);
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(Duration::from_secs(60));
                continue;
            }
        };
        info!("control: watching {watch_url}");
        client.connected.store(true, Ordering::Relaxed);
        backoff = Duration::from_secs(1);

        let mut stream = resp.bytes_stream();
        let mut buf = String::new();
        let mut data = String::new();
        loop {
            let chunk = tokio::select! {
                c = stream.next() => c,
                _ = tokio::time::sleep(Duration::from_secs(60)) => {
                    warn!("control: watch idle for 60s; reconnecting");
                    None
                }
            };
            let Some(chunk) = chunk else { break };
            let chunk = match chunk {
                Ok(c) => c,
                Err(e) => {
                    warn!("control: watch stream error: {e}");
                    break;
                }
            };
            buf.push_str(&String::from_utf8_lossy(&chunk));
            while let Some(nl) = buf.find('\n') {
                let line = buf[..nl].trim_end_matches('\r').to_string();
                buf.drain(..=nl);
                if let Some(d) = line.strip_prefix("data:") {
                    data.push_str(d.trim_start());
                } else if line.is_empty() && !data.is_empty() {
                    match serde_json::from_str::<Snapshot>(&data) {
                        Ok(snap) => {
                            client.apply(&snap, &watch_url);
                            write_cache(&cache, &snap);
                            ack(&http, &base, &token, snap.version).await;
                        }
                        Err(e) => warn!("control: bad snapshot on watch stream: {e}"),
                    }
                    data.clear();
                }
            }
            if exit.load(Ordering::Relaxed) {
                return;
            }
        }
        client.connected.store(false, Ordering::Relaxed);
        warn!(
            "control: watch disconnected; keeping v{} until reconnect",
            client.version()
        );
    }
}
