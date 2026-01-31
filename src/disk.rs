use bytes::Bytes;
use http::HeaderMap;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[derive(Debug)]
pub struct DiskStore {
    root: PathBuf,
    db: sled::Db,
    // Sled is thread-safe, but we want to serialize multi-key updates for tag index.
    lock: Mutex<()>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StoredMeta {
    pub stored_at_ms: u64,
    pub ttl_ms: u64,
    pub grace_ms: u64,
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub tags: Vec<String>,
    pub invalidation_states: Option<String>,
}

impl DiskStore {
    pub fn open(root: impl AsRef<Path>) -> Result<Self, String> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(root.join("entries")).map_err(|e| format!("create cache dir: {e}"))?;
        let db = sled::open(root.join("index")).map_err(|e| format!("open sled: {e}"))?;
        Ok(Self {
            root,
            db,
            lock: Mutex::new(()),
        })
    }

    fn entry_dir(&self, key: &str) -> PathBuf {
        self.root.join("entries").join(key)
    }

    pub fn get(&self, key: &str) -> Result<Option<(StoredMeta, Bytes)>, String> {
        let dir = self.entry_dir(key);
        let meta_path = dir.join("meta.json");
        let body_path = dir.join("body.bin");

        if !meta_path.exists() || !body_path.exists() {
            return Ok(None);
        }

        let meta_bytes = fs::read(&meta_path).map_err(|e| format!("read meta: {e}"))?;
        let meta: StoredMeta =
            serde_json::from_slice(&meta_bytes).map_err(|e| format!("parse meta: {e}"))?;
        let body = fs::read(&body_path).map_err(|e| format!("read body: {e}"))?;
        Ok(Some((meta, Bytes::from(body))))
    }

    pub fn put(&self, key: &str, meta: &StoredMeta, body: &[u8]) -> Result<(), String> {
        let _g = self.lock.lock();

        let dir = self.entry_dir(key);
        fs::create_dir_all(&dir).map_err(|e| format!("create entry dir: {e}"))?;

        let meta_bytes = serde_json::to_vec(meta).map_err(|e| format!("encode meta: {e}"))?;
        fs::write(dir.join("meta.json"), meta_bytes).map_err(|e| format!("write meta: {e}"))?;
        fs::write(dir.join("body.bin"), body).map_err(|e| format!("write body: {e}"))?;

        // Update tag index in sled: tag:<tag> -> Vec<String>
        for tag in &meta.tags {
            let k = format!("tag:{tag}");
            let mut set: std::collections::BTreeSet<String> = self
                .db
                .get(&k)
                .map_err(|e| format!("sled get: {e}"))?
                .map(|v| bincode::deserialize(&v).unwrap_or_default())
                .unwrap_or_default();
            set.insert(key.to_string());
            let enc = bincode::serialize(&set).map_err(|e| format!("bincode: {e}"))?;
            self.db
                .insert(k.as_bytes(), enc)
                .map_err(|e| format!("sled insert: {e}"))?;
        }

        self.db.flush().map_err(|e| format!("sled flush: {e}"))?;
        Ok(())
    }

    pub fn remove_key(&self, key: &str) -> Result<bool, String> {
        let _g = self.lock.lock();
        let dir = self.entry_dir(key);
        if !dir.exists() {
            return Ok(false);
        }

        // Read meta to remove tag index
        if let Ok(meta_bytes) = fs::read(dir.join("meta.json")) {
            if let Ok(meta) = serde_json::from_slice::<StoredMeta>(&meta_bytes) {
                for tag in meta.tags {
                    let k = format!("tag:{tag}");
                    if let Some(v) = self.db.get(&k).map_err(|e| format!("sled get: {e}"))? {
                        let mut set: std::collections::BTreeSet<String> =
                            bincode::deserialize(&v).unwrap_or_default();
                        set.remove(key);
                        if set.is_empty() {
                            self.db
                                .remove(k.as_bytes())
                                .map_err(|e| format!("sled remove: {e}"))?;
                        } else {
                            let enc =
                                bincode::serialize(&set).map_err(|e| format!("bincode: {e}"))?;
                            self.db
                                .insert(k.as_bytes(), enc)
                                .map_err(|e| format!("sled insert: {e}"))?;
                        }
                    }
                }
            }
        }

        remove_dir_all_best_effort(&dir);
        self.db.flush().map_err(|e| format!("sled flush: {e}"))?;
        Ok(true)
    }

    pub fn remove_by_tags(&self, tags: &[String]) -> Result<usize, String> {
        let _g = self.lock.lock();
        let mut keys: std::collections::BTreeSet<String> = Default::default();

        for tag in tags {
            let k = format!("tag:{tag}");
            if let Some(v) = self.db.get(&k).map_err(|e| format!("sled get: {e}"))? {
                let set: std::collections::BTreeSet<String> =
                    bincode::deserialize(&v).unwrap_or_default();
                keys.extend(set);
            }
        }

        let mut gone = 0;
        for key in keys {
            // use remove_key to clean tag index
            if self.remove_key(&key)? {
                gone += 1;
            }
        }
        Ok(gone)
    }
}

pub fn headers_to_pairs(headers: &HeaderMap) -> Vec<(String, String)> {
    headers
        .iter()
        .filter_map(|(k, v)| Some((k.to_string(), v.to_str().ok()?.to_string())))
        .collect()
}

pub fn pairs_to_headers(pairs: &[(String, String)]) -> HeaderMap {
    let mut out = HeaderMap::new();
    for (k, v) in pairs {
        if let (Ok(name), Ok(val)) = (
            http::header::HeaderName::from_bytes(k.as_bytes()),
            http::HeaderValue::from_str(v),
        ) {
            out.insert(name, val);
        }
    }
    out
}

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_millis() as u64
}

fn remove_dir_all_best_effort(path: &Path) {
    // tolerate partial deletes
    let _ = fs::remove_file(path.join("meta.json"));
    let _ = fs::remove_file(path.join("body.bin"));
    let _ = fs::remove_dir(path);
    let _ = fs::remove_dir_all(path);
}
