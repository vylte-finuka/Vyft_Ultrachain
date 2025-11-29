use serde::{Serialize, Deserialize};
use std::sync::Arc;
use tokio::sync::RwLock;
use rocksdb::{DB, Options};
use std::path::Path;

#[derive(Serialize, Deserialize, Clone)]
pub struct SlurachainMetadata {
    pub from_op: String,
    pub receiver_op: String,
    pub fees_tx: u64,
    pub value_tx: String,
    pub nonce_tx: u64,
    pub hash_tx: String,
}

#[async_trait::async_trait]
pub trait RocksDBManager: Send + Sync {
    fn new() -> Self where Self: Sized;

    async fn store_metadata(&self, key: &str, metadata: &SlurachainMetadata) -> Result<(), Box<dyn std::error::Error>>;
    async fn get_metadata(&self, key: &str) -> Result<Option<SlurachainMetadata>, Box<dyn std::error::Error>>;

    fn read(&self, key: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>>;
    fn write(&self, key: &str, value: Vec<u8>) -> Result<(), Box<dyn std::error::Error>>;
    fn store(&self, key: &str, value: Vec<u8>) -> Result<(), Box<dyn std::error::Error>>;
}

#[derive(Clone)]
pub struct RocksDBManagerImpl {
    db: Arc<DB>,
}

#[async_trait::async_trait]
impl RocksDBManager for RocksDBManagerImpl {
    fn new() -> Self {
        let path = "./vyft_rocksdb";
        let mut opts = Options::default();
        opts.create_if_missing(true);
        let db = DB::open(&opts, Path::new(path)).expect("Erreur ouverture RocksDB");
        RocksDBManagerImpl {
            db: Arc::new(db),
        }
    }

    async fn store_metadata(&self, key: &str, metadata: &SlurachainMetadata) -> Result<(), Box<dyn std::error::Error>> {
        // Sérialise en JSON pour stockage dans RocksDB
        let bytes = serde_json::to_vec(metadata)?;
        self.db.put(key.as_bytes(), &bytes)?;
        Ok(())
    }

    async fn get_metadata(&self, key: &str) -> Result<Option<SlurachainMetadata>, Box<dyn std::error::Error>> {
        if let Some(bytes) = self.db.get(key.as_bytes())? {
            let meta: SlurachainMetadata = serde_json::from_slice(&bytes)?;
            Ok(Some(meta))
        } else {
            Ok(None)
        }
    }

    fn read(&self, key: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let val = self.db.get(key.as_bytes())?.ok_or("Clé non trouvée")?;
        Ok(val)
    }

    fn write(&self, key: &str, value: Vec<u8>) -> Result<(), Box<dyn std::error::Error>> {
        self.db.put(key.as_bytes(), &value)?;
        Ok(())
    }

    fn store(&self, key: &str, value: Vec<u8>) -> Result<(), Box<dyn std::error::Error>> {
        self.write(key, value)
    }
}

impl RocksDBManagerImpl {
    pub async fn put_metadata(&self, key: &str, value: SlurachainMetadata) -> Result<(), String> {
        let bytes = serde_json::to_vec(&value).map_err(|e| e.to_string())?;
        self.db.put(key.as_bytes(), &bytes).map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn read_sync(&self, key: &str) -> Result<Vec<u8>, String> {
        self.db.get(key.as_bytes())
            .map_err(|e| e.to_string())?
            .ok_or_else(|| "Clé non trouvée".to_string())
    }

    pub fn write_sync(&self, key: &str, value: Vec<u8>) -> Result<(), String> {
        self.db.put(key.as_bytes(), &value).map_err(|e| e.to_string())
    }

    pub fn store_sync(&self, key: &str, value: Vec<u8>) -> Result<(), String> {
        self.write_sync(key, value)
    }

    pub fn put(&self, key: &str, value: &[u8]) -> Result<(), String> {
        self.db.put(key.as_bytes(), value).map_err(|e| e.to_string())
    }
}