use rocksdb::{DB, Options};
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use bincode::Encode;

#[derive(Serialize, Deserialize, Clone, Encode)]
pub struct UltrachainMetadata {
    pub from_op: String,
    pub receiver_op: String,
    pub fees_tx: u64,
    pub value_tx: String,
    pub nonce_tx: u64,
    pub hash_tx: String,
}

#[async_trait::async_trait]
pub trait RocksDBManager: Send + Sync {
    fn new(_path: &str) -> Self where Self: Sized;

    async fn store_metadata(&self, key: &str, metadata: &UltrachainMetadata) -> Result<(), Box<dyn std::error::Error>>;

    async fn get_metadata(&self, key: &str) -> Result<Option<UltrachainMetadata>, Box<dyn std::error::Error>>;
}

#[derive(Clone)]
pub struct RocksDBManagerImpl {
    db: Arc<DB>,
}

#[async_trait::async_trait]
impl RocksDBManager for RocksDBManagerImpl {
    fn new(path: &str) -> Self {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        let db = DB::open(&opts, path).expect("Failed to open RocksDB");
        RocksDBManagerImpl { db: Arc::new(db) }
    }

    async fn store_metadata(&self, key: &str, metadata: &UltrachainMetadata) -> Result<(), Box<dyn std::error::Error>> {
        let serialized = serde_json::to_vec(metadata)?;
        self.db.put(key.as_bytes(), &serialized)?;
        Ok(())
    }

    async fn get_metadata(&self, key: &str) -> Result<Option<UltrachainMetadata>, Box<dyn std::error::Error>> {
        match self.db.get(key.as_bytes())? {
            Some(value) => {
                let metadata: UltrachainMetadata = serde_json::from_slice(&value)?;
                Ok(Some(metadata))
            },
            None => Ok(None),
        }
    }
}

impl RocksDBManagerImpl {
    pub async fn put_metadata(&self, key: &str, value: &[u8]) -> Result<(), String> {
        // Utilisation correcte de RocksDB pour insérer une clé et une valeur
        self.db.put(key.as_bytes(), value)
            .map_err(|e| format!("Erreur RocksDB put: {}", e))?;
        Ok(())
    }
}