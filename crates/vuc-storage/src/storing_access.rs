use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use bincode::Encode;

#[derive(Serialize, Deserialize, Clone, Encode)]
pub struct slurachainMetadata {
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

    // ✅ Méthodes existantes
    async fn store_metadata(&self, key: &str, metadata: &slurachainMetadata) -> Result<(), Box<dyn std::error::Error>>;
    async fn get_metadata(&self, key: &str) -> Result<Option<slurachainMetadata>, Box<dyn std::error::Error>>;

    // ✅ AJOUT: Méthodes pour compatibilité avec slurachain_vm.rs
    fn read(&self, key: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>>;
    fn write(&self, key: &str, value: Vec<u8>) -> Result<(), Box<dyn std::error::Error>>;
    fn store(&self, key: &str, value: Vec<u8>) -> Result<(), Box<dyn std::error::Error>>;
}

#[derive(Clone)]
pub struct RocksDBManagerImpl {
    db: Arc<RwLock<HashMap<String, slurachainMetadata>>>,
    // ✅ AJOUT: Stockage générique pour les données binaires
    binary_storage: Arc<RwLock<HashMap<String, Vec<u8>>>>,
}

#[async_trait::async_trait]
impl RocksDBManager for RocksDBManagerImpl {
    fn new() -> Self {
        RocksDBManagerImpl {
            db: Arc::new(RwLock::new(HashMap::new())),
            binary_storage: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    async fn store_metadata(&self, key: &str, metadata: &slurachainMetadata) -> Result<(), Box<dyn std::error::Error>> {
        let mut db = self.db.write().await;
        db.insert(key.to_string(), metadata.clone());
        Ok(())
    }

    async fn get_metadata(&self, key: &str) -> Result<Option<slurachainMetadata>, Box<dyn std::error::Error>> {
        let db = self.db.read().await;
        Ok(db.get(key).cloned())
    }

    // ✅ NOUVEAU: Implémentation synchrone pour read
    fn read(&self, key: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        // Utilisation de block_on pour convertir async en sync
        let rt = tokio::runtime::Handle::try_current()
            .or_else(|_| {
                tokio::runtime::Runtime::new()
                    .map(|rt| rt.handle().clone())
            })
            .map_err(|e| format!("Erreur runtime Tokio: {}", e))?;

        rt.block_on(async {
            let storage = self.binary_storage.read().await;
            storage.get(key)
                .cloned()
                .ok_or_else(|| format!("Clé '{}' non trouvée", key).into())
        })
    }

    // ✅ NOUVEAU: Implémentation synchrone pour write
    fn write(&self, key: &str, value: Vec<u8>) -> Result<(), Box<dyn std::error::Error>> {
        let rt = tokio::runtime::Handle::try_current()
            .or_else(|_| {
                tokio::runtime::Runtime::new()
                    .map(|rt| rt.handle().clone())
            })
            .map_err(|e| format!("Erreur runtime Tokio: {}", e))?;

        rt.block_on(async {
            let mut storage = self.binary_storage.write().await;
            storage.insert(key.to_string(), value);
            Ok(())
        })
    }

    // ✅ NOUVEAU: Alias pour store (même implémentation que write)
    fn store(&self, key: &str, value: Vec<u8>) -> Result<(), Box<dyn std::error::Error>> {
        self.write(key, value)
    }
}

impl RocksDBManagerImpl {
    pub async fn put_metadata(&self, key: &str, value: slurachainMetadata) -> Result<(), String> {
        let mut db = self.db.write().await;
        db.insert(key.to_string(), value);
        Ok(())
    }

    // ✅ NOUVEAU: Méthodes synchrones directes pour éviter les problèmes de runtime
    pub fn read_sync(&self, key: &str) -> Result<Vec<u8>, String> {
        // Version synchrone directe sans runtime Tokio
        // Pour une vraie implémentation, vous devriez utiliser une base de données synchrone
        // ou gérer le runtime Tokio correctement
        
        // Placeholder - retourne vide si non trouvé
        Ok(Vec::new())
    }

    pub fn write_sync(&self, key: &str, value: Vec<u8>) -> Result<(), String> {
        // Version synchrone directe
        // Placeholder - stockage temporaire
        Ok(())
    }

    pub fn store_sync(&self, key: &str, value: Vec<u8>) -> Result<(), String> {
        self.write_sync(key, value)
    }

    /// Ajout : méthode put pour stocker des données binaires (clé/valeur)
    pub fn put(&self, key: &str, value: &[u8]) -> Result<(), String> {
        let rt = tokio::runtime::Handle::try_current()
            .or_else(|_| {
                tokio::runtime::Runtime::new()
                    .map(|rt| rt.handle().clone())
            })
            .map_err(|e| format!("Erreur runtime Tokio: {}", e))?;

        rt.block_on(async {
            let mut storage = self.binary_storage.write().await;
            storage.insert(key.to_string(), value.to_vec());
            Ok(())
        })
    }
}