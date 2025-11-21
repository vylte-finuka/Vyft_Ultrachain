use serde::{Deserialize, Serialize};
use jsonrpsee_http_client::HttpClient;

use vuc_core::service::slurachain_service::SlurEthService;
use tokio::sync::{Mutex, mpsc};
use std::sync::Arc;
use hashbrown::HashMap;
use vuc_storage::storing_access::{RocksDBManager, RocksDBManagerImpl};
use vuc_events::timestamp_release::TimestampRelease;
use crate::consensus::lurosonie_manager::LurosonieManager;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ViewRequest {
    pub function: String,
    pub type_arguments: Option<Vec<String>>,
    pub arguments: Option<Vec<String>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StatusResponse {
    pub latest_block: String,
    pub vuc_response: String,
    pub total_blocks_mined: u64,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct TxRequest {
    pub from_op: String,
    pub receiver_op: String,
    pub value_tx: String,
    pub nonce_tx: u64,
    pub hash: String,
    // Ajout pour multicontrat
    pub contract_addr: Option<String>,
    pub function_name: Option<String>,
    pub arguments: Option<Vec<serde_json::Value>>,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct TxResponse {
    pub success: bool,
    pub message: String,
    pub block_number: u64, // Numéro du bloc
    pub vm_response: Option<String>, // Réponse de la VM
}

#[derive(Deserialize)]
struct StatusNodeParams {
    vslurachain: i32,
}

#[derive(Clone)]
pub struct slurachainRpcService {
    pub port: u16,
    pub http_url: String,
    pub ws_url: String,
    pub client: HttpClient,
    pub engine: Arc<Mutex<SlurEthService>>,
    pub storage: Arc<RocksDBManagerImpl>,
    pub latest_block: Arc<Mutex<Option<TimestampRelease>>>,
    pub block_receiver: Arc<Mutex<mpsc::Receiver<TimestampRelease>>>,
    pub total_blocks_mined: Arc<Mutex<u64>>,
    pub vyftid: String,
    pub lurosonie_manager: Arc<LurosonieManager>,
    pub pending_transactions: Arc<Mutex<HashMap<String, TxRequest>>>,
    pub vm: Arc<Mutex<SlurEthService>>, // Added vm field
}

impl slurachainRpcService {
    pub fn new(
        port: u16,
        http_url: String,
        ws_url: String,
        engine: Arc<Mutex<SlurEthService>>,
        storage: Arc<RocksDBManagerImpl>, // <-- Correction ici
        block_receiver: mpsc::Receiver<TimestampRelease>,
        lurosonie_manager: Arc<LurosonieManager>,
    ) -> Self {
        let client = HttpClient::builder().build(http_url.clone()).unwrap();
        Self {
            port,
            http_url,
            ws_url,
            client,
            engine: engine.clone(),
            storage, // <-- Utilise directement l'objet reçu
            latest_block: Arc::new(Mutex::new(None)),
            block_receiver: Arc::new(Mutex::new(block_receiver)),
            total_blocks_mined: Arc::new(Mutex::new(0)),
            vyftid: "vyftslurachain".to_string(),
            lurosonie_manager,
            pending_transactions: Arc::new(Mutex::new(HashMap::new())),
            vm: engine, // Initialize vm field
        }
    }

    /// Récupère l'identifiant de la chaîne
    pub fn get_chain_id(&self) -> u16 {
        // Retourne un identifiant unique pour la chaîne
        self.port // Exemple : Utiliser le port comme identifiant de la chaîne
    }

    /// Récupère l'époque actuelle depuis LurosonieManager
    pub fn get_epoch(&self) -> String {
        self.lurosonie_manager.epoch_id.to_string()
    }

    /// Récupère la version actuelle du registre
    pub async fn get_ledger_version(&self) -> u64 {
        // Récupère la dernière version du registre depuis le stockage
        1
    }

    /// Récupère la plus ancienne version du registre
    pub async fn get_oldest_ledger_version(&self) -> u64 {
        // Récupère la plus ancienne version du registre depuis le stockage
        1
    }

    /// Récupère le rôle du nœud
    pub fn get_node_role(&self) -> String {
        // Retourne le rôle du nœud (par exemple, "validator" ou "full_node")
        "validator".to_string()
    }

    /// Récupère la hauteur du plus ancien bloc
    pub async fn get_oldest_block_height(&self) -> u64 {
        // Récupère la hauteur du plus ancien bloc depuis LurosonieManager
        self.lurosonie_manager.get_oldest_block_height().await
    }

    /// Récupère la hauteur actuelle du bloc
    pub async fn get_block_height(&self) -> u64 {
        // Récupère la hauteur actuelle du bloc depuis LurosonieManager
        self.lurosonie_manager.get_block_height().await
    }

    /// Récupère le hash Git
    pub fn get_git_hash(&self) -> String {
        // Retourne le hash Git défini au moment de la compilation
        std::env::var("GIT_HASH").unwrap_or_else(|_| "unknown".to_string())
    }

    /// Récupère le nombre total de blocs minés
    pub async fn get_total_blocks_mined(&self) -> u64 {
        // Retourne le nombre total de blocs minés
        let total_blocks = self.total_blocks_mined.lock().await;
        *total_blocks
    }

    /// Récupère les informations du dernier bloc
    pub async fn get_latest_block(&self) -> Option<TimestampRelease> {
        // Retourne les informations du dernier bloc miné
        let latest_block = self.latest_block.lock().await;
        latest_block.clone()
    }

    /// Récupère les transactions en attente
    pub async fn get_pending_transactions(&self) -> Vec<TxRequest> {
        // Retourne la liste des transactions en attente
        let pending_transactions = self.pending_transactions.lock().await;
        pending_transactions.values().cloned().collect()
    }
}