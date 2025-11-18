use tokio::runtime;
use tokio::sync::Mutex;
use vuc_types::tx_op::TxOpPart;
use std::sync::Arc;
use tracing::info;
use hashbrown::HashMap;
use std::fmt;

/// Service global adapté pour endpoints Ethereum
#[derive(Clone)]
pub struct SlurEthService {
    pub accounts: Arc<Mutex<HashMap<String, u64>>>, // address -> balance
    pub last_nonce: Arc<Mutex<HashMap<String, u64>>>, // address -> nonce
}

impl SlurEthService {
    /// Crée un nouveau service Ethereum
    pub fn new() -> Self {
        SlurEthService {
            accounts: Arc::new(Mutex::new(HashMap::new())),
            last_nonce: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Ajoute ou met à jour le solde d'un compte
    pub async fn set_balance(&self, address: &str, balance: u64) {
        let mut accounts = self.accounts.lock().await;
        accounts.insert(address.to_lowercase(), balance);
    }

    /// Récupère le solde d'un compte
    pub async fn get_balance(&self, address: &str) -> u64 {
        let accounts = self.accounts.lock().await;
        accounts.get(&address.to_lowercase()).copied().unwrap_or(0)
    }

    /// Met à jour le nonce d'un compte
    pub async fn set_nonce(&self, address: &str, nonce: u64) {
        let mut nonces = self.last_nonce.lock().await;
        nonces.insert(address.to_lowercase(), nonce);
    }

    /// Récupère le nonce d'un compte
    pub async fn get_nonce(&self, address: &str) -> u64 {
        let nonces = self.last_nonce.lock().await;
        nonces.get(&address.to_lowercase()).copied().unwrap_or(0)
    }

    /// Monitoring simple pour Ethereum
    pub async fn log_eth_status(&self) {
        let accounts = self.accounts.lock().await;
        info!("Ethereum accounts: {:?}", accounts.keys().collect::<Vec<_>>());
    }
}

impl fmt::Display for SlurEthService {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SlurEthService {{ accounts: {}, nonces: {} }}",
            self.accounts.blocking_lock().len(),
            self.last_nonce.blocking_lock().len()
        )
    }
}

///___ Global service of slurachain process
#[derive(Clone)]
pub struct slurachainService {
    pub sign_op: String,
    pub tx_op: Vec<TxOpPart>,
    pub nonce_tx: u64,
    pub creator_id: String,
}

impl slurachainService {
    ///___ Service of consensus Lurosonie
    pub async fn lurosonie_process(_mutex: Arc<Mutex<HashMap<String, String>>>) {
        // Utilisez le runtime existant au lieu de créer un nouveau runtime
        info!("Le consensus Lurosonie est démarré.");
    }

    ///___ Service of slurachain process
    pub async fn slurachain_process(&self, _mutex: Arc<Mutex<HashMap<String, String>>>) {
        // Implémentez la logique du processus slurachain ici
    }
}

impl fmt::Display for slurachainService {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "slurachainService {{ tx_op: {:?}, nonce_tx: {}, sign_op: {}, creator_id: {} }}",
               self.tx_op, self.nonce_tx, self.sign_op, self.creator_id)
    }
}
