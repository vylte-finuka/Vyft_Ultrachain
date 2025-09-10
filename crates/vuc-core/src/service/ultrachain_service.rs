use tokio::runtime;
use tokio::sync::Mutex;
use vuc_types::tx_op::TxOpPart;
use std::sync::Arc;
use tracing::info;
use hashbrown::HashMap;
use std::fmt;

///___ Global service of ultrachain process
#[derive(Clone)]
pub struct UltrachainService {
    pub sign_op: String,
    pub tx_op: Vec<TxOpPart>,
    pub nonce_tx: u64,
    pub creator_id: String,
}

impl UltrachainService {
    ///___ Service of consensus Lurosonie
    pub async fn lurosonie_process(_mutex: Arc<Mutex<HashMap<String, String>>>) {
        // Utilisez le runtime existant au lieu de créer un nouveau runtime
        info!("Le consensus Lurosonie est démarré.");
    }

    ///___ Service of ultrachain process
    pub async fn ultrachain_process(&self, _mutex: Arc<Mutex<HashMap<String, String>>>) {
        // Implémentez la logique du processus ultrachain ici
    }
}

impl fmt::Display for UltrachainService {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UltrachainService {{ tx_op: {:?}, nonce_tx: {}, sign_op: {}, creator_id: {} }}",
               self.tx_op, self.nonce_tx, self.sign_op, self.creator_id)
    }
}
