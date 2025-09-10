use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use base64::encode as Base64_encode;

pub const GAS_UNIT_COST: u64 = 10 / 1;
pub const GAS_UNIT_COST_VALIDATORS: u64 = 10000;
pub const GAS_UNIT_COST_VALIDATORS_VOTE: u64 = 1000;
pub const GAS_UNIT_COST_VALIDATORS_VOTE_UPDATE: u64 = 1000;
pub const GAS_UNIT_COST_VALIDATORS_VOTE_REMOVE: u64 = 1000;
pub const GAS_UNIT_COST_VALIDATORS_VOTE_ADD: u64 = 1000;

pub const VALIDATOR_THRESHOLD: u64 = 3;
pub const MIN_VALIDATOR_VOTES: u64 = 1;
pub const MAX_VALIDATOR_VOTES: u64 = 10;


use bincode::Encode;



#[derive(Debug, Clone, Serialize, Deserialize, Encode)]
pub enum TxOpPart {
    OneLimitAccessEnabledStacking,
    ExpensiveData {
        from: String,
        to: String,
        value: u64,
    },
    Address(String),      // Pour les adresses Move
    U64(u64),             // Pour les valeurs u64
    Bytes(Vec<u8>),       // Pour les données binaires
    String(String),       // Pour les chaînes de caractères
    Bool(bool),           // Pour les booléens
    List(Vec<TxOpPart>),  // Pour les listes d'opérations
    Boolean(bool),        // Pour les booléens (doublon possible)
    Number(u64),          // Pour les nombres (doublon possible)
    Signer(String),    // À retirer, inutile pour Move
}

impl TxOpPart {
    /// Constante pour une opération de stacking avec accès limité
    pub const ONE_LIMIT_ACCESS_ENABLED_STACKING: Self = Self::OneLimitAccessEnabledStacking;

    /// Vérifie si l'opération est coûteuse
    pub fn is_expensive(&self) -> bool {
        matches!(
            self,
            Self::OneLimitAccessEnabledStacking
                | Self::ExpensiveData { .. }
                | Self::Address(_)
                | Self::U64(_)
        )
    }

    /// Génère une architecture de consensus pour l'opération
    pub fn tx_op_consensus_arch(self) -> ConsensusArch {
        // Créer une intention pour le consensus
        let topology = Intent::new(IntentScope::Consensus, self);

        // Créer une architecture de consensus basée sur l'intention
        let consensus_arch = ConsensusArch::new(topology);

        // Envoyer un message d'alerte pour le consensus
        let worthalert = IntentMessage::new("Consensus alert");
        let flowing = Base64_encode("lens".as_bytes());
        worthalert.send(flowing);

        consensus_arch
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxRequest {
    pub from_op: String,
    pub receiver_op: String,
    pub value_tx: String,
    pub nonce_tx: u64,
    pub tx_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxResponse {
    pub success: bool,
    pub message: String,
    pub block_number: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ViewRequest {
    pub function: String,
    pub type_arguments: Option<Vec<String>>,
    pub arguments: Option<Vec<String>>,
}

pub struct ConsensusArch {
    topology: Intent,
}

impl ConsensusArch {
    pub fn new(topology: Intent) -> Self {
        ConsensusArch { topology }
    }

    pub fn modele_type(&self) -> String {
        let mut model_type = String::new();

        if self.topology.scope == IntentScope::Consensus {
            model_type.push_str("Consensus Model");
        } else {
            model_type.push_str("Basic Model");
        }

        let Intent { scope: _, intent: tx_op } = &self.topology;
        if tx_op.is_expensive() {
            model_type.push_str(" - Expensive Data");
        } else {
            model_type.push_str(" - Standard Data");
        }

        model_type
    }
}

pub struct IntentMessage {
    message: String,
}

impl IntentMessage {
    pub fn new(message: &str) -> Self {
        IntentMessage {
            message: message.to_string(),
        }
    }

    pub fn send(&self, data: String) {
        println!("Sending message: {} with data: {}", self.message, data);
    }
}

pub trait VoteJudge {
    fn handle_vote(&self, vote: TxOpPart) -> Result<(), String>;
    fn update_vote(&self, vote: TxOpPart) -> Result<(), String>;
    fn remove_vote(&self, vote: TxOpPart) -> Result<(), String>;
    fn add_vote(&self, vote: TxOpPart) -> Result<(), String>;
}

impl VoteJudge for dyn VoteManager {
    fn handle_vote(&self, vote: TxOpPart) -> Result<(), String> {
        let gas_cost = GAS_UNIT_COST_VALIDATORS_VOTE;
        VoteManager::log_vote_action(self, "handle", vote, gas_cost)
    }

    fn update_vote(&self, vote: TxOpPart) -> Result<(), String> {
        let gas_cost = GAS_UNIT_COST_VALIDATORS_VOTE_UPDATE;
        VoteManager::log_vote_action(self, "update", vote, gas_cost)
    }

    fn remove_vote(&self, vote: TxOpPart) -> Result<(), String> {
        let gas_cost = GAS_UNIT_COST_VALIDATORS_VOTE_REMOVE;
        VoteManager::log_vote_action(self, "remove", vote, gas_cost)
    }

    fn add_vote(&self, vote: TxOpPart) -> Result<(), String> {
        let gas_cost = GAS_UNIT_COST_VALIDATORS_VOTE_ADD;
        VoteManager::log_vote_action(self, "add", vote, gas_cost)
    }
}

pub trait VoteManager {
    fn log_vote_action(&self, action: &str, vote: TxOpPart, gas_cost: u64) -> Result<(), String>;
}

#[derive(PartialEq, Debug, Clone, Serialize, Deserialize)]
pub enum IntentScope {
    Consensus,
    Basic,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Intent {
    pub scope: IntentScope,
    pub intent: TxOpPart,
}

impl Intent {
    pub fn new(scope: IntentScope, intent: TxOpPart) -> Self {
        Intent { scope, intent }
    }
}