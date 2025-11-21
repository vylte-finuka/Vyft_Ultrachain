use std::collections::HashMap;
use std::sync::Arc;
use base64::Engine as _;
use chrono::Utc;
use tracing::{info, error, warn};
use tokio::sync::mpsc;
use tokio::time::{interval, Duration, Instant};
use sha3::{Sha3_256, Digest};
use serde_json;
use lazy_static::lazy_static;
use base64::engine::general_purpose::STANDARD as base64_standard;
use vuc_events::timestamp_release::TimestampRelease;
use vuc_events::time_warp::TimeWarp;
use vuc_types::committee::committee::EpochId;
use vuc_types::supported_protocol_versions::SupportedProtocolVersions;
use crate::slurachain_rpc_service::TxRequest;
use vuc_tx::slurachain_vm::SlurachainVm;
use crate::consensus::slurachain_gov::slurachainGovernance;
use vuc_storage::storing_access::{RocksDBManager, RocksDBManagerImpl, slurachainMetadata};
use tokio::sync::{RwLock, Mutex};

lazy_static! {
    static ref CONTRACT_STATE_HISTORY: Mutex<HashMap<String, Vec<Vec<u8>>>> = Mutex::new(HashMap::new());
}

// ✅ CONSTANTES LUROSONIE
pub const LUROSONIE_DECENTRALIZATION_THRESHOLD: u128 = 42_500_000_000_000_000_000_000_000_000u128;
pub const LUROSONIE_MIN_RELAY_STAKE: u64 = 30_000; // 30k VEZ minimum
pub const LUROSONIE_SYSTEM_VALIDATOR: &str = "0x53ae54b11251d5003e9aa51422405bc35a2ef32d";

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct BlockData {
    pub block: TimestampRelease,
    pub transactions: Vec<TxRequest>,
    pub validator: String,
    pub contract_states: HashMap<String, Vec<u8>>,
    pub execution_results: HashMap<String, serde_json::Value>,
    pub relay_power: u64,
    pub delegated_stake: u64,
    pub is_system_block: bool, // ✅ Nouveau: indique si c'est un bloc système
}

#[derive(Clone, Debug)]
pub struct RelayValidator {
    pub address: String,
    pub stake: u64,
    pub delegated_stake: u64,
    pub total_power: u64,
    pub is_active: bool,
    pub relay_count: u64,
    pub last_relay_time: u64,
    pub is_system: bool, // ✅ Nouveau: validateur système
}

#[derive(Clone, Debug)]
pub struct StakeDelegation {
    pub delegator: String,
    pub validator: String,
    pub amount: u64,
    pub timestamp: u64,
}

pub struct LurosonieManager {
    pub epoch_id: EpochId,
    pub committee: Vec<String>,
    pub supported_protocol_versions: SupportedProtocolVersions,
    pub balances: Arc<RwLock<HashMap<String, u64>>>,
    pub time_warp: TimeWarp,
    pub storage: Arc<RocksDBManagerImpl>,
    pub block_sender: mpsc::Sender<TimestampRelease>,
    pub pending_transactions: Arc<RwLock<HashMap<String, TxRequest>>>,
    pub block_counts: Arc<RwLock<HashMap<String, u64>>>,
    pub vm: Arc<RwLock<SlurachainVm>>,
    pub governance: Arc<RwLock<HashMap<String, slurachainGovernance>>>,
    pub last_block_hash: Arc<RwLock<Option<String>>>,
    pub validators: Arc<RwLock<Vec<String>>>,
    pub slurachain_data: Arc<RwLock<Vec<BlockData>>>,
    pub current_validator_index: Arc<RwLock<usize>>,
    pub block_time_ms: u64,
    // ✅ CHAMPS LUROSONIE BFT RELAYED POS
    pub relay_validators: Arc<RwLock<HashMap<String, RelayValidator>>>,
    pub delegations: Arc<RwLock<Vec<StakeDelegation>>>,
    pub min_relay_stake: u64,
    pub relay_round_duration: u64,
    pub current_relay_leader: Arc<RwLock<Option<String>>>,
    pub total_vez_supply: Arc<RwLock<u64>>, // ✅ Nouveau: suivi total VEZ
    pub is_decentralized: Arc<RwLock<bool>>, // ✅ Nouveau: état décentralisé
}

impl LurosonieManager {
    /// Ajoute une transaction dans le mempool Lurosonie
    pub async fn add_transaction_to_mempool(&self, tx: TxRequest) {
        let tx_hash = tx.hash.clone();
        let mut pending = self.pending_transactions.write().await;
        pending.insert(tx_hash.clone(), tx);
        println!("✅ Transaction ajoutée au mempool Lurosonie : {}", tx_hash);
    }
}

impl LurosonieManager {

    pub async fn new_with_storage(
        storage: Arc<RocksDBManagerImpl>, 
        vm: Arc<RwLock<SlurachainVm>>,
        block_sender: mpsc::Sender<TimestampRelease>
    ) -> Self {
        let mut vm_instance = vm.write().await;
        vm_instance.set_storage_manager(storage.clone());
        drop(vm_instance);

        LurosonieManager {
            epoch_id: EpochId::default(),
            committee: vec![],
            supported_protocol_versions: SupportedProtocolVersions::default(),
            governance: Arc::new(RwLock::new(HashMap::new())),
            balances: Arc::new(RwLock::new(HashMap::new())),
            time_warp: TimeWarp::default(),
            block_sender,
            pending_transactions: Arc::new(RwLock::new(HashMap::<String, TxRequest>::new())),
            block_counts: Arc::new(RwLock::new(HashMap::new())),
            vm: vm.clone(),
            last_block_hash: Arc::new(RwLock::new(None)),
            validators: Arc::new(RwLock::new(Vec::new())),
            storage,
            slurachain_data: Arc::new(RwLock::new(Vec::new())),
            current_validator_index: Arc::new(RwLock::new(0)),
            block_time_ms: 3000,
            relay_validators: Arc::new(RwLock::new(HashMap::new())),
            delegations: Arc::new(RwLock::new(Vec::new())),
            min_relay_stake: LUROSONIE_MIN_RELAY_STAKE,
            relay_round_duration: 15_000,
            current_relay_leader: Arc::new(RwLock::new(None)),
            total_vez_supply: Arc::new(RwLock::new(0)), // ✅ Nouveau
            is_decentralized: Arc::new(RwLock::new(false)), // ✅ Nouveau
        }
    }

    /// ✅ CONSENSUS LUROSONIE BFT RELAYED POS avec seuil système
    pub async fn start_lurosonie_consensus(&self) {
        println!("🚀 Démarrage du consensus LUROSONIE - Relayed PoS BFT");
        println!("🏛️ Validateur système actif jusqu'à {} VEZ de supply totale", LUROSONIE_DECENTRALIZATION_THRESHOLD);
        println!("💰 Stake minimum pour validateurs décentralisés: {} VEZ", self.min_relay_stake);
        println!("⏰ Durée d'un round de relais: {}ms", self.relay_round_duration);
        
        // ✅ Initialisation du validateur système
        self.initialize_system_validator().await;
        
        let mut block_interval = tokio::time::interval(Duration::from_millis(self.block_time_ms));
        let mut relay_interval = tokio::time::interval(Duration::from_millis(self.relay_round_duration));
        let mut supply_check_interval = tokio::time::interval(Duration::from_secs(30)); // Vérification toutes les 30s
        let mut block_number = 0u64;
        let mut relay_round = 0u64;
        
        loop {
            tokio::select! {
                // ✅ VÉRIFICATION DU SEUIL DE DÉCENTRALISATION
                _ = supply_check_interval.tick() => {
                    if let Err(e) = self.check_decentralization_threshold().await {
                        error!("❌ Erreur vérification seuil décentralisation: {}", e);
                    }
                }
                
                // ✅ RELAIS DE POUVOIR (seulement si décentralisé)
                _ = relay_interval.tick() => {
                    let is_decentralized = *self.is_decentralized.read().await;
                    if is_decentralized {
                        relay_round += 1;
                        println!("🔄 Round de relais #{} - Sélection du nouveau leader", relay_round);
                        
                        if let Err(e) = self.lurosonie_relay_power_rotation().await {
                            error!("❌ Erreur rotation relais #{}: {}", relay_round, e);
                        }
                    }
                }
                
                // ✅ PRODUCTION DE BLOCS
                _ = block_interval.tick() => {
                    // Synchronise le numéro de bloc avec la hauteur réelle
                    let block_number = self.get_block_height().await + 1;

                    // Sélection du producteur de bloc
                    let block_producer = self.select_block_producer().await;
                    let is_system_block = block_producer == LUROSONIE_SYSTEM_VALIDATOR;

                    println!("🔄 Bloc #{} - Producteur: {} {}", 
                             block_number, block_producer, 
                             if is_system_block { "(SYSTÈME)" } else { "(DÉCENTRALISÉ)" });
                    
                    // Production du bloc
                    if let Err(e) = self.produce_lurosonie_block(block_number, &block_producer, is_system_block).await {
                        error!("❌ Erreur production bloc #{}: {}", block_number, e);
                        continue;
                    }
                    
                    // Consensus BFT
                    if let Err(e) = self.lurosonie_bft_consensus(block_number).await {
                        error!("❌ Consensus Lurosonie échoué pour bloc #{}: {}", block_number, e);
                        continue;
                    }
                    
                    println!("✅ Bloc #{} produit et validé par consensus Lurosonie", block_number);
                }
            }
        }
    }

    /// ✅ INITIALISATION DU VALIDATEUR SYSTÈME
    async fn initialize_system_validator(&self) {
        let system_validator = RelayValidator {
            address: LUROSONIE_SYSTEM_VALIDATOR.to_string(),
            stake: u64::MAX, // Stake infini pour le système
            delegated_stake: 0,
            total_power: u64::MAX,
            is_active: true,
            relay_count: 0,
            last_relay_time: chrono::Utc::now().timestamp() as u64,
            is_system: true,
        };
        
        let mut validators = self.relay_validators.write().await;
        validators.insert(LUROSONIE_SYSTEM_VALIDATOR.to_string(), system_validator);
        
        // Définit le système comme leader initial
        {
            let mut current_leader = self.current_relay_leader.write().await;
            *current_leader = Some(LUROSONIE_SYSTEM_VALIDATOR.to_string());
        }
        
        println!("🏛️ Validateur système Lurosonie initialisé");
    }
    
    /// ✅ VÉRIFICATION DU SEUIL DE DÉCENTRALISATION
    async fn check_decentralization_threshold(&self) -> Result<(), String> {
        let current_supply = self.calculate_total_vez_supply().await?;
        
        {
            let mut total_supply = self.total_vez_supply.write().await;
            *total_supply = current_supply.try_into().unwrap_or(0);
        }
        
        let is_currently_decentralized = *self.is_decentralized.read().await;
        let should_be_decentralized = current_supply >= LUROSONIE_DECENTRALIZATION_THRESHOLD as u128;
        
        if !is_currently_decentralized && should_be_decentralized {
            // ✅ TRANSITION VERS LA DÉCENTRALISATION
            println!("🎉 SEUIL DE DÉCENTRALISATION ATTEINT!");
            println!("📊 Supply totale: {} VEZ >= {} VEZ (seuil)", current_supply, LUROSONIE_DECENTRALIZATION_THRESHOLD);
            println!("🔄 Activation des validateurs décentralisés...");
            
            {
                let mut is_decentralized = self.is_decentralized.write().await;
                *is_decentralized = true;
            }
            
            // Synchronise les validateurs depuis la VM
            self.sync_relay_validators_from_vm().await?;
            
            println!("✅ Transition vers consensus décentralisé Lurosonie terminée");
        } else if is_currently_decentralized && !should_be_decentralized {
            // ✅ RETOUR AU MODE SYSTÈME (improbable mais géré)
            println!("⚠️ RETOUR AU MODE SYSTÈME (supply insuffisante)");
            {
                let mut is_decentralized = self.is_decentralized.write().await;
                *is_decentralized = false;
            }
        }
        
        Ok(())
    }

    /// ✅ CALCUL DE LA SUPPLY TOTALE VEZ
    async fn calculate_total_vez_supply(&self) -> Result<u128, String> {
        let accounts: Vec<(String, u64)> = {
            let vm = self.vm.read().await;
            let accounts = vm.state.accounts.read().unwrap();
            accounts.iter()
                .filter(|(address, _)| *address != "system" && *address != "0x0")
                .map(|(address, account)| (address.clone(), account.balance as u64))
                .collect()
        };
        
        let mut total_supply = 0u64;
        
        // Check if VEZ contract is available
        let vezcur_address = self.find_vezcur_contract_address().await.ok();
        
        for (address, account_balance) in accounts {
            if let Some(ref vezcur_addr) = vezcur_address {
                // Try to get balance from VEZ contract
                let mut vm_write = self.vm.write().await;
                match vm_write.execute_module(vezcur_addr, "balanceOf",
                    vec![serde_json::Value::String(address.clone())], Some("system")) {
                    Ok(result) => {
                        if let Some(solde) = result.as_u64() {
                            total_supply = total_supply.saturating_add(solde);
                        }
                    }
                    Err(_) => {
                        // Fallback sur le solde du compte
                        total_supply = total_supply.saturating_add(account_balance);
                    }
                }
            } else {
                // Pas de contrat VEZ, utilise les soldes des comptes
                total_supply = total_supply.saturating_add(account_balance);
            }
        }
        
        Ok(total_supply as u128)
    }

    /// ✅ SÉLECTION DU PRODUCTEUR DE BLOC
    async fn select_block_producer(&self) -> String {
        let is_decentralized = *self.is_decentralized.read().await;
        
        if !is_decentralized {
            // Mode système: le validateur système produit tous les blocs
            return LUROSONIE_SYSTEM_VALIDATOR.to_string();
        }
        
        // Mode décentralisé: utilise le leader de relais actuel
        let current_leader = self.current_relay_leader.read().await;
        current_leader.clone().unwrap_or_else(|| LUROSONIE_SYSTEM_VALIDATOR.to_string())
    }

    /// ✅ PRODUCTION D'UN BLOC LUROSONIE (système ou décentralisé)
        pub async fn produce_lurosonie_block(&self, block_number: u64, producer: &str, is_system_block: bool) -> Result<(), String> {
        let start_time = Instant::now();
    
        // ✅ Vérification des droits de production
        if !is_system_block {
            let can_produce = {
                let validators = self.relay_validators.read().await;
                validators.get(producer)
                    .map(|v| v.is_active && (v.is_system || v.total_power >= self.min_relay_stake))
                    .unwrap_or(false)
            };
    
            if !can_produce {
                return Err(format!("Producteur {} n'a pas le droit de produire un bloc", producer));
            }
        }
    
        // ✅ Collecte des transactions
        let transactions = self.get_pending_transactions().await;
        println!("📦 {} transactions à traiter dans le bloc Lurosonie #{}", transactions.len(), block_number);
    
        // ✅ Récupération du pouvoir de relais
        let relay_power = if is_system_block {
            u64::MAX // Pouvoir infini pour le système
        } else {
            let validators = self.relay_validators.read().await;
            validators.get(producer).map(|v| v.total_power).unwrap_or(0)
        };
    
        let delegated_stake = if is_system_block { 0 } else { self.get_delegated_stake(producer).await };
    
        // ✅ Création du bloc avec métadonnées Lurosonie
        let block = TimestampRelease {
            timestamp: Utc::now(),
            log: format!("Bloc Lurosonie #{} produit par {} {} (pouvoir: {} VEZ)", 
                        block_number, 
                        if is_system_block { "validateur système" } else { "leader de relais" },
                        producer, 
                        if relay_power == u64::MAX { "∞".to_string() } else { relay_power.to_string() }),
            block_number,
            vyfties_id: producer.to_string(),
        };
    
        // ✅ Exécution des transactions
        let mut contract_states: HashMap<String, Vec<u8>> = HashMap::new();
        let mut execution_results = HashMap::new();
        let mut processed_hashes = Vec::new();

        for tx in &transactions {
            match self.execute_transaction_in_block(tx).await {
                Ok(result) => {
                    execution_results.insert(tx.hash.clone(), result);
                    processed_hashes.push(tx.hash.clone());

                    let metadata = slurachainMetadata {
                        from_op: tx.from_op.clone(),
                        receiver_op: tx.receiver_op.clone(),
                        fees_tx: 0,
                        value_tx: tx.value_tx.clone(),
                        nonce_tx: tx.nonce_tx,
                        hash_tx: tx.hash.clone(),
                    };
                    if let Err(e) = self.storage.store_metadata(&tx.hash, &metadata).await {
                        error!("❌ Erreur sauvegarde transaction {}: {}", tx.hash, e);
                    }
                }
                Err(e) => {
                    error!("❌ Échec exécution tx {} (restera dans le mempool): {}", tx.hash, e);
                    execution_results.insert(tx.hash.clone(), serde_json::json!({
                        "status": "failed",
                        "error": e
                    }));
                }
            }
        }
    
        // ✅ Création des données complètes du bloc Lurosonie
        let block_data = BlockData {
            block: block.clone(),
            transactions: transactions.clone(),
            validator: producer.to_string(),
            contract_states: HashMap::new(), // vide ici
            execution_results,
            relay_power,
            delegated_stake,
            is_system_block,
        };
    
        // ✅ Ajout à la slurachain
        self.add_lurosonie_block_to_chain(block_data).await?;
    
        // ✅ Mise à jour des statistiques du validateur
        if !is_system_block {
            let mut validators = self.relay_validators.write().await;
            if let Some(validator) = validators.get_mut(producer) {
                validator.relay_count += 1;
                validator.last_relay_time = chrono::Utc::now().timestamp() as u64;
            }
        }
    
        // ✅ Nettoyage des transactions traitées
        self.remove_processed_transactions(processed_hashes).await;
    
        println!("⚡ Bloc Lurosonie #{} produit en {:?} par {} {} (pouvoir: {} VEZ)", 
                 block_number, start_time.elapsed(), 
                 if is_system_block { "système" } else { "validateur" },
                 producer, 
                 if relay_power == u64::MAX { "∞".to_string() } else { relay_power.to_string() });
        Ok(())
    }

    /// ✅ AJOUT: Récupération des transactions en attente
    pub async fn get_pending_transactions(&self) -> Vec<TxRequest> {
        let pending = self.pending_transactions.read().await;
        pending.values().cloned().collect()
    }

    /// ✅ AJOUT: Récupération d'un bloc par son numéro
    pub async fn get_block_by_number(&self, block_number: u64) -> Option<BlockData> {
        let slurachain = self.slurachain_data.read().await;
        slurachain.iter()
            .find(|bd| bd.block.block_number == block_number)
            .cloned()
    }

    /// ✅ AJOUT: Récupération des derniers blocs
    pub async fn get_latest_blocks(&self, count: usize) -> Vec<BlockData> {
        let slurachain = self.slurachain_data.read().await;
        slurachain.iter()
            .rev()
            .take(count)
            .cloned()
            .collect()
    }

    /// ✅ AJOUT: Statistiques des transactions en attente
    pub async fn get_pending_transaction_count(&self) -> usize {
        let pending = self.pending_transactions.read().await;
        pending.len()
    }

    /// ✅ AJOUT: Nettoyage des anciennes transactions en attente
    pub async fn cleanup_old_pending_transactions(&self, max_age_seconds: u64) {
        let current_time = chrono::Utc::now().timestamp() as u64;
        let mut pending = self.pending_transactions.write().await;
        
        // Garde seulement les transactions récentes
        pending.retain(|_, tx| {
            current_time.saturating_sub(tx.nonce_tx) < max_age_seconds
        });
    }

    /// ✅ CONSENSUS BFT LUROSONIE (adapté système + décentralisé)
    pub async fn lurosonie_bft_consensus(&self, block_number: u64) -> Result<(), String> {
        let is_decentralized = *self.is_decentralized.read().await;
        
        if !is_decentralized {
            // ✅ MODE SYSTÈME: consensus automatique (1/1)
            println!("✅ Consensus Lurosonie système automatique pour bloc #{}", block_number);
            return Ok(());
        }
        
        // ✅ MODE DÉCENTRALISÉ: consensus BFT classique
        let validators = {
            let relay_validators = self.relay_validators.read().await;
            relay_validators.iter()
                .filter(|(_, v)| !v.is_system) // Exclut le validateur système
                .map(|(addr, _)| addr.clone())
                .collect::<Vec<_>>()
        };
        
        if validators.is_empty() {
            return Ok(()); // Pas de validateurs décentralisés disponibles
        }
        
        // ✅ CONSENSUS BFT: 2/3 + 1 des validateurs de relais doivent confirmer
        let required_confirmations = ((validators.len() * 2) / 3) + 1;
        let mut confirmations = 0;
        let mut confirmed_voting_power = 0u64;
        
        // ✅ CORRECTION: Calcul du pouvoir de vote total
        let total_voting_power = {
            let relay_validators = self.relay_validators.read().await;
            relay_validators.values()
                .filter(|v| !v.is_system)
                .map(|v| v.total_power)
                .sum::<u64>()
        };
        
        // ✅ VALIDATION PAR CHAQUE VALIDATEUR DE RELAIS
        for validator in &validators {
            if self.validate_lurosonie_block(block_number, validator).await {
                confirmations += 1;
                
                // Ajoute le pouvoir de vote du validateur
                let voting_power = {
                    let relay_validators = self.relay_validators.read().await;
                    relay_validators.get(validator).map(|v| v.total_power).unwrap_or(0)
                };
                confirmed_voting_power += voting_power;
                
                println!("✅ Validateur {} confirme bloc #{} (pouvoir: {} VEZ)", 
                         validator, block_number, voting_power);
                
                // Vérifie si on a assez de confirmations ET de pouvoir de vote
                if confirmations >= required_confirmations && 
                   confirmed_voting_power > (total_voting_power * 2 / 3) {
                    println!("✅ Consensus Lurosonie BFT atteint: {}/{} validateurs, {}/{} VEZ de pouvoir", 
                            confirmations, validators.len(), confirmed_voting_power, total_voting_power);
                    return Ok(());
                }
            }
        }
        
        Err(format!("Consensus Lurosonie échoué: {}/{} confirmations, {}/{} VEZ de pouvoir", 
                   confirmations, required_confirmations, confirmed_voting_power, total_voting_power))
    }

    /// ✅ ROTATION DU POUVOIR DE RELAIS (seulement en mode décentralisé)
    async fn lurosonie_relay_power_rotation(&self) -> Result<(), String> {
        // ✅ 1. Synchroniser les stakes avec la VM
        self.sync_relay_validators_from_vm().await?;
        
        // ✅ 2. Calculer les pouvoirs de relais
        self.calculate_relay_powers().await?;
        
        // ✅ 3. Sélectionner le nouveau leader selon l'algorithme Lurosonie
        let new_leader = self.select_lurosonie_relay_leader().await?;
        
        // ✅ 4. Mettre à jour le leader actuel
        {
            let mut current_leader = self.current_relay_leader.write().await;
            *current_leader = Some(new_leader.clone());
        }
        
        println!("🎯 Nouveau leader de relais Lurosonie: {}", new_leader);
        Ok(())
    }

    /// ✅ SYNCHRONISATION DES VALIDATEURS DE RELAIS DEPUIS LA VM
    async fn sync_relay_validators_from_vm(&self) -> Result<(), String> {
        let accounts: Vec<String> = {
            let vm = self.vm.read().await;
            let state = vm.state.accounts.read().unwrap();
            state.keys().cloned().collect()
        };
        
        let mut new_validators = HashMap::new();
        
        // ✅ Garde toujours le validateur système
        {
            let current_validators = self.relay_validators.read().await;
            if let Some(system_validator) = current_validators.get(LUROSONIE_SYSTEM_VALIDATOR) {
                new_validators.insert(LUROSONIE_SYSTEM_VALIDATOR.to_string(), system_validator.clone());
            }
        }
        
        // ✅ Synchronise les validateurs depuis les comptes VEZ
        for account in accounts {
            if account == "0x0" || account == "0x6" || account == "system" || account == LUROSONIE_SYSTEM_VALIDATOR {
                continue;
            }
            
            let stake = {
                let mut vm = self.vm.write().await;
                
                let vezcur_address = self.find_vezcur_contract_address().await
                    .unwrap_or_else(|_| "*frame000*".to_string());
                
                match vm.execute_module(&vezcur_address, "solde_of",
                    vec![serde_json::Value::String(account.clone())], Some(&account)) {
                    Ok(result) => {
                        if let Some(solde) = result.as_u64() {
                            solde
                        } else if let Some(result_str) = result.as_str() {
                            result_str.parse::<u64>().unwrap_or(0)
                        } else {
                            0
                        }
                    }
                    Err(_) => 0,
                }
            };
            
            if stake >= self.min_relay_stake {
                let delegated_stake = self.get_delegated_stake(&account).await;
                let total_power = stake + delegated_stake;
                
                new_validators.insert(account.clone(), RelayValidator {
                    address: account.clone(),
                    stake,
                    delegated_stake,
                    total_power,
                    is_active: true,
                    relay_count: 0,
                    last_relay_time: chrono::Utc::now().timestamp() as u64,
                    is_system: false,
                });
                
                println!("✅ Validateur de relais: {} (stake: {} VEZ, délégué: {} VEZ, pouvoir total: {} VEZ)", 
                         account, stake, delegated_stake, total_power);
            }
        }
        
        // ✅ Mise à jour des validateurs de relais
        {
            let mut validators = self.relay_validators.write().await;
            *validators = new_validators;
        }
        
        Ok(())
    }

    /// ✅ NOUVELLE FONCTION HELPER pour trouver l'adresse du contrat VEZ
    async fn find_vezcur_contract_address(&self) -> Result<String, String> {
        let vm = self.vm.read().await;
        
        // ✅ Cherche dans tous les modules chargés celui qui contient VEZ
        for (address, module) in &vm.modules {
            let meta_str = String::from_utf8_lossy(&module.context.meta);
            
            // ✅ Vérifie si c'est le contrat VEZ
            if meta_str.contains("ticker=VEZ") || meta_str.contains("title=Vyft enhancing ZER") {
                println!("DEBUG: ✅ Contrat VEZ trouvé à l'adresse: {}", address);
                return Ok(address.clone());
            }
        }
        
        // ✅ Fallback: utilise address_map
        if let Some(vezcur_addr) = vm.address_map.get("vezcur") {
            return Ok(vezcur_addr.clone());
        }
        
        Err("Aucun contrat VEZ trouvé dans les modules chargés".to_string())
    }
    
    /// ✅ CALCUL DES POUVOIRS DE RELAIS
    async fn calculate_relay_powers(&self) -> Result<(), String> {
        let mut validators = self.relay_validators.write().await;
        
        for (address, validator) in validators.iter_mut() {
            // Recalcule le pouvoir total (stake personnel + délégué)
            validator.delegated_stake = self.get_delegated_stake(address).await;
            validator.total_power = validator.stake + validator.delegated_stake;
            
            println!("🔢 Pouvoir de relais calculé: {} = {} VEZ", address, validator.total_power);
        }
        
        Ok(())
    }
    
    /// ✅ SÉLECTION DU LEADER DE RELAIS SELON L'ALGORITHME LUROSONIE
    async fn select_lurosonie_relay_leader(&self) -> Result<String, String> {
        let validators = self.relay_validators.read().await;
        
        if validators.is_empty() {
            return Ok("system".to_string());
        }
        
        // ✅ ALGORITHME LUROSONIE: Sélection pondérée par le pouvoir de relais
        let total_power: u64 = validators.values().map(|v| v.total_power).sum();
        if total_power == 0 {
            return Ok("system".to_string());
        }
        
        // Génère un nombre aléatoire basé sur le timestamp + hash du dernier bloc
        let mut random_seed = chrono::Utc::now().timestamp() as u64;
        if let Some(last_hash) = &*self.last_block_hash.read().await {
            let hash_bytes = last_hash.as_bytes();
            for &byte in hash_bytes.iter().take(8) {
                random_seed ^= byte as u64;
            }
        }
        
        let target = random_seed % total_power;
        let mut cumulative_power = 0;
        
        for (address, validator) in validators.iter() {
            cumulative_power += validator.total_power;
            if cumulative_power > target {
                println!("🎯 Leader sélectionné par algorithme Lurosonie: {} (pouvoir: {} VEZ)", 
                         address, validator.total_power);
                return Ok(address.clone());
            }
        }
        
        // Fallback sur le premier validateur
        Ok(validators.keys().next().unwrap().clone())
    }
    
    /// ✅ RÉCUPÉRATION DU STAKE DÉLÉGUÉ
    async fn get_delegated_stake(&self, validator: &str) -> u64 {
        let delegations = self.delegations.read().await;
        delegations.iter()
            .filter(|d| d.validator == validator)
            .map(|d| d.amount)
            .sum()
    }
    
    /// ✅ VALIDATION D'UN BLOC POUR LUROSONIE
    async fn validate_lurosonie_block(&self, block_number: u64, validator: &str) -> bool {
        let slurachain = self.slurachain_data.read().await;
        if let Some(block_data) = slurachain.iter().find(|bd| bd.block.block_number == block_number) {
            // ✅ Critères de validation Lurosonie
            let is_valid = !block_data.block.vyfties_id.is_empty() 
                && block_data.block.block_number > 0
                && block_data.relay_power >= self.min_relay_stake; // Le producteur doit avoir le stake minimum
                
            if is_valid {
                println!("✅ Validateur {} confirme bloc Lurosonie #{}", validator, block_number);
            } else {
                println!("❌ Validateur {} rejette bloc Lurosonie #{}", validator, block_number);
            }
            
            return is_valid;
        }
        false
    }
    
    /// ✅ AJOUT D'UN BLOC À LA CHAÎNE LUROSONIE
    async fn add_lurosonie_block_to_chain(&self, block_data: BlockData) -> Result<(), String> {
        // Calcul du hash avec métadonnées Lurosonie
        let block_serialized = serde_json::to_string(&serde_json::json!({
            "block": block_data.block,
            "relay_power": block_data.relay_power,
            "delegated_stake": block_data.delegated_stake,
            "validator": block_data.validator
        })).map_err(|e| format!("Erreur sérialisation bloc Lurosonie: {}", e))?;
        
        let mut hasher = Sha3_256::new();
        hasher.update(block_serialized.as_bytes());
        let hash = format!("{:x}", hasher.finalize());
        
        // Mise à jour du hash du dernier bloc
        {
            let mut last_hash = self.last_block_hash.write().await;
            *last_hash = Some(hash.clone());
        }
        
        // Ajout à la slurachain
        {
            let mut slurachain = self.slurachain_data.write().await;
            slurachain.push(block_data.clone());
        }
        
        // Sauvegarde des états de contrat avec métadonnées Lurosonie
        for (contract_address, state) in &block_data.contract_states {
            let state_key = format!("lurosonie_contract_state:{}:{}", contract_address, block_data.block.block_number);
            let state_metadata = slurachainMetadata {
                from_op: "lurosonie_system".to_string(),
                receiver_op: contract_address.clone(),
                fees_tx: 0,
                value_tx: base64_standard.encode(state),
                nonce_tx: block_data.block.block_number,
                hash_tx: hash.clone(),
            };
            
            if let Err(e) = self.storage.store_metadata(&state_key, &state_metadata).await {
                error!("❌ Erreur sauvegarde état contrat Lurosonie {}: {}", contract_address, e);
            }
        }
        
        // Envoi du bloc aux listeners
        if let Err(e) = self.block_sender.send(block_data.block.clone()).await {
            error!("❌ Erreur envoi bloc Lurosonie: {}", e);
        }
        
        println!("🔗 Bloc Lurosonie #{} ajouté à la chaîne (hash: {}, pouvoir: {} VEZ)", 
                block_data.block.block_number, &hash[..8], block_data.relay_power);
        
        Ok(())
    }
    
    /// ✅ DÉLÉGATION DE STAKE POUR LE RELAIS
    pub async fn delegate_stake(&self, delegator: &str, validator: &str, amount: u64) -> Result<(), String> {
        // Vérifier que le validateur existe et peut recevoir des délégations
        {
            let validators = self.relay_validators.read().await;
            if !validators.contains_key(validator) {
                return Err(format!("Validateur {} non trouvé dans les validateurs de relais", validator));
            }
        }
        
        // Vérifier que le délégateur a assez de VEZ
        let delegator_balance = {
            let mut vm = self.vm.write().await;
            let default_addr = "*frame000*".to_string();
            let module_address = vm.address_map.get("vezcur").unwrap_or(&default_addr);
            let module_path = format!("{}::vezcur", module_address);

            match vm.execute_module(&module_path, "solde_of",
                vec![serde_json::Value::String(delegator.to_string())], Some(&delegator)) {
                Ok(result) => result.as_u64().unwrap_or(0),
                Err(_) => 0,
            }
        };
        
        if delegator_balance < amount {
            return Err(format!("Solde insuffisant pour déléguer: {} < {} VEZ", delegator_balance, amount));
        }
        
        // Créer la délégation
        let delegation = StakeDelegation {
            delegator: delegator.to_string(),
            validator: validator.to_string(),
            amount,
            timestamp: chrono::Utc::now().timestamp() as u64,
        };
        
        {
            let mut delegations = self.delegations.write().await;
            delegations.push(delegation);
        }
        
        println!("✅ Délégation créée: {} délègue {} VEZ à {}", delegator, amount, validator);
        Ok(())
    }
    
    /// ✅ STATISTIQUES LUROSONIE
    pub async fn get_lurosonie_stats(&self) -> serde_json::Value {
        let slurachain = self.slurachain_data.read().await;
        let validators = self.relay_validators.read().await;
        let delegations = self.delegations.read().await;
        let current_leader = self.current_relay_leader.read().await;
        
        let total_blocks = slurachain.len();
        let total_relay_power: u64 = validators.values().map(|v| v.total_power).sum();
        let total_delegated: u64 = delegations.iter().map(|d| d.amount).sum();
        
        let validator_stats: HashMap<String, serde_json::Value> = validators.iter()
            .map(|(addr, validator)| {
                (addr.clone(), serde_json::json!({
                    "stake": validator.stake,
                    "delegated_stake": validator.delegated_stake,
                    "total_power": validator.total_power,
                    "relay_count": validator.relay_count,
                    "is_active": validator.is_active
                }))
            })
            .collect();
        
        serde_json::json!({
            "consensus": "Lurosonie Relayed PoS BFT",
            "min_relay_stake": self.min_relay_stake,
            "relay_round_duration_ms": self.relay_round_duration,
            "current_relay_leader": current_leader.clone(),
            "total_blocks": total_blocks,
            "total_relay_validators": validators.len(),
            "total_relay_power": total_relay_power,
            "total_delegated_stake": total_delegated,
            "block_time_ms": self.block_time_ms,
            "validators": validator_stats,
            "delegation_count": delegations.len()
        })
    }

    /// ✅ AJOUT: Méthodes utilitaires pour la gestion des blocs

    /// Obtient le hash du dernier bloc
    pub async fn get_last_block_hash(&self) -> Option<String> {
        let hash = self.last_block_hash.read().await;
        hash.clone()
    }

    /// Obtient les informations du dernier bloc
    pub async fn get_last_block_info(&self) -> Option<(u64, String)> {
        let slurachain = self.slurachain_data.read().await;
        if let Some(last_block) = slurachain.last() {
            Some((
                last_block.block.block_number, 
                last_block.validator.clone()
            ))
        } else {
            None
        }
    }

    /// Vérifie si un validateur peut produire un bloc
    pub async fn can_validator_produce_block(&self, validator: &str) -> bool {
        let validators = self.relay_validators.read().await;
        if let Some(validator_info) = validators.get(validator) {
            validator_info.is_active && 
            (validator_info.is_system || validator_info.total_power >= self.min_relay_stake)
        } else {
            false
        }
    }

    /// ✅ AJOUT: Méthodes pour les statistiques avancées

    /// Obtient les statistiques par validateur
    pub async fn get_validator_performance_stats(&self) -> HashMap<String, serde_json::Value> {
        let validators = self.relay_validators.read().await;
        let slurachain = self.slurachain_data.read().await;
        
        let mut stats = HashMap::new();
        
        for (addr, validator) in validators.iter() {
            let blocks_produced = slurachain.iter()
                .filter(|bd| bd.validator == *addr)
                .count();
                
            let avg_relay_time = if validator.relay_count > 0 {
                validator.last_relay_time / validator.relay_count
            } else {
                0
            };
            
            stats.insert(addr.clone(), serde_json::json!({
                "blocks_produced": blocks_produced,
                "relay_count": validator.relay_count,
                "average_relay_time": avg_relay_time,
                "stake_efficiency": if validator.stake > 0 { 
                    (blocks_produced as f64) / (validator.stake as f64) 
                } else { 
                    0.0 
                },
                "is_system": validator.is_system,
                "uptime_percentage": if validator.is_active { 100.0 } else { 0.0 }
            }));
        }
        
        stats
    }

    /// Obtient les métriques du réseau
    pub async fn get_network_metrics(&self) -> serde_json::Value {
        let is_decentralized = *self.is_decentralized.read().await;
        let total_supply = *self.total_vez_supply.read().await;
        let validators = self.relay_validators.read().await;
        let slurachain = self.slurachain_data.read().await;
        let pending_count = self.get_pending_transaction_count().await;
        
        let active_validators = validators.values()
            .filter(|v| v.is_active && !v.is_system)
            .count();
            
        let total_staked = validators.values()
            .filter(|v| !v.is_system)
            .map(|v| v.total_power)
            .sum::<u64>();
            
        let latest_blocks = slurachain.iter()
            .rev()
            .take(10)
            .collect::<Vec<_>>();
            
        let avg_block_time = if latest_blocks.len() > 1 {
            let time_diffs: Vec<i64> = latest_blocks.windows(2)
                .map(|window| {
                    window[0].block.timestamp.timestamp() - window[1].block.timestamp.timestamp()
                })
                .collect();
            time_diffs.iter().sum::<i64>() / time_diffs.len() as i64
        } else {
            (self.block_time_ms / 1000) as i64
        };

        serde_json::json!({
            "network_status": if is_decentralized { "DECENTRALIZED" } else { "CENTRALIZED_BOOTSTRAP" },
            "consensus_algorithm": "Lurosonie Relayed PoS BFT",
            "total_vez_supply": total_supply,
            "decentralization_threshold": LUROSONIE_DECENTRALIZATION_THRESHOLD,
            "decentralization_progress": (total_supply as f64 / LUROSONIE_DECENTRALIZATION_THRESHOLD as f64) * 100.0,
            "active_validators": active_validators,
            "total_staked_vez": total_staked,
            "staking_ratio": if total_supply > 0 { (total_staked as f64 / total_supply as f64) * 100.0 } else { 0.0 },
            "total_blocks": slurachain.len(),
            "pending_transactions": pending_count,
            "average_block_time_seconds": avg_block_time,
            "min_relay_stake": self.min_relay_stake,
            "relay_round_duration_ms": self.relay_round_duration,
            "block_time_ms": self.block_time_ms
        })
    }

    // --- Fonctions sync qui utilisaient .await sur les verrous ---
    // Correction : retire .await et utilise .unwrap() pour les verrous dans les fonctions sync

    pub async fn verify_relay_validator(&self, validator_id: &str) -> bool {
        let validators = self.relay_validators.read().await;
        validators.get(validator_id)
            .map(|v| v.is_active && v.total_power >= self.min_relay_stake)
            .unwrap_or(false)
    }

    fn required_stake(&self) -> u64 {
        self.min_relay_stake
    }

    pub async fn select_validators(&self) -> Vec<String> {
        let validators = self.relay_validators.read().await;
        validators.iter()
            .filter(|(_, v)| v.is_active && v.total_power >= self.min_relay_stake)
            .map(|(addr, _)| addr.clone())
            .collect()
    }

    pub async fn add_block_to_chain(&self, block: TimestampRelease, prev_hash: Option<String>) {
        // Calcul du hash du bloc courant
        let block_serialized = serde_json::to_string(&block).unwrap();
        let mut hasher = Sha3_256::new();
        hasher.update(block_serialized.as_bytes());
        let hash = format!("{:x}", hasher.finalize());

        // Mise à jour du hash du dernier bloc
        {
            let mut last_hash = self.last_block_hash.write().await;
            *last_hash = Some(hash.clone());
        }

        let prev = prev_hash.unwrap_or_else(|| "None".to_string());
        println!(
            "Bloc ajouté à l'slurachain : {:?}, précédent : {}",
            block, prev
        );
    }

    pub async fn get_oldest_block_height(&self) -> u64 {
        let slurachain = self.slurachain_data.read().await;
        slurachain.first().map(|bd| bd.block.block_number).unwrap_or(0)
    }

    pub async fn get_block_height(&self) -> u64 {
        let slurachain = self.slurachain_data.read().await;
        slurachain.last().map(|bd| bd.block.block_number).unwrap_or(0)
    }

    pub async fn add_pending_transaction(&self, tx: TxRequest) {
        self.update_balance(&tx.from_op, 0).await;
        let mut pending_transactions = self.pending_transactions.write().await;
        let tx_hash = format!("{}:{}:{}:{}", tx.from_op, tx.receiver_op, tx.value_tx, tx.nonce_tx);
        pending_transactions.insert(tx_hash, tx);
    }

    pub async fn remove_processed_transactions(&self, processed_hashes: Vec<String>) {
        let mut pending_transactions = self.pending_transactions.write().await;
        for hash in processed_hashes {
            pending_transactions.remove(&hash);
        }
    }

    pub async fn update_balance(&self, account: &str, amount: u64) {
        let mut balances = self.balances.write().await;
        balances.insert(account.to_string(), amount);
        println!("Solde Lurosonie synchronisé pour {} : {} VEZ", account, amount);
    }

    pub async fn validate_transaction(&self, tx: &TxRequest) -> bool {
        let balances = self.balances.read().await;
        if let Some(balance) = balances.get(&tx.from_op) {
            *balance >= tx.value_tx.parse::<u64>().unwrap_or(0)
        } else {
            self.update_balance(&tx.from_op, 0).await;
            false
        }
    }

    // --- Correction pour CONTRACT_STATE_HISTORY ---
    pub async fn get_complete_contract_data(&self, contract_address: &str) -> serde_json::Value {
        let vm = self.vm.read().await;
        let current_state = vm.load_contract_state(contract_address)
            .unwrap_or_else(|_| vec![0u8; 4096]);
        let history_lock = CONTRACT_STATE_HISTORY.lock().await;
        let history = history_lock.get(contract_address).cloned().unwrap_or_default();
        
        // Métadonnées du module
        let module_info = if let Some(module) = vm.modules.get(contract_address) {
            // ✅ CORRECTION: Extraire les fonctions depuis les métadonnées du module
            let functions: Vec<String> = module.functions.keys().cloned().collect();
            
            serde_json::json!({
                "name": module.name,
                "address": module.address,
                "bytecode_size": module.bytecode.len(),
                "functions": functions
            })
        } else {
            serde_json::Value::Null
        };
        
        serde_json::json!({
            "contract_address": contract_address,
            "current_state_size": current_state.len(),
            "state_history_count": history.len(),
            "module_info": module_info,
            // ✅ CORRECTION: Vérifier si le module existe au lieu d'utiliser is_deployed_address
            "is_deployed": vm.modules.contains_key(contract_address),
            "latest_states": history.iter().rev().take(5).collect::<Vec<_>>()
        })
    }

    // ✅ FONCTIONS UTILITAIRES POUR LUROSONIE    
        pub async fn execute_transaction_in_block(&self, tx: &TxRequest) -> Result<serde_json::Value, String> {
        let mut vm = self.vm.write().await;
    
        // Adresse du contrat cible (optionnelle)
        let contract_addr = tx.contract_addr.as_deref();
        let function = tx.function_name.as_deref().unwrap_or("transfer");
        let to_addr = tx.receiver_op.clone();
        let value = tx.value_tx.parse::<u128>().unwrap_or(0);
    
        // Vérifie si l'adresse cible est un contrat déployé
        let is_contract = contract_addr
            .and_then(|addr| vm.modules.get(addr))
            .is_some();
    
        println!("🔁 Exécution tx {} sur {} : {} -> {} (valeur {})", tx.hash, contract_addr.unwrap_or(&to_addr), tx.from_op, to_addr, value);
    
        if is_contract {
            // Exécution sur le contrat cible
            let mut args = tx.arguments.clone().unwrap_or_else(|| {
                vec![
                    serde_json::Value::String(to_addr.clone()),
                    serde_json::Value::Number(serde_json::Number::from(value)),
                ]
            });
            match vm.execute_module(contract_addr.unwrap(), function, args, Some(&tx.from_op)) {
                Ok(result) => {
                    println!("✅ VM {} ok pour tx {}", function, tx.hash);
                    Ok(serde_json::json!({
                        "status": "success",
                        "from": tx.from_op,
                        "to": to_addr,
                        "value": value,
                        "nonce": tx.nonce_tx,
                        "hash": tx.hash,
                        "result": result
                    }))
                }
                Err(e) => {
                    error!("❌ VM.execute_module {} failed for tx {}: {}", function, tx.hash, e);
                    Err(format!("execute_module failed: {}", e))
                }
            }
        } else {
            // Si ce n'est pas un contrat, effectue un transfert VEZ natif (ERC-20)
            let vez_contract_addr = "0xe3cf7102e5f8dfd6ec247daea8ca3e96579e8448";
            let args = vec![
                serde_json::Value::String(to_addr.clone()),
                serde_json::Value::Number(serde_json::Number::from(value)),
            ];
            match vm.execute_module(vez_contract_addr, "transfer", args, Some(&tx.from_op)) {
                Ok(result) => {
                    println!("✅ VM transfer ok pour tx {}", tx.hash);
                    Ok(serde_json::json!({
                        "status": "success",
                        "from": tx.from_op,
                        "to": to_addr,
                        "value": value,
                        "nonce": tx.nonce_tx,
                        "hash": tx.hash,
                        "result": result
                    }))
                }
                Err(e) => {
                    error!("❌ VM.execute_module transfer failed for tx {}: {}", tx.hash, e);
                    // Fallback natif si besoin
                    if value <= u64::MAX as u128 {
                        match vm.vez_native_transfer(&tx.from_op, &to_addr, value as u64) {
                            Ok(_) => {
                                println!("✅ Fallback vez_native_transfer succeeded for tx {}", tx.hash);
                                Ok(serde_json::json!({
                                    "status": "success(fallback)",
                                    "from": tx.from_op,
                                    "to": to_addr,
                                    "value": value,
                                    "nonce": tx.nonce_tx,
                                    "hash": tx.hash,
                                    "result": "fallback transfer applied"
                                }))
                            }
                            Err(e2) => {
                                error!("❌ Fallback vez_native_transfer failed for tx {}: {}", tx.hash, e2);
                                Err(format!("execute_module failed: {}; fallback failed: {}", e, e2))
                            }
                        }
                    } else {
                        Err(format!("execute_module failed: {}; value too large for fallback", e))
                    }
                }
            }
        }
    }

    // ✅ CORRECTION: Récupération d'état de contrat simplifiée
    pub async fn get_contract_state_at_block(&self, contract_address: &str, block_number: u64) -> Option<Vec<u8>> {
        // ✅ PRIORITÉ 1: Recherche en mémoire dans la slurachain
        if let Some(block_data) = self.get_block_by_number(block_number).await {
            if let Some(state) = block_data.contract_states.get(contract_address) {
                println!("DEBUG: 📚 État contrat {} récupéré depuis slurachain en mémoire (bloc {})", 
                         contract_address, block_number);
                return Some(state.clone());
            }
        }
        
        // ✅ PRIORITÉ 2: Recherche dans l'historique en mémoire
        {
            let history_lock = CONTRACT_STATE_HISTORY.lock().await;
            if let Some(history) = history_lock.get(contract_address) {
                // Retourne le dernier état disponible
                if let Some(last_state) = history.last() {
                    println!("DEBUG: 📚 État contrat {} récupéré depuis historique en mémoire", contract_address);
                    return Some(last_state.clone());
                }
            }
        }
        
        // ✅ PRIORITÉ 3: Récupération de l'état courant depuis la VM
        {
            let vm = self.vm.read().await;
            if let Ok(state) = vm.load_contract_state(contract_address) {
                if state != vec![0u8; 4096] { // Ignore les états vides
                    println!("DEBUG: 📚 État contrat {} récupéré depuis VM courante", contract_address);
                    return Some(state);
                }
            }
        }
        
        println!("DEBUG: ❌ Aucun état trouvé pour contrat {} au bloc {}", contract_address, block_number);
        None
    }

    /// ✅ CORRECTION: Récupère l'état du contrat (wrapper pour la UVM)
    pub async fn get_contract_state(&self, contract_address: &str) -> Result<Vec<u8>, String> {
        let vm = self.vm.read().await;
        vm.load_contract_state(contract_address)
    }

    /// ✅ AJOUT: Valider et ajouter une transaction
    pub async fn validate_and_add_transaction(&self, tx: TxRequest, validator_addr: &str) -> Result<(), String> {
        // 1. Vérifier que le validateur peut produire un bloc
        if !self.can_validator_produce_block(validator_addr).await {
            return Err(format!("Le validateur {} n'a pas le droit de produire un bloc", validator_addr));
        }

        // 2. Ajouter la transaction dans la file d'attente
        self.add_pending_transaction(tx.clone()).await;

        // 3. Produire le bloc (le producteur est le validateur)
        let block_height = self.get_block_height().await + 1;
        self.produce_lurosonie_block(block_height, validator_addr, false).await?;

        // 4. Consensus BFT
        self.lurosonie_bft_consensus(block_height).await?;

        Ok(())
    }
}