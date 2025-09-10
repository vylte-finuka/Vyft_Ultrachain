use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use chrono::Utc;
use tracing::{info, error, warn};
use tokio::sync::mpsc;
use tokio::time::{interval, Duration};
use sha3::{Sha3_256, Digest};
use serde_json;
use num_traits::cast::AsPrimitive;
use vuc_events::timestamp_release::TimestampRelease;
use vuc_events::time_warp::TimeWarp;
use vuc_types::committee::committee::EpochId;
use vuc_types::supported_protocol_versions::SupportedProtocolVersions;
use vuc_types::tx_op::GAS_UNIT_COST_VALIDATORS;
use crate::ultrachain_rpc_service::TxRequest;
use vuc_tx::ultrachain_vm::UltrachainVm;
use crate::consensus::ultrachain_gov::UltrachainGovernance;

pub struct LurosonieManager {
    pub epoch_id: EpochId,
    pub committee: Vec<String>,
    pub supported_protocol_versions: SupportedProtocolVersions,
    pub balances: Arc<RwLock<HashMap<String, u64>>>,
    pub time_warp: TimeWarp,
    pub block_sender: mpsc::Sender<TimestampRelease>,
    pub pending_transactions: Arc<RwLock<HashMap<String, TxRequest>>>,
    pub block_counts: Arc<RwLock<HashMap<String, u64>>>, // Comptage des blocs minés par validateur
    pub vm: Arc<RwLock<UltrachainVm>>,
    pub governance: Arc<RwLock<HashMap<String, UltrachainGovernance>>>,
    pub last_block_hash: Arc<RwLock<Option<String>>>,
    pub validators: Arc<RwLock<Vec<String>>>,
}

impl LurosonieManager {
    /// Initialise le minage pour un validateur (appel Move mining_impl::initialize)
    pub async fn initialize_mining(&self, validator: &str) -> Result<(), anyhow::Error> {
        let vm = &mut self.vm.write().unwrap();
        let module_address = vm.address_map.get("mining_impl")
            .ok_or_else(|| anyhow::anyhow!("Adresse du module mining_impl non trouvée"))?;
        let module_path = format!("{}::mining_impl", module_address);
        let function_name = "initialize";
        vm.execute_module(
            &module_path,
            vec![function_name.to_string()],
            vec![], // Ajoute ici les arguments si besoin
        ).map_err(anyhow::Error::msg)?;
        Ok(())
    }

    /// Implémente le protocole Lurosonie pour traiter un bloc
    pub async fn lurosonie_protocole_impl(&self, block: &TimestampRelease) -> Result<(), String> {
        if !self.verify_block_creator(&block.vyfties_id) {
            error!("Block creator identity verification failed.");
            return Err("Block creator identity verification failed.".to_string());
        }

        // Comptage des blocs minés par validateur
        {
            let mut block_counts = self.block_counts.write().unwrap();
            let count = block_counts.entry(block.vyfties_id.clone()).or_insert(0);
            *count += 1;

            // Récompense après 130 blocs
            if *count % 130 == 0 {
                if let Some(gov) = self.governance.write().unwrap().get_mut(&block.vyfties_id) {
                    // Récompense 200 VEZ via le contrat Move (stake)
                    let _ = gov.stake_vez(&mut self.vm.write().unwrap(), 200).await;
                    info!("Récompense de 200 VEZ attribuée à {} pour 130 blocs minés.", block.vyfties_id);
                }
            }
        }

        let timestamp_release = TimestampRelease {
            timestamp: Utc::now(),
            log: format!("Block processed successfully: {:?}.", block),
            block_number: block.block_number,
            vyfties_id: block.vyfties_id.clone(),
        };

        println!("TimestampRelease: {} - Block Number: {}.", timestamp_release.timestamp, timestamp_release.block_number);

        if let Err(e) = self.block_sender.send(timestamp_release.clone()).await {
            error!("Failed to send block: {}", e);
            return Err(e.to_string());
        }

        Ok(())
    }

    pub fn validate_transaction(&self, tx: &TxRequest) -> bool {
        // Exemple de validation : vérifier le solde de l'expéditeur
        let balances = self.balances.read().unwrap();
        if let Some(balance) = balances.get(&tx.from_op) {
            *balance >= tx.value_tx.parse::<u64>().unwrap_or(0)
        } else {
            self.update_balance(&tx.from_op, 0); // Ajoute le compte si absent (le solde sera synchronisé)
            false
        }
    }

    pub fn sign_block(&self, block: &TimestampRelease, validator: &str) -> String {
        // Exemple : Retourner une signature fictive
        format!("Signature de {} pour le bloc {}", validator, block.block_number)
    }

    pub async fn add_block_to_chain(&self, block: TimestampRelease, prev_hash: Option<String>) {
        // Calcul du hash du bloc courant
        let block_serialized = serde_json::to_string(&block).unwrap();
        let mut hasher = Sha3_256::new();
        hasher.update(block_serialized.as_bytes());
        let hash = format!("{:x}", hasher.finalize());

        // Mise à jour du hash du dernier bloc
        {
            let mut last_hash = self.last_block_hash.write().unwrap();
            *last_hash = Some(hash.clone());
        }

        let prev = prev_hash.unwrap_or_else(|| "None".to_string());
        println!(
            "Bloc ajouté à l'ultrachain : {:?}, précédent : {}",
            block, prev
        );
    }

    /// Produit un bloc en utilisant un validateur sélectionné
    pub async fn produce_block(&self, validator: &str) -> Result<(), String> {
        let pending_transactions = self.get_pending_transactions().await;

        if pending_transactions.is_empty() {
            println!("Aucune transaction en attente. Aucun bloc produit.");
            return Ok(());
        }

        let block_number = self.get_block_height() + 1;
        let timestamp = Utc::now();

        let block = TimestampRelease {
            timestamp,
            log: format!("Bloc produit avec {} transactions", pending_transactions.len()),
            block_number,
            vyfties_id: validator.to_string(),
        };

        let prev_block_hash = {
            let last_hash = self.last_block_hash.read().unwrap();
            last_hash.clone().unwrap_or_else(|| "None".to_string())
        };
        self.add_block_to_chain(block.clone(), Some(prev_block_hash)).await;

        let mut processed_hashes = Vec::new();
        for tx in &pending_transactions {
            if self.validate_transaction(tx) {
                processed_hashes.push(format!("{}:{}:{}:{}", tx.from_op, tx.receiver_op, tx.value_tx, tx.nonce_tx));
            }
        }
        self.remove_processed_transactions(processed_hashes);

        println!("Bloc produit : {:?}", block);
        Ok(())
    }

    /// Vérifie si le créateur du bloc est valide
    fn verify_block_creator(&self, creator_id: &str) -> bool {
        // Optionnel : tu peux vérifier que creator_id est bien dans la liste des validateurs actifs
        self.select_validators().contains(&creator_id.to_string())
    }

    /// Retourne le montant de stake requis pour être validateur
    fn required_stake(&self) -> u64 {
        500
    }

    /// Récupère les transactions en attente
    pub async fn get_pending_transactions(&self) -> Vec<TxRequest> {
        let pending_transactions = self.pending_transactions.read().unwrap();
        pending_transactions.values().cloned().collect()
    }

    pub async fn can_produce_block(&self, validator: &str) -> bool {
        let vm = self.vm.write().unwrap();
        let default_addr = "*frame000*".to_string();
        let module_address = vm.address_map.get("vezcur")
            .unwrap_or(&default_addr);
        let module_path = format!("{}::vezcur", module_address);
        let function_name = "solde_of";
        let result = vm.execute_module(
            &module_path,
            vec![function_name.to_string()],
            vec![serde_json::Value::String(validator.to_string())],
        );
        if let Ok(solde) = result {
            if solde["result"].as_u64().unwrap_or(0) >= 500 {
                return true;
            }
        }
        false
    }

    pub async fn sync_balances_periodically(&self) {
        let accounts: Vec<String> = {
            let vm = self.vm.read().unwrap();
            let state = vm.state.accounts.read().unwrap();
            state.keys().cloned().collect()
        };

        for account in accounts {
            if account == "0x0" || account == "0x6" {
                continue;
            }
            let vm = self.vm.write().unwrap();
            let default_addr = "*frame000*".to_string();
            let module_address = vm.address_map.get("vezcur")
                .unwrap_or(&default_addr);
            let module_path = format!("{}::vezcur", module_address);
            let function_name = "solde_of";
            if let Ok(result) = vm.execute_module(
                &module_path,
                vec![function_name.to_string()],
                vec![serde_json::Value::String(account.clone())],
            ) {
                if let Some(solde) = result["result"].as_u64() {
                    self.update_balance(&account, solde);
                }
            }
        }
    }

    // Démarre la production de blocs et le maintien en continue à l'intervalle régulier utlisant la fonction produce_block
    pub async fn start_block_production(&self) {
        loop {
            let validators = self.select_validators();
            for validator in validators {
                if self.can_produce_block(&validator).await {
                    // Ajoute cet appel :
                    let _ = self.produce_block(&validator).await;
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }

    /// Sélectionne les validateurs actifs en fonction des votes
    pub fn select_validators(&self) -> Vec<String> {
        let mut validators = Vec::new();
        let balances = self.balances.read().unwrap();

        for (account, balance) in balances.iter() {
            if *balance >= self.required_stake() {
                validators.push(account.clone());
            }
        }

        validators
    }

    /// Retourne la hauteur du plus ancien bloc
    pub fn get_oldest_block_height(&self) -> u64 {
        let balances = self.balances.read().unwrap();
        balances.values().min().cloned().unwrap_or(0)
    }

    /// Retourne la hauteur actuelle du bloc
    pub fn get_block_height(&self) -> u64 {
        let balances = self.balances.read().unwrap();
        balances.values().max().cloned().unwrap_or(0)
    }

    /// Ajoute une transaction à la liste des transactions en attente
    pub fn add_pending_transaction(&self, tx: TxRequest) {
        self.update_balance(&tx.from_op, 0); // Ajoute le compte si absent
        let mut pending_transactions = self.pending_transactions.write().unwrap();
        let tx_hash = format!("{}:{}:{}:{}", tx.from_op, tx.receiver_op, tx.value_tx, tx.nonce_tx);
        pending_transactions.insert(tx_hash, tx);
    }

    /// Supprime les transactions traitées de la liste des transactions en attente
    pub fn remove_processed_transactions(&self, processed_hashes: Vec<String>) {
        let mut pending_transactions = self.pending_transactions.write().unwrap();
        for hash in processed_hashes {
            pending_transactions.remove(&hash);
        }
    }

    pub async fn monitor_validator_balances(&self) {
        let mut interval = interval(Duration::from_secs(2));

        loop {
            interval.tick().await;

            let balances = self.balances.read().unwrap();
            for (account, balance) in balances.iter() {
                if *balance >= self.required_stake() {
                    println!("Validateur éligible : {} avec un solde de {}", account, balance);
                } else {
                    warn!("Validateur non éligible : {} avec un solde de {}", account, balance);
                }
            }
        }
    }

    pub fn update_balance(&self, account: &str, amount: u64) {
        let mut balances = self.balances.write().unwrap();
        balances.insert(account.to_string(), amount);
        println!("Solde synchronisé pour {} : {}", account, amount);
    }

    /// Récompense un validateur si conditions atteintes (10 000 VEZ et actif)
    pub async fn reward_validator_if_eligible(&self, validator: &str) -> Result<(), anyhow::Error> {
        let vm = self.vm.read().unwrap();
        let state = vm.state.accounts.read().unwrap();
        let account_opt = state.iter().find(|(_, account)| account.address == validator);

        if let Some((_, account)) = account_opt {
            if account.balance >= 10_000 {
                let is_active = self.select_validators().contains(&validator.to_string());
                if is_active {
                    let gas_fees = 10; // Exemple de frais
                    let vez_to_credit = 200u64;
                    let total = vez_to_credit + gas_fees;
                    self.update_balance(validator, total);

                    let mut vm = self.vm.write().unwrap();
                    if let Some(gov) = self.governance.write().unwrap().get_mut(validator) {
                        gov.stake_vez(&mut vm, vez_to_credit).await?;
                        info!("Validateur {} récompensé de {} VEZ (frais gas: {})", validator, vez_to_credit, gas_fees);
                    }
                }
            }
        }
        Ok(())
    }
}