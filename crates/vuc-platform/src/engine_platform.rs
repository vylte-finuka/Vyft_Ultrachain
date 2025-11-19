use tokio::sync::{Mutex, mpsc};
use rand::Rng;

// Ensure the correct module path for TimestampRelease
use vuc_events::timestamp_release::TimestampRelease;
use vuc_platform::slurachain_rpc_service::TxRequest;
use vuc_tx::slurachain_tx::{HookOp, slurachainTx, ValueTx};
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use tokio::sync::RwLock as TokioRwLock;
use hashbrown::HashMap;
use tracing::{info, error};
use chrono::Utc;
use jsonrpsee_types::error::ErrorCode;
use tracing_subscriber;
use sha3::Digest;
use tokio::time::{Duration, timeout};

// ✅ AJOUTS POUR LA FONCTION MAIN
use vuc_core::service::slurachain_service::SlurEthService;
use vuc_types::{committee::committee::EpochId, supported_protocol_versions::SupportedProtocolVersions};
use vuc_events::time_warp::TimeWarp;
use vuc_platform::{slurachain_rpc_service::slurachainRpcService, consensus::lurosonie_manager::LurosonieManager};
use vuc_storage::storing_access::RocksDBManagerImpl;
use vuc_storage::storing_access::RocksDBManager;
use jsonrpsee_server::{RpcModule, ServerBuilder};
use vuc_tx::slurachain_vm::SlurachainVm;

use vuc_tx::slurachain_vm::{AccountState, Signer};

// ✅ AJOUT: Structures pour le déploiement avec possession
#[derive(Clone, Debug)]
pub struct ContractDeploymentArgsWithOwnership {
    pub deployer: String,
    pub owner_address: String,
    pub owner_private_key_hash: String,
    pub bytecode: Vec<u8>,
    pub constructor_args: Vec<serde_json::Value>,
    pub gas_limit: u64,
    pub value: u64,
    pub hex_format_enabled: bool,
    pub salt: Option<Vec<u8>>,
    pub ownership_type: OwnershipType,
}

#[derive(Clone, Debug)]
pub enum OwnershipType {
    SingleOwner,
    MultiSig,
    Dao,
}

#[derive(Clone, Debug)]
pub struct DeploymentResult {
    pub contract_address: String,
    pub transaction_hash: String,
    pub gas_used: u64,
    pub deployment_cost: u64,
}

#[derive(Clone)]
pub struct EnginePlatform {
    pub vyftid: String,
    pub bytecode: Vec<u8>,
    pub rpc_service: slurachainRpcService,
    pub vm: Arc<tokio::sync::RwLock<SlurachainVm>>,
    pub tx_receipts: Arc<tokio::sync::RwLock<HashMap<String, serde_json::Value>>>,
    pub validator_address: String, // AJOUT
    pub current_block_number: Arc<TokioRwLock<u64>>, // Ajoute ce champ
    pub block_transactions: Arc<TokioRwLock<HashMap<u64, Vec<String>>>>, // Ajoute ce champ
}

impl EnginePlatform {
    pub fn new(
        vyftid: String,
        bytecode: Vec<u8>,
        rpc_service: slurachainRpcService,
        vm: Arc<tokio::sync::RwLock<SlurachainVm>>,
        validator_address: String, // AJOUT
    ) -> Self {
        EnginePlatform {
            vyftid,
            bytecode,
            rpc_service,
            vm,
            tx_receipts: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
            validator_address, // AJOUT
            current_block_number: Arc::new(TokioRwLock::new(1)),
            block_transactions: Arc::new(TokioRwLock::new(HashMap::new())),
        }
    }

                fn extract_sender_from_raw(raw_bytes: &[u8]) -> Option<String> {
            use sha3::{Digest, Keccak256};
            let mut hasher = Keccak256::new();
            hasher.update(raw_bytes);
            let hash = hasher.finalize();
            // Format sur 64 caractères hexadécimaux (padding à gauche si besoin)
            Some(format!("0x{:0>64}", hex::encode(hash)))
        }

    pub async fn execute_transaction(&self) -> Result<(), anyhow::Error> {
        let mut vm = self.vm.write().await;

        let slurachain_tx = slurachainTx {
            from_op: "sender_address".to_string(),
            receiver_op: "receiver_address".to_string(),
            fees_tx: 10,
            value_tx: ValueTx::default(),
            arguments: vec![],
            nonce_tx: 0,
            hash_tx: "hash_value".to_string(),
            func_tx: "module_address::module_name::function_name".to_string(),
        };

        slurachain_tx
            .functiontx_impl(&mut vm, HookOp::default(), self.rpc_service.storage.clone())
            .await
            .map_err(|e| anyhow::Error::msg(e.to_string()))?;
        Ok(())
    }

    pub async fn build_account(&self) -> Result<(String, String), anyhow::Error> {
        let mut vm = self.vm.write().await;
        vuc_platform::operator::crypto_perf::generate_and_create_account(&mut vm, "acc").await
    }

    /// ✅ AJOUT: Méthode manquante deploy_contract
    pub async fn deploy_contract(&self, deployment_request: serde_json::Value) -> Result<serde_json::Value, String> {
        println!("🚀 Deploying contract with request: {:?}", deployment_request);
        
        // Extraction des paramètres de déploiement
        let bytecode = deployment_request.get("bytecode")
            .and_then(|b| b.as_str())
            .unwrap_or("")
            .to_string();
            
        let constructor_args = deployment_request.get("constructorArgs")
            .and_then(|a| a.as_array())
            .cloned()
            .unwrap_or_default();
            
        let value = deployment_request.get("value")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);

        // Génération d'une adresse de contrat
        use sha3::{Digest, Sha3_256};
        let mut hasher = Sha3_256::new();
        hasher.update(&bytecode);
        hasher.update(&chrono::Utc::now().timestamp().to_string());
        let hex_addr = format!("{:x}", hasher.finalize());
        let contract_address = format!("0x{}", &hex_addr[..40]).to_lowercase();
        let decoded_bytecode = if bytecode.starts_with("0x") {
            hex::decode(&bytecode[2..]).unwrap_or_default()
        } else {
            hex::decode(&bytecode).unwrap_or_default()
        };
        let account_state = vuc_tx::slurachain_vm::AccountState {
            address: contract_address.clone(),
            balance: value as u128,
            contract_state: decoded_bytecode.clone(), // <-- stocke le vrai bytecode
            resources: std::collections::BTreeMap::new(),
            state_version: 1,
            last_block_number: 0,
            nonce: 0,
            code_hash: format!("contract_{}", chrono::Utc::now().timestamp()),
            storage_root: format!("storage_{}", contract_address),
            is_contract: true,
            gas_used: 0,
        };

        // Déploiement via la VM
        {
            let mut vm = self.vm.write().await;
            if let Ok(decoded_bytecode) = hex::decode(&bytecode[2..]) {
                let account_state = vuc_tx::slurachain_vm::AccountState {
                    address: contract_address.clone(),
                    balance: value as u128,
                    contract_state: decoded_bytecode,
                    resources: std::collections::BTreeMap::new(),
                    state_version: 1,
                    last_block_number: 0,
                    nonce: 0,
                    code_hash: format!("contract_{}", chrono::Utc::now().timestamp()),
                    storage_root: format!("storage_{}", contract_address),
                    is_contract: true,
                    gas_used: 0,
                };

                vm.state.accounts.write().unwrap().insert(contract_address.clone(), account_state);
            }
        }

        // Génération d'un hash de transaction
        let mut hasher = Sha3_256::new();
        hasher.update(&contract_address);
        hasher.update(&chrono::Utc::now().timestamp().to_string());
        let tx_hash = format!("0x{:x}", hasher.finalize());

        Ok(serde_json::json!({
            "status": "success",
            "contractAddress": contract_address,
            "transactionHash": tx_hash,
            "gasUsed": "0x5208",
            "blockNumber": "0x1"
        }))
    }

    /// ✅ AJOUT: Méthode manquante get_gas_price
        pub async fn get_gas_price(&self) -> u64 {
        1_000_000_000u64 // exemple: 1 Gwei
    }
        
        /// ✅ CORRECTION: get_account_balance retourne le solde ERC20 si VEZproxy existe
        pub async fn get_account_balance(&self, address: &str) -> Result<u128, String> {
            let addr_lc = address.to_lowercase();
            let vm = self.vm.read().await;
            let accounts = match vm.state.accounts.try_read() {
                Ok(guard) => guard,
                Err(_) => return Err("Verrou VM bloqué, réessayez plus tard".to_string()),
            };
            vuc_tx::slurachain_vm::ensure_account_exists(&accounts, &addr_lc)?;
        
            // 1) Recherche dans le contrat VEZproxy (ERC20)
            let vez_contract_addr = "0xe3cf7102e5f8dfd6ec247daea8ca3e96579e8448";
            if let Some(vez) = accounts.get(vez_contract_addr) {
                let key = format!("balance_{}", addr_lc);
                if let Some(val) = vez.resources.get(&key) {
                    if let Some(bal) = val.as_u64() {
                        return Ok(bal as u128);
                    } else if let Some(bal) = val.as_str().and_then(|s| s.parse::<u128>().ok()) {
                        return Ok(bal);
                    } else if let Some(bal) = val.as_u64() {
                        return Ok(bal as u128);
                    }
                }
                // Essai sans le préfixe 0x
                let stripped = addr_lc.strip_prefix("0x").unwrap_or(&addr_lc);
                let key2 = format!("balance_{}", stripped);
                if let Some(val) = vez.resources.get(&key2) {
                    if let Some(bal) = val.as_u64() {
                        return Ok(bal as u128);
                    } else if let Some(bal_str) = val.as_str() {
                        if let Ok(bal) = bal_str.parse::<u128>() {
                            return Ok(bal);
                        }
                    }
                }
            }
        
            // 2) Recherche directe (champ natif balance)
            if let Some(account) = accounts.get(&addr_lc) {
                return Ok(account.balance);
            }
            if let Some(account) = accounts.get(address) {
                return Ok(account.balance);
            }
            let stripped = addr_lc.strip_prefix("0x").unwrap_or(&addr_lc);
            for (k, acc) in accounts.iter() {
                let kstr = k.to_lowercase();
                if kstr.strip_prefix("0x").unwrap_or(&kstr) == stripped {
                    return Ok(acc.balance);
                }
            }
            // 3) Conversion UIP-10 → Ethereum
            for (k, acc) in accounts.iter() {
                let eth = self.convert_uip10_to_ethereum(k).to_lowercase();
                if eth == addr_lc || eth.strip_prefix("0x").unwrap_or(&eth) == stripped {
                    return Ok(acc.balance);
                }
            }
            // Compte inexistant => balance 0
            Ok(0)
        }

    /// ✅ AJOUT: Méthode manquante get_ledger_info
    pub async fn get_ledger_info(&self) -> Result<serde_json::Value, String> {
        let vm = self.vm.read().await;
        let accounts = match vm.state.accounts.try_read() {
            Ok(guard) => guard,
            Err(_) => return Err("Verrou VM bloqué, réessayez plus tard".to_string()),
        };

        let total_accounts = accounts.len();
        let contract_count = accounts.iter().filter(|(_, acc)| acc.is_contract).count();
        let user_count = total_accounts - contract_count;
        
        // Calcul de la supply totale VEZ
        let mut total_vez_supply = 0u64;
        for (_, account) in accounts.iter() {
            total_vez_supply = total_vez_supply.saturating_add(account.balance as u64);
        }

        Ok(serde_json::json!({
            "status": "active",
            "chainId": self.get_chain_id(),
            "networkName": "Slurachain Charene",
            "consensus": "Lurosonie BFT Relayed PoS",
            "nativeToken": "VEZ",
            "totalAccounts": total_accounts,
            "userAccounts": user_count,
            "contractAccounts": contract_count,
            "totalVezSupply": total_vez_supply,
            "blockHeight": 1,
            "timestamp": chrono::Utc::now().timestamp()
        }))
    }

    /// ✅ AJOUT: Méthode manquante get_current_block_number
    pub async fn get_current_block_number(&self) -> u64 {
        // Pour l'instant, retourner un numéro de bloc fixe
        // Dans une implémentation complète, cela viendrait du consensus Lurosonie
        1u64
    }

    /// ✅ Récupération du Chain ID pour Slurachain
    pub fn get_chain_id(&self) -> u64 {
        45056 // ID développement local, peut être changé pour mainnet
    }

    /// ✅ Récupération du nombre de transactions (nonce)
    pub async fn get_transaction_count(&self, address: &str) -> Result<u64, String> {
        let vm = self.vm.read().await;
        let accounts = match vm.state.accounts.try_read() {
            Ok(guard) => guard,
            Err(_) => return Err("Verrou VM bloqué, réessayez plus tard".to_string()),
        };

        if let Some(account) = accounts.get(address) {
            Ok(account.nonce)
        } else {
            Ok(0)
        }
    }

    /// ✅ Récupération d'un bloc par numéro/tag
    pub async fn get_block_by_number(&self, block_tag: &str) -> Result<serde_json::Value, String> {
        let current_block = self.get_current_block_number().await;
        let block_number = match block_tag {
            "latest" | "pending" => current_block,
            "earliest" => 0,
            _ => {
                if block_tag.starts_with("0x") {
                    u64::from_str_radix(&block_tag[2..], 16).unwrap_or(current_block)
                } else {
                    block_tag.parse().unwrap_or(current_block)
                }
            }
        };
    
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
    
        Ok(serde_json::json!({
            "number": format!("0x{:x}", block_number),
            "hash": format!("0x{:064x}", block_number),
            "parentHash": format!("0x{:064x}", block_number.saturating_sub(1)),
            "timestamp": format!("0x{:x}", current_time),
            "gasLimit": "0x1c9c380", // 30M gas
            "gasUsed": "0x0",
            "difficulty": "0x1",
            "miner": "0x0000000000000000000000000000000000000000",
            "transactions": [],
            "size": "0x200",
            "nonce": "0x0000000000000000",
            "extraData": "0x0000000000000000000000000000000000000000000000000000000000000000"        }))
    }

        /// ✅ Envoi d'une transaction (pour MetaMask)
    pub async fn send_transaction(&self, tx_params: serde_json::Value) -> Result<String, String> {
    use sha3::{Digest, Sha3_256};

    println!("➡️ [send_transaction] Transaction reçue : {:?}", tx_params);

    let mut hasher = Sha3_256::new();
    hasher.update(serde_json::to_string(&tx_params).unwrap_or_default());
    let tx_hash = format!("0x{:x}", hasher.finalize());

    let to_opt = tx_params.get("to").and_then(|v| v.as_str()).map(|s| s.to_lowercase());
    let data_opt = tx_params.get("data").and_then(|v| v.as_str()).map(|s| s.to_string());

    // Lecture des champs Ethereum standards
    let value = tx_params.get("value")
        .or(tx_params.get("amount"))
        .and_then(|v| {
            if v.is_string() {
                let s = v.as_str().unwrap();
                if s.starts_with("0x") {
                    u128::from_str_radix(s.trim_start_matches("0x"), 16).ok()
                } else {
                    s.parse::<u128>().ok()
                }
            } else if v.is_u64() {
                Some(v.as_u64().unwrap() as u128)
            } else if v.is_number() {
                v.as_u64().map(|n| n as u128)
            } else {
                None
            }
        }).unwrap_or(0);

    let gas = tx_params.get("gas")
        .and_then(|v| v.as_str().and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok()))
        .or(tx_params.get("gas").and_then(|v| v.as_u64()))
        .unwrap_or(21000);

    let gas_price = tx_params.get("gasPrice")
        .and_then(|v| v.as_str().and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok()))
        .or(tx_params.get("gasPrice").and_then(|v| v.as_u64()))
        .unwrap_or(1_000_000_000);

    let nonce = tx_params.get("nonce")
        .and_then(|v| v.as_str().and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok()))
        .or(tx_params.get("nonce").and_then(|v| v.as_u64()))
        .unwrap_or(0);

    // Si data présent et to est une adresse de contrat
    
    if let Some(to_addr) = to_opt.clone() {
        let to_addr_lc = to_addr.to_lowercase();
        // Si le destinataire est le contrat VEZ, effectue un transfert ERC20
        if to_addr_lc == "0xe3cf7102e5f8dfd6ec247daea8ca3e96579e8448" && value > 0 {
            let mut vm_guard = self.vm.write().await;
            let sender = tx_params.get("from").and_then(|v| v.as_str()).unwrap_or(&self.validator_address).to_lowercase();
            let mint_args = vec![
                serde_json::Value::String(sender.clone()),
                serde_json::Value::Number(value.into()),
            ];
            let result = vm_guard.execute_module(
                &to_addr_lc,
                "mint",
                mint_args,
                Some(&sender),
            );
            match result {
                Ok(_res) => {
                    let block_number = self.get_current_block_number().await;
                    let block_hash = {
                        use sha3::{Digest, Keccak256};
                        let mut hasher = Keccak256::new();
                        hasher.update(format!("block_{}", block_number));
                        format!("0x{:x}", hasher.finalize())
                    };
                    let transaction_index = 0; // à incrémenter si plusieurs tx par bloc

                    let logs_bloom = "0x".to_owned() + &"0".repeat(512); // 256 bytes = 512 hex chars

                    let mut receipts = self.tx_receipts.write().await;
                    receipts.insert(tx_hash.clone(), serde_json::json!({
                        "transactionHash": tx_hash,
                        "blockNumber": format!("0x{:x}", block_number),
                        "blockHash": block_hash,
                        "transactionIndex": format!("0x{:x}", transaction_index),
                        "from": sender,
                        "to": to_addr_lc,
                        "contractAddress": serde_json::Value::Null,
                        "gasUsed": format!("0x{:x}", gas),
                        "cumulativeGasUsed": format!("0x{:x}", gas),
                        "blobGasUsed": "0x20000",
                        "effectiveGasPrice": format!("0x{:x}", gas_price),
                        "blobGasPrice": "0x3",
                        "logs": [],
                        "logsBloom": logs_bloom,
                        "status": "0x1"
                    }));
                    return Ok(tx_hash);
                }
                Err(e) => {
                    // ✅ LOG terminal en cas d'erreur
                    eprintln!("❌ [send_transaction] Erreur transfert natif VEZ (mint): {}", e);
                    return Err(format!("Erreur transfert natif VEZ (mint): {}", e));
                }
            }
        } else if let Some(data) = data_opt {
            // ✅ Si data présent, tente un appel contractuel générique
            let mut vm_guard = self.vm.write().await;
            let sender = tx_params.get("from").and_then(|v| v.as_str()).unwrap_or(&self.validator_address).to_lowercase();
            let args = vec![]; // Tu peux parser les args depuis data si besoin
            let function_name = ""; // À déduire du selector dans data si possible

            // Ici, on tente d'exécuter le module avec le selector du data
            // (pour une VM compatible EVM, il faudrait parser le selector et router vers la bonne fonction)
            match vm_guard.execute_module(
                &to_addr_lc,
                function_name,
                args,
                Some(&sender),
            ) {
                Ok(_res) => {
                    let mut receipts = self.tx_receipts.write().await;
                    receipts.insert(tx_hash.clone(), serde_json::json!({
                        "transactionHash": tx_hash,
                        "status": "0x1",
                        "blockNumber": "0x1",
                        "gasUsed": format!("0x{:x}", gas),
                        "from": sender,
                        "to": to_addr_lc,
                        "nonce": format!("0x{:x}", nonce),
                        "gasPrice": format!("0x{:x}", gas_price),
                        "logs": []
                    }));
                    println!("✅ [send_transaction] Transaction contractuelle exécutée sur {}", to_addr_lc);
                    return Ok(tx_hash);
                }
                Err(e) => {
                    eprintln!("❌ [send_transaction] Erreur appel contractuel: {}", e);
                    return Err(format!("Erreur appel contractuel: {}", e));
                }
            }
        } else {
            // ✅ NOUVEAU: transfert natif VEZ via la fonction transfer du contrat VEZ
            // Vérifie que la destination n'est PAS un contrat
            let is_contract = {
    let vm_guard = self.vm.read().await;
    let accounts = vm_guard.state.accounts.read().unwrap();
    accounts.get(&to_addr_lc).map(|acc| acc.is_contract).unwrap_or(false)
};

            if !is_contract && value > 0 {
                let mut vm_guard = self.vm.write().await;
                let sender = tx_params.get("from").and_then(|v| v.as_str()).unwrap_or(&self.validator_address).to_lowercase();
                // Correction: le destinataire doit être l'adresse "to" de la transaction, sauf si c'est le contrat VEZ
                let dest_addr = if to_addr_lc == "0xe3cf7102e5f8dfd6ec247daea8ca3e96579e8448" {
                    // Si le destinataire est le contrat VEZ, on ne fait pas de transfert natif
                    // (évite la boucle infinie)
                    return Err("Transfert natif VEZ vers le contrat VEZ interdit".to_string());
                } else {
                    to_addr_lc.clone()
                };
                let transfer_args = vec![
                    serde_json::Value::String(dest_addr), // <-- destinataire réel
                    serde_json::Value::Number(value.into()),
                ];
                match vm_guard.execute_module(
                    "0xe3cf7102e5f8dfd6ec247daea8ca3e96579e8448",
                    "transfer",
                    transfer_args,
                    Some(&sender),
                ) {
                    Ok(_res) => {
                        let mut receipts = self.tx_receipts.write().await;
                        receipts.insert(tx_hash.clone(), serde_json::json!({
                            "transactionHash": tx_hash,
                            "status": "0x1",
                            "blockNumber": "0x1",
                            "gasUsed": format!("0x{:x}", gas),
                            "from": sender,
                            "to": to_addr_lc,
                            "nonce": format!("0x{:x}", nonce),
                            "gasPrice": format!("0x{:x}", gas_price),
                            "logs": []
                        }));
                        println!("✅ [send_transaction] Transfert natif VEZ via transfer exécuté vers {}", to_addr_lc);
                        return Ok(tx_hash);
                    }
                    Err(e) => {
                        eprintln!("❌ [send_transaction] Erreur transfert natif VEZ (transfer): {}", e);
                        return Err(format!("Erreur transfert natif VEZ (transfer): {}", e));
                    }
                }
            } else {
                eprintln!("❌ [send_transaction] Transaction non reconnue : ni appel contrat ni transfert natif");
                return Err("Transaction non reconnue : ni appel contrat ni transfert natif".to_string());
            }
        }
    } else {
            // Transfert natif VEZ entre comptes externes
            let from_addr = tx_params.get("from").and_then(|v| v.as_str()).unwrap_or(&self.validator_address).to_lowercase();
            let to_addr_lc = to_opt.unwrap_or("".to_string()).to_lowercase();
    
            if value > 0 {
                {
                    let vm_guard = self.vm.read().await;
                    drop(vm_guard);
                    let mut vm_guard = self.vm.write().await;
                    let mut accounts = vm_guard.state.accounts.write().unwrap();
    
                    if let Some(sender_acc) = accounts.get_mut(&from_addr) {
                        if sender_acc.balance < value as u128 {
                            // ✅ LOG terminal pour solde insuffisant
                            eprintln!("❌ [send_transaction] Solde insuffisant pour le transfert : {} VEZ", value);
                            return Err(format!("Solde insuffisant pour le transfert : {} VEZ", value));
                        }
                        sender_acc.balance -= value as u128;
                        sender_acc.nonce = nonce.max(sender_acc.nonce + 1);
                    } else {
                        // ✅ LOG terminal pour compte expéditeur inexistant
                        eprintln!("❌ [send_transaction] Compte expéditeur inexistant : {}", from_addr);
                        return Err(format!("Compte expéditeur inexistant : {}", from_addr));
                    }
    
                    if let Some(receiver_acc) = accounts.get_mut(&to_addr_lc) {
                        receiver_acc.balance += value as u128;
                    } else {
                        accounts.insert(
                            to_addr_lc.clone(),
                            vuc_tx::slurachain_vm::AccountState {
                                address: to_addr_lc.clone(),
                                balance: value as u128,
                                contract_state: vec![], // <-- Mettre un buffer vide, pas 4096 zéros
                                resources: {
                                    let mut r = std::collections::BTreeMap::new();
                                    r.insert("created_by".to_string(), serde_json::Value::String("transfer".to_string()));
                                    r
                                },
                                state_version: 1,
                                last_block_number: 0,
                                nonce: 0,
                                code_hash: String::new(),
                                storage_root: String::new(),
                                is_contract: false,
                                gas_used: 0,
                            }
                        );
                    }
                }
                let mut receipts = self.tx_receipts.write().await;
                receipts.insert(tx_hash.clone(), serde_json::json!({
                    "transactionHash": tx_hash,
                    "status": "0x1",
                    "blockNumber": "0x1",
                    "gasUsed": format!("0x{:x}", gas),
                    "from": from_addr,
                    "to": to_addr_lc,
                    "nonce": format!("0x{:x}", nonce),
                    "gasPrice": format!("0x{:x}", gas_price),
                    "logs": []
                }));
                return Ok(tx_hash);
            }
            else {
                // ✅ LOG terminal pour transaction non reconnue
                eprintln!("❌ [send_transaction] Transaction non reconnue : ni appel contrat ni transfert natif");
                return Err("Transaction non reconnue : ni appel contrat ni transfert natif".to_string());
            }
        }
    }

    /// ✅ Récupération d'un reçu de transaction
    pub async fn get_transaction_receipt(&self, _tx_hash: String) -> Result<serde_json::Value, String> {
        let receipts = self.tx_receipts.read().await;
        if let Some(receipt) = receipts.get(&_tx_hash) {
            // Ajoute les champs blockNumber, blockHash, transactionIndex si manquants
            let mut receipt_obj = receipt.clone();
            let block_number = receipt_obj.get("blockNumber").cloned().unwrap_or(serde_json::Value::String("0x1".to_string()));
            let block_hash = receipt_obj.get("blockHash").cloned().unwrap_or(serde_json::Value::String("0x0000000000000000000000000000000000000000000000000000000000000001".to_string()));
            let tx_index = receipt_obj.get("transactionIndex").cloned().unwrap_or(serde_json::Value::String("0x0".to_string()));
            let from = receipt_obj.get("from").cloned().unwrap_or(serde_json::Value::String("".to_string()));
            let to = receipt_obj.get("to").cloned().unwrap_or(serde_json::Value::String("".to_string()));
            receipt_obj["blockNumber"] = block_number;
            receipt_obj["blockHash"] = block_hash;
            receipt_obj["transactionIndex"] = tx_index;
            receipt_obj["from"] = from;
            receipt_obj["to"] = to;
            return Ok(receipt_obj);
        }
        // Valeurs par défaut si non trouvé
        Ok(serde_json::json!({
            "transactionHash": _tx_hash,
            "blockNumber": "0x1",
            "blockHash": "0x0000000000000000000000000000000000000000000000000000000000000001",
            "transactionIndex": "0x0",
            "from": "",
            "to": "",
            "gasUsed": "0x5208",
            "cumulativeGasUsed": "0x5208",
            "status": "0x1",
            "logs": []
        }))
    }

    /// ✅ Appel de fonction read-only    
    pub async fn eth_call(&self, call_object: serde_json::Value) -> Result<String, String> {
        let contract_address = call_object.get("to")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_lowercase();
    
        let data = call_object.get("data")
            .and_then(|v| v.as_str())
            .unwrap_or("");
    
        if !data.starts_with("0x") || (data.len() < 10) {
            return Err("Champ 'data' manquant ou trop court".to_string());
        }
    
        let selector_hex = &data[2..10];
        let selector = u32::from_str_radix(selector_hex, 16)
            .map_err(|_| format!("Selector hex incorrect: {}", selector_hex))?;
    
        let vm = self.vm.read().await;
        let module = vm.modules.get(&contract_address)
            .ok_or_else(|| format!("Contrat non trouvé: {}", contract_address))?;
    
        let function_name = module.functions.iter()
            .find(|(_, meta)| meta.selector == selector)
            .map(|(name, _)| name.clone())
            .ok_or_else(|| format!("Fonction non trouvée pour selector 0x{:08x}", selector))?;
    
        let mut arguments = Vec::new();
        if function_name == "balanceOf" && data.len() >= 74 {
            let addr_hex = &data[34..74];
            let arg_addr = format!("0x{}", addr_hex);
            arguments.push(serde_json::Value::String(arg_addr));
        }

        let mut vm = self.vm.write().await;
        let result = vm.execute_module(
            &contract_address,
            &function_name,
            arguments,
            Some(&self.validator_address)
        )?;

        let result_hex = match result {
            serde_json::Value::Number(n) => {
                let v = n.as_u64().unwrap_or(0);
                format!("0x{:064x}", v)
            }
            serde_json::Value::String(s) => {
                let bytes = s.as_bytes();
                format!("0x{}", hex::encode(bytes))
            }
            _ => "0x".to_string(),
        };
    
        Ok(result_hex)
    }
    
        /// ✅ Estimation du gas
    pub async fn estimate_gas(&self) -> u64 {
        21000u64 // Gas de base pour une transaction simple
    }

    /// ✅ Récupération des comptes disponibles au format MetaMask
    pub async fn get_available_accounts(&self) -> Result<Vec<String>, String> {
        let vm = self.vm.read().await;
        let accounts = match vm.state.accounts.try_read() {
            Ok(guard) => guard,
            Err(_) => return Err("Verrou VM bloqué, réessayez plus tard".to_string()),
        };
        
        // Convertir les adresses UIP-10 en format Ethereum si nécessaire
        let ethereum_accounts: Vec<String> = accounts.keys()
            .map(|addr| {
                if addr.starts_with("0x") {
                    addr.clone()
                } else {
                    // Conversion UIP-10 vers format Ethereum
                    self.convert_uip10_to_ethereum(addr)
                }
            })
            .collect();
        
        Ok(ethereum_accounts)
    }

        pub async fn start_server(&self) {
        let socket_addr: SocketAddr = format!("{}:{}", "0.0.0.0", self.rpc_service.port)
            .parse()
            .expect("Invalid socket address");

        println!("Starting server on {}", socket_addr);

        let server = ServerBuilder::default()
            .build(socket_addr)
            .await
            .unwrap_or_else(|e| panic!("Failed to build server: {}", e));

        println!("Server successfully built on {}", socket_addr);

        let mut module = RpcModule::new(());
        
        // Endpoint eth_blockNumber
        let engine_platform_clone = self.clone();
        module.register_async_method("eth_blockNumber", move |_params, _meta, _| {
            let engine_platform = engine_platform_clone.clone();
            async move {
                let block_number = engine_platform.get_current_block_number().await;
                Ok::<_, jsonrpsee_types::error::ErrorObject>(serde_json::json!(format!("0x{:x}", block_number)))
            }
        }).expect("Failed to register eth_blockNumber method");

        // Endpoint eth_getTransactionCount
        let engine_platform_clone = self.clone();
        module.register_async_method("eth_getTransactionCount", move |params, _meta, _| {
            let engine_platform = engine_platform_clone.clone();
            async move {
                let params_array: Vec<serde_json::Value> = match params.parse() {
                    Ok(p) => p,
                    Err(e) => {
                        return Err(jsonrpsee_types::error::ErrorObject::owned(
                            ErrorCode::InvalidParams.code(),
                            "Paramètres invalides",
                            Some(format!("{}", e)),
                        ));
                    }
                };
                let address = params_array.get(0).and_then(|v| v.as_str()).unwrap_or("");
                match engine_platform.get_transaction_count(address).await {
                    Ok(nonce) => Ok::<_, jsonrpsee_types::error::ErrorObject>(serde_json::json!(format!("0x{:x}", nonce))),
                    Err(e) => Err(jsonrpsee_types::error::ErrorObject::owned(
                        ErrorCode::ServerError(-32000).code(),
                        "Erreur récupération nonce",
                        Some(format!("{}", e)),
                    )),
                }
            }
        }).expect("Failed to register eth_getTransactionCount method");

        // Endpoint eth_blockByNumber
        let engine_platform_clone = self.clone();
        module.register_async_method("eth_getBlockByNumber", move |params, _meta, _| {
            let engine_platform = engine_platform_clone.clone();
            async move {
                let params_array: Vec<serde_json::Value> = match params.parse() {
                    Ok(p) => p,
                    Err(e) => {
                        return Err(jsonrpsee_types::error::ErrorObject::owned(
                            ErrorCode::InvalidParams.code(),
                            "Paramètres invalides",
                            Some(format!("{}", e)),
                        ));
                    }
                };
                let block_tag = params_array.get(0).and_then(|v| v.as_str()).unwrap_or("latest");
                match engine_platform.get_block_by_number(block_tag).await {
                    Ok(block) => Ok::<_, jsonrpsee_types::error::ErrorObject>(block),
                    Err(e) => Err(jsonrpsee_types::error::ErrorObject::owned(
                        ErrorCode::ServerError(-32000).code(),
                        "Erreur récupération bloc",
                        Some(format!("{}", e)),
                    )),
                }
            }
        }).expect("Failed to register eth_getBlockByNumber method");

        // Endpoint eth_sendTransaction
    let engine_platform_clone = self.clone();
    module.register_async_method("eth_sendTransaction", move |params, _meta, _| {
        let engine_platform = engine_platform_clone.clone();
        async move {
            let tx_params: serde_json::Value = match params.parse::<serde_json::Value>() {
                Ok(req) => req,
                Err(e) => {
                    return Err(jsonrpsee_types::error::ErrorObject::owned(
                        ErrorCode::InvalidParams.code(),
                        "Paramètres invalides",
                        Some(format!("{}", e)),
                    ));
                }
            };
            // Correction : support Remix/MetaMask (array ou objet)
            let tx_obj = if tx_params.is_array() {
                tx_params.as_array().unwrap().get(0).cloned().unwrap_or_default()
            } else {
                tx_params
            };
            match engine_platform.send_transaction(tx_obj).await {
                Ok(tx_hash) => Ok::<_, jsonrpsee_types::error::ErrorObject>(serde_json::json!(tx_hash)),
                Err(e) => Err(jsonrpsee_types::error::ErrorObject::owned(
                    ErrorCode::ServerError(-32000).code(),
                    "Erreur envoi transaction",
                    Some(format!("{}", e)),
                )),
            }
        }
    }).expect("Failed to register eth_sendTransaction method");

                // Endpoint eth_sendRawTransaction
                let engine_platform_clone = self.clone();
                module.register_async_method("eth_sendRawTransaction", move |params, _meta, _| {
                    let engine_platform = engine_platform_clone.clone();
                    async move {
                        let params_array: Vec<serde_json::Value> = match params.parse() {
                            Ok(p) => p,
                            Err(e) => {
                                return Err(jsonrpsee_types::error::ErrorObject::owned(
                                    ErrorCode::InvalidParams.code(),
                                    "Paramètres invalides",
                                    Some(format!("{}", e)),
                                ));
                            }
                        };
                        let raw_tx = params_array.get(0).and_then(|v| v.as_str()).unwrap_or("");
                        println!("➡️ [eth_sendRawTransaction] raw_tx reçu: {}", raw_tx);
                
                        // Décodage hex safe (gère longueur impaire)
                        let raw_tx_str = raw_tx.trim_start_matches("0x");
                        let raw_tx_fixed = if raw_tx_str.len() % 2 != 0 {
                            format!("0{}", raw_tx_str)
                        } else {
                            raw_tx_str.to_string()
                        };
                        let raw_bytes = match hex::decode(&raw_tx_fixed) {
                            Ok(b) => b,
                            Err(e) => {
                                return Err(jsonrpsee_types::error::ErrorObject::owned(
                                    ErrorCode::InvalidParams.code(),
                                    "Hex RLP invalide",
                                    Some(format!("{}", e)),
                                ));
                            }
                        };
                
                        println!("➡️ [eth_sendRawTransaction] raw_bytes: {:?}", raw_bytes);
                
                        // Calcul du hash de la tx (Keccak256 sur le raw bytes fournis)
                        use sha3::{Digest, Keccak256};
                        let mut hasher = Keccak256::new();
                        hasher.update(&raw_bytes);
                        let tx_hash = format!("0x{:x}", hasher.finalize());
                
                        // Tentative de décodage RLP — supporte legacy list et typed (0x02 etc.)
                        let mut nonce: u64 = 0;
                        let mut gas_price: u64 = 0;
                        let mut gas_limit: u64 = 0;
                        let mut to_addr = String::new();
                        let mut value: u128 = 0;
                        let mut input_hex = "0x".to_string();
                        let mut data_b: Vec<u8> = Vec::new(); // <-- Add this line to declare data_b
                        // input_hex will be set after RLP parsing below
                
                        let parse_from_rlp = |rlp: rlp::Rlp| -> (u64,u64,u64,Vec<u8>,u128,Vec<u8>) {
                            let item_count = rlp.item_count().unwrap_or(0);
                            let nonce = rlp.at(0).map(|r| r.as_val::<u64>().unwrap_or(0)).unwrap_or(0);
                            let gas_price = if item_count > 1 { rlp.at(1).map(|r| r.as_val::<u64>().unwrap_or(0)).unwrap_or(0) } else { 0 };
                            let gas_limit = if item_count > 2 { rlp.at(2).map(|r| r.as_val::<u64>().unwrap_or(0)).unwrap_or(0) } else { 0 };
                            let to = if item_count > 3 { rlp.at(3).map(|r| r.as_val::<Vec<u8>>().unwrap_or_default()).unwrap_or_default() } else { Vec::new() };
                            let value = if item_count > 4 { rlp.at(4).map(|r| r.as_val::<u128>().unwrap_or(0)).unwrap_or(0) } else { 0 };
                            let data = if item_count > 5 { rlp.at(5).map(|r| r.as_val::<Vec<u8>>().unwrap_or_default()).unwrap_or_default() } else { Vec::new() };
                            (nonce, gas_price, gas_limit, to, value, data)
                        };
                
                        if !raw_bytes.is_empty() {
                            if raw_bytes[0] == 0x02 || raw_bytes[0] == 0x01 {
                                // Typed tx: first byte is type, payload is RLP after that
                                if raw_bytes.len() > 1 {
                                    let payload = &raw_bytes[1..];
                                    let rlp_t = rlp::Rlp::new(payload);
                                    if rlp_t.is_list() {
                                        let (n, gp, gl, to_b, val, data_b) = parse_from_rlp(rlp_t);
                                        nonce = n; gas_price = gp; gas_limit = gl; value = val;
                                        // Correction: adresse Ethereum = 20 octets
                                        if !to_b.is_empty() && to_b.len() == 20 {
                                            to_addr = format!("0x{}", hex::encode(&to_b));
                                        }
                                        // Si to vide, c'est un déploiement de contrat
                                        if !data_b.is_empty() {
                                            input_hex = format!("0x{}", hex::encode(&data_b));
                                        }
                                    }
                                }
                            } else {
                                // legacy or raw RLP list
                                let rlp0 = rlp::Rlp::new(&raw_bytes);
                                if rlp0.is_list() {
                                    let (n, gp, gl, to_b, val, data_b) = parse_from_rlp(rlp0);
                                    nonce = n; gas_price = gp; gas_limit = gl; value = val;
                                    if !to_b.is_empty() && to_b.len() == 20 {
                                        to_addr = format!("0x{}", hex::encode(&to_b));
                                    }
                                    if !data_b.is_empty() {
                                        input_hex = format!("0x{}", hex::encode(&data_b));
                                    }
                                }
                            }
                        }
                
                        // Construction de l'objet JSON pour send_transaction
                        // Remplacer l'ancien bloc serde_json::json! par la construction explicite ci-dessous
                        let mut map = serde_json::Map::new();
                        map.insert("value".to_string(), serde_json::Value::String(format!("{}", value)));
                        map.insert("gas".to_string(), serde_json::Value::Number(serde_json::Number::from(gas_limit)));
                        map.insert("gasPrice".to_string(), serde_json::Value::Number(serde_json::Number::from(gas_price)));
                        map.insert("nonce".to_string(), serde_json::Value::Number(serde_json::Number::from(nonce)));
                        
                        if !data_b.is_empty() {
                            map.insert("data".to_string(), serde_json::Value::String(format!("0x{}", hex::encode(&data_b))));
                        }
                        if !to_addr.is_empty() {
                            map.insert("to".to_string(), serde_json::Value::String(to_addr.clone()));
                        }
                        
                        // Ajoute le champ "from" si possible
                        if let Some(sender_addr) = Self::extract_sender_from_raw(&raw_bytes) {
                            map.insert("from".to_string(), serde_json::Value::String(sender_addr));
                        }

                        let tx_obj = serde_json::Value::Object(map);

                        // Appel VM via send_transaction
                        match engine_platform.send_transaction(tx_obj).await {
                            Ok(tx_hash) => Ok::<_, jsonrpsee_types::error::ErrorObject>(serde_json::json!(tx_hash)),
                            Err(e) => Err(jsonrpsee_types::error::ErrorObject::owned(
                                ErrorCode::ServerError(-32000).code(),
                                "Erreur VM send_transaction",
                                Some(format!("{}", e)),
                            )),
                        }
                    }
                }).expect("Failed to register eth_sendRawTransaction method");

        let engine_platform_clone = self.clone();
        module.register_async_method("eth_getTransactionReceipt", move |params, _meta, _| {
            let engine_platform = engine_platform_clone.clone();
            async move {
        let params_array: Vec<serde_json::Value> = match params.parse() {
            Ok(p) => p,
            Err(e) => {
                return Err(jsonrpsee_types::error::ErrorObject::owned(
                    ErrorCode::InvalidParams.code(),
                    "Paramètres invalides",
                    Some(format!("{}", e)),
                ));
            }
        };
                let tx_hash = params_array.get(0).and_then(|v| v.as_str()).unwrap_or("");
                match engine_platform.get_transaction_receipt(tx_hash.to_string()).await {
                    Ok(result) => Ok::<_, jsonrpsee_types::error::ErrorObject>(serde_json::json!(result)),
                    Err(e) => Err(jsonrpsee_types::error::ErrorObject::owned(
                        ErrorCode::ServerError(-32000).code(),
                        "Erreur eth_getTransactionReceipt",
                        Some(format!("{}", e)),
                    )),
                }
            }
        }).expect("Failed to register eth_getTransactionReceipt method");

        // Endpoint eth_call
        let engine_platform_clone = self.clone();
        module.register_async_method("eth_call", move |params, _meta, _| {
            let engine_platform = engine_platform_clone.clone();
            async move {
                let call_object: serde_json::Value = match params.parse::<serde_json::Value>() {
                    Ok(req) => req,
                    Err(e) => {
                        return Err(jsonrpsee_types::error::ErrorObject::owned(
                            ErrorCode::InvalidParams.code(),
                            "Paramètres invalides",
                            Some(format!("{}", e)),
                        ));
                    }
                };
                match engine_platform.eth_call(call_object).await {
                    Ok(result) => Ok::<_, jsonrpsee_types::error::ErrorObject>(serde_json::json!(result)),
                    Err(e) => Err(jsonrpsee_types::error::ErrorObject::owned(
                        ErrorCode::ServerError(-32000).code(),
                        "Erreur eth_call",
                        Some(format!("{}", e)),
                    )),
                }
            }
        }).expect("Failed to register eth_call method");

        // Endpoint eth_estimateGas
        let engine_platform_clone = self.clone();
        module.register_async_method("eth_estimateGas", move |_params, _meta, _| {
            let engine_platform = engine_platform_clone.clone();
            async move {
                let gas = engine_platform.estimate_gas().await;
                Ok::<_, jsonrpsee_types::error::ErrorObject>(serde_json::json!(format!("0x{:x}", gas)))
            }
        }).expect("Failed to register eth_estimateGas method");

// Endpoint eth_getCode
let engine_platform_clone = self.clone();
module.register_async_method("eth_getCode", move |params, _meta, _| {
    let engine_platform = engine_platform_clone.clone();
    async move {
        use tokio::time::timeout;
        use std::time::Duration;

        println!("➡️ eth_getCode appelé avec params: {:?}", params); // LOG

        let params_array: Vec<serde_json::Value> = match params.parse() {
            Ok(p) => p,
            Err(e) => {
                return Err(jsonrpsee_types::error::ErrorObject::owned(
                    ErrorCode::InvalidParams.code(),
                    "Paramètres invalides",
                    Some(format!("{}", e)),
                ));
            }
        };
        let address = params_array.get(0).and_then(|v| v.as_str()).unwrap_or("").to_lowercase();
        println!("➡️ eth_getCode address: {}", address); // LOG

        // Timeout sur la lecture VM
        let code_opt = match timeout(Duration::from_secs(20), async {
            let vm = engine_platform.vm.read().await;
            let accounts = vm.state.accounts.read().unwrap();
            accounts.get(&address).map(|account| account.contract_state.clone())
        }).await {
            Ok(result) => result,
            Err(_) => {
                println!("⏰ Timeout eth_getCode pour address: {}", address);
                return Err(jsonrpsee_types::error::ErrorObject::owned(
                    ErrorCode::ServerError(-32002).code(),
                    "Timeout VM (plus de 20 secondes)",
                    Some("La VM est trop lente ou bloquée".to_string()),
                ));
            }
        };

        let code_hex = match code_opt {
            Some(ref code) if !code.is_empty() => {
                println!("🟢 [eth_getCode] Bytecode trouvé pour {} : {} octets, hex: {}...", address, code.len(), hex::encode(&code[..std::cmp::min(16, code.len())]));
                format!("0x{}", hex::encode(code))
            },
            _ => {
                println!("🔴 [eth_getCode] Aucun bytecode pour {}", address);
                "0x".to_string()
            }
        };

        println!("➡️ eth_getCode retourne: {}", code_hex); // LOG

        Ok::<_, jsonrpsee_types::error::ErrorObject>(serde_json::json!(code_hex))
    }
}).expect("Failed to register eth_getCode method");

        // ✅ AJOUT: Endpoint eth_chainId pour Remix
        let engine_platform_clone = self.clone();
        module.register_async_method("eth_chainId", move |_params, _meta, _| {
            let engine_platform = engine_platform_clone.clone();
            async move {
                let chain_id = engine_platform.get_chain_id();
                Ok::<_, jsonrpsee_types::error::ErrorObject>(serde_json::json!(format!("0x{:x}", chain_id)))
            }
        }).expect("Failed to register eth_chainId method");

        println!("Registered endpoint: eth_chainId");

        // ✅ AJOUT: Endpoint net_version pour compatibilité Remix
        let engine_platform_clone = self.clone();
        module.register_async_method("net_version", move |_params, _meta, _| {
            let engine_platform = engine_platform_clone.clone();
            async move {
                let chain_id = engine_platform.get_chain_id();
                Ok::<_, jsonrpsee_types::error::ErrorObject>(serde_json::json!(chain_id.to_string()))
            }
        }).expect("Failed to register net_version method");

        println!("Registered endpoint: net_version");

        // ✅ AJOUT: Endpoint eth_accounts pour Remix
        let engine_platform_clone = self.clone();
        module.register_async_method("eth_accounts", move |_params, _meta, _| {
            let engine_platform = engine_platform_clone.clone();
            async move {
                match engine_platform.get_available_accounts().await {
                    Ok(accounts) => Ok::<_, jsonrpsee_types::error::ErrorObject>(serde_json::json!(accounts)),
                    Err(e) => Err(jsonrpsee_types::error::ErrorObject::owned(
                        ErrorCode::ServerError(-32000).code(),
                        "Erreur récupération comptes",
                        Some(format!("{}", e)),
                    )),
                }
            }
        }).expect("Failed to register eth_accounts method");

        println!("Registered endpoint: eth_accounts");

        // ✅ AJOUT: Endpoint eth_gasPrice pour Remix
        let engine_platform_clone = self.clone();
        module.register_async_method("eth_gasPrice", move |_params, _meta, _| {
            let engine_platform = engine_platform_clone.clone();
            async move {
                let gas_price = engine_platform.get_gas_price().await;
                Ok::<_ , jsonrpsee_types::error::ErrorObject>(serde_json::json!(format!("0x{:x}", gas_price)))
            }
        }).expect("Failed to register eth_gasPrice method");

        println!("Registered endpoint: eth_gasPrice");

        // ✅ CORRECTION: Endpoint eth_getBalance pour Remix
        let engine_platform_clone = self.clone();
        module.register_async_method("eth_getBalance", move |params, _meta, _| {
            let engine_platform = engine_platform_clone.clone();
            async move {
                let params_array: Vec<serde_json::Value> = match params.parse() {
                    Ok(p) => p,
                    Err(e) => {
                        return Err(jsonrpsee_types::error::ErrorObject::owned(
                            ErrorCode::InvalidParams.code(),
                            "Paramètres invalides",
                            Some(format!("{}", e)),
                        ));
                    }
                };

                if params_array.is_empty() {
                    return Err(jsonrpsee_types::error::ErrorObject::owned(
                        ErrorCode::InvalidParams.code(),
                        "Adresse manquante",
                        None::<String>, // ✅ CORRECTION: Type explicite
                    ));
                }

                let address = params_array[0].as_str().unwrap_or("");
                match engine_platform.get_account_balance(address).await {
                    Ok(balance) => Ok::<_, jsonrpsee_types::error::ErrorObject>(serde_json::json!(format!("0x{:x}", balance))),
                    Err(e) => Err(jsonrpsee_types::error::ErrorObject::owned(
                        ErrorCode::ServerError(-32000).code(),
                        "Erreur récupération balance",
                        Some(format!("{}", e)),
                    )),
                }
            }
        }).expect("Failed to register eth_getBalance method");

        // Enregistrer le endpoint `get_ledger_info`
        let engine_platform_clone = self.clone();
        module.register_async_method("get_ledger_info", move |_params, _meta, _| {
            let engine_platform = engine_platform_clone.clone();
            async move {
                match engine_platform.get_ledger_info().await {
                    Ok(response) => Ok::<_, jsonrpsee_types::error::ErrorObject>(response),
                    Err(e) => Err(jsonrpsee_types::error::ErrorObject::owned(
                        ErrorCode::ServerError(-32000).code(),
                        "Erreur lors de la récupération des informations du ledger",
                        Some(format!("{}", e)),
                    )),
                }
            }
        }).expect("Failed to register get_ledger_info method");
        
        let engine_platform_clone = self.clone();
        module.register_async_method("build_acc", {
            let vm = engine_platform_clone.vm.clone();
            move |_params, _meta, _| {
                let vm = vm.clone();
                async move {
                    let mut vm_guard = vm.write().await;
                    match vuc_platform::operator::crypto_perf::generate_and_create_account(&mut vm_guard, "acc_el").await {
                        Ok((address, privkey)) => Ok(serde_json::json!({
                            "status": "success",
                            "address": address,
                            "private_key": privkey
                        })),
                        Err(e) => Err(jsonrpsee_types::error::ErrorObject::owned(
                            ErrorCode::ServerError(-32010).code(),
                            "Erreur lors de la génération du compte",
                            Some(format!("{}", e)),
                        )),
                    }
                }
            }
        }).expect("Failed to register build_acc method");
        
        println!("Registered endpoint: build_acc");

        // Démarrer le serveur
        let server_handle = server.start(module.clone()).clone();
        println!("Server started successfully: {:?}", server_handle);
        println!("🌐 Slurachain ready for Remix deployment!");
        println!("🔗 Chain ID: 0x{:x} ({})", self.rpc_service.port, self.rpc_service.port);
        println!("📡 RPC URL: http://0.0.0.0:{}", self.rpc_service.port);

        // Maintenir le serveur actif
        tokio::signal::ctrl_c().await.expect("Failed to listen for Ctrl+C");
        println!("Shutting down server...");
    }

    /// ✅ Conversion d'adresse UIP-10 vers format Ethereum
    fn convert_uip10_to_ethereum(&self, uip10_addr: &str) -> String {
        use sha3::{Digest, Sha3_256};
        let mut hasher = Sha3_256::new();
        hasher.update(uip10_addr.as_bytes());
        let hash = format!("{:x}", hasher.finalize());
        format!("0x{}", &hash[..40])
    }

    /// ✅ AJOUT: Conversion d'adresse Ethereum vers UIP-10 
    fn convert_ethereum_to_uip10(&self, eth_addr: &str) -> String {
        // Pour l'instant, retourner l'adresse telle quelle
        // Dans une implémentation complète, il faudrait une table de mapping
        eth_addr.to_string()
    }
}

// ✅ CORRECTION COMPLÈTE: Fonction main avec initialisation VEZ via bytecode
#[tokio::main]
async fn main() {
    dotenv::dotenv().ok(); // ← Ajoute cette ligne
    tracing_subscriber::fmt::init();
    println!("🚀 Starting Slurachain network with Lurosonie consensus...");

    // ✅ Ouvre RocksDB UNE SEULE FOIS et partage l'Arc partout
    let storage: Arc<RocksDBManagerImpl> = Arc::new(RocksDBManagerImpl::new());

    // ✅ Service Ethereum adapté (not required by current slurachainRpcService::new signature)
    // Note: the eth service creation is omitted because slurachainRpcService::new expects storage as the 4th argument.

    // ✅ Initialisation de la VM Slurachain
    let vm = Arc::new(TokioRwLock::new(SlurachainVm::new()));
    let mut validator_address_generated = String::new();
    {
        let mut vm_guard = vm.write().await;
        vm_guard.set_storage_manager(storage.clone());
        
        // ✅ DÉPLOIEMENT DU CONTRAT VEZ avec bytecode spécifique
        println!("🪙 Deploying VEZ contract with bytecode...");
        if let Err(e) = deploy_vez_contract_evm(&mut vm_guard).await {
            eprintln!("❌ Failed to deploy VEZ contract: {}", e);
            return;
        }

        // ✅ VÉRIFICATION QUE LE MODULE EST BIEN ENREGISTRÉ
        if vm_guard.modules.contains_key("0xe3cf7102e5f8dfd6ec247daea8ca3e96579e8448") {
            println!("✅ VEZ module correctly registered");
            println!("   • Functions available: {:?}", 
                   vm_guard.modules["0xe3cf7102e5f8dfd6ec247daea8ca3e96579e8448"].functions.keys().collect::<Vec<_>>());
        } else {
            eprintln!("❌ VEZ module NOT registered - initialization will fail");
        }
        
        // ✅ CRÉATION DU COMPTE SYSTÈME
        println!("🏛️ Creating system account...");
        // Génère l'adresse du validateur principal
        validator_address_generated = {
            match assign_private_key_to_system_account(&mut vm_guard) {
                Ok(privkey_hex) => {
                    let accounts = vm_guard.state.accounts.read().unwrap();
                    accounts.iter()
                        .find(|(_, acc)| acc.resources.get("private_key").map(|v| v.as_str().unwrap_or("")) == Some(privkey_hex.as_str()))
                        .map(|(addr, _)| addr.clone())
                        .unwrap_or_else(|| {
                            // Fallback: génère une adresse aléatoire si non trouvée
                            // ⚠️ Supprimer ce fallback pour garantir l'adresse liée à la clé privée
                            panic!("Adresse liée à la clé privée non trouvée !");
                        })
                }
                Err(e) => {
                    eprintln!("❌ Erreur lors de la génération de la clé privée du validateur: {}", e);
                    panic!("Impossible de générer l'adresse du validateur !");
                }
            }
        };

// proxy account : stocke le bytecode et la référence d'implémentation dans resources

// Calculate impl_address using the same logic as deploy_vez_contract_evm
use sha3::{Digest, Keccak256};
let impl_bytecode_hex = include_str!("../../../vez_bytecode.hex");
let impl_bytecode = match hex::decode(impl_bytecode_hex.trim()) {
    Ok(bytes) => bytes,
    Err(e) => {
        eprintln!("Bytecode decode error: {}", e);
        vec![]
    }
};
let mut hasher = Keccak256::new();
hasher.update(&impl_bytecode);
let impl_hash = hasher.finalize();
let impl_address = format!("0x{}", hex::encode(&impl_hash)[..40].to_string()).to_lowercase();

let mut proxy_resources = std::collections::BTreeMap::new();
proxy_resources.insert("implementation".to_string(), serde_json::Value::String(impl_address.clone()));
proxy_resources.insert("initialized".to_string(), serde_json::Value::Bool(false));
let proxy_bytecode_hex = include_str!("../../../vezcurpoxycore_bytecode.hex");
let proxy_bytecode = match hex::decode(proxy_bytecode_hex.trim()) {
    Ok(bytes) => bytes,
    Err(e) => {
        eprintln!("Proxy bytecode decode error: {}", e);
        vec![]
    }
};
vm_guard.state.accounts.write().unwrap().insert(
    validator_address_generated.clone(),
    vuc_tx::slurachain_vm::AccountState {
        address: validator_address_generated.clone(),
        balance: 30_000_000_000_000_000_000_000_000u128,
        contract_state: proxy_bytecode.clone(), // <-- doit être le vrai bytecode !
        resources: proxy_resources.clone(),
        state_version: 0,
        last_block_number: 0,
        nonce: 0,
        code_hash: String::new(),
        storage_root: String::new(),
        is_contract: false,
        gas_used: 0,
    }
);

        // ✅ ASSIGNATION ET AFFICHAGE DE LA CLÉ PRIVÉE DU VALIDATEUR
        match assign_private_key_to_system_account(&mut vm_guard) {
            Ok(privkey_hex) => {
                println!("🔑 Clé privée du validateur (système): {}", privkey_hex);
            }
            Err(e) => {
                eprintln!("❌ Erreur lors de la génération de la clé privée du validateur: {}", e);
            }
        }
        
        // ✅ DÉPLOIEMENT DU CONTRAT VEZ avec bytecode spécifique
        println!("🪙 Deploying VEZ contract with bytecode...");
        if let Err(e) = deploy_vez_contract_evm(&mut vm_guard).await {
            eprintln!("❌ Failed to deploy VEZ contract: {}", e);
        } else {
            println!("✅ VEZ contract deployed successfully with bytecode");
        }
        
        // ✅ CRÉATION DES COMPTES INITIAUX avec VEZ
        println!("👥 Creating initial accounts...");
        if let Err(e) = create_initial_accounts_with_vez(&mut vm_guard, &validator_address_generated).await {
            eprintln!("❌ Failed to create initial accounts: {}", e);
        } else {
            println!("✅ Initial accounts created with VEZ");
        }
        
        println!("✅ VM Slurachain fully initialized with VEZ ecosystem");
    }

    // ✅ Canal pour les blocs
    let (block_sender, block_receiver) = mpsc::channel(100);

    // ✅ Manager Lurosonie avec storage
    let lurosonie_manager = Arc::new(LurosonieManager::new_with_storage(
        storage.clone(),
        vm.clone(),
        block_sender.clone()
    ).await);

    println!("✅ Manager Lurosonie initialisé");

    // ✅ Service RPC Slurachain (storage is the 4th argument in the current constructor)
    let slurachain_service = Arc::new(tokio::sync::Mutex::new(SlurEthService::new()));
    let rpc_service = slurachainRpcService::new(8080, "http://0.0.0.0:8080".to_string(), "ws://0.0.0.0:8080".to_string(), slurachain_service.clone(), storage.clone(), block_receiver, lurosonie_manager.clone());

    println!("✅ Service RPC Slurachain initialisé sur le port 8080");

    // ✅ Récupération de l'adresse du validateur (système)
    let validator_address_system = &validator_address_generated;
    let validator_address = validator_address_generated.clone();

    // ✅ Engine Platform
    let engine_platform = Arc::new(EnginePlatform::new(
        "vyft_slurachain".to_string(),
        vec![],
        rpc_service.clone(),
        vm.clone(),
        validator_address.clone(),
    ));

    println!("✅ Engine Platform initialisé");

    // ✅ Créer et émettre le bloc genesis Lurosonie
    println!("📦 Creating Lurosonie genesis block...");
    let genesis_block = TimestampRelease {
        timestamp: Utc::now(),
        log: "Lurosonie Genesis Block - Slurachain Network Initialized with VEZ Token".to_string(),
        block_number: 0,
        vyfties_id: "lurosonie_genesis".to_string(),
    };

    // ✅ Ajouter le bloc genesis à la chaîne Lurosonie
    lurosonie_manager.add_block_to_chain(genesis_block.clone(), None).await;
    println!("✅ Bloc genesis Lurosonie ajouté: {:?}", genesis_block);

    // ✅ Initialisation du contrat VEZ après déploiement
    println!("🔧 Initializing VEZ contract...");
    if let Err(e) = initialize_vez_contract(&vm, &validator_address).await {
        eprintln!("❌ Failed to initialize VEZ contract: {}", e);
    } else {
        println!("✅ VEZ contract initialized successfully");
    }

    // ✅ Démarrage des services...
    let lurosonie_consensus = lurosonie_manager.clone();
    let consensus_handle = tokio::spawn(async move {
        println!("🔄 Démarrage du consensus Lurosonie BFT Relayed PoS");
        lurosonie_consensus.start_lurosonie_consensus().await;
    });

    let engine_clone = engine_platform.clone();
    let server_handle = tokio::spawn(async move {
        engine_clone.start_server().await;
    });

    // ✅ Tasks de monitoring...
    let cleanup_manager = lurosonie_manager.clone();
    let cleanup_handle = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            cleanup_manager.cleanup_old_pending_transactions(3600).await;
        }
    });

    let metrics_manager = lurosonie_manager.clone();
    let metrics_handle = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        loop {
            interval.tick().await;
            let metrics = metrics_manager.get_network_metrics().await;
            
            if let Some(status) = metrics.get("network_status") {
                if let Some(supply) = metrics.get("total_vez_supply") {
                    if let Some(validators) = metrics.get("active_validators") {
                        if let Some(blocks) = metrics.get("total_blocks") {
                            println!("📊 Métriques réseau - Status: {}, Supply: {} VEZ, Validateurs: {}, Blocs: {}", 
                                   status, supply, validators, blocks);
                        }
                    }
                }
            }
        }
    });

    let validation_vm = vm.clone();
    let validator_address_clone = validator_address.clone();
    let validation_handle = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(300));
        loop {
            interval.tick().await;
            if let Err(e) = validate_system_integrity(&validation_vm, &validator_address_clone).await {
                eprintln!("⚠️ System integrity check failed: {}", e);
            }
        }
    });

    // ✅ Affichage des informations de démarrage
    println!("\n🎉 Slurachain Network fully operational!");
    println!("📡 RPC Endpoint: http://0.0.0.0:8080");
    println!("🔗 Chain ID: 0x{:x} ({})", engine_platform.get_chain_id(), engine_platform.get_chain_id());
    println!("⚡ Consensus: Lurosonie Relayed PoS BFT");
    println!("🪙 Native Token: VEZ (Vyft enhancing ZER)");
    println!("📄 Contract Address: 0xe3cf7102e5f8dfd6ec247daea8ca3e96579e8448");
    
    // ✅ Informations sur les tokens et comptes
    {
        let vm_read = vm.read().await;
        let accounts = vm_read.state.accounts.read().unwrap();
        
        if let Some(vez_contract) = accounts.get("0xe3cf7102e5f8dfd6ec247daea8ca3e96579e8448") {
            if let Some(total_supply) = vez_contract.resources.get("total_supply") {
                println!("🏦 VEZ Total Supply: {}", total_supply);
            }
            if let Some(initialized) = vez_contract.resources.get("initialized") {
                println!("🔧 VEZ Initialized: {}", initialized);
            }
        }
        
        let user_accounts = accounts.iter()
            .filter(|(addr, _)| ![&validator_address, "0xe3cf7102e5f8dfd6ec247daea8ca3e96579e8448"].contains(&addr.as_str()))
            .count();
        
        println!("👥 Total accounts created: {}", user_accounts);
        println!("🏦 System accounts: {} (system + VEZ contract)", accounts.len() - user_accounts);
    }
    
    println!("🛑 Press Ctrl+C to stop\n");

    // ✅ Endpoints et instructions pour MetaMask/Remix
    println!("🔧 Available endpoints (MetaMask compatible):");
    println!("   • eth_chainId - Chain ID for MetaMask");
    println!("   • eth_accounts - Available accounts");
    println!("   • eth_getBalance - Account balances");
    println!("   • eth_gasPrice - Gas price");
    println!("   • eth_blockNumber - Current block number");
    println!("   • eth_getTransactionCount - Account nonce");
    println!("   • eth_sendTransaction - Send transactions");
    println!("   • eth_call - Read-only calls");
    println!("   • deploy_contract - Deploy smart contracts");
    println!("   • tx_int - Execute transactions");
    println!("   • view - Read-only function calls");
    println!("   • build_acc - Generate new accounts");
    println!("");

    println!("💡 MetaMask Configuration:");
    println!("   1. Network Name: Slurachain");
    println!("   2. RPC URL: http://localhost:8080");
    println!("   3. Chain ID: {}", engine_platform.get_chain_id());
    println!("   4. Currency Symbol: VEZ");
    println!("   5. Block Explorer: Not configured");
    println!("");

    // ✅ Gestionnaire de signaux
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            println!("🛑 Signal d'arrêt reçu...");
        }
        result = consensus_handle => {
            if let Err(e) = result {
                eprintln!("❌ Erreur dans le consensus: {}", e);
            }
        }
        result = server_handle => {
            if let Err(e) = result {
                eprintln!("❌ Erreur dans le serveur RPC: {}", e);
            }
        }
        result = cleanup_handle => {
            if let Err(e) = result {
                eprintln!("❌ Erreur dans le nettoyage: {}", e);
            }
        }
        result = metrics_handle => {
            if let Err(e) = result {
                eprintln!("❌ Erreur dans les métriques: {}", e);
            }
        }
        result = validation_handle => {
            if let Err(e) = result {
                eprintln!("❌ Erreur dans la validation: {}", e);
            }
        }
    }







    // ✅ Arrêt propre
    println!("🔄 Arrêt en cours...");
    
    
    if let Err(e) = save_system_state(&vm, &storage, &validator_address).await {
        eprintln!("⚠️ Failed to save system state: {}", e);
    } else {
        println!("💾 System state saved successfully");
    }
    
    let final_stats = lurosonie_manager.get_lurosonie_stats().await;
    println!("📈 Final Statistics:");
    if let Some(total_blocks) = final_stats.get("total_blocks") {
        println!("   • Blocks produced: {}", total_blocks);
    }
    if let Some(validators) = final_stats.get("total_relay_validators") {
        println!("   • Validators: {}", validators);
    }

    println!("🛑 Slurachain Network stopped gracefully");
}

async fn create_initial_accounts_with_vez(vm: &mut SlurachainVm, validator_address: &str) -> Result<(), String> {
    use vuc_tx::slurachain_vm::AccountState;

    println!("👥 Creating initial user accounts with VEZ...");

    // Utilise des adresses Ethereum valides
    let initial_accounts = vec![
        (validator_address, 888_000_000_000_000_000_000u128), // <-- 888 VEZ
    ];

    let mut accounts = vm.state.accounts.write().unwrap();

    for (account_eth, initial_balance) in initial_accounts {
        let account = AccountState {
            address: account_eth.to_string(),
            balance: initial_balance as u128,
            contract_state: vec![],
            resources: {
                let mut resources = std::collections::BTreeMap::new();
                resources.insert("account_type".to_string(), serde_json::Value::String("user".to_string()));
                resources.insert("created_at".to_string(), serde_json::Value::Number(chrono::Utc::now().timestamp().into()));
                resources.insert("is_initial_account".to_string(), serde_json::Value::Bool(true));
                resources.insert("supports_vez".to_string(), serde_json::Value::Bool(true));
                resources
            },
            state_version: 1,
            last_block_number: 0,
            nonce: 0,
            code_hash: String::new(),
            storage_root: String::new(),
            is_contract: false,
            gas_used: 0,
        };

        accounts.insert(account_eth.to_string(), account);

        println!("✅ Created account '{}' with {} VEZ", account_eth, initial_balance / 10_u128.pow(18));
    }

    println!("✅ Initial accounts creation completed with VEZ balances");
    Ok(())
}

async fn save_system_state(
    vm: &Arc<TokioRwLock<SlurachainVm>>, 
    storage: &Arc<RocksDBManagerImpl>,
    validator_address: &str
) -> Result<(), String> {
    println!("💾 Saving system state...");
    
    let vm_read = vm.read().await;
    let accounts = vm_read.state.accounts.read().unwrap();
    
    // ✅ Sauvegarde du contrat VEZ et des comptes système
   
   

   
   
    for (address, account) in accounts.iter() {
        if account.is_contract || address == validator_address || address.starts_with("*") {
            let account_data = serde_json::to_vec(account)
               
                .map_err(|e| format!("Failed to serialize account {}: {}", address, e))?;
            
            let storage_key = format!("account:{}", address);
            if let Err(e) = storage.store(&storage_key, account_data) {
                eprintln!("⚠️ Failed to save account {}: {}", address, e);
            }
        }
    }
    
    println!("✅ System state saved successfully");
    Ok(())
}
async fn validate_system_integrity(vm: &Arc<TokioRwLock<SlurachainVm>>, validator_address: &str) -> Result<(), String> {
    let vm_read = vm.read().await;
    let accounts = vm_read.state.accounts.read().unwrap();
    
    // ✅ Vérification du contrat VEZ

    let vez_address = "0xe3cf7102e5f8dfd6ec247daea8ca3e96579e8448";
    if !accounts.contains_key(vez_address) {
        return Err("Missing VEZ contract".to_string());
    }
    
    // ✅ Vérification des comptes système
       let required_system_accounts = [validator_address];
    for account_name in &required_system_accounts {
        if !accounts.contains_key(*account_name) {
            return Err(format!("Missing required system account: {}", account_name));
        }
    }
    
    // ✅ Vérification de l'initialisation VEZ
    if let Some(vez_contract) = accounts.get(vez_address) {
        if let Some(initialized) = vez_contract.resources.get("initialized") {
            if !initialized.as_bool().unwrap_or(false) {
                return Err("VEZ contract not initialized".to_string());
            }
        } else {
            return Err("VEZ contract initialization status unknown".to_string());
        }
    }
    
    Ok(())
}

// ✅ CORRECTION 2: Fonction helper pour calculer les sélecteurs (à ajouter avant deploy_vez_contract_with_bytecode)
fn calculate_function_selector(function_name: &str) -> u32 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    
    let mut hasher = DefaultHasher::new();
    function_name.hash(&mut hasher);
    (hasher.finish() & 0xFFFFFFFF) as u32
}

/// ✅ ADAPTÉ: Déploiement du contrat VezCurProxy avec bytecode Solidity compilé
async fn deploy_vez_contract_evm(vm: &mut SlurachainVm) -> Result<(), String> {
    use vuc_tx::slurachain_vm::AccountState;
    use sha3::{Digest, Keccak256};
    use std::collections::BTreeMap;

    println!("🪙 [EVM] Déploiement du contrat VEZ (implémentation + proxy)...");

    // 1) Déployer l'implémentation VEZ
    let impl_bytecode_hex = include_str!("../../../vez_bytecode.hex");
    let impl_bytecode = hex::decode(impl_bytecode_hex.trim()).map_err(|e| format!("Bytecode decode error: {}", e))?;

    // Adresse déterministe de l'implémentation
    let mut hasher = Keccak256::new();
    hasher.update(&impl_bytecode);
    let impl_hash = hasher.finalize();
    let impl_address = format!("0x{}", hex::encode(&impl_hash)[..40].to_string()).to_lowercase();

    // Lecture ABI VEZ
    let abi_json = std::fs::read_to_string("VEZABI.json").map_err(|e| format!("VEZABI.json manquant: {}", e))?;
    let abi: serde_json::Value = serde_json::from_str(&abi_json).map_err(|e| format!("VEZABI.json invalide: {}", e))?;

    // Lecture ABI proxy
    let proxy_abi_json = std::fs::read_to_string("vezcurproxycore.json").map_err(|e| format!("vezcurproxycore.json manquant: {}", e))?;
    let proxy_abi: serde_json::Value = serde_json::from_str(&proxy_abi_json).map_err(|e| format!("vezcurproxycore.json invalide: {}", e))?;

    // Fusionne les deux ABI
    let mut full_abi = Vec::new();
    if let Some(arr) = abi.as_array() {
        full_abi.extend(arr.clone());
    }
    if let Some(arr) = proxy_abi.as_array() {
        full_abi.extend(arr.clone());
    }

    // Détection des fonctions pour l'implémentation + proxy
    let mut impl_functions = hashbrown::HashMap::new();
    for item in &full_abi {
        if item.get("type").and_then(|v| v.as_str()) == Some("function") {
            let name = item.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let inputs_vec = item.get("inputs").and_then(|v| v.as_array()).cloned().unwrap_or_else(Vec::new);
            let mut types = Vec::new();
            for inp in &inputs_vec {
                if let Some(t) = inp.get("type").and_then(|v| v.as_str()) {
                    types.push(t.to_string());
                }
            }
            let signature = format!("{}({})", name, types.join(","));
            let mut hasher = Keccak256::new();
            hasher.update(signature.as_bytes());
            let selector_bytes = hasher.finalize();
            let selector = u32::from_be_bytes([selector_bytes[0], selector_bytes[1], selector_bytes[2], selector_bytes[3]]);
            let offset = find_function_offset_in_bytecode(&impl_bytecode, selector).unwrap_or(0);

            impl_functions.insert(name.clone(), vuc_tx::slurachain_vm::FunctionMetadata {
                name,
                offset,
                is_view: item.get("stateMutability").and_then(|v| v.as_str()) == Some("view"),
                args_count: types.len(),
                return_type: item.get("outputs")
                    .and_then(|v| v.as_array())
                    .and_then(|arr| arr.get(0))
                    .and_then(|out| out.get("type"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown")
                    .to_string(),
                gas_limit: 50000,
                payable: item.get("stateMutability").and_then(|v| v.as_str()) == Some("payable"),
                mutability: item.get("stateMutability").and_then(|v| v.as_str()).unwrap_or("nonpayable").to_string(),
                selector,
            });
        }
    }

    
    /// Finds the offset of a function selector in EVM bytecode (looks for PUSH4 + selector pattern).
    fn find_function_offset_in_bytecode(bytecode: &[u8], selector: u32) -> Option<usize> {
        // EVM PUSH4 opcode is 0x63, followed by 4 bytes (the selector)
        let selector_bytes = selector.to_be_bytes();
        let pattern: [u8; 5] = [0x63, selector_bytes[0], selector_bytes[1], selector_bytes[2], selector_bytes[3]];
        bytecode.windows(5).position(|window| window == pattern)
    }

    // Insère l'implémentation dans l'état VM (adresse privée)
    let impl_account = AccountState {
        address: impl_address.clone(),
               balance: 0,
        contract_state: impl_bytecode.clone(),
        resources: BTreeMap::new(),
        state_version: 1,
        last_block_number: 0,
        nonce: 0,
        code_hash: "vez_impl_evm".to_string(),
        storage_root: "vez_impl_root".to_string(),
        is_contract: true,
        gas_used: 0,
    };
    {
        let mut accounts = vm.state.accounts.write().unwrap();
        accounts.insert(impl_address.clone(), impl_account);
    }

    let impl_module = vuc_tx::slurachain_vm::Module {
        name: "VezImpl".to_string(),
        address: impl_address.clone(),
        bytecode: impl_bytecode.clone(),
        elf_buffer: vec![],
        context: uvm_runtime::UbfContext::new(),
        stack_usage: None,
        functions: impl_functions.clone(),
        gas_estimates: hashbrown::HashMap::new(),
        storage_layout: hashbrown::HashMap::new(),
        events: vec![],
        constructor_params: vec![],
    };
    vm.modules.insert(impl_address.clone(), impl_module);

    println!("✅ [EVM] Implémentation VEZ déployée à {}", impl_address);

    // 2) Déployer le proxy ERC1967 à l'adresse publique VEZ
    let proxy_bytecode_hex = include_str!("../../../vezcurpoxycore_bytecode.hex");
    let proxy_bytecode = hex::decode(proxy_bytecode_hex.trim()).map_err(|e| format!("Proxy bytecode decode error: {}", e))?;

    // Adresse proxy = adresse publique VEZ
    let proxy_address = "0xe3cf7102e5f8dfd6ec247daea8ca3e96579e8448".to_string();

    // proxy account : stocke le bytecode et la référence d'implémentation dans resources
    let mut proxy_resources = BTreeMap::new();
    proxy_resources.insert("implementation".to_string(), serde_json::Value::String(impl_address.clone()));
    proxy_resources.insert("initialized".to_string(), serde_json::Value::Bool(false));

    let proxy_account = AccountState {
        address: proxy_address.clone(),
        balance: 0,
        contract_state: proxy_bytecode.clone(), // <-- doit être le vrai bytecode !
        resources: proxy_resources.clone(),
        state_version: 1,
        last_block_number: 0,
        nonce: 0,
        code_hash: "vez_proxy_core".to_string(),
        storage_root: "vez_proxy_root".to_string(),
        is_contract: true,
        gas_used: 0,
    };
    {
        let mut accounts = vm.state.accounts.write().unwrap();
        accounts.insert(proxy_address.clone(), proxy_account);
    }

    // Module proxy : copie les fonctions de l'implémentation pour que la VM trouve les selectors
    let proxy_module = vuc_tx::slurachain_vm::Module {
        name: "VezProxy".to_string(),
        address: proxy_address.clone(),
        bytecode: proxy_bytecode.clone(),
        elf_buffer: vec![],
        context: uvm_runtime::UbfContext::new(),
        stack_usage: None,
        functions: impl_functions, // <--- COPIE des fonctions de l'implémentation
        gas_estimates: hashbrown::HashMap::new(),
        storage_layout: hashbrown::HashMap::new(),
        events: vec![],
        constructor_params: vec!["address".to_string(), "bytes".to_string()],
    };
    vm.modules.insert(proxy_address.clone(), proxy_module);

    // mappe le nom public "vezcur" vers l'adresse proxy
    vm.address_map.insert("vezcur".to_string(), proxy_address.clone());

    println!("✅ [EVM] Proxy VEZ déployé à {} -> impl {}", proxy_address, impl_address);
    println!("   • NOTE: address publique 'vezcur' mapée vers proxy");

    Ok(())
}

/// ✅ NOUVELLE FONCTION: Initialisation du contrat VEZ via execute_module
async fn initialize_vez_contract(vm: &Arc<TokioRwLock<SlurachainVm>>, validator_address: &str) -> Result<(), String> {
    println!("🔧 Initializing VEZ contract via bytecode execution...");

    let vez_contract_address = "0xe3cf7102e5f8dfd6ec247daea8ca3e96579e8448";
    let initial_supply: u128 = 888_000_000_000_000_000_000_000_000u128; // ← 888 millions VEZ
    let initial_holder = validator_address;
    let owner = validator_address;

    // 1. Appel initialize() SANS ARGUMENT
    let init_args = vec![];
    let mut vm_guard = vm.write().await;
    match vm_guard.execute_module(
        vez_contract_address,
        "initialize",
        init_args,
        Some(validator_address)
    ) {
        Ok(result) => {
            println!("✅ VEZ initialize returned: {:?}", result);

            // 2. Appel mint(address,uint256) pour créditer le holder initial
            let mint_args = vec![
                serde_json::Value::String(initial_holder.to_string()),
                serde_json::Value::Number(initial_supply.into()),
            ];
            match vm_guard.execute_module(
                vez_contract_address,
                "mint",
                mint_args,
                Some(validator_address)
            ) {
                Ok(mint_result) => {
                    println!("✅ VEZ mint returned: {:?}", mint_result);

                    // Mise à jour explicite du storage/proxy pour garantir l'effet réel
                    let mut accounts = vm_guard.state.accounts.write().unwrap();
                    if let Some(proxy_acc) = accounts.get_mut(vez_contract_address) {
                        proxy_acc.resources.insert(
                            "total_supply".to_string(),
                            serde_json::Value::Number(serde_json::Number::from(initial_supply)),
                        );
                        proxy_acc.resources.insert(
                            "owner".to_string(),
                            serde_json::Value::String(owner.to_string()),
                        );
                        proxy_acc.resources.insert(
                            "initialized".to_string(),
                            serde_json::Value::Bool(true),
                        );
                        proxy_acc.resources.insert("name".to_string(), serde_json::Value::String("Vyft Enhancing ZER".to_string()));
                        proxy_acc.resources.insert("symbol".to_string(), serde_json::Value::String("VEZ".to_string()));
                        proxy_acc.resources.insert("decimals".to_string(), serde_json::Value::Number(serde_json::Number::from(18)));
                        let holder_key = format!("balance_{}", initial_holder.to_lowercase());
                        proxy_acc.resources.insert(
                            holder_key.clone(),
                            serde_json::Value::Number(serde_json::Number::from(initial_supply)),
                        );

                        // Mise à jour du compte utilisateur
                        let holder_lc = initial_holder.to_lowercase();
                        match accounts.get_mut(&holder_lc) {
                            Some(user_acc) => {
                                user_acc.balance = user_acc.balance.saturating_add(initial_supply as u128);
                                user_acc.resources.insert("supports_vez".to_string(), serde_json::Value::Bool(true));
                            }
                            None => {
                                accounts.insert(
                                    holder_lc.clone(),
                                    vuc_tx::slurachain_vm::AccountState {
                                        address: holder_lc.clone(),
                                        balance: initial_supply as u128,
                                        contract_state: vec![],
                                        resources: {
                                            let mut r = std::collections::BTreeMap::new();
                                            r.insert("created_by".to_string(), serde_json::Value::String("genesis".to_string()));
                                            r.insert("supports_vez".to_string(), serde_json::Value::Bool(true));
                                            r
                                        },
                                        state_version: 1,
                                        last_block_number: 0,
                                        nonce: 0,
                                        code_hash: String::new(),
                                        storage_root: String::new(),
                                        is_contract: false,
                                        gas_used: 0,
                                    }
                                );
                            }
                        }

                        println!("✅ VEZ storage updated on proxy {}: total_supply={}, holder={} credited", vez_contract_address, initial_supply, initial_holder);
                    } else {
                        eprintln!("❌ Proxy account {} not found in VM state", vez_contract_address);
                        return Err(format!("Proxy {} not found", vez_contract_address));
                    }
                }
                Err(e) => {
                    eprintln!("❌ Failed to mint VEZ: {}", e);
                    return Err(e);
                }
            }

            Ok(())
        }
        Err(e) => {
            eprintln!("❌ Failed to initialize VEZ contract via VM: {}", e);
            Err(e)
        }
    }    
}

/// Génère une clé privée secp256k1 et l'associe à l'adresse système aléatoire
pub fn assign_private_key_to_system_account(vm: &mut SlurachainVm) -> Result<String, anyhow::Error> {
    use k256::ecdsa::SigningKey;
    use sha3::{Digest, Keccak256};
    use hex;

    // Charge la clé privée depuis .env
    let validator_privkey = std::env::var("PRIMARY_VALIDATOR_PRIVKEY")?;
    let mut privkey = validator_privkey.clone();
    if privkey.len() % 2 != 0 {
        privkey = format!("0{}", privkey);
    }

    // Calcul de l'adresse Ethereum à partir de la clé privée
    let priv_bytes = hex::decode(&privkey).map_err(|e| anyhow::anyhow!("Invalid privkey hex: {}", e))?;
    use k256::elliptic_curve::generic_array;
    use typenum::U32;
    let priv_bytes_array = generic_array::GenericArray::<u8, U32>::clone_from_slice(&priv_bytes);
    let signing_key = k256::ecdsa::SigningKey::from_bytes(&priv_bytes_array).map_err(|e| anyhow::anyhow!("Invalid privkey: {}", e))?;
    let verifying_key = signing_key.verifying_key();
    let pubkey = verifying_key.to_encoded_point(false);
    let pubkey_bytes = pubkey.as_bytes();
    // Ethereum address = Keccak256(pubkey[1..])[12..]
    let mut hasher = Keccak256::new();
    hasher.update(&pubkey_bytes[1..]);
    let hash = hasher.finalize();
    let eth_address = format!("0x{}", hex::encode(&hash[12..]));

    // Enregistre la clé privée dans le champ resources du compte validateur
    vm.state.accounts.write().unwrap().insert(
        eth_address.clone().to_lowercase(),
        vuc_tx::slurachain_vm::AccountState {
            address: eth_address.clone().to_lowercase(),
            balance: 30_000_000_000_000_000_000_000_000u128,
            contract_state: vec![],
            resources: {
                let mut r = std::collections::BTreeMap::new();
                r.insert("private_key".to_string(), serde_json::Value::String(privkey.clone()));
                r.insert("account_type".to_string(), serde_json::Value::String("validator".to_string()));
                r
            },
            state_version: 0,
            last_block_number: 0,
            nonce: 0,
            code_hash: String::new(),
            storage_root: String::new(),
            is_contract: false,
            gas_used: 0,
        }
    );
    Ok(privkey)
}

/// Détecte les fonctions Solidity dans le bytecode et génère la table des fonctions
fn detect_functions_from_bytecode(bytecode: &[u8]) -> hashbrown::HashMap<String, vuc_tx::slurachain_vm::FunctionMetadata> {
    use sha3::{Digest, Keccak256};
    use std::collections::HashMap;

    let mut functions = hashbrown::HashMap::new();

    // Recherche des sélecteurs de fonction (4 bytes après PUSH4)
    let mut i = 0;
    while i + 4 < bytecode.len() {
        // PUSH4 opcode = 0x63
        if bytecode[i] == 0x63 {
            let selector = u32::from_be_bytes([bytecode[i+1], bytecode[i+2], bytecode[i+3], bytecode[i+4]]);
            // Recherche du nom de la fonction via une table de correspondance ou ABI (à améliorer)
            let name = format!("func_{:08x}", selector);
            functions.insert(name.clone(), vuc_tx::slurachain_vm::FunctionMetadata {
                name,
                offset: i,
                is_view: false, // À améliorer si ABI disponible
                args_count: 0,  // À améliorer si ABI disponible
                return_type: "unknown".to_string(),
                gas_limit: 50000,
                payable: false,
                mutability: "nonpayable".to_string(),
                selector,
            });
            i += 5;
        } else {
            i += 1;
        }
    }

    functions
}

/// Détecte les fonctions Solidity via l'ABI JSON (VEZABI.json à la racine)
fn detect_functions_from_abi_file() -> hashbrown::HashMap<String, vuc_tx::slurachain_vm::FunctionMetadata> {
    use sha3::{Digest, Keccak256};
    use std::fs;
    let abi_json = fs::read_to_string("VEZABI.json").expect("VEZABI.json manquant à la racine");
    let abi: serde_json::Value = serde_json::from_str(&abi_json).expect("VEZABI.json invalide");
    let mut functions = hashbrown::HashMap::new();
    if let Some(items) = abi.as_array() {
        for item in items {
            if item.get("type").and_then(|v| v.as_str()) == Some("function") {
                let name = item.get("name").and_then(|v| v.as_str()).unwrap_or("");
                let inputs_vec = item.get("inputs").and_then(|v| v.as_array()).cloned().unwrap_or_else(Vec::new);
                let mut types = Vec::new();
                for inp in &inputs_vec {
                    if let Some(t) = inp.get("type").and_then(|v| v.as_str()) {
                        types.push(t);
                    }
                }
                let signature = format!("{}({})", name, types.join(","));
                let mut hasher = Keccak256::new();
                hasher.update(signature.as_bytes());
                let selector_bytes = hasher.finalize();
                let selector = u32::from_be_bytes([selector_bytes[0], selector_bytes[1], selector_bytes[2], selector_bytes[3]]);
                functions.insert(name.to_string(), vuc_tx::slurachain_vm::FunctionMetadata {
                    name: name.to_string(),
                    offset: 0,
                    is_view: item.get("stateMutability").and_then(|v| v.as_str()) == Some("view"),
                    args_count: types.len(),
                    return_type: item.get("outputs")
                        .and_then(|v| v.as_array())
                        .and_then(|arr| arr.get(0))
                        .and_then(|out| out.get("type"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown")
                        .to_string(),
                    gas_limit: 50000,
                    payable: item.get("stateMutability").and_then(|v| v.as_str()) == Some("payable"),
                    mutability: item.get("stateMutability").and_then(|v| v.as_str()).unwrap_or("nonpayable").to_string(),
                    selector,
                });
            }
        }
        // try to merge ABI functions if VEZABI.json exists (non-panicking)
        if let Ok(abi_json) = std::fs::read_to_string("VEZABI.json") {
            if let Ok(abi_val) = serde_json::from_str::<serde_json::Value>(&abi_json) {
                if let Some(items) = abi_val.as_array() {
                    let found = items.iter().any(|item| {
                        item.get("type").and_then(|v| v.as_str()) == Some("function")
                            && item.get("name").and_then(|v| v.as_str()) == Some("initialize")
                            && item.get("inputs").and_then(|v| v.as_array()).map(|arr| arr.len() == 3).unwrap_or(false)
                    });
                    if found && !functions.contains_key("initialize") {
                        use sha3::Keccak256;
                        let sig = "initialize(uint256,address,address)";
                        let mut hasher = Keccak256::new();
                        hasher.update(sig.as_bytes());
                        let sel = hasher.finalize();
                        let selector = u32::from_be_bytes([sel[0], sel[1], sel[2], sel[3]]);
                        functions.insert("initialize".to_string(), vuc_tx::slurachain_vm::FunctionMetadata {
                            name: "initialize".to_string(),
                            offset: 0,
                            is_view: false,
                            args_count: 3,
                            return_type: "unknown".to_string(),
                            gas_limit: 200_000,
                            payable: false,
                            mutability: "nonpayable".to_string(),
                            selector,
                        });
                        println!("ℹ️ Added ABI-based 'initialize(uint256,address,address)' function metadata with selector 0x{:08x}", selector);
                    }
                }
            }
        }
    }
    functions
}