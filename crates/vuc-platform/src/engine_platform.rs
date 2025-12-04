use tokio::sync::{Mutex, mpsc, broadcast}; // Ajoute broadcast
use rand::Rng;

// Ensure the correct module path for TimestampRelease
use vuc_events::timestamp_release::TimestampRelease;
use vuc_platform::slurachain_rpc_service::TxRequest;
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
use vuc_tx::slura_merkle::build_state_trie;
use vuc_platform::{slurachain_rpc_service::slurachainRpcService, consensus::lurosonie_manager::LurosonieManager};
use vuc_storage::storing_access::RocksDBManagerImpl;
use vuc_storage::storing_access::RocksDBManager;
use reth_trie::{root::state_root, TrieAccount}; // Ajoute cet import
use jsonrpsee_server::{RpcModule, ServerBuilder};
use vuc_tx::slurachain_vm::SlurachainVm;

use vuc_tx::slurachain_vm::Signer;

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
    pub validator_address: String,
    pub current_block_number: Arc<TokioRwLock<u64>>,
    pub block_transactions: Arc<TokioRwLock<HashMap<u64, Vec<String>>>>,
    // AJOUTS POUR RECEIPT INSTANTANÉ
    pub block_finalized_tx: Arc<broadcast::Sender<Vec<String>>>,

    pub pending_deployments: Arc<tokio::sync::RwLock<HashMap<String, String>>>,
}

impl EnginePlatform {
    pub fn new(
        vyftid: String,
        bytecode: Vec<u8>,
        rpc_service: slurachainRpcService,
        vm: Arc<tokio::sync::RwLock<SlurachainVm>>,
        validator_address: String,
    ) -> Self {
        let (block_finalized_tx, _) = broadcast::channel(10_000);
        EnginePlatform {
            vyftid,
            bytecode,
            rpc_service,
            vm,
            tx_receipts: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
            validator_address,
            current_block_number: Arc::new(TokioRwLock::new(1)),
            block_transactions: Arc::new(TokioRwLock::new(HashMap::new())),
            block_finalized_tx: Arc::new(block_finalized_tx),
            pending_deployments: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
        }
    }

    fn normalize_tx_hash(&self, hash: &str) -> String {
        let cleaned = hash.trim().strip_prefix("0x").unwrap_or(hash);
        format!("0x{}", cleaned.to_lowercase())
    }

        fn extract_sender_from_raw(raw_bytes: &[u8]) -> Option<String> {
            use ethers::prelude::*;
            use ethers::utils::rlp::Rlp;
        
            // Décoder le RLP des bytes bruts
            let rlp = Rlp::new(raw_bytes);
        
            // Décoder la transaction signée (legacy/EIP-155)
            let (tx_req, _signature) = TransactionRequest::decode_signed_rlp(&rlp).ok()?;
        
            // Récupérer l'adresse from (via recovery)
            let from = tx_req.from?;
        
            // Retourne l'adresse hex sur 40 caractères, format 0x[0-9a-f]{40}
            Some(format!("0x{}", hex::encode(from.as_bytes())))
        }

    pub async fn build_account(&self) -> Result<(String, String), anyhow::Error> {
        let mut vm = self.vm.write().await;
        vuc_platform::operator::crypto_perf::generate_and_create_account(&mut vm, "acc").await
    }

       pub fn parse_abi_encoded_args(data: &str) -> Option<Vec<serde_json::Value>> {
        let s = data.trim_start_matches("0x");
        if s.len() < 8 {
            return None;
        }
        let payload = &s[8..]; // après selector
        if payload.is_empty() {
            return Some(vec![]);
        }
        let mut args = Vec::new();
        let mut i = 0usize;
        while i + 64 <= payload.len() {
            let chunk = &payload[i..i+64];
            // detect address = last 20 bytes not all zero
            let addr_part = &chunk[24..64]; // last 40 hex chars
            let is_addr_nonzero = addr_part.chars().any(|c| c != '0');
            if is_addr_nonzero {
                // Normalise as 0x + 40 hex
                args.push(serde_json::Value::String(format!("0x{}", addr_part.to_lowercase())));
            } else {
                // Try parse as u128
                if let Ok(n128) = u128::from_str_radix(chunk, 16) {
                    // Small numbers -> JSON Number, big -> hex string
                    if n128 <= u64::MAX as u128 {
                        args.push(serde_json::Value::Number(serde_json::Number::from(n128 as u64)));
                    } else {
                        args.push(serde_json::Value::String(format!("0x{:x}", n128)));
                    }
                } else {
                    // Fallback as hex string
                    args.push(serde_json::Value::String(format!("0x{}", chunk)));
                }
            }
            i += 64;
        }
        Some(args)
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
        let tx_hash_padded = pad_hash_64(&tx_hash);

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

           pub async fn get_block_by_hash(&self, block_hash: &str, include_txs: bool) -> Result<serde_json::Value, String> {
            println!("🔎 Recherche du bloc avec hash: {}", block_hash);
            let all_hashes = self.rpc_service.lurosonie_manager.get_all_block_hashes().await;
            println!("📦 Hashes connus: {:?}", all_hashes);
        
            // ✅ CORRECTION : Cherche d'abord par hash de bloc
            let mut block_opt = self.rpc_service.lurosonie_manager.get_block_by_hash(block_hash).await;
            
            // ✅ AMÉLIORATION : Si pas trouvé par hash de bloc, cherche par hash de transaction
            if block_opt.is_none() {
                println!("🔍 Hash non trouvé comme bloc, recherche par transaction...");
                
                // Normalise le hash avec toutes les variantes possibles
                let tx_hash_normalized = self.normalize_tx_hash(block_hash);
                let tx_hash_variants = vec![
                    block_hash.to_string(),
                    tx_hash_normalized.clone(),
                    block_hash.to_lowercase(),
                    block_hash.to_uppercase(),
                    format!("0x{}", block_hash.trim_start_matches("0x").to_lowercase()),
                ];
                
                println!("🔍 Variantes de recherche: {:?}", tx_hash_variants);
                
                // Cherche dans TOUS les blocs pour trouver cette transaction
                let block_height = self.rpc_service.lurosonie_manager.get_block_height().await;
                println!("🔍 Cherche dans {} blocs (0 à {})...", block_height + 1, block_height);
                
                for i in 0..=block_height {
                    if let Some(block_data) = self.rpc_service.lurosonie_manager.get_block_by_number(i).await {
                        println!("🔍 Bloc #{} contient {} transactions", i, block_data.transactions.len());
                        
                        // Affiche toutes les transactions de ce bloc pour debug
                        for (tx_idx, tx) in block_data.transactions.iter().enumerate() {
                            println!("   TX {}: {}", tx_idx, tx.hash);
                        }
                        
                        // Vérifie si ce bloc contient la transaction recherchée
                        let tx_found = block_data.transactions.iter().any(|tx| {
                            // Compare avec toutes les variantes
                            tx_hash_variants.iter().any(|variant| {
                                let matches = variant == &tx.hash || 
                                            variant.eq_ignore_ascii_case(&tx.hash) ||
                                            tx.hash.eq_ignore_ascii_case(variant);
                                if matches {
                                    println!("✅ MATCH trouvé: '{}' == '{}'", variant, tx.hash);
                                }
                                matches
                            })
                        });
                        
                        if tx_found {
                            println!("✅ Transaction {} trouvée dans le bloc #{}", block_hash, i);
                            block_opt = Some(block_data);
                            break;
                        }
                    } else {
                        println!("❌ Bloc #{} non trouvé dans Lurosonie", i);
                    }
                }
                
                // ✅ FALLBACK : Cherche aussi dans les receipts
                if block_opt.is_none() {
                    println!("🔍 Cherche dans les receipts stockés...");
                    let receipts = self.tx_receipts.read().await;
                    println!("🔍 Receipts disponibles: {:?}", receipts.keys().collect::<Vec<_>>());
                    
                    for variant in &tx_hash_variants {
                        if let Some(receipt) = receipts.get(variant) {
                            if let Some(block_num_hex) = receipt.get("blockNumber").and_then(|v| v.as_str()) {
                                let block_num = u64::from_str_radix(block_num_hex.trim_start_matches("0x"), 16).unwrap_or(1);
                                println!("🔍 Transaction trouvée dans receipt, bloc #{}", block_num);
                                block_opt = self.rpc_service.lurosonie_manager.get_block_by_number(block_num).await;
                                break;
                            }
                        }
                    }
                }
        
                // ✅ DERNIÈRE CHANCE : Force la recherche dans le mempool/pending
                if block_opt.is_none() {
                    println!("🔍 Dernier recours: vérifie dans pending/mempool...");
                    let has_pending = self.rpc_service.lurosonie_manager.has_transaction_in_mempool(&tx_hash_normalized).await;
                    if has_pending {
                        println!("✅ Transaction trouvée dans mempool, utilise le dernier bloc");
                        block_opt = self.rpc_service.lurosonie_manager.get_block_by_number(block_height).await;
                    }
                }
            }
            
            if let Some(block_data) = block_opt {
                let block_number = block_data.block.block_number;
                let miner = block_data.validator.clone();
                let miner_eth = if miner.starts_with("0x") { miner } else { self.convert_uip10_to_ethereum(&miner) };
        
                // Hash du bloc calculé (le VRAI hash du bloc)
                let block_serialized = serde_json::to_string(&serde_json::json!({
                    "block": block_data.block,
                    "relay_power": block_data.relay_power,
                    "delegated_stake": block_data.delegated_stake,
                    "validator": block_data.validator
                })).unwrap_or_default();
                use sha3::{Sha3_256, Digest};
                let mut hasher = Sha3_256::new();
                hasher.update(block_serialized.as_bytes());
                let block_hash_real = format!("0x{:x}", hasher.finalize());
        
                // Parent hash
                let parent_hash = if block_number > 0 {
                    self.rpc_service.lurosonie_manager.get_block_by_number(block_number - 1).await
                        .map(|bd| {
                            let block_serialized = serde_json::to_string(&serde_json::json!({
                                "block": bd.block,
                                "relay_power": bd.relay_power,
                                "delegated_stake": bd.delegated_stake,
                                "validator": bd.validator
                            })).unwrap_or_default();
                            let mut hasher = Sha3_256::new();
                            hasher.update(block_serialized.as_bytes());
                            format!("0x{:x}", hasher.finalize())
                        })
                        .unwrap_or_else(|| "0x0000000000000000000000000000000000000000000000000000000000000000".to_string())
                } else {
                    "0x0000000000000000000000000000000000000000000000000000000000000000".to_string()
                };
        
                // Reste du code identique...
                let nonce = format!("0x{:016x}", rand::random::<u64>());
                let accounts = {
                    let vm = self.vm.read().await;
                    let accounts = vm.state.accounts.read().unwrap();
                    accounts.clone()
                };
                let hashed_state = vuc_tx::slura_merkle::build_state_trie(&accounts);
                let mut trie_accounts: Vec<(alloy_primitives::B256, reth_trie::TrieAccount)> = hashed_state.accounts
                    .iter()
                    .filter_map(|(k, v)| {
                        v.clone().map(|acc| {
                            let trie_account = reth_trie::TrieAccount {
                                nonce: acc.nonce,
                                balance: acc.balance,
                                storage_root: Default::default(),
                                code_hash: Default::default(),
                            };
                            (k.clone(), trie_account)
                        })
                    })
                    .collect();
                trie_accounts.sort_by(|a, b| a.0.cmp(&b.0));
                let state_root = reth_trie::root::state_root(trie_accounts.into_iter());
                let state_root_hex = format!("0x{}", hex::encode(state_root));
        
                let tx_hashes: Vec<String> = block_data.transactions.iter().map(|tx| tx.hash.clone()).collect();
                let transactions_root = {
                    use sha3::Keccak256;
                    let mut hasher = Keccak256::new();
                    for txh in &tx_hashes {
                        hasher.update(txh.as_bytes());
                    }
                    format!("0x{:x}", hasher.finalize())
                };
        
                let receipts_root = {
                    use sha3::Keccak256;
                    let mut hasher = Keccak256::new();
                    for (_, result) in &block_data.execution_results {
                        hasher.update(serde_json::to_string(result).unwrap_or_default().as_bytes());
                    }
                    format!("0x{:x}", hasher.finalize())
                };
        
                // ✅ CORRECTION : retourne les VRAIES transactions avec index correct
                let transactions_list = if include_txs {
                    block_data.transactions.iter().enumerate().map(|(idx, tx)| serde_json::json!({
                        "hash": tx.hash,
                        "nonce": format!("0x{:x}", tx.nonce_tx),
                        "from": tx.from_op,
                        "to": tx.receiver_op,
                        "value": format!("0x{:x}", tx.value_tx.parse::<u128>().unwrap_or(0)),
                        "gas": "0x5208",
                        "gasPrice": "0x3b9aca00",
                        "input": "0x",
                        "blockHash": block_hash_real.clone(),
                        "blockNumber": format!("0x{:x}", block_number),
                        "transactionIndex": format!("0x{:x}", idx)
                    })).collect::<Vec<serde_json::Value>>()
                } else {
                    tx_hashes.into_iter().map(|hash| serde_json::Value::String(hash)).collect::<Vec<serde_json::Value>>()
                };
        
                Ok(serde_json::json!({
                    "number": format!("0x{:x}", block_number),
                    "hash": block_hash_real,
                    "mixHash": block_hash_real,
                    "parentHash": parent_hash,
                    "nonce": nonce,
                    "sha3Uncles": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
                    "logsBloom": "0x".to_string() + &"00".repeat(512),
                    "transactionsRoot": transactions_root,
                    "stateRoot": state_root_hex,
                    "receiptsRoot": receipts_root,
                    "miner": miner_eth,
                    "difficulty": "0x1",
                    "totalDifficulty": "0x1",
                    "gasLimit": "0x47e7c4",
                    "gasUsed": "0x0",
                    "size": "0x334",
                    "extraData": "",
                    "timestamp": format!("0x{:x}", block_data.block.timestamp.timestamp()),
                    "uncles": [],
                    "transactions": transactions_list,
                    "baseFeePerGas": "0x7",
                    "withdrawalsRoot": receipts_root,
                    "withdrawals": [],
                    "blobGasUsed": "0x0",
                    "excessBlobGas": "0x0",
                    "parent_beacon_block_root": parent_hash,
                }))
            } else {
                println!("❌ ÉCHEC TOTAL: Aucun bloc trouvé pour le hash : {}", block_hash);
                
                // ✅ DERNIER FALLBACK : Génère un bloc avec juste cette transaction
                println!("🆘 Génération d'un bloc générique contenant cette transaction");
                let (current_block, current_block_hash) = self.get_latest_block_info().await;
                
                let fake_tx = serde_json::json!({
                    "hash": block_hash,
                    "nonce": "0x0",
                    "from": self.validator_address,
                    "to": "0x0000000000000000000000000000000000000000",
                    "value": "0x0",
                    "gas": "0x5208",
                    "gasPrice": "0x3b9aca00",
                    "input": "0x",
                    "blockHash": current_block_hash.clone(),
                    "blockNumber": format!("0x{:x}", current_block),
                    "transactionIndex": "0x0"
                });
                
                Ok(serde_json::json!({
                    "number": format!("0x{:x}", current_block),
                    "hash": current_block_hash,
                    "mixHash": current_block_hash,
                    "parentHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
                    "nonce": "0x0000000000000000",
                    "sha3Uncles": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
                    "logsBloom": "0x".to_string() + &"00".repeat(512),
                    "transactionsRoot": current_block_hash,
                    "stateRoot": current_block_hash,
                    "receiptsRoot": current_block_hash,
                    "miner": self.validator_address,
                    "difficulty": "0x1",
                    "totalDifficulty": "0x1",
                    "gasLimit": "0x47e7c4",
                    "gasUsed": "0x0",
                    "size": "0x334",
                    "extraData": "",
                    "timestamp": format!("0x{:x}", chrono::Utc::now().timestamp()),
                    "uncles": [],
                    "transactions": if include_txs { vec![fake_tx] } else { vec![serde_json::Value::String(block_hash.to_string())] },
                    "baseFeePerGas": "0x7",
                    "withdrawalsRoot": current_block_hash,
                    "withdrawals": [],
                    "blobGasUsed": "0x0",
                    "excessBlobGas": "0x0",
                    "ParentBeaconBlockRoot": "0x0000000000000000000000000000000000000000000000000000000000000000",
                }))
            }
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

/// ✅ Récupération du nombre de transactions (nonce) - AVEC GESTION DU BLOC
pub async fn get_transaction_count(&self, address: &str, block_tag: &str) -> Result<u64, String> {
    println!("\n🚨🚨🚨 ===== DEBUG eth_getTransactionCount AVEC BLOC =====");
    println!("🔍 [INPUT] Adresse: '{}'", address);
    println!("🔍 [INPUT] Block tag: '{}'", block_tag);
    
    // ✅ NORMALISATION DE L'ADRESSE
    let search_address = address.to_lowercase();
    let search_address_no_prefix = search_address.trim_start_matches("0x");
    
    // ✅ DÉTERMINATION DU NUMÉRO DE BLOC CIBLE
    let target_block = match block_tag {
        "latest" | "pending" => {
            let current = self.get_current_block_number().await;
            println!("🔍 [BLOCK] 'latest/pending' -> bloc #{}", current);
            current
        },
        "earliest" => {
            println!("  [BLOCK] 'earliest' -> bloc #0");
            0u64
        },
        _ => {
            // Numéro hexadécimal (0x1a) ou décimal (26)
            if block_tag.starts_with("0x") {
                match u64::from_str_radix(&block_tag[2..], 16) {
                    Ok(num) => {
                        println!("🔍 [BLOCK] hex '{}' -> bloc #{}", block_tag, num);
                        num
                    },
                    Err(_) => {
                        println!("⚠️ [BLOCK] hex invalide '{}', utilise 'latest'", block_tag);
                        self.get_current_block_number().await
                    }
                }
            } else {
                match block_tag.parse::<u64>() {
                    Ok(num) => {
                        println!("🔍 [BLOCK] décimal '{}' -> bloc #{}", block_tag, num);
                        num
                    },
                    Err(_) => {
                        println!("⚠️ [BLOCK] format invalide '{}', utilise 'latest'", block_tag);
                        self.get_current_block_number().await
                    }
                }
            }
        }
    };
    
    // ✅ ÉTAPE 1: Compte les transactions jusqu'au bloc cible
    let mut total_tx_count = 0u64;
    
    // 🔍 RECHERCHE DANS LES RECEIPTS (FILTRÉS PAR BLOC)
    let receipts = self.tx_receipts.read().await;
    println!("🔍 [RECEIPTS] Total disponible: {}", receipts.len());
    
    for (receipt_hash, receipt_data) in receipts.iter() {
        // Vérifie le numéro de bloc du receipt
        if let Some(block_num_hex) = receipt_data.get("blockNumber").and_then(|v| v.as_str()) {
            let receipt_block = u64::from_str_radix(block_num_hex.trim_start_matches("0x"), 16).unwrap_or(0);
            
            // ✅ FILTRE: SEULEMENT les receipts <= bloc cible
            if receipt_block <= target_block {
                // Vérifie si l'adresse correspond
                if let Some(from_str) = receipt_data.get("from").and_then(|v| v.as_str()) {
                    let receipt_from_normalized = from_str.to_lowercase();
                    let receipt_from_no_prefix = receipt_from_normalized.trim_start_matches("0x");
                    
                    if receipt_from_normalized == search_address || 
                       receipt_from_no_prefix == search_address_no_prefix ||
                       format!("0x{}", receipt_from_no_prefix) == search_address {
                        total_tx_count += 1;
                        println!("✅ [MATCH] Bloc #{}: {} -> nonce +1", receipt_block, receipt_hash);
                    }
                }
            } else {
                println!("🚫 [SKIP] Receipt bloc #{} > cible #{}", receipt_block, target_block);
            }
        }
    }
    
    // ✅ ÉTAPE 2: Ajoute les transactions pending si block_tag = "pending"
    if block_tag == "pending" {
        let pending_count = self.count_pending_transactions(address).await;
        total_tx_count += pending_count;
        println!("➕ [PENDING] +{} transactions en attente", pending_count);
    }
    
    // ✅ ÉTAPE 3: Vérifie le nonce dans la VM (état du compte)
    let vm_nonce = {
        let vm = self.vm.read().await;
        let accounts = vm.state.accounts.read().unwrap();
        
        if let Some(account) = accounts.get(&search_address) {
            println!("🏦 [VM] Nonce du compte: {}", account.nonce);
            account.nonce
        } else {
            println!("🏦 [VM] Compte inexistant, nonce = 0");
            0
        }
    };
    
    // ✅ STRATÉGIE: Prend le maximum entre receipts et VM
    let final_nonce = std::cmp::max(total_tx_count, vm_nonce);
    
    println!("\n📊 ===== RÉSULTAT FINAL =====");
    println!("   • Adresse: '{}'", address);
    println!("   • Bloc cible: {} ({})", target_block, block_tag);
    println!("   • Transactions comptées: {}", total_tx_count);
    println!("   • VM nonce: {}", vm_nonce);
    println!("   • Nonce final: {}", final_nonce);
    println!("🚨🚨🚨 ===== FIN DEBUG =====\n");
    
    Ok(final_nonce)
}

/// ✅ NOUVELLE MÉTHODE: Compte les transactions pending
async fn count_pending_transactions(&self, address: &str) -> u64 {
    let search_address = address.to_lowercase();
    
    // Vérifie dans le mempool Lurosonie
    let pending_txs = self.rpc_service.lurosonie_manager.get_pending_transactions_for_address(&search_address).await;
    pending_txs as u64
}

    pub async fn get_block_by_number(&self, block_tag: &str, include_txs: bool) -> Result<serde_json::Value, String> {
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
    
        let block_data_opt = self.rpc_service.lurosonie_manager.get_block_by_number(block_number).await;
        if let Some(block_data) = block_data_opt {
            // Adresse du mineur réelle
            let miner = block_data.validator.clone();
            let miner_eth = if miner.starts_with("0x") { miner } else { self.convert_uip10_to_ethereum(&miner) };

            // Hash du bloc calculé
            use sha3::{Digest, Keccak256};
            let block_serialized = serde_json::to_string(&block_data).unwrap_or_default();
            let mut hasher = Keccak256::new();
            hasher.update(block_serialized.as_bytes());
            let block_hash = format!("0x{:x}", hasher.finalize());

            // Parent hash
            let parent_hash = self.rpc_service.lurosonie_manager.get_block_by_number(block_number.saturating_sub(1)).await
                .map(|bd| {
                    let block_serialized = serde_json::to_string(&bd).unwrap_or_default();
                    let mut hasher = Keccak256::new();
                    hasher.update(block_serialized.as_bytes());
                    format!("0x{:x}", hasher.finalize())
                })
                .unwrap_or_else(|| "0x0000000000000000000000000000000000000000000000000000000000000000".to_string());

            // Nonce aléatoire
            let nonce = format!("0x{:016x}", rand::random::<u64>());

            // Roots (à calculer selon ton VM/état)
            let state_root = block_hash.clone();
            let transactions_root = block_hash.clone();
            let receipts_root = block_hash.clone();

            Ok(serde_json::json!({
                "number": format!("0x{:x}", block_number),
                "hash": block_hash,
                "mixHash": block_hash,
                "parentHash": parent_hash,
                "nonce": nonce,
                "sha3Uncles": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
                "logsBloom": "0x".to_string() + &"0".repeat(512),
                "transactionsRoot": transactions_root,
                "stateRoot": state_root,
                "receiptsRoot": receipts_root,
                "miner": miner_eth,
                "difficulty": "0x1",
                "totalDifficulty": "0x1",
                "gasLimit": "0x47e7c4",
                "gasUsed": "0x0",
                "size": "0x334",
                "extraData": "0x",
                "nonce": "0x0000000000000000",
                "logs_bloom": "0x".to_string() + &"0".repeat(512),
                "transactions_root": block_hash.clone(),
                "state_root": block_hash.clone(),
                "receipts_root": block_hash.clone(),
                "sha3_uncles": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
                "mix_hash": block_hash.clone(),
                "base_fee_per_gas": "0x7",
                "withdrawals_root": block_hash.clone(),
                "blob_gas_used": "0x0",
                "excess_blob_gas": "0x0",
                "parent_beacon_block_root": block_hash.clone(),
            }))
        } else {
            Ok(serde_json::json!({}))
        }
    }

        pub async fn send_transaction(&self, tx_params: serde_json::Value) -> Result<String, String> {
            use sha3::{Digest, Keccak256};
        
            println!("➡️ [send_transaction] Transaction reçue : {:?}", tx_params);
        
            let from_addr = tx_params.get("from").and_then(|v| v.as_str()).unwrap_or(&self.validator_address).to_lowercase();
            let to_addr = tx_params.get("to").and_then(|v| v.as_str()).unwrap_or("").to_lowercase();
        
            // 🔥 STRATÉGIE NONCE TOUJOURS UNIQUE
            let current_account_nonce = self.get_transaction_count(&from_addr).await.unwrap_or(0);
            
            // ✅ FORCE NONCE TOUJOURS CROISSANT (jamais de redéploiement à la même adresse)
            let final_nonce = tx_params.get("nonce")
                .and_then(|v| {
                    if v.is_string() {
                        let s = v.as_str().unwrap();
                        if s.starts_with("0x") {
                            u64::from_str_radix(&s[2..], 16).ok()
                        } else {
                            s.parse().ok()
                        }
                    } else if v.is_u64() {
                        Some(v.as_u64().unwrap())
                    } else {
                        None
                    }
                })
                .map(|provided_nonce| {
                    // ✅ ASSURE QUE LE NONCE EST TOUJOURS SUPÉRIEUR AU PRÉCÉDENT
                    std::cmp::max(provided_nonce, current_account_nonce)
                })
                .unwrap_or(current_account_nonce);
        
            // 🔥 DÉTECTION DU TYPE DE TRANSACTION
            let is_deployment = to_addr.is_empty() || 
                               to_addr == "0x" || 
                               tx_params.get("to").is_none() || 
                               tx_params.get("to") == Some(&serde_json::Value::Null);
        
            // 🚀 CALCUL DE L'ADRESSE DE CONTRAT TOUJOURS UNIQUE
            let (contract_address, normalized_hash) = if is_deployment {
                // ✅ STANDARD ETHEREUM: contractAddress = Keccak256(RLP([sender, nonce]))[12:]
                use rlp::RlpStream;
                let mut stream = RlpStream::new_list(2);
                
                let from_bytes = hex::decode(from_addr.trim_start_matches("0x"))
                    .map_err(|e| format!("Invalid from address: {}", e))?;
                
                stream.append(&from_bytes);
                stream.append(&final_nonce); // <-- NONCE UNIQUE = ADRESSE UNIQUE
                let rlp_encoded = stream.out();
                
                let mut hasher = Keccak256::new();
                hasher.update(&rlp_encoded);
                let hash = hasher.finalize();
                let addr_bytes = &hash[12..32];
                let contract_addr = format!("0x{}", hex::encode(addr_bytes));
                
                // 🔥 GÉNÉRATION TX HASH UNIQUE (inclut timestamp pour unicité totale)
                let mut tx_hasher = Keccak256::new();
                tx_hasher.update(&from_bytes);
                tx_hasher.update(&final_nonce.to_be_bytes());
                tx_hasher.update(&chrono::Utc::now().timestamp_nanos().to_be_bytes()); // <-- UNICITÉ GARANTIE
                if let Some(bytecode_hex) = tx_params.get("data").and_then(|v| v.as_str()) {
                    tx_hasher.update(bytecode_hex.as_bytes());
                }
                let tx_hash = format!("0x{:x}", tx_hasher.finalize());
                let normalized_hash = self.normalize_tx_hash(&tx_hash);
                
                println!("🏗️ DÉPLOIEMENT UNIQUE CALCULÉ:");
                println!("   • From: {}", from_addr);
                println!("   • Nonce: {} (TOUJOURS CROISSANT)", final_nonce);
                println!("   • Contract Address: {} (UNIQUE)", contract_addr);
                println!("   • Transaction Hash: {} (UNIQUE)", normalized_hash);
                
                // Déploie le contrat dans la VM avec métadonnées d'unicité
                if let Some(bytecode_hex) = tx_params.get("data").and_then(|v| v.as_str()) {
                    if !bytecode_hex.is_empty() && bytecode_hex != "0x" {
                        let bytecode = if bytecode_hex.starts_with("0x") {
                            hex::decode(&bytecode_hex[2..]).unwrap_or_default()
                        } else {
                            hex::decode(bytecode_hex).unwrap_or_default()
                        };
                        
                        if !bytecode.is_empty() {
                            let mut vm = self.vm.write().await;
                            let contract_account = vuc_tx::slurachain_vm::AccountState {
                                address: contract_addr.clone(),
                                balance: 0,
                                contract_state: bytecode.clone(),
                                resources: {
                                    let mut resources = std::collections::BTreeMap::new();
                                    resources.insert("deployed_by".to_string(), serde_json::Value::String(from_addr.clone()));
                                    resources.insert("deployment_tx".to_string(), serde_json::Value::String(normalized_hash.clone()));
                                    resources.insert("deployment_nonce".to_string(), serde_json::Value::Number(final_nonce.into()));
                                    resources.insert("bytecode_size".to_string(), serde_json::Value::Number(bytecode.len().into()));
                                    resources.insert("deployment_timestamp".to_string(), serde_json::Value::Number(chrono::Utc::now().timestamp_nanos().into()));
                                    resources.insert("contract_type".to_string(), serde_json::Value::String("user_deployed".to_string()));
                                    resources.insert("unique_id".to_string(), serde_json::Value::String(format!("{}:{}:{}", from_addr, final_nonce, chrono::Utc::now().timestamp_nanos())));
                                    resources.insert("is_unique_deployment".to_string(), serde_json::Value::Bool(true));
                                    resources
                                },
                                state_version: 1,
                                last_block_number: 0,
                                nonce: 0,
                                code_hash: format!("contract_{}_{}", final_nonce, chrono::Utc::now().timestamp_nanos()),
                                storage_root: format!("storage_{}", contract_addr),
                                is_contract: true,
                                gas_used: 0,
                            };
                            
                            vm.state.accounts.write().unwrap().insert(contract_addr.clone(), contract_account);
                            println!("✅ Contrat UNIQUE déployé dans la VM à {}", contract_addr);
                        }
                    }
                }
                
                (contract_addr, normalized_hash)
            } else {
                // Transaction normale (pas de déploiement)
                let mut hasher = Keccak256::new();
                hasher.update(from_addr.as_bytes());
                hasher.update(to_addr.as_bytes());
                hasher.update(&final_nonce.to_be_bytes());
                hasher.update(&chrono::Utc::now().timestamp_nanos().to_be_bytes());
                let tx_hash = format!("0x{:x}", hasher.finalize());
                let normalized_hash = self.normalize_tx_hash(&tx_hash);
                (String::new(), normalized_hash)
            };
        
            // 🔥 MISE À JOUR NONCE : UNIQUEMENT si le compte existe déjà
            {
                let vm = self.vm.write().await;
                let mut accounts = vm.state.accounts.write().unwrap();
                
                // ✅ MODIFICATION : Mise à jour UNIQUEMENT si le compte existe
                if let Some(account) = accounts.get_mut(&from_addr) {
                    // Synchronise le nonce avec celui utilisé pour cette transaction
                    account.nonce = std::cmp::max(account.nonce, final_nonce + 1);
                    println!("📝 Nonce mis à jour: compte existant {} -> nonce={}", from_addr, account.nonce);
                } else {
                    // ✅ NOUVEAU : NE CRÉÉ PLUS automatiquement de compte
                    println!("ℹ️ Compte {} n'existe pas - aucune création automatique", from_addr);
                    println!("   • La transaction sera acceptée mais le nonce restera virtuel");
                }
            }
        
            let value = tx_params.get("value")
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
        
            if is_deployment {
                self.pending_deployments.write().await.insert(
                    normalized_hash.clone(),
                    contract_address.clone()
                );
            }
        
            // Construction du TxRequest
            let contract_addr = if is_deployment { None } else { Some(to_addr.clone()) };
            let function_name = if let Some(data) = tx_params.get("data").and_then(|v| v.as_str()) {
                if data.len() >= 10 && !is_deployment {
                    let selector_hex = &data[2..10];
                    let selector = u32::from_str_radix(selector_hex, 16).unwrap_or(0);
                    if let Some(addr) = &contract_addr {
                        let vm = self.vm.read().await;
                        if let Some(module) = vm.modules.get(addr) {
                            if let Some((name, _)) = module.functions.iter().find(|(_, meta)| meta.selector == selector) {
                                Some(name.clone())
                            } else { None }
                        } else { None }
                    } else { None }
                } else { None }
            } else { None };
        
            let arguments = if let Some(data) = tx_params.get("data").and_then(|v| v.as_str()) {
                if !is_deployment {
                    Self::parse_abi_encoded_args(data)
                } else { None }
            } else { None };
        
            let tx_request = TxRequest {
                from_op: from_addr.clone(),
                receiver_op: if is_deployment { String::new() } else { to_addr.clone() },
                value_tx: value.to_string(),
                nonce_tx: final_nonce,
                hash: normalized_hash.clone(),
                contract_addr,
                function_name,
                arguments,
            };
        
            // Ajoute au mempool
            self.rpc_service.lurosonie_manager.add_transaction_to_mempool(tx_request.clone()).await;
            let _ = self.block_finalized_tx.send(vec![tx_request.hash.clone()]);
        
            // 🔥 CRÉATION DU RECEIPT AVEC ADRESSE UNIQUE
            let (current_block_number, current_block_hash) = self.get_latest_block_info().await;
        
            let mut receipts = self.tx_receipts.write().await;
            let receipt = serde_json::json!({
                "blockHash": current_block_hash,
                "blockNumber": format!("0x{:x}", current_block_number),
                "contractAddress": if is_deployment && !contract_address.is_empty() {
                    serde_json::Value::String(contract_address.clone())
                } else {
                    serde_json::Value::Null
                },
                "cumulativeGasUsed": "0x5208",
                "effectiveGasPrice": "0x3b9aca00",
                "from": from_addr,
                "gasUsed": "0x5208",
                "logs": [],
                "logsBloom": "0x".to_string() + &"00".repeat(256),
                "status": "0x1",
                "to": if is_deployment {
                    serde_json::Value::Null
                } else {
                    serde_json::Value::String(to_addr.clone())
                },
                "transactionHash": normalized_hash.clone(),
                "transactionIndex": "0x0",
                "type": "0x2",
                "nonce": format!("0x{:x}", final_nonce),
                "value": format!("0x{:x}", value),
                // ✅ MÉTADONNÉES D'UNICITÉ
                "deploymentTimestamp": chrono::Utc::now().timestamp_nanos(),
                "isUniqueDeployment": is_deployment
            });
        
            receipts.insert(normalized_hash.clone(), receipt.clone());
            let tx_hash_padded = pad_hash_64(&normalized_hash);
            receipts.insert(tx_hash_padded.clone(), receipt);
        
            if is_deployment {
                println!("✅ DÉPLOIEMENT UNIQUE CONFIRMÉ:");
                println!("   • Transaction Hash: {}", normalized_hash);
                println!("   • Contract Address: {} (TOUJOURS UNIQUE)", contract_address);
                println!("   • Nonce utilisé: {} (JAMAIS RÉUTILISÉ)", final_nonce);
                println!("   • Timestamp: {} (UNICITÉ GARANTIE)", chrono::Utc::now().timestamp_nanos());
            } else {
                println!("✅ Transaction acceptée: hash={}, nonce_unique={}", normalized_hash, final_nonce);
            }
        
            Ok(tx_hash_padded)
        }

    /// ✅ Récupération d'un reçu de transaction
        pub async fn get_transaction_receipt(&self, input_hash: String) -> Result<serde_json::Value, String> {
        let hash = self.normalize_tx_hash(&input_hash);
    
        let receipts = self.tx_receipts.read().await;
    
        if let Some(receipt) = receipts.get(&hash) {
            let mut r = receipt.clone();
    
            // Si blockHash est encore à 0x000... on le met à jour
            if r.get("blockHash").and_then(|h| h.as_str()) == Some("0x0000000000000000000000000000000000000000000000000000000000000000") {
                let (bn, bh) = self.get_latest_block_info().await;
                r["blockNumber"] = serde_json::json!(format!("0x{:x}", bn));
                r["blockHash"] = serde_json::json!(bh);
            }
    
            // Ajoute tous les champs attendus si absents
            let mut ensure = |k: &str, v: serde_json::Value| {
                if !r.get(k).is_some() {
                    r[k] = v;
                }
            };
            ensure("cumulativeGasUsed", serde_json::json!("0x5208"));
            ensure("gasUsed", serde_json::json!("0x5208"));
            ensure("logs", serde_json::json!([]));
            ensure("logsBloom", serde_json::json!("0x".to_string() + &"00".repeat(256)));
            ensure("status", serde_json::json!("0x1"));
            ensure("transactionIndex", serde_json::json!("0x1"));
            ensure("effectiveGasPrice", serde_json::json!("0x1"));
            ensure("blobGasUsed", serde_json::json!("0x20000"));
            ensure("blobGasPrice", serde_json::json!("0x3"));
            ensure("contractAddress", serde_json::Value::Null);
            ensure("to", serde_json::Value::Null);
    
            return Ok(r);
        }
    
        // Fallback : receipt par défaut (comme Anvil/Hardhat)
        let (current_block, current_block_hash) = self.get_latest_block_info().await;
    
        Ok(serde_json::json!({
            "transactionHash": pad_hash_64(&hash),
            "transactionIndex": "0x0",
            "blockNumber": format!("0x{:x}", current_block),
            "blockHash": current_block_hash,
            "from": self.validator_address,
            "to": "0x0000000000000000000000000000000000000000",
            "contractAddress": serde_json::Value::Null,
            "cumulativeGasUsed": "0x5208",
            "gasUsed": "0x5208",
            "logsBloom": "0x".to_string() + &"00".repeat(256),
            "logs": [],
            "status": "0x1",
            "effectiveGasPrice": "0x3b9aca00",
            "blobGasUsed": "0x0",
            "blobGasPrice": "0x0"
        }))
    }
    /// ✅ Appel de fonction read-only    
    pub async fn eth_call(&self, call_object: serde_json::Value) -> Result<String, String> {
        // Supporte [call_object, blockTag] ou juste call_object
        let (tx_obj, _block_tag) = if call_object.is_array() {
            let arr = call_object.as_array().unwrap();
            let obj = arr.get(0).cloned().unwrap_or_default();
            let tag = arr.get(1).cloned().unwrap_or(serde_json::Value::String("latest".to_string()));
            (obj, tag)
        } else {
            (call_object, serde_json::Value::String("latest".to_string()))
        };
    
        // Extraction des champs selon la spec
        let to_addr = tx_obj.get("to").and_then(|v| v.as_str()).unwrap_or("").to_lowercase();
        let from_addr = tx_obj.get("from").and_then(|v| v.as_str()).unwrap_or(&self.validator_address).to_lowercase();
    
        let value = tx_obj.get("value")
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
    
        let gas = tx_obj.get("gas")
            .and_then(|v| v.as_str().and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok()))
            .or(tx_obj.get("gas").and_then(|v| v.as_u64()))
            .unwrap_or(21000);
    
        let gas_price = tx_obj.get("gasPrice")
            .and_then(|v| v.as_str().and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok()))
            .or(tx_obj.get("gasPrice").and_then(|v| v.as_u64()))
            .unwrap_or(1_000_000_000);
    
        let nonce = tx_obj.get("nonce")
            .and_then(|v| v.as_str().and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok()))
            .or(tx_obj.get("nonce").and_then(|v| v.as_u64()))
            .unwrap_or(0);
    
        // Supporte "data" ou "input"
        let data = tx_obj.get("data")
            .or_else(|| tx_obj.get("input"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
    
        // Construction du TxRequest comme send_transaction
        let contract_addr = if !to_addr.is_empty() { Some(to_addr.clone()) } else { None };
        let function_name = if !data.is_empty() && data.len() >= 10 {
            let selector_hex = &data[2..10];
            let selector = u32::from_str_radix(selector_hex, 16).unwrap_or(0);
            if let Some(addr) = &contract_addr {
                let vm = self.vm.read().await;
                if let Some(module) = vm.modules.get(addr) {
                    if let Some((name, _)) = module.functions.iter().find(|(_, meta)| meta.selector == selector) {
                        Some(name.clone())
                    } else { None }
                } else { None }
            } else { None }
        } else { None };

// Arguments (à améliorer pour décodage ABI)
let arguments = if let Some(data) = tx_obj.get("data").and_then(|v| v.as_str()) {
    Self::parse_abi_encoded_args(data)
} else { None };
    
        // Simulation VM : clone la VM pour ne pas modifier l'état
        let vm_arc = self.vm.clone();
        let mut vm_sim = vm_arc.write().await;
    
        // Si c'est un contrat, exécute la fonction demandée
        if let Some(addr) = &contract_addr {
            if vm_sim.modules.contains_key(addr) {
                let args = arguments.clone().unwrap_or_else(|| {
                    if value > 0 {
                        vec![serde_json::Value::Number(serde_json::Number::from(value))]
                    } else {
                        vec![]
                    }
                });
                let fname = function_name.clone().unwrap_or("transfer".to_string());
                match vm_sim.execute_module(addr, &fname, args, Some(&from_addr)) {
                    Ok(result) => {
                        let result_hex = match result {
                            serde_json::Value::Number(n) => format!("0x{:064x}", n.as_u64().unwrap_or(0)),
                            serde_json::Value::String(s) => format!("0x{}", hex::encode(s.as_bytes())),
                            _ => "0x".to_string(),
                        };
                        return Ok(result_hex);
                    }
                    Err(e) => return Err(format!("Erreur VM execute_module: {}", e)),
                }
            }
        }
    
        // Si ce n'est pas un contrat, simule un transfert natif VEZ
        let vez_contract_addr = "0xe3cf7102e5f8dfd6ec247daea8ca3e96579e8448";
        let args = vec![
            serde_json::Value::String(to_addr.clone()),
            serde_json::Value::Number(serde_json::Number::from(value)),
        ];
        match vm_sim.execute_module(vez_contract_addr, "transfer", args, Some(&from_addr)) {
            Ok(result) => {
                let result_hex = match result {
                    serde_json::Value::Number(n) => format!("0x{:064x}", n.as_u64().unwrap_or(0)),
                    serde_json::Value::String(s) => format!("0x{}", hex::encode(s.as_bytes())),
                    _ => "0x".to_string(),
                };
                Ok(result_hex)
            }
            Err(e) => Err(format!("Erreur VM transfer: {}", e)),
        }
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

        // Endpoint eth_getTransactionByHash
        let engine_platform_clone = self.clone();
module.register_async_method("eth_getTransactionByHash", move |params, _meta, _| {
    let engine_platform = engine_platform_clone.clone();
    async move {
        let params_array: Vec<serde_json::Value> = params.parse().unwrap_or_default();
        let tx_hash = params_array.get(0).and_then(|v| v.as_str()).unwrap_or("");
        
        let receipts = engine_platform.tx_receipts.read().await;
        let normalized_hash = engine_platform.normalize_tx_hash(tx_hash);
        
        if let Some(receipt) = receipts.get(&normalized_hash) {
            // ✅ CONSTRUIT UN OBJET TRANSACTION COMPLET POUR METAMASK
            let tx = serde_json::json!({
                "hash": normalized_hash,
                "nonce": receipt.get("nonce").unwrap_or(&serde_json::json!("0x0")),
                "blockHash": receipt.get("blockHash").unwrap_or(&serde_json::json!(null)),
                "blockNumber": receipt.get("blockNumber").unwrap_or(&serde_json::json!(null)),
                "transactionIndex": receipt.get("transactionIndex").unwrap_or(&serde_json::json!("0x0")),
                "from": receipt.get("from").unwrap_or(&serde_json::json!(engine_platform.validator_address)),
                "to": receipt.get("to").unwrap_or(&serde_json::json!(null)),
                "value": receipt.get("value").unwrap_or(&serde_json::json!("0x0")),
                "gas": "0x5208",
                "gasPrice": "0x3b9aca00",
                "maxFeePerGas": "0x3b9aca00", // ✅ EIP-1559 support
                "maxPriorityFeePerGas": "0x3b9aca00",
                "input": "0x",
                "r": "0x0", "s": "0x0", "v": "0x0", // ✅ Signature placeholder
                "type": "0x2", // ✅ EIP-1559 transaction type
                "accessList": [], // ✅ EIP-2930 access list
                "chainId": format!("0x{:x}", engine_platform.get_chain_id())
            });
            Ok::<_, jsonrpsee_types::error::ErrorObject>(tx)
        } else {
            // ✅ Transaction non trouvée = null (standard Ethereum)
            Ok::<_, jsonrpsee_types::error::ErrorObject>(serde_json::json!(null))
        }
    }
}).expect("Failed to register eth_getTransactionByHash");

        // Endpoint eth_getBlockByHash
        let engine_platform_clone = self.clone();
module.register_async_method("eth_getBlockByHash", move |params, _meta, _| {
    let engine_platform = engine_platform_clone.clone();
    async move {
        let params_array: Vec<serde_json::Value> = params.parse().unwrap_or_default();
        let block_hash = params_array.get(0).and_then(|v| v.as_str()).unwrap_or("");
        let include_txs = params_array.get(1).and_then(|v| v.as_bool()).unwrap_or(false);
        match engine_platform.get_block_by_hash(block_hash, include_txs).await {
            Ok(block) => Ok::<_, jsonrpsee_types::error::ErrorObject>(block),
            Err(e) => Err(jsonrpsee_types::error::ErrorObject::owned(
                ErrorCode::ServerError(-32000).code(),
                "Erreur récupération bloc par hash",
                Some(format!("{}", e)),
            )),
        }
    }
}).expect("Failed to register eth_getBlockByHash method");

// Endpoint eth_getTransactionCount - CORRECTION AVEC BLOC
let engine_platform_clone = self.clone();
module.register_async_method("eth_getTransactionCount", move |params, _meta, _| {
    let engine_platform = engine_platform_clone.clone();
    async move {
        let params_array: Vec<serde_json::Value> = params.parse().unwrap_or_default();
        let address = params_array.get(0).and_then(|v| v.as_str()).unwrap_or("");
        let block_tag = params_array.get(1).and_then(|v| v.as_str()).unwrap_or("latest"); // ✅ CORRECTION
        
        println!("🚨🚨🚨 [DEBUG] ===== eth_getTransactionCount HANDLER =====");
        println!("🚨 [DEBUG] Paramètres: address='{}', block='{}'", address, block_tag);
        
        if address.is_empty() {
            return Err(jsonrpsee_types::error::ErrorObject::owned(
                ErrorCode::InvalidParams.code(),
                "Adresse manquante",
                Some("eth_getTransactionCount nécessite une adresse".to_string()),
            ));
        }
        
        // ✅ APPEL AVEC BLOCK TAG !
        match engine_platform.get_transaction_count(address, block_tag).await {
            Ok(nonce) => {
                println!("📤 [eth_getTransactionCount] RÉPONSE:");
                println!("   • Address: '{}', Block: '{}'", address, block_tag);
                println!("   • Nonce: {} (hex: 0x{:x})", nonce, nonce);
                Ok::<_, jsonrpsee_types::error::ErrorObject>(serde_json::json!(format!("0x{:x}", nonce)))
            },
            Err(e) => {
                println!("❌ [eth_getTransactionCount] ERREUR: {}", e);
                Err(jsonrpsee_types::error::ErrorObject::owned(
                    ErrorCode::ServerError(-32000).code(),
                    "Erreur récupération nonce",
                    Some(format!("{}", e)),
                ))
            }
        }
    }
}).expect("Failed to register eth_getTransactionCount method");

// Endpoint wallet_getCallsStatus        
        let engine_platform_clone = self.clone();
        module.register_async_method("wallet_getCallsStatus", move |params, _meta, _ctx| {
            let engine = engine_platform_clone.clone();
            async move {
                let hash_param: Vec<String> = params.parse().unwrap_or_default();
                let batch_id = hash_param.get(0).map(|s| s.as_str()).unwrap_or("");
        
                if batch_id.is_empty() {
                    return Err(jsonrpsee_types::error::ErrorObject::owned(
                        -32602,
                        "Invalid params",
                        None::<()>,
                    ));
                }
        
                let normalized = engine.normalize_tx_hash(batch_id);
                let receipts_map = engine.tx_receipts.read().await;
                let receipt = receipts_map.get(&normalized);
        
                let (status_code, status_str) = if receipt.is_some() {
                    (200, "0x1")
                } else if engine.rpc_service.lurosonie_manager.has_transaction_in_mempool(&normalized).await {
                    (100, "0x0")
                } else {
                    (400, "0x0")
                };
        
                let chain_id = format!("0x{:x}", engine.get_chain_id());
                let version = "2.0.0";
                let atomic = true;
        
                let receipts = if let Some(receipt) = receipt {
                    let logs = receipt.get("logs").cloned().unwrap_or(serde_json::json!([]));
                    let block_hash = receipt.get("blockHash").and_then(|v| v.as_str()).unwrap_or("0x0");
                    let block_number = receipt.get("blockNumber").and_then(|v| v.as_str()).unwrap_or("0x0");
                    let gas_used = receipt.get("gasUsed").and_then(|v| v.as_str()).unwrap_or("0x0");
                    let transaction_hash = receipt.get("transactionHash").and_then(|v| v.as_str()).unwrap_or(batch_id);
        
                    vec![serde_json::json!({
                        "logs": logs,
                        "status": status_str,
                        "blockHash": block_hash,
                        "blockNumber": block_number,
                        "gasUsed": gas_used,
                        "transactionHash": transaction_hash
                    })]
                } else {
                    vec![]
                };
        
                // --- AJOUT CAPABILITY EIP-7702 ---
                let mut response = serde_json::json!({
                    "version": version,
                    "chainId": chain_id,
                    "id": batch_id,
                    "status": status_code,
                    "atomic": atomic,
                    "receipts": receipts,
                    "capabilities": { "eip7702": true }
                });
        
                Ok(response)
            }
        })
        .expect("Failed to register wallet_getCallsStatus");

        // Endpoint wallet_sendCalls (EIP-5792 MetaMask batch calls)
        let engine_platform_clone = self.clone();
        module.register_async_method("wallet_sendCalls", move |params, _meta, _ctx| {
            let engine = engine_platform_clone.clone();
            async move {
                let params_array: Vec<serde_json::Value> = params.parse().unwrap_or_default();
                let batch_obj = params_array.get(0).cloned().unwrap_or_default();

                // Vérification version
                let version = batch_obj.get("version").and_then(|v| v.as_str()).unwrap_or("");
                if version != "2.0.0" {
                    return Err(jsonrpsee_types::error::ErrorObject::owned(
                        -32000,
                        "Version not supported",
                        None::<()>,
                    ));
                }

                // Détection de la capability EIP-7702 (Account Abstraction)
                let capabilities = batch_obj.get("capabilities").cloned().unwrap_or_default();
                let eip7702_requested = capabilities.get("eip7702").is_some();

                // Ici, tu peux gérer des traitements spécifiques EIP-7702 si besoin
                if eip7702_requested {
                    println!("✅ EIP-7702 demandé et accepté pour ce batch !");
                    // Tu pourrais stocker ce batch différemment ou activer des logiques AA ici
                }

                // Génère un batch_id unique (hash du batch)
                use sha3::{Digest, Keccak256};
                let mut hasher = Keccak256::new();
                hasher.update(serde_json::to_string(&batch_obj).unwrap_or_default());
                let batch_id = format!("0x{:x}", hasher.finalize());

                // Réponse conforme EIP-5792 (MetaMask attend juste l'id)
                Ok(serde_json::json!({
                    "id": batch_id
                }))
            }
        }).expect("Failed to register wallet_sendCalls");

        // 4. (Optionnel) Ajoute ces endpoints pour forcer le polling rapide MetaMask/Remix
        module.register_async_method("eth_mining", move |_, _, _| async move {
            Ok::<_, jsonrpsee_types::error::ErrorObject>(serde_json::json!(true))
        }).expect("Failed to register eth_mining method");

        let engine_platform_clone = self.clone();
        module.register_async_method("net_listening", move |_, _, _| async move {
            Ok::<_, jsonrpsee_types::error::ErrorObject>(serde_json::json!(true))
        }).expect("Failed to register net_listening method");
        module.register_async_method("eth_syncing", move |_, _, _| async move {
        Ok::<_, jsonrpsee_types::error::ErrorObject>(serde_json::json!(false))
        }).expect("Failed to register eth_syncing");
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
                let include_txs = params_array.get(1).and_then(|v| v.as_bool()).unwrap_or(false);
                match engine_platform.get_block_by_number(block_tag, include_txs).await {
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
                        let tx_hash_padded = pad_hash_64(&tx_hash);
                
                        // ✅ CORRECTION: Décodage RLP amélioré
                        let mut nonce: u64 = 0;
                        let mut gas_price: u64 = 0;
                        let mut gas_limit: u64 = 0;
                        let mut to_addr = String::new();
                        let mut value: u128 = 0;
                        let mut data_b: Vec<u8> = Vec::new();
                
                        // ✅ Fonction de décodage RLP corrigée
                        let parse_from_rlp = |rlp: rlp::Rlp| -> Result<(u64, u64, u64, Vec<u8>, u128, Vec<u8>), String> {
                            let item_count = rlp.item_count().map_err(|e| format!("RLP item count error: {}", e))?;
                            println!("🔍 RLP items count: {}", item_count);
                            
                            // Nonce (item 0)
                            let nonce = if item_count > 0 {
                                match rlp.at(0) {
                                    Ok(item) => {
                                        if item.is_empty() {
                                            0u64
                                        } else {
                                            item.as_val::<u64>().unwrap_or_else(|_| {
                                                // Fallback: décodage manuel des bytes
                                                let bytes = item.data().unwrap_or(&[]);
                                                if bytes.is_empty() {
                                                    0
                                                } else {
                                                    // Conversion big-endian
                                                    let mut result = 0u64;
                                                    for &byte in bytes.iter().take(8) {
                                                        result = (result << 8) | (byte as u64);
                                                    }
                                                    result
                                                }
                                            })
                                        }
                                    }
                                    Err(_) => 0u64
                                }
                            } else { 0u64 };
                            
                            // Gas price (item 1)
                            let gas_price = if item_count > 1 {
                                match rlp.at(1) {
                                    Ok(item) => item.as_val::<u64>().unwrap_or(1_000_000_000),
                                    Err(_) => 1_000_000_000u64
                                }
                            } else { 1_000_000_000u64 };
                            
                            // Gas limit (item 2)
                            let gas_limit = if item_count > 2 {
                                match rlp.at(2) {
                                    Ok(item) => item.as_val::<u64>().unwrap_or(21000),
                                    Err(_) => 21000u64
                                }
                            } else { 21000u64 };
                            
                            // To address (item 3)
                            let to = if item_count > 3 {
                                match rlp.at(3) {
                                    Ok(item) => item.as_val::<Vec<u8>>().unwrap_or_default(),
                                    Err(_) => Vec::new()
                                }
                            } else { Vec::new() };
                            
                            // Value (item 4)
                            let value = if item_count > 4 {
                                match rlp.at(4) {
                                    Ok(item) => {
                                        if item.is_empty() {
                                            0u128
                                        } else {
                                            item.as_val::<u128>().unwrap_or_else(|_| {
                                                // Fallback: décodage manuel des bytes pour les gros nombres
                                                let bytes = item.data().unwrap_or(&[]);
                                                let mut result = 0u128;
                                                for &byte in bytes.iter().take(16) {
                                                    result = (result << 8) | (byte as u128);
                                                }
                                                result
                                            })
                                        }
                                    }
                                    Err(_) => 0u128
                                }
                            } else { 0u128 };
                            
                            // Data (item 5)
                            let data = if item_count > 5 {
                                match rlp.at(5) {
                                    Ok(item) => item.as_val::<Vec<u8>>().unwrap_or_default(),
                                    Err(_) => Vec::new()
                                }
                            } else { Vec::new() };
                            
                            println!("🔍 Decoded values: nonce={}, gas_price={}, gas_limit={}, value={}, to_len={}, data_len={}", 
                                   nonce, gas_price, gas_limit, value, to.len(), data.len());
                            
                            Ok((nonce, gas_price, gas_limit, to, value, data))
                        };
                
                        if !raw_bytes.is_empty() {
                            if raw_bytes[0] == 0x02 || raw_bytes[0] == 0x01 {
                                // Typed tx: first byte is type, payload is RLP after that
                                if raw_bytes.len() > 1 {
                                    let payload = &raw_bytes[1..];
                                    let rlp_t = rlp::Rlp::new(payload);
                                    if rlp_t.is_list() {
                                        match parse_from_rlp(rlp_t) {
                                            Ok((n, gp, gl, to_b, val, data_bytes)) => {
                                                nonce = n; gas_price = gp; gas_limit = gl; value = val;
                                                data_b = data_bytes;
                                                // Correction: adresse Ethereum = 20 octets
                                                if !to_b.is_empty() && to_b.len() == 20 {
                                                    to_addr = format!("0x{}", hex::encode(&to_b));
                                                }
                                            }
                                            Err(e) => {
                                                println!("❌ Error parsing typed RLP: {}", e);
                                            }
                                        }
                                    }
                                }
                            } else {
                                // legacy or raw RLP list
                                let rlp0 = rlp::Rlp::new(&raw_bytes);
                                if rlp0.is_list() {
                                    match parse_from_rlp(rlp0) {
                                        Ok((n, gp, gl, to_b, val, data_bytes)) => {
                                            nonce = n; gas_price = gp; gas_limit = gl; value = val;
                                            data_b = data_bytes;
                                            if !to_b.is_empty() && to_b.len() == 20 {
                                                to_addr = format!("0x{}", hex::encode(&to_b));
                                            }
                                        }
                                        Err(e) => {
                                            println!("❌ Error parsing legacy RLP: {}", e);
                                        }
                                    }
                                }
                            }
                        }
                
                        println!("🔍 Final decoded values: nonce={}, gas_price={}, gas_limit={}, value={}, to={}", 
                               nonce, gas_price, gas_limit, value, to_addr);
                
                        // ✅ Construction de l'objet JSON pour send_transaction
                        let mut map = serde_json::Map::new();
                        map.insert("value".to_string(), serde_json::Value::String(format!("{}", value)));
                        map.insert("gas".to_string(), serde_json::Value::Number(serde_json::Number::from(gas_limit)));
                        map.insert("gasPrice".to_string(), serde_json::Value::Number(serde_json::Number::from(gas_price)));
                        map.insert("nonce".to_string(), serde_json::Value::Number(serde_json::Number::from(nonce))); // ✅ NONCE CORRECT
                        
                        if !data_b.is_empty() {
                            map.insert("data".to_string(), serde_json::Value::String(format!("0x{}", hex::encode(&data_b))));
                        }
                        if !to_addr.is_empty() {
                            map.insert("to".to_string(), serde_json::Value::String(to_addr.clone()));
                        }
                        
                        // ✅ Extraction du sender depuis la signature (si possible)
                        if let Some(sender_addr) = Self::extract_sender_from_raw(&raw_bytes) {
                            map.insert("from".to_string(), serde_json::Value::String(sender_addr));
                            println!("🔍 Extracted sender: {}", map.get("from").unwrap().as_str().unwrap());
                        }
                
                        map.insert("externalTxHash".to_string(), serde_json::Value::String(tx_hash.clone()));
                
                        let tx_obj = serde_json::Value::Object(map);
                
                        // ✅ Appel VM via send_transaction avec les bonnes données
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
                // Correction : tente les deux formats de hash
                // Try both the original and padded hash, awaiting both futures
                let receipt_result = match engine_platform.get_transaction_receipt(tx_hash.to_string()).await {
                    Ok(receipt) => Ok(receipt),
                    Err(_) => {
                        let padded = pad_hash_64(tx_hash);
                        engine_platform.get_transaction_receipt(padded).await
                    }
                };
                match receipt_result {
                    Ok(receipt) => Ok::<_, jsonrpsee_types::error::ErrorObject>(serde_json::json!(receipt)),
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

impl EnginePlatform {
    pub async fn get_latest_block_info(&self) -> (u64, String) {
        let height = self.rpc_service.lurosonie_manager.get_block_height().await;
        let hash = self.rpc_service.lurosonie_manager.get_last_block_hash().await
            .unwrap_or_else(|| format!("0x{:064x}", height));
        (height, hash)
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

#[tokio::main]
async fn main() {
    dotenv::dotenv().ok();
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
                            panic!("Adresse liée à la clé privée non trouvée !");
                        })
                }
                Err(e) => {
                    eprintln!("❌ Erreur lors de la génération de la clé privée du validateur: {}", e);
                    panic!("Impossible de générer l'adresse du validateur !");
                }
            }
        };

        // ✅ DÉPLOIEMENT DU CONTRAT VEZ avec bytecode spécifique
        println!("🪙 Deploying VEZ contract with bytecode...");
        if let Err(e) = deploy_vez_contract_evm(&mut vm_guard, &validator_address_generated).await {
            eprintln!("❌ Failed to deploy VEZ contract: {}", e);
        } else {
            println!("✅ VEZ contract deployed successfully with bytecode");
        }

        // ✅ VÉRIFICATION QUE LE MODULE EST BIEN ENREGISTRÉ
        if vm_guard.modules.contains_key("0xe3cf7102e5f8dfd6ec247daea8ca3e96579e8448") {
            println!("✅ VEZ module correctly registered");
            println!("   • Functions available: {:?}", 
                   vm_guard.modules["0xe3cf7102e5f8dfd6ec247daea8ca3e96579e8448"].functions.keys().collect::<Vec<_>>());
        } else {
            eprintln!("❌ VEZ module NOT registered - initialization will fail");
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
    
    // ✅ MODE INSTANT-FINALITY POUR DEV LOCAL (MetaMask UX parfaite)
    let engine_clone = engine_platform.clone();
    tokio::spawn(async move {
        // Mode "instant block" : chaque tx = 1 bloc finalisé immédiatement
        let mut rx = engine_clone.rpc_service.lurosonie_manager.mempool_tx_receiver().await;
        while let Some(tx_request) = rx.recv().await {
            // Crée et finalise un bloc IMMÉDIATEMENT avec juste cette tx
            let block_number = {
                let height = engine_clone.rpc_service.lurosonie_manager.get_block_height().await;
                height + 1
            };
        
            let tx_hashes = vec![tx_request.hash.clone()];
        
            // Émet le bloc finalisé via le canal broadcast
            let _ = engine_clone.block_finalized_tx.send(tx_hashes.clone());
        
            // Optionnel : log
            println!("INSTANT BLOCK #{} avec tx {}", block_number, tx_request.hash);
        }
    });

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
    println!("🔧 Endpoints RPC disponibles :");
    println!("   • eth_blockNumber");
    println!("   • eth_getBlockByHash");
    println!("   • eth_getBlockByNumber");
    println!("   • eth_sendTransaction");
    println!("   • eth_sendRawTransaction");
    println!("   • eth_getTransactionReceipt");
    println!("   • eth_call");
    println!("   • eth_estimateGas");
    println!("   • eth_getCode");
    println!("   • eth_chainId");
    println!("   • net_version");
    println!("   • eth_accounts");
    println!("   • eth_gasPrice");
    println!("   • eth_getBalance");
    println!("   • get_ledger_info");
    println!("   • build_acc");
    println!("   • wallet_getCallsStatus");
    println!("   • wallet_sendCalls");
    println!("   • eth_mining");
    println!("   • net_listening");
    println!("   • eth_syncing");
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
        println!("   • Total blocks: {}", total_blocks);
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
        (validator_address, 888_000_000_000_000_000_000_000_000u128), // <-- 888 VEZ
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
async fn deploy_vez_contract_evm(vm: &mut SlurachainVm, validator_address: &str) -> Result<(), String> {
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
            if name == "initialize" && types.is_empty() {
                println!("✅ Correction: initialize() détectée avec 0 argument");
            }
            let signature = format!("{}({})", name, types.join(","));
            let mut hasher = Keccak256::new();
            hasher.update(signature.as_bytes());
            let selector_bytes = hasher.finalize();
            let selector = u32::from_be_bytes([selector_bytes[0], selector_bytes[1], selector_bytes[2], selector_bytes[3]]);
            // --- AJOUT : calcul offset réel ---
            let offset = find_function_offset_in_bytecode(&impl_bytecode, selector).unwrap_or(0);

            impl_functions.insert(name.clone(), vuc_tx::slurachain_vm::FunctionMetadata {
                name,
                offset, // <-- offset correct ici !
                is_view: item.get("stateMutability").and_then(|v| v.as_str()) == Some("view"),
                args_count: types.len(),
                arg_types: types.clone(),
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
    // Calldata pour initialize()
    let init_selector = [0x81, 0x29, 0xfc, 0x1c]; // initialize()
    let proxy_constructor_data = init_selector.to_vec(); // Pas d'arguments
    proxy_resources.insert("constructor_data".to_string(), serde_json::Value::String(hex::encode(&proxy_constructor_data)));

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

    {
        let accounts = vm.state.accounts.read().unwrap();
        if let Some(proxy_acc) = accounts.get(&proxy_address) {
            println!("🧩 Proxy resources: {:?}", proxy_acc.resources);
        }
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

    {
        let accounts_guard = vm.state.accounts.read().unwrap();
        let proxy_addr = "0xe3cf7102e5f8dfd6ec247daea8ca3e96579e8448";
        let proxy_acc = accounts_guard.get(proxy_addr);
        let impl_addr = proxy_acc.and_then(|acc| acc.resources.get("implementation")).and_then(|v| v.as_str());
        println!("🧩 Proxy resources: {:?}", proxy_acc.map(|acc| &acc.resources));
        println!("🧩 Impl address in proxy: {:?}", impl_addr);
        println!("🧩 Impl module present? {}", impl_addr.map(|a| vm.modules.contains_key(a)).unwrap_or(false));
        println!("🧩 Modules keys: {:?}", vm.modules.keys().collect::<Vec<_>>());
    }

    // Récupère le calldata d'init (selector initialize)
let init_selector = [0x81, 0x29, 0xfc, 0x1c];
let calldata = init_selector.to_vec();

// Simule le delegatecall d'init sur le proxy
let mut vm_guard = vm; // ou Arc<RwLock<...>> selon ton contexte
let proxy_addr = proxy_address.clone();
let sender = validator_address.to_string(); // ou l'adresse système

// Appel le module directement sans passer par execute_module
let result = vm_guard.execute_module(
    &proxy_addr,
    "initialize",
    vec![],
    Some(&sender),
);

if let Ok(_) = result {
    if let Some(proxy_acc) = vm_guard.state.accounts.write().unwrap().get_mut(&proxy_address) {
        proxy_acc.resources.insert("initialized".to_string(), serde_json::Value::Bool(true));
    }
    println!("✅ Proxy VEZ initialisé via initialize()");
} else {
    println!("❌ Erreur lors de l'initialisation du proxy VEZ : {:?}", result);
}

    Ok(())
}

/// ✅ NOUVELLE FONCTION: Initialisation du contrat VEZ via execute_module
async fn initialize_vez_contract(vm: &Arc<TokioRwLock<SlurachainVm>>, validator_address: &str) -> Result<(), String> {
    println!("🔧 Initializing VEZ contract via bytecode execution...");

    let vez_contract_address = "0xe3cf7102e5f8dfd6ec247daea8ca3e96579e8448";

    // Charger l'ABI du proxy pour détecter la signature d'initialize
    let proxy_abi_json = std::fs::read_to_string("vezcurproxycore.json")
        .map_err(|e| format!("vezcurproxycore.json manquant: {}", e))?;
    let proxy_abi: serde_json::Value = serde_json::from_str(&proxy_abi_json)
        .map_err(|e| format!("vezcurproxycore.json invalide: {}", e))?;

    // Cherche la fonction initialize dans l'ABI du proxy
    let initialize_abi = proxy_abi.as_array()
        .and_then(|arr| arr.iter().find(|item| {
            item.get("type").and_then(|v| v.as_str()) == Some("function")
                && item.get("name").and_then(|v| v.as_str()) == Some("initialize")
        }));

    let args_count = initialize_abi
        .and_then(|item| item.get("inputs").and_then(|v| v.as_array()).map(|arr| arr.len()))
        .unwrap_or(0);

    // Charge l'ABI de l'implémentation VEZ
    let impl_abi_json = std::fs::read_to_string("VEZABI.json")
        .map_err(|e| format!("VEZABI.json manquant: {}", e))?;
    let impl_abi: serde_json::Value = serde_json::from_str(&impl_abi_json)
        .map_err(|e| format!("VEZABI.json invalide: {}", e))?;

    // Cherche la fonction initialize dans l'ABI de l'implémentation
    let initialize_abi = impl_abi.as_array()
        .and_then(|arr| arr.iter().find(|item| {
            item.get("type").and_then(|v| v.as_str()) == Some("function")
                && item.get("name").and_then(|v| v.as_str()) == Some("initialize")
        }));

    let args_count = initialize_abi
        .and_then(|item| item.get("inputs").and_then(|v| v.as_array()).map(|arr| arr.len()))
        .unwrap_or(0);

    // Prépare les arguments selon la signature de l'implémentation
    let initial_supply: u128 = 888_000_000_000_000_000_000_000_000u128;
    let initial_holder = validator_address;
    let owner = validator_address;
    let init_args = vec![]; // <-- aucun argument pour le proxy VEZ

    let mut vm_guard = vm.write().await;
    match vm_guard.execute_module(
        vez_contract_address,
        "initialize",
        init_args,
        Some(validator_address)
    ) {
        Ok(result) => {
            println!("✅ VEZ initialize returned: {:?}", result);
            Ok(())
        }
        Err(e) => {
            eprintln!("❌ Failed to initialize VEZ contract via UVM: {}", e);
            Err(e)
        }
    }
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
                arg_types: Vec::new(), // Ajout du champ manquant
                return_type: "unknown".to_string(),
                gas_limit: 50000,
                payable: false, // Default value, as ABI is not available here
                mutability: "nonpayable".to_string(), // Default value
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
                        types.push(t.to_string());
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
                    arg_types: types.clone(),
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
                            arg_types: vec![],
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

fn pad_hash_64(hex: &str) -> String {
    // Enlève le préfixe "0x" si présent
    let hex = hex.strip_prefix("0x").unwrap_or(hex);
    format!("0x{:0>64}", hex)
}

// Add this method to the EnginePlatform impl block:
impl EnginePlatform {
    /// Déploie un contrat via l'opcode EVM CREATE (0xf0)
    pub async fn deploy_contract_evm_create(&self, bytecode_hex: &str, from: &str, value: u64) -> Result<String, String> {
        let bytecode = if bytecode_hex.starts_with("0x") {
            hex::decode(&bytecode_hex[2..]).map_err(|e| format!("Invalid hex: {}", e))?
        } else {
            hex::decode(bytecode_hex).map_err(|e| format!("Invalid hex: {}", e))?
        };

        // Appel VM avec une transaction de déploiement (to = None)
        let mut vm = self.vm.write().await;
        let deploy_args = vec![
            serde_json::Value::String(hex::encode(&bytecode)), // data
            serde_json::Value::Number(serde_json::Number::from(value)),
        ];
        // Convention : module_path = "evm", function_name = "deploy"
        let result = vm.execute_module("evm", "deploy", deploy_args, Some(from))
            .map_err(|e| format!("VM deploy error: {}", e))?;

        // L’adresse du contrat est retournée par l’opcode CREATE (dans r0)
        let contract_address = match result {
            serde_json::Value::String(addr) => addr,
            serde_json::Value::Number(n) => format!("0x{:x}", n.as_u64().unwrap_or(0)),
            _ => return Err("Invalid deploy result".to_string()),
        };
        Ok(contract_address)
    }
}