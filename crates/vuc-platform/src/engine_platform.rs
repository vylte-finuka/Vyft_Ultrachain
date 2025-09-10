use sha3::Digest;
use tokio::sync::{Mutex, mpsc};
use rand::Rng; // Ajoute ce use

// Ensure the correct module path for TimestampRelease
use vuc_events::timestamp_release::TimestampRelease;
use vuc_platform::ultrachain_rpc_service::TxRequest;
use vuc_tx::ultrachain_tx::{HookOp, UltrachainTx, ValueTx};
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use tokio::sync::RwLock as TokioRwLock;
use std::collections::HashMap;
use tracing::{info, error};
use chrono::Utc;
use jsonrpsee_types::error::ErrorCode;
use tracing_subscriber;

use vuc_core::service::ultrachain_service::UltrachainService;
use vuc_types::{committee::committee::EpochId, supported_protocol_versions::SupportedProtocolVersions};
use vuc_events::time_warp::TimeWarp;
use vuc_platform::{ultrachain_rpc_service::UltrachainRpcService, consensus::lurosonie_manager::LurosonieManager};
use vuc_storage::storing_access::RocksDBManagerImpl;
use vuc_storage::storing_access::RocksDBManager;
use jsonrpsee_server::{RpcModule, ServerBuilder};
use vuc_tx::ultrachain_vm::UltrachainVm;

use vuc_tx::ultrachain_vm::{Address, Signer}; // Ajoute ce use pour les types natifs Nerena

#[derive(Clone)]
pub struct EnginePlatform {
    pub vyftid: String,
    pub bytecode: Vec<u8>,
    pub rpc_service: UltrachainRpcService,
    pub vm: Arc<RwLock<UltrachainVm>>, // Accepte un RwLock
}

impl EnginePlatform {
    pub fn new(
        vyftid: String,
        bytecode: Vec<u8>,
        rpc_service: UltrachainRpcService,
        vm: Arc<RwLock<UltrachainVm>>,
    ) -> Self {
        EnginePlatform {
            vyftid,
            bytecode,
            rpc_service,
            vm,
        }
    }

    pub async fn execute_transaction(&self) -> Result<(), anyhow::Error> {
        let mut vm = match self.vm.write() {
            Ok(guard) => guard,
            Err(poisoned) => {
                eprintln!("UVM lock is poisoned, recovering...");
                poisoned.into_inner()
            }
        };

        let ultrachain_tx = UltrachainTx {
            from_op: "sender_address".to_string(),
            receiver_op: "receiver_address".to_string(),
            fees_tx: 10,
            value_tx: ValueTx::default(),
            arguments: vec![],
            nonce_tx: 0,
            hash_tx: "hash_value".to_string(),
            func_tx: "module_address::module_name::function_name".to_string(),
        };

        ultrachain_tx
            .functiontx_impl(&mut vm, HookOp::default(), self.rpc_service.storage.clone())
            .await
            .map_err(|e| anyhow::Error::msg(e.to_string()))?;
        Ok(())
    }

    pub async fn build_account(&self) -> Result<(String, String), anyhow::Error> {
        let mut vm = self.vm.write().unwrap();
        vuc_platform::operator::crypto_perf::generate_and_create_account(&mut vm, "acc").await
    }
}

impl EnginePlatform {
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
        
        println!("Registered endpoint: get_ledger_info");
        
        // Enregistrer le endpoint `tx_int`
        let engine_platform_clone = self.clone();
        module.register_async_method("tx_int", move |params, _meta, _| {
            let engine_platform = engine_platform_clone.clone();
            async move {
                let tx_request: serde_json::Value = match params.parse::<serde_json::Value>() {
                    Ok(req) => {
                        if req.is_array() {
                            req.as_array().unwrap().get(0).cloned().unwrap_or_default()
                        } else {
                            req
                        }
                    }
                    Err(e) => {
                        println!("Failed to parse request: {}", e);
                        return Err(jsonrpsee_types::error::ErrorObject::from(ErrorCode::InvalidParams)).into();
                    }
                };

                // Nerena all VM operations into a blocking thread to avoid Send/Sync issues
                let result = tokio::task::spawn_blocking(move || {
                    let rt = tokio::runtime::Handle::current();
                    rt.block_on(async move {
                        // Décoder les adresses dans la requête
                        if let Some(sender) = tx_request.get("sender").and_then(|v| v.as_str()) {
                            let sender_decoded = match percent_encoding::percent_decode_str(sender).decode_utf8() {
                                Ok(decoded) => decoded.to_string(),
                                Err(e) => {
                                    return Err(jsonrpsee_types::error::ErrorObject::owned(
                                        ErrorCode::InvalidParams.code(),
                                        "Failed to decode sender address",
                                        Some(format!("{}", e)),
                                    ));
                                }
                            };
                            println!("Decoded sender address: {}", sender_decoded);
                        }

                        match engine_platform.tx_int(tx_request).await {
                            Ok(response) => Ok::<_, jsonrpsee_types::error::ErrorObject>(response),
                            Err(e) => Err(jsonrpsee_types::error::ErrorObject::owned(
                                ErrorCode::ServerError(-32000).code(),
                                "Erreur lors de l'exécution de la transaction",
                                Some(format!("{}", e)),
                            )),
                        }
                    })
                }).await;

                match result {
                    Ok(Ok(val)) => Ok(val),
                    Ok(Err(e)) => Err(e),
                    Err(e) => Err(jsonrpsee_types::error::ErrorObject::owned(
                        ErrorCode::ServerError(-32001).code(),
                        "Internal error in tx_int",
                        Some(e.to_string()),
                    )),
                }
            }
        }).expect("Failed to register tx_int method");

        println!("Registered endpoint: tx_int");

        // Enregistrer le endpoint `tx_int/by_hash`
        let engine_platform_clone = self.clone();
        module.register_async_method("tx_int/by_hash", move |params, _meta, _| {
            let engine_platform = engine_platform_clone.clone();
            async move {
                let hash: String = match params.parse() {
                    Ok(req) => req,
                    Err(e) => {
                        println!("Failed to parse hash parameter: {}", e);
                        return Err(jsonrpsee_types::error::ErrorObject::from(ErrorCode::InvalidParams)).into();
                    }
                };

                match engine_platform.tx_int_by_hash(hash).await {
                    Ok(response) => Ok::<_, jsonrpsee_types::error::ErrorObject>(response),
                    Err(e) => Err(jsonrpsee_types::error::ErrorObject::owned(
                        ErrorCode::ServerError(-32004).code(),
                        "Transaction not found",
                        Some(format!("{}", e)),
                    )),
                }
            }
        }).expect("Failed to register tx_int/by_hash method");

        println!("Registered endpoint: tx_int/by_hash");

         // Enregistrer le endpoint `view`
        let engine_platform_clone = self.clone();
        module.register_async_method("view", move |params, _meta, _| {
            let engine_platform = engine_platform_clone.clone();
            async move {
                // Parse parameters outside blocking
                let view_request: serde_json::Value = match params.parse() {
                    Ok(req) => req,
                    Err(e) => {
                        error!("Failed to parse view request: {}", e);
                        return Err(jsonrpsee_types::error::ErrorObject::owned(
                            ErrorCode::InvalidParams.code(),
                            "Invalid JSON parameters",
                            Some(format!("Parsing error: {}", e)),
                        ));
                    }
                };

                // Nerena the engine_platform and view_request into a blocking thread
                let result = tokio::task::spawn_blocking(move || {
                    // Use a synchronous runtime for the view_function
                    // If view_function is async, use block_on
                    let rt = tokio::runtime::Handle::current();
                    rt.block_on(engine_platform.view_function(view_request))
                }).await;

                match result {
                    Ok(Ok(response)) => Ok::<_, jsonrpsee_types::error::ErrorObject>(response),
                    Ok(Err(e)) => {
                        error!("Error executing view function: {}", e);
                        Err(jsonrpsee_types::error::ErrorObject::owned(
                            ErrorCode::ServerError(-32000).code(),
                            "Error executing view function",
                            Some(e.to_string()),
                        ))
                    }
                    Err(e) => {
                        error!("Panic or JoinError in view_function: {}", e);
                        Err(jsonrpsee_types::error::ErrorObject::owned(
                            ErrorCode::ServerError(-32001).code(),
                            "Internal error in view function",
                            Some(e.to_string()),
                        ))
                    }
                }
            }
        }).expect("Failed to register view method");
        
        println!("Registered endpoint: view");

        let engine_platform_clone = self.clone();
        module.register_async_method("build_acc", {
            let vm = engine_platform_clone.vm.clone();
            move |_params, _meta, _| {
                let vm = vm.clone();
                // On exécute la création de compte dans un thread bloquant pour respecter Send + Sync
                async move {
                    let result = tokio::task::spawn_blocking(move || {
                        // Si la fonction appelée est async, utilise block_on
                        let rt = tokio::runtime::Handle::current();
                        rt.block_on(vuc_platform::operator::crypto_perf::generate_and_create_account(&mut vm.write().unwrap(), "second_argument"))
                    }).await;
        
                    match result {
                        Ok(Ok((address, privkey))) => Ok::<_, jsonrpsee_types::error::ErrorObject>(serde_json::json!({
                            "status": "success",
                            "address": address,
                            "private_key": privkey
                        })),
                        Ok(Err(e)) => Err(jsonrpsee_types::error::ErrorObject::owned(
                            ErrorCode::ServerError(-32010).code(),
                            "Erreur lors de la génération du compte",
                            Some(format!("{}", e)),
                        )),
                        Err(e) => Err(jsonrpsee_types::error::ErrorObject::owned(
                            ErrorCode::ServerError(-32011).code(),
                            "Internal error in build_acc",
                            Some(e.to_string()),
                        )),
                    }
                }
            }
        }).expect("Failed to register build_acc method");
        
        println!("Registered endpoint: build_acc");

        // Démarrer le serveur
        let server_handle = server.start(module.clone()).clone();
        println!("Server started successfully: {:?}", server_handle);

        // Maintenir le serveur actif
        tokio::signal::ctrl_c().await.expect("Failed to listen for Ctrl+C");
        println!("Shutting down server...");
    }

    /// Fonction asynchrone pour exécuter une transaction
     pub async fn tx_int(
        &self,
        tx_request: serde_json::Value,
    ) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        info!("Starting transaction processing via tx_int");

        // Si tx_request est un tableau (cas d'un appel via "view"), prends le premier élément
        let tx_request = if tx_request.is_array() {
            tx_request.as_array().unwrap().get(0).cloned().unwrap_or_default()
        } else {
            tx_request
        };

        // Appeler la méthode `contract_op` pour exécuter la transaction
        self.contract_op(tx_request, false).await
    }

    pub async fn view_function(
        &self,
        view_request: serde_json::Value,
    ) -> Result<serde_json::Value, Box<dyn std::error::Error + Send + Sync>> {
        info!("Starting view function execution");

        // Ajoute ce bloc :
        let view_request = if view_request.is_array() {
            view_request.as_array().unwrap().get(0).cloned().unwrap_or_default()
        } else {
            view_request
        };

        let result = self.contract_op(view_request, true)
            .await
            .map_err(|e| anyhow::Error::msg(e.to_string()))?;

        // --- Retourne directement le résultat ---
        Ok(result)
    }

    /// Fonction asynchrone pour rechercher une transaction par son hash
    pub async fn tx_int_by_hash(
        &self,
        hash: String,
    ) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
       println!("Searching for transaction with hash: {}", hash);

        // Rechercher la transaction dans le stockage
        let metadata = self
            .rpc_service
            .storage
            .get_metadata(&hash)
            .await
            .map_err(|e| {
                error!("Erreur lors de la recherche de la transaction : {}", e);
                e
            })?;

        if let Some(metadata) = metadata {
            let response = serde_json::json!({
                "type": "transaction_metadata",
                "hash": hash,
                "metadata": metadata,
            });
            Ok(response)
        } else {
            error!("Transaction not found for hash: {}", hash);
            Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "Transaction not found",
            )))
        }
    }

    pub async fn get_ledger_info(&self) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        // Récupérer les informations nécessaires via rpc_service
        let chain_id = self.rpc_service.get_chain_id();
        let epoch = self.rpc_service.get_epoch();
        let ledger_version = self.rpc_service.get_ledger_version().await;
        let oldest_ledger_version = self.rpc_service.get_oldest_ledger_version().await;
        let node_role = self.rpc_service.get_node_role();
        let oldest_block_height = self.rpc_service.get_oldest_block_height();
        let block_height = self.rpc_service.get_block_height();
        let git_hash = self.rpc_service.get_git_hash();

        // Construire la réponse JSON
        let response = serde_json::json!({
            "chain_id": chain_id,
            "epoch": epoch,
            "ledger_version": ledger_version,
            "oldest_ledger_version": oldest_ledger_version,
            "node_role": node_role,
            "oldest_block_height": oldest_block_height,
            "block_height": block_height,
            "git_hash": git_hash,
        });

        Ok(response)
    }

    /// Fonction pour gérer une transaction
    pub async fn handle_tx_int(
        &self,
        tx_request: TxRequest,
    ) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        // Ajouter la transaction aux transactions en attente
        let mut pending_transactions = self.rpc_service.pending_transactions.lock().await;
        let tx_request = tx_request.clone();
        pending_transactions.insert(tx_request.hash.clone(), tx_request.clone());

        // Construire la réponse au format demandé
        let response = serde_json::json!([{
            "type": "pending_transaction",
            "hash": tx_request.hash,
            "sender": tx_request.from_op,
            "sequence_number": tx_request.nonce_tx.to_string(),
            "max_gas_amount": tx_request.max_gas_amount.unwrap_or_default().to_string(),
            "gas_unit_price": tx_request.gas_unit_price.unwrap_or_default().to_string(),
            "expiration_timestamp_secs": tx_request.expiration_timestamp_secs.unwrap_or_default().to_string(),
            "payload": {
                "type": tx_request.payload_type,
                "function": tx_request.function,
                "type_arguments": tx_request.type_arguments,
                "arguments": tx_request.arguments
            },
            "signature": {
                "type": tx_request.signature_type,
                "public_key": tx_request.public_key,
                "signature": tx_request.signature
            },
            "replay_protection_nonce": tx_request.replay_protection_nonce.to_string()
        }]);

        Ok(response)
    }

     pub async fn contract_op(
        &self,
        tx_request: serde_json::Value,
        is_view_call: bool,
    ) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        use std::time::Instant;

        println!("Starting contract operation");
        let start_time = Instant::now();

        // Étape 1 : Décoder l'adresse de l'expéditeur
        let sender = tx_request.get("sender").and_then(|v| v.as_str()).unwrap_or_default().trim();

        // Étape 3 : Extraire les arguments du payload
        let default_payload = serde_json::json!({});
        let payload = tx_request.get("payload").unwrap_or(&default_payload);
        let empty_vec = Vec::new();
        let arguments = payload.get("arguments").and_then(|v| v.as_array()).unwrap_or(&empty_vec);

        println!("DEBUG tx_request: {}", tx_request);
        println!("DEBUG payload: {}", payload);
        println!("DEBUG arguments: {:?}", arguments);

        // Construire arguments_vt en utilisant serde_json::Value
        let mut arguments_vt: Vec<serde_json::Value> = arguments.iter().map(|v| {
            if let Some(s) = v.as_str() {
                serde_json::Value::String(s.to_string())
            } else if let Some(n) = v.as_u64() {
                serde_json::Value::Number(serde_json::Number::from(n))
            } else if let Some(b) = v.as_bool() {
                serde_json::Value::Bool(b)
            } else {
                v.clone()
            }
        }).collect();

        let receiver = arguments.get(0).and_then(|v| v.as_str()).unwrap_or_default().to_string();
        let value = arguments.get(1).and_then(|v| v.as_str()).unwrap_or_default().to_string();
        let value_clone = value.clone();

        // Extraction du nom de fonction Move
        let function = payload.get("function").and_then(|v| v.as_str()).unwrap_or_default();
        let parts: Vec<&str> = function.split("::").collect();
        if parts.len() != 3 {
            return Err("Nom de fonction Move invalide".into());
        }
        let module_address = parts[0].to_string();
        let module_name = parts[1].to_string();
        let function_name = parts[2].to_string();

        // Charger le module compilé (remplacez cette logique par une implémentation existante)
        // let compiled_module = self.vm.load_compiled_module(&module_address, &module_name).await?;

        // Parcourir les fonctions du module (remplacez ModuleView par une logique personnalisée)
        // let func_view_opt = compiled_module.functions.iter().find(|f| f.name == function_name);

        // let func_view = match func_view_opt {
        //     Some(f) => f,
        //     None => return Err("Fonction Move introuvable dans le module".into()),
        // };

        // println!("--- Fonctions disponibles dans le module ---");
        // for func in &compiled_module.functions {
        //     println!("{}::{}", module_name, func.name);
        // }
        // println!("--------------------------------------------");

        // Vérifier si la fonction est une vue
        // let is_sight = func_view.is_view;
        // if is_sight && !is_view_call {
        //     return Err("Cette fonction Move n'est accessible que via /view".into());
        // }
        // if !is_sight && is_view_call {
        //     return Err("Cette fonction Move n'est accessible que via /tx_int".into());
        // }

        // Toujours définir signer_address pour from_op
        let signer_address = sender.to_string();

        // --- Ajoute la version native Address et Signer dans les arguments pour la VM ---
        let native_address = Address::new(&signer_address);
        let native_signer = Signer::new(&signer_address);
        arguments_vt.insert(0, serde_json::to_value(native_signer.clone()).unwrap());
        arguments_vt.insert(1, serde_json::to_value(native_address.clone()).unwrap());
        println!(">>> Signer et Address natifs injectés dans arguments_vt (view ou tx_int) !");

        // Étape 4 : Construire l'objet UltrachainTx
        let sequence_number = tx_request.get("sequence_number").and_then(|v| v.as_str()).unwrap_or_default();
        let max_gas_amount = tx_request.get("max_gas_amount").and_then(|v| v.as_str()).unwrap_or_default();
        let gas_unit_price = tx_request.get("gas_unit_price").and_then(|v| v.as_str()).unwrap_or_default();
        let expiration_timestamp_secs = tx_request.get("expiration_timestamp_secs").and_then(|v| v.as_str()).unwrap_or_default();
        let mut rng = rand::thread_rng();
        let nonce: u64 = rng.gen(); // Nonce aléatoire
        
        // Ajoute le nonce dans la transaction et dans le hash
        // Récupérer le hash du dernier bloc
        let last_block_hash = {
            let lurosonie_manager = &self.rpc_service.lurosonie_manager;
            let last_hash = lurosonie_manager.last_block_hash.read().unwrap();
            last_hash.clone().unwrap_or_else(|| "None".to_string())
        };

        // Calcul du hash unique incluant le hash du bloc précédent
        let mut hasher = sha3::Sha3_256::new();
        
        hasher.update(sender.as_bytes());
        hasher.update(sequence_number.as_bytes());
        hasher.update(max_gas_amount.as_bytes());
        hasher.update(gas_unit_price.as_bytes());
        hasher.update(expiration_timestamp_secs.as_bytes());
        hasher.update(payload.to_string().as_bytes());
        hasher.update(last_block_hash.as_bytes());
        hasher.update(nonce.to_le_bytes()); // Ajoute le nonce dans le hash
        for arg in &arguments_vt {
            hasher.update(format!("{:?}", arg).as_bytes());
        }
        let hash = format!("0x{}", hex::encode(hasher.finalize()));

        // Construire UltrachainTx
        let ultrachain_tx = UltrachainTx {
            from_op: signer_address.clone(),
            receiver_op: receiver.clone(),
            fees_tx: max_gas_amount.parse::<u64>().unwrap_or(0),
            value_tx: vuc_tx::ultrachain_tx::ValueTx::Str(value),
            arguments: arguments_vt.clone(),
            nonce_tx: nonce, // <-- ici
            hash_tx: hash.clone(),
            func_tx: function.to_string(),
        };

        // Étape 5 : Exécuter la transaction immédiatement
        let execution_start = Instant::now();
        let execution_result = ultrachain_tx
            .functiontx_impl(&mut self.vm.write().unwrap(), HookOp::default(), self.rpc_service.storage.clone())
            .await;
        println!("Executed transaction in UVM (took {:?})", execution_start.elapsed());

        // Étape 6 : Retourner la réponse
        match execution_result {
            Ok(vm_response) => {
                let response = serde_json::json!({
                    "type": "transaction",
                    "hash": hash,
                    "sender": sender,
                    "sequence_number": sequence_number,
                    "max_gas_amount": max_gas_amount,
                    "gas_unit_price": gas_unit_price,
                    "expiration_timestamp_secs": expiration_timestamp_secs,
                    "payload": payload,
                    "status": "success",
                    "result": vm_response
                });
                Ok(response)
            }
            Err(e) => {
                let response = serde_json::json!({
                    "type": "transaction",
                    "hash": hash,
                    "sender": sender,
                    "sequence_number": sequence_number,
                    "max_gas_amount": max_gas_amount,
                    "gas_unit_price": gas_unit_price,
                    "expiration_timestamp_secs": expiration_timestamp_secs,
                    "payload": payload,
                    "status": "failed",
                    "error": format!("Error executing in the VM: {}", e)
                });
                Ok(response)
            }
        }
    }
}
    
    #[tokio::main]
    async fn main() {
        tracing_subscriber::fmt::init();  
        println!("Starting Ultrachain network...");

        // Ouvre RocksDB UNE SEULE FOIS et partage l'Arc partout
        let storage: Arc<RocksDBManagerImpl> = Arc::new(RocksDBManagerImpl::new("simulation"));

        // Passe storage à UltrachainRpcService et partout où il faut
        let ultrachain_service = Arc::new(Mutex::new(UltrachainService {
            sign_op: String::new(),
            tx_op: vec![],
            nonce_tx: 0,
            creator_id: String::new(),
        }));

        let vm = Arc::new(RwLock::new(UltrachainVm::new()));
        if let Err(e) = vm.write().unwrap().initialize_all_modules("./target") {
            eprintln!("Failed to initialize modules: {}", e);
            return;
        }

        let (block_sender, block_receiver) = mpsc::channel(100);
        let lurosonie_manager = Arc::new(LurosonieManager {
            epoch_id: EpochId::default(),
            committee: vec![],
            supported_protocol_versions: SupportedProtocolVersions::default(),
            governance: Arc::new(std::sync::RwLock::new(HashMap::new())),
            balances: Arc::new(std::sync::RwLock::new(HashMap::new())),
            time_warp: TimeWarp::default(),
            block_sender,
            pending_transactions: Arc::new(std::sync::RwLock::new(HashMap::<String, TxRequest>::new())),
            block_counts: Arc::new(std::sync::RwLock::new(HashMap::new())),
            vm: vm.clone(),
            last_block_hash: Arc::new(std::sync::RwLock::new(None)),
            validators: Arc::new(std::sync::RwLock::new(Vec::new())),
        });

        // Passe l'Arc<storage> ici
        let rpc_service = UltrachainRpcService::new(
            8080,
            "http://0.0.0.0:8080".to_string(),
            "ws://0.0.0.0:8080".to_string(),
            ultrachain_service.clone(),
            storage.clone(), // <-- Passe l'objet, PAS le chemin
            block_receiver,
            lurosonie_manager.clone(),
        );

        let engine_platform = Arc::new(EnginePlatform::new(
            "vyftultrachain".to_string(),
            vec![],
            rpc_service.clone(),
            vm.clone(),
        ));

        // Créer et émettre le bloc genesis
        println!("Creating genesis block...");
        let genesis_block = TimestampRelease {
            timestamp: Utc::now(),
            log: "Genesis block created".to_string(),
            block_number: 0,
            vyfties_id: "genesis".to_string(),
        };
    
        // Ajouter le bloc genesis à la chaîne
        lurosonie_manager.add_block_to_chain(genesis_block.clone(), None).await;
        println!("Genesis block added to the chain: {:?}", genesis_block);

        // Démarrer le serveur RPC avec EnginePlatform
        engine_platform.start_server().await;
        println!("Démarrage ou arrêt d'Ultrachain");

        // Maintenir l'application active
        tokio::signal::ctrl_c().await.expect("Failed to listen for Ctrl+C");
        println!("Arrêt de la blockchain Ultrachain...");
    }