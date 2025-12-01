use anyhow::Result;
use goblin::elf::Elf;
use uvm_runtime::interpreter;
use std::collections::BTreeMap;
use serde::{Deserialize, Serialize};
use std::hash::{Hash, DefaultHasher};
use std::sync::{Arc, RwLock, Mutex};
use lazy_static::lazy_static;
use vuc_storage::storing_access::RocksDBManager;
use hashbrown::{HashSet, HashMap};
use std::sync::TryLockError;
use hex; // <-- ajout pour décoder le hex du bytecode
use sha3::{Digest, Keccak256};

pub type NerenaValue = serde_json::Value;

// ============================================================================
// HELPERS POUR DÉCODAGE/ENCODAGE (PLACÉS EN DÉBUT DE FICHIER)
// ============================================================================

/// ✅ Helpers pour décodage/encodage
fn decode_address_from_register(reg_value: u64) -> String {
    if reg_value == 0 {
        return "*system*#default#".to_string();
    }
    
    // Logique de décodage d'adresse depuis registre
    format!("*addr_{}*#decoded#", reg_value)
}

fn encode_string_to_u64(s: &str) -> u64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    
    let mut hasher = DefaultHasher::new();
    s.hash(&mut hasher);
    hasher.finish()
}

fn decode_u64_to_address(value: u64) -> String {
    format!("*decoded_{}*#address#", value)
}

fn decode_u64_to_string(value: u64) -> Option<String> {
    // Conversion basique - peut être améliorée
    if value == encode_string_to_u64("VEZ") {
        Some("VEZ".to_string())
    } else if value == encode_string_to_u64("Vyft enhancing ZER") {
        Some("Vyft enhancing ZER".to_string())
    } else {
        Some(format!("decoded_{}", value))
    }
}

/// ✅ Fonction helper pour calculer les sélecteurs
fn calculate_function_selector(function_name: &str) -> u32 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    
    let mut hasher = DefaultHasher::new();
    function_name.hash(&mut hasher);
    (hasher.finish() & 0xFFFFFFFF) as u32
}

fn solidity_selector(signature: &str) -> [u8; 4] {
    let mut hasher = Keccak256::new();
    hasher.update(signature.as_bytes());
    let hash = hasher.finalize();
    [hash[0], hash[1], hash[2], hash[3]]
}

// ============================================================================
// TYPES UVM UNIVERSELS (DÉPLACÉS AVANT LES STRUCTURES)
// ============================================================================

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Address(pub String);

impl Address {
    pub fn new(addr: &str) -> Self {
        Address(addr.to_string())
    }
    
    pub fn as_str(&self) -> &str {
        &self.0
    }
    
    // ✅ AJOUT: Validation UIP-10
    pub fn is_valid(&self) -> bool {
        // Validation basique - peut être améliorée
        self.0.contains("*") && self.0.contains("#")
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Signer {
    pub address: Address,
    // ✅ AJOUT: Métadonnées UVM
    pub nonce: u64,
    pub gas_limit: u64,
    pub gas_price: u64,
}

impl Signer {
    pub fn new(addr: &str) -> Self {
        Signer { 
            address: Address::new(addr),
            nonce: 0,
            gas_limit: 1000000,
            gas_price: 1,
        }
    }
    
    pub fn address(&self) -> &Address {
        &self.address
    }
}

// ============================================================================
// STRUCTURES COMPATIBLES ARCHITECTURE BASÉE SUR PILE UVM
// ============================================================================

#[derive(Clone)]
pub struct Module {
    pub name: String,
    pub address: String,
    pub bytecode: Vec<u8>,
    pub elf_buffer: Vec<u8>,
    pub context: uvm_runtime::UbfContext,
    pub stack_usage: Option<uvm_runtime::stack::StackUsage>,
    pub functions: HashMap<String, FunctionMetadata>,
    // ✅ AJOUT: Métadonnées UVM étendues
    pub gas_estimates: HashMap<String, u64>,
    pub storage_layout: HashMap<String, StorageSlot>,
    pub events: Vec<EventDefinition>,
    pub constructor_params: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct FunctionMetadata {
    pub name: String,
    pub offset: usize,
    pub is_view: bool,
    pub args_count: usize,
    pub return_type: String,
    // ✅ AJOUT: Métadonnées compatibles UVM
    pub gas_limit: u64,
    pub payable: bool,
    pub mutability: String,
    pub selector: u32,
    // ✅ AJOUT: Types d'arguments (pour validation et encodage)
    pub arg_types: Vec<String>,
}

// ✅ AJOUT: Structures pour compatibilité UVM
#[derive(Clone, Debug)]
pub struct StorageSlot {
    pub name: String,
    pub slot: u32,
    pub offset: u32,
    pub size: u32,
    pub type_info: String,
}

#[derive(Clone, Debug)]
pub struct EventDefinition {
    pub name: String,
    pub signature: String,
    pub indexed_params: Vec<String>,
    pub data_params: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccountState {
    pub address: String,
    pub balance: u128,
    pub contract_state: Vec<u8>,
    pub resources: BTreeMap<String, serde_json::Value>,
    pub state_version: u64,
    pub last_block_number: u64,
    // ✅ AJOUT: Champs compatibles UVM
    pub nonce: u64,
    pub code_hash: String,
    pub storage_root: String,
    pub is_contract: bool,
    pub gas_used: u64,
}

#[derive(Default, Clone)]
pub struct VmState {
    pub accounts: Arc<RwLock<BTreeMap<String, AccountState>>>,
    // ✅ AJOUT: État mondial UVM
    pub world_state: Arc<RwLock<UvmWorldState>>,
    pub pending_logs: Arc<RwLock<Vec<UvmLog>>>,
    pub gas_price: u64,
    pub block_info: Arc<RwLock<BlockInfo>>,
}

// ✅ AJOUT: Structures d'état mondial UVM
#[derive(Clone, Debug)]
pub struct UvmWorldState {
    pub accounts: HashMap<String, UvmAccountState>,
    pub storage: HashMap<String, HashMap<String, Vec<u8>>>,
    pub code: HashMap<String, Vec<u8>>,
    pub balances: HashMap<String, u64>,
}

#[derive(Clone, Debug)]
pub struct UvmAccountState {
    pub balance: u64,
    pub nonce: u64,
    pub code_hash: String,
    pub storage_root: String,
}

#[derive(Clone, Debug)]
pub struct UvmLog {
    pub address: String,
    pub topics: Vec<String>,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct BlockInfo {
    pub number: u64,
    pub timestamp: u64,
    pub gas_limit: u64,
    pub gas_used: u64,
    pub difficulty: u64,
    pub coinbase: String,
}

impl Default for UvmWorldState {
    fn default() -> Self {
        UvmWorldState {
            accounts: HashMap::new(),
            storage: HashMap::new(),
            code: HashMap::new(),
            balances: HashMap::new(),
        }
    }
}

impl Default for BlockInfo {
    fn default() -> Self {
        BlockInfo {
            number: 1,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            gas_limit: 30000000,
            gas_used: 0,
            difficulty: 1,
            coinbase: "*coinbase*#miner#".to_string(),
        }
    }
}

// ✅ AJOUT: Structures pour le déploiement de contrats
#[derive(Clone, Debug)]
pub struct ContractDeploymentArgs {
    pub deployer: String,
    pub bytecode: Vec<u8>,
    pub constructor_args: Vec<serde_json::Value>,
    pub gas_limit: u64,
    pub value: u64,
    pub salt: Option<Vec<u8>>, // Pour CREATE2
}

#[derive(Clone, Debug)]
pub struct DeploymentResult {
    pub contract_address: String,
    pub transaction_hash: String,
    pub gas_used: u64,
    pub deployment_cost: u64,
}

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
    DAO,
    Upgradeable,
}

impl Default for OwnershipType {
    fn default() -> Self {
        OwnershipType::SingleOwner
    }
}

/// ✅ Structure pour paramètres du jeton natif
#[derive(Clone, Debug)]
pub struct NativeTokenParams {
    pub name: String,
    pub symbol: String,
    pub decimals: u8,
    pub total_supply: u64,
    pub mintable: bool,
    pub burnable: bool,
}

impl Default for NativeTokenParams {
    fn default() -> Self {
        NativeTokenParams {
            name: "Vyft Enhancing ZER".to_string(),
            symbol: "VEZ".to_string(),
            decimals: 18,
            total_supply: 1_000_000,
            mintable: true,
            burnable: false,
        }
    }
}

// ✅ CORRECTION: Interpréteur avec compatibilité UVM
pub struct SimpleInterpreter {
    pub helpers: HashMap<u32, fn(u64, u64, u64, u64, u64) -> u64>,
    pub allowed_memory: HashSet<std::ops::Range<u64>>,
    pub uvm_helpers: HashMap<u32, fn(u64, u64, u64, u64, u64) -> u64>, // <-- clé u32 et type fn
    pub last_storage: Option<HashMap<String, Vec<u8>>>,
}

impl SimpleInterpreter {
    pub fn new() -> Self {
        let mut interpreter = SimpleInterpreter {
            helpers: HashMap::new(),
            allowed_memory: HashSet::new(),
            uvm_helpers: HashMap::new(),
            last_storage: None,
        };
        interpreter.setup_uvm_helpers();
        interpreter
    }

    fn setup_uvm_helpers(&mut self) {
        // balance(address)
        self.uvm_helpers.insert(
            calculate_function_selector("balance"),
            |a, _, _, _, _| {
                // logiquement, a = adresse encodée
                0 // Placeholder
            }
        );
        // transfer(address, amount)
        self.uvm_helpers.insert(
            calculate_function_selector("transfer"),
            |to, amount, _, _, _| {
                1 // Succès
            }
        );
        // approve(address, amount)
        self.uvm_helpers.insert(
            calculate_function_selector("approve"),
            |spender, amount, _, _, _| {
                1 // Succès
            }
        );
    }

    pub fn get_last_storage(&self) -> Option<&HashMap<String, Vec<u8>>> {
        self.last_storage.as_ref()
    }

    pub fn execute_program(
        &mut self,
        bytecode: &[u8],
        args: &uvm_runtime::interpreter::InterpreterArgs,
        stack_usage: Option<&uvm_runtime::stack::StackUsage>,
        vm_state: Arc<RwLock<BTreeMap<String, AccountState>>>,
        return_type: Option<&str>,
    ) -> Result<serde_json::Value, String> {
    let mem = [0u8; 4096];
    let mbuff = &args.state_data;
    let exports: HashMap<u32, usize> = HashMap::new();

    // --- PATCH SYNCHRO STORAGE ---
    // 1. Récupère le storage du compte cible
    let mut storage_map: hashbrown::HashMap<String, hashbrown::HashMap<String, Vec<u8>>> = hashbrown::HashMap::new();
    if let Ok(accounts) = vm_state.read() {
        if let Some(account) = accounts.get(&args.contract_address) {
            let mut contract_storage = hashbrown::HashMap::new();
            for (k, v) in &account.resources {
                // On ne prend que les slots EVM (clé = 64 hex chars)
                if k.len() == 64 {
                    if let Some(s) = v.as_str() {
                        // Si c'est une string hex, décode-la
                        if let Ok(bytes) = hex::decode(s) {
                            contract_storage.insert(k.clone(), bytes);
                        }
                    } else if let Some(n) = v.as_u64() {
                        // Encode en 32 bytes big endian
                        let mut bytes = vec![0u8; 32];
                        bytes[24..].copy_from_slice(&n.to_be_bytes());
                        contract_storage.insert(k.clone(), bytes);
                    }
                }
            }
            storage_map.insert(args.contract_address.clone(), contract_storage);
        }
    }

    // 2. Passe ce storage à l'interpréteur via un champ du contexte (à adapter dans interpreter.rs si besoin)
    // Pour cela, tu dois modifier interpreter.rs pour accepter un storage initial dans UvmWorldState

    // --- FIN PATCH SYNCHRO STORAGE ---

    interpreter::execute_program(
        Some(bytecode),
        stack_usage,
        &mem,
        mbuff,
        &self.uvm_helpers,
        &self.allowed_memory,
        return_type,
        &exports,
        args,
        Some(storage_map), // <-- passe le vrai storage ici
    ).map_err(|e| e.to_string())
}
}

pub struct SlurachainVm {
    pub state: VmState,
    pub modules: BTreeMap<String, Module>,
    pub address_map: BTreeMap<String, String>,
    pub interpreter: Arc<Mutex<SimpleInterpreter>>,
    pub storage_manager: Option<Arc<dyn RocksDBManager>>,
    // ✅ AJOUT: Configuration UVM
    pub gas_price: u64,
    pub chain_id: u64,
    pub debug_mode: bool,
}

impl SlurachainVm {
    pub fn new() -> Self {
        let mut vm = SlurachainVm {
            state: VmState::default(),
            modules: BTreeMap::new(),
            address_map: BTreeMap::new(),
            interpreter: Arc::new(Mutex::new(SimpleInterpreter::new())),
            storage_manager: None,
            gas_price: 1,
            chain_id: 45056,
            debug_mode: true,
        };

        // Ajoute le module EVM générique pour le déploiement
        let mut functions = HashMap::new();
        functions.insert("deploy".to_string(), FunctionMetadata {
            name: "deploy".to_string(),
            offset: 0, // L'opcode CREATE sera appelé directement
            is_view: false,
            args_count: 2, // [bytecode, value]
            return_type: "address".to_string(),
            gas_limit: 3_000_000,
            payable: true,
            mutability: "nonpayable".to_string(),
            selector: 0, // Pas utilisé ici
            arg_types: vec![],
        });
        vm.modules.insert("evm".to_string(), Module {
            name: "evm".to_string(),
            address: "evm".to_string(),
            bytecode: vec![], // Pas de bytecode, c'est un pseudo-module
            elf_buffer: vec![],
            context: uvm_runtime::UbfContext::new(),
            stack_usage: None,
            functions,
            gas_estimates: HashMap::new(),
            storage_layout: HashMap::new(),
            events: vec![],
            constructor_params: vec!["bytes".to_string(), "uint256".to_string()],
        });

        vm
    }

    /// Configure le gestionnaire de stockage
    pub fn set_storage_manager(&mut self, storage: Arc<dyn RocksDBManager>) {
        self.storage_manager = Some(storage);
    }

    /// ✅ Extraction d'adresse depuis un chemin de module
    fn extract_address(module_path: &str) -> &str {
        // Si le chemin contient déjà une adresse UIP-10, l'extraire
        if module_path.contains("*") && module_path.contains("#") {
            return module_path;
        }
        
        // Sinon, utiliser le chemin comme adresse
        module_path
    }

    /// ✅ AJOUT: Vérification de module et fonction
    pub fn verify_module_and_function(&self, module_path: &str, function_name: &str) -> Result<(), String> {
        let vyid = Self::extract_address(module_path);
        
        // Vérification que le module existe
        if !self.modules.contains_key(vyid) {
            return Err(format!("Module/Contrat '{}' non déployé", vyid));
        }
        
        // Vérification que la fonction existe
        let module = &self.modules[vyid];
        if !module.functions.contains_key(function_name) {
            return Err(format!("Fonction '{}' non trouvée dans le module '{}'", function_name, vyid));
        }
        
        Ok(())
    }

    /// ✅ Point d'entrée principal UVM avec gestion COMPLÈTE des contrats
    pub fn execute_module(
        &mut self,
        module_path: &str,
        function_name: &str,
        mut args: Vec<NerenaValue>, // <-- mut pour modifier
        sender_vyid: Option<&str>,
    ) -> Result<NerenaValue, String> {
        let vyid = Self::extract_address(module_path);
        let sender = sender_vyid.unwrap_or("*system*#default#");

        // Protection anti-récursion VEZ transfer
        if vyid == "0xe3cf7102e5f8dfd6ec247daea8ca3e96579e8448"
            && function_name == "transfer"
            && args.get(0).and_then(|v| v.as_str()) == Some("0xe3cf7102e5f8dfd6ec247daea8ca3e96579e8448")
        {
            return Err("Boucle infinie détectée : transfert vers le contrat VEZ interdit".to_string());
        }

        // Protection anti-overflow : limite la profondeur d'appel
        let call_depth = args.get(2).and_then(|v| v.as_u64()).unwrap_or(0);
        if call_depth > 2 {
            return Err("Overflow d'appels détecté : profondeur d'appel trop élevée".to_string());
        }

        // Incrémente la profondeur d'appel AVANT tout appel interne
        let call_depth = call_depth; // reuse previous value
        let next_call_depth = call_depth + 1;
        let mut args = args.clone(); // clone to take ownership

        // Vérification du compte, puis on libère le verrou immédiatement
        {
            let accounts = match self.state.accounts.try_read() {
                Ok(guard) => guard,
                Err(_) => return Err("Verrou VM bloqué, réessayez plus tard".to_string()),
            };
            ensure_account_exists(&accounts, sender)?;
        }

        if self.debug_mode {
            println!("🔧 EXÉCUTION MODULE UVM");
            println!("   Module: {}", vyid);
            println!("   Fonction: {}", function_name);
            println!("   Arguments: {:?}", args);
            println!("   Sender: {}", sender);
        }

        // --- GESTION UNIVERSELLE DES VIEWS EVM (support Uniswap, ERC20, customs) ---
        if vyid.starts_with("0x") && vyid.len() == 42 && function_name == "totalSupply" {
            if let Ok(accounts) = self.state.accounts.read() {
                if let Some(account) = accounts.get(vyid) {
                    // 1. Cherche dans resources (clé = nom de la fonction)
                    if let Some(val) = account.resources.get(function_name) {
                        return Ok(val.clone());
                    }
                }
            }
            // Si rien trouvé, retourne null (ou adapte selon besoin)
            return Ok(serde_json::Value::Null);
        }

        // ✅ VALIDATION: Vérification que le module/contrat existe
        let contract_module_exists = self.modules.get(vyid)
            .ok_or_else(|| format!("Module/Contrat '{}' non déployé ou non trouvé", vyid))?;

        // ✅ VALIDATION: La fonction DOIT être définie dans le contrat
        let function_meta_exists = contract_module_exists.functions.get(function_name)
            .ok_or_else(|| format!("Fonction '{}' non trouvée dans le contrat '{}'", function_name, vyid))?
            .clone();

        // Correction automatique de l'offset si absent ou 0 (hors constructor/init)
        let mut function_meta = function_meta_exists.clone();
    

        // --- Résolution stricte de l'offset ---
        let is_proxy = {
            let accounts = self.state.accounts.read().unwrap();
            accounts.get(vyid)
                .and_then(|acc| acc.resources.get("implementation"))
                .is_some()
        };

        // Correction : pour un proxy EVM, on démarre TOUJOURS à l'offset 0 (convention EVM)
        if !is_proxy && function_meta.offset == 0 {
            let module_bytecode = &contract_module_exists.bytecode;
            if let Some(offset) = find_function_offset_in_bytecode(module_bytecode, function_meta.selector) {
                if self.debug_mode {
                    println!("🟢 [DEBUG] Offset résolu pour '{}': {}", function_name, offset);
                }
                function_meta.offset = offset;
            } else {
                return Err(format!(
                    "Offset de fonction '{}' introuvable dans le bytecode (aucune exécution à l'offset 0 autorisée)",
                    function_name
                ));
            }
        }
        // Pour un proxy, on laisse offset = 0 (démarrage à 0, EVM-style)

        // ✅ VALIDATION: Arguments conformes aux spécifications du contrat
        let mut args_for_check = args.clone();
        // Ignore le call_depth si présent en dernier argument
        if args_for_check.len() > function_meta.args_count {
            args_for_check.truncate(function_meta.args_count);
        }
        if args_for_check.len() < function_meta.args_count {
            // Complète avec Null jusqu'à 1000 max
            while args_for_check.len() < function_meta.args_count && args_for_check.len() < 1000 {
                args_for_check.push(serde_json::Value::Null);
            }
        }
        if args_for_check.len() > 1000 {
            return Err("Trop d'arguments (max 1000)".to_string());
        }
        if args_for_check.len() != function_meta.args_count {
            return Err(format!("Arguments incorrects pour '{}': attendu {}, reçu {}", 
                             function_name, function_meta.args_count, args_for_check.len()));
        }

        // ✅ CHARGEMENT: État complet du contrat depuis le stockage
        let contract_state = self.load_complete_contract_state(vyid)?;

        // ✅ PRÉPARATION: Arguments d'exécution basés sur le contrat
        let mut interpreter_args = self.prepare_contract_execution_args(
            vyid, function_name, args.clone(), sender, &function_meta, contract_state
        )?;

        // CORRECTION ICI : renseigne l'offset pour les non-proxy
        if !is_proxy {
            interpreter_args.function_offset = Some(function_meta.offset);
        } else {
            interpreter_args.function_offset = Some(0);
        }

        // Synchronisation du bytecode du module avec l'état du compte si besoin (EVM)
        if vyid.starts_with("0x") && vyid.len() == 42 {
            if let Ok(accounts) = self.state.accounts.read() {
                if let Some(account) = accounts.get(vyid) {
                    if !account.contract_state.is_empty() {
                        if let Some(module_mut) = self.modules.get_mut(vyid) {
                            module_mut.bytecode = account.contract_state.clone();
                            if self.debug_mode {
                                println!("🟢 [DEBUG] Bytecode EVM synchronisé depuis l'état du compte ({} octets)", module_mut.bytecode.len());
                            }
                        }
                    }
                }
            }
        }

        // Calculate gas_fee before using it
        let gas_limit = function_meta.gas_limit;
        let gas_price = self.gas_price;
        let gas_fee = gas_limit * gas_price;

        // Protection anti-boucle de fees
        if vyid == "0xe3cf7102e5f8dfd6ec247daea8ca3e96579e8448" && function_name == "transfer" {
            // On n'applique pas de frais sur le transfert de fees lui-même
        } else if gas_fee > 0 {
            let fee_recipient = "0x53ae54b11251d5003e9aa51422405bc35a2ef32d";
            let sender_lc = sender.to_lowercase();
            // Récupère le call_depth courant
            let call_depth = args.get(2).and_then(|v| v.as_u64()).unwrap_or(0);

            // Correction : arguments explicites pour transfer(address,uint256)
            let transfer_args = vec![
                serde_json::Value::String(fee_recipient.to_string()), // to (address)
                serde_json::Value::String(gas_fee.to_string()),       // amount (uint256 sous forme de string)
            ];
            let vez_contract_addr = "0xe3cf7102e5f8dfd6ec247daea8ca3e96579e8448";
            let _ = self.execute_module(
                vez_contract_addr,
                "transfer",
                transfer_args,
                Some(sender),
            );
        }

        // ✅ EXÉCUTION: Dans le contexte complet du contrat (MÊME POUR L'INITIALISATION)
        let mut interpreter = self.interpreter.lock().map_err(|e| format!("Erreur lock interpréteur: {}", e))?;
        let function_meta_cloned = function_meta.clone();
        // Clone the contract module before any mutable borrow of self
        let contract_module_cloned = self.modules.get(vyid).cloned().ok_or_else(|| format!("Module/Contrat '{}' non déployé ou non trouvé", vyid))?;
        // Compute result and clone interpreter_args/result before any mutable borrow of self
        let (interpreter_args_clone, result_clone) = {
            let result = {
                let accounts_read = self.state.accounts.read().unwrap();
                // Gestion proxy (delegate) : si le compte a une implémentation, on exécute sur l'implémentation            
                if let Some(proxy_account) = accounts_read.get(vyid) {
                    if let Some(serde_impl) = proxy_account.resources.get("implementation") {
                        let impl_addr = serde_impl.as_str().unwrap_or("");
                        // Clone the implementation module before use
                        let impl_module_cloned = self.modules.get(impl_addr).cloned();
                        if let Some(impl_module) = impl_module_cloned {
                            // Utilise le FunctionMetadata de l’implémentation !
                            let impl_function_meta = impl_module.functions.get(function_name)
                                .ok_or_else(|| format!("Fonction '{}' non trouvée dans l'implémentation '{}'", function_name, impl_addr))?;
                            let offset = if impl_function_meta.offset == 0 {
                                find_function_offset_in_bytecode(&impl_module.bytecode, impl_function_meta.selector)
                                    .ok_or_else(|| format!("Offset de '{}' introuvable dans l'impl '{}'", function_name, impl_addr))?
                            } else {
                                impl_function_meta.offset
                            };
                    
                            let mut delegate_args = interpreter_args.clone();
                            delegate_args.contract_address = vyid.to_string(); // storage = proxy
                            delegate_args.state_data = interpreter_args.state_data.clone(); // calldata inchangé
                            // Utiliser l'offset résolu pour l'implémentation (pas 0)
                            delegate_args.function_offset = Some(offset);
                            let raw_result = interpreter.execute_program(
                                &impl_module.bytecode,
                                &delegate_args,
                                impl_module.stack_usage.as_ref().or(contract_module_cloned.stack_usage.as_ref()),
                                self.state.accounts.clone(),
                                Some(impl_function_meta.return_type.as_str()),
                            ).map_err(|e| e.to_string())?;
                            
                            // Ajoute ce bloc pour formater le résultat comme EVM (hex string)
                            return self.format_contract_function_result(raw_result, &delegate_args, impl_function_meta);
                        }
                    }
                }
                // Sinon, exécution normale sur le module courant
                interpreter.execute_program(
                    &contract_module_cloned.bytecode,
                    &interpreter_args,
                    contract_module_cloned.stack_usage.as_ref(),
                    self.state.accounts.clone(),
                    Some(function_meta_cloned.return_type.as_str()),
                ).map_err(|e| e.to_string())?
            };
            (interpreter_args.clone(), result.clone())
        };

        if self.debug_mode {
            println!("✅ Contrat '{}' fonction '{}' exécutée avec succès", vyid, function_name);
            println!("   Résultat: {:?}", result_clone);
        }

        // Après exécution et calcul du gas utilisé (par exemple après result = self.execute_contract_function(...)?;)
        // Suppose que gas_used est accessible (sinon, adapte pour le récupérer depuis l’interpréteur)
        let gas_used = gas_limit; // Remplace par la vraie valeur si possible

        {
            let mut accounts = match self.state.accounts.try_write() {
                Ok(guard) => guard,
                Err(_) => return Err("Verrou VM bloqué, réessayez plus tard".to_string()),
            };
            let sender_lc = sender.to_lowercase();
            let vez_contract_addr = "0xe3cf7102e5f8dfd6ec247daea8ca3e96579e8448";
            // Rembourse le gas non utilisé
            let gas_fee_used = gas_price * gas_used;
            let gas_fee_initial = gas_price * gas_limit;
            let refund = gas_fee_initial.saturating_sub(gas_fee_used);
            if refund > 0 {
                if let Some(vez) = accounts.get_mut(vez_contract_addr) {
                    let key = format!("balance_{}", sender_lc);
                    let sender_balance = vez.resources.get(&key).and_then(|v| v.as_u64()).unwrap_or(0);
                    vez.resources.insert(key.clone(), serde_json::Value::Number(serde_json::Number::from(sender_balance + refund)));
                }
            }
        }

        // Synchronisation du storage EVM modifié vers l'état du compte
        if let Ok(mut accounts) = self.state.accounts.try_write() {
            if let Some(account) = accounts.get_mut(vyid) {
                // Récupère le storage modifié depuis l'interpréteur
                if let Some(storage_map) = interpreter.get_last_storage() {
                    for (slot, value) in storage_map.iter() {
                        // Stocke chaque slot modifié dans resources (clé = slot 64 hex)
                        account.resources.insert(slot.clone(), serde_json::Value::String(hex::encode(value)));
                    }
                }
            }
        }

        // ...dans execute_module, après la synchronisation du storage EVM modifié vers l'état du compte...
        if let Some(storage_manager) = &self.storage_manager {
            if let Ok(accounts) = self.state.accounts.read() {
                if let Some(account) = accounts.get(vyid) {
                    // On ne stocke que les slots EVM (clé = 64 hex)
                    for (slot, value) in account.resources.iter() {
                        if slot.len() == 64 {
                            if let Some(val_str) = value.as_str() {
                                // Persiste dans RocksDB (clé = "vyid:slot")
                                let db_key = format!("{}:{}", vyid, slot);
                                let _ = storage_manager.write(&db_key, val_str.as_bytes().to_vec());
                            }
                        }
                    }
                }
            }
        }

        Ok(result_clone)
    }

     /// ✅ AMÉLIORATION: Chargement complet de l'état du contrat depuis le stockage
    fn load_complete_contract_state(&self, contract_address: &str) -> Result<Vec<u8>, String> {
        if let Ok(accounts) = self.state.accounts.read() {
            if let Some(account) = accounts.get(contract_address) {
                // ✅ Sérialisation complète de l'état du contrat
                let mut state_data = Vec::new();
                
                // ✅ Métadonnées de base
                state_data.extend_from_slice(&account.balance.to_le_bytes());
                state_data.extend_from_slice(&account.nonce.to_le_bytes());
                state_data.extend_from_slice(&account.state_version.to_le_bytes());
                
                // ✅ Sérialisation des resources (état étendu)
                if let Ok(resources_bytes) = serde_json::to_vec(&account.resources) {
                    state_data.extend_from_slice(&(resources_bytes.len() as u32).to_le_bytes());
                    state_data.extend_from_slice(&resources_bytes);
                }
                
                // ✅ Padding pour alignement
                while state_data.len() % 8 != 0 {
                    state_data.push(0);
                }
                
                return Ok(state_data);
            }
        }
        
        // ✅ État par défaut si contrat non trouvé
        Ok(vec![0u8; 1024])
    }

    /// ✅ AMÉLIORATION: Exécution de fonction contrat avec VIEW spécialisé
    pub fn execute_contract_function(
        &self,
        contract_address: &str,
        args: &uvm_runtime::interpreter::InterpreterArgs,
    ) -> Result<NerenaValue, String> {
        
        // ✅ Récupération du module contrat
        let contract_module = self.modules.get(contract_address)
            .ok_or_else(|| format!("Module contrat '{}' non trouvé", contract_address))?;

        // ✅ Récupération des métadonnées de fonction
        let accounts_read = self.state.accounts.read().unwrap();
        let proxy_account_opt = accounts_read.get(contract_address);

        let function_meta = contract_module.functions.get(&args.function_name)
            .or_else(|| {
                // Si non trouvée dans le proxy, cherche dans l'implémentation
                if let Some(proxy_account) = proxy_account_opt {
                    if let Some(impl_addr) = proxy_account.resources.get("implementation").and_then(|v| v.as_str()) {
                        self.modules.get(impl_addr)?.functions.get(&args.function_name)
                    } else { None }
                } else { None }
            })
            .ok_or_else(|| format!("Fonction '{}' non trouvée dans le contrat ou l'implémentation", args.function_name))?;

        let mut interpreter = self.interpreter.lock()
            .map_err(|e| format!("Erreur lock interpréteur: {}", e))?;

        let result = {
            let accounts_read = self.state.accounts.read().unwrap();
            if let Some(proxy_account) = accounts_read.get(contract_address) {
                if let Some(serde_impl) = proxy_account.resources.get("implementation") {
                    if let Some(impl_addr) = serde_impl.as_str() {
                        if let Some(impl_module) = self.modules.get(impl_addr) {
                            let mut delegate_args = args.clone();
                            delegate_args.contract_address = contract_address.to_string();
                            return interpreter.execute_program(
                                &impl_module.bytecode,
                                &delegate_args,
                                impl_module.stack_usage.as_ref().or(contract_module.stack_usage.as_ref()),
                                self.state.accounts.clone(),
                                Some(function_meta.return_type.as_str()),
                            );
                        }
                    }
                }
            }
            interpreter.execute_program(
                &contract_module.bytecode,
                args,
                contract_module.stack_usage.as_ref(),
                self.state.accounts.clone(),
                Some(function_meta.return_type.as_str()),
            )
        }?;

        if self.debug_mode {
            println!("🎯 RÉSULTAT EXÉCUTION (de l'état du contrat):");
            println!("   Résultat brut: {:?}", result);
        }
        
        // ✅ Formatage du résultat selon le type de fonction
        self.format_contract_function_result(result, args, function_meta)
    }

    /// ✅ NOUVEAU: Gestion spécifique de l'initialisation du contrat
    fn handle_contract_initialization(
        &mut self,
        contract_address: &str,
        args: &uvm_runtime::interpreter::InterpreterArgs,
        _result: &NerenaValue,
    ) -> Result<(), String> {
        if self.debug_mode {
            println!("🔧 TRAITEMENT INITIALISATION CONTRAT");
            println!("   Contrat: {}", contract_address);
            println!("   Fonction: {}", args.function_name);
        }

        let (total_supply, account_addr_str, owner_addr_str) = if args.args.len() >= 3 {
            let supply = args.args[0].as_u64();
            let account = args.args[1].as_str().map(|s| s.to_string());
            let owner = args.args[2].as_str().map(|s| s.to_string());
            (supply, account, owner)
        } else {
            (None, None, None)
        };

        // Utilisation du verrou non bloquant
        if let Some(mut accounts) = try_accounts_write(&self.state.accounts) {
            if let Some(account) = accounts.get_mut(contract_address) {
                account.resources.insert("initialized".to_string(), serde_json::Value::Bool(true));
                account.resources.insert("initialization_block".to_string(), 
                    serde_json::Value::Number(serde_json::Number::from(args.block_number)));
                account.resources.insert("initializer".to_string(), 
                    serde_json::Value::String(args.sender_address.clone()));
                
                if contract_address == "0xe3cf7102e5f8dfd6ec247daea8ca3e96579e8448" {
                    if let Some(total_supply) = total_supply {
                        account.resources.insert("total_supply".to_string(), 
                            serde_json::Value::Number(serde_json::Number::from(total_supply)));
                        account.balance = total_supply as u128;
                    }
                    if let Some(ref account_addr_str) = account_addr_str {
                        account.resources.insert("initial_holder".to_string(), 
                            serde_json::Value::String(account_addr_str.clone()));
                    }
                    if let Some(owner_addr_str) = owner_addr_str {
                        account.resources.insert("owner".to_string(), 
                            serde_json::Value::String(owner_addr_str.clone()));
                        account.resources.insert(format!("allowed_{}", owner_addr_str), 
                            serde_json::Value::Bool(true));
                    }
                }
                account.state_version += 1;
            }
        } else {
            // Réponse immédiate si verrou non disponible
            return Ok(());
        }

        if contract_address == "0xe3cf7102e5f8dfd6ec247daea8ca3e96579e8448" {
            if let (Some(supply), Some(ref account_addr)) = (total_supply, account_addr_str) {
                self.transfer_initial_supply(contract_address, account_addr, supply)?;
            }
        }

        if self.debug_mode {
            println!("✅ Initialisation du contrat '{}' terminée", contract_address);
        }

        Ok(())
    }

fn prepare_contract_execution_args(
    &self,
    contract_address: &str,
    function_name: &str,
    args: Vec<NerenaValue>,
    sender: &str,
    function_meta: &FunctionMetadata,
    contract_state: Vec<u8>,
) -> Result<uvm_runtime::interpreter::InterpreterArgs, String> {

    let current_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let block_number = self.state.block_info.read()
        .map(|b| b.number)
        .unwrap_or(1);

    // =================================================================
    // 1. CALCUL DU VRAI SÉLECTEUR KECCAK256 (CELUI QU'ATTEND SOLIDITY)
    // =================================================================
    let arg_types_str = function_meta.arg_types.iter()
        .map(|s| s.trim())
        .collect::<Vec<_>>()
        .join(",");

    let full_signature = format!("{}({})", function_meta.name.trim(), arg_types_str);
    let keccak_hash = Keccak256::digest(full_signature.as_bytes());
    let real_selector = u32::from_be_bytes([keccak_hash[0], keccak_hash[1], keccak_hash[2], keccak_hash[3]]);

    if self.debug_mode {
        println!("FONCTION: {}", function_name);
        println!("SIGNATURE: {}", full_signature);
        println!("SÉLECTEUR KECCAK256 (réel): 0x{:08x}", real_selector);
    }

    // =================================================================
    // 2. ENCODAGE ABI DES ARGUMENTS
    // =================================================================
    use ethabi::{Token, encode};

    let tokens: Vec<Token> = function_meta.arg_types.iter().zip(&args).map(|(typ, val)| {
        match (typ.trim(), val) {
            ("address", serde_json::Value::String(s)) => {
                let addr = s.trim_start_matches("0x");
                let mut bytes = [0u8; 20];
                hex::decode_to_slice(addr, &mut bytes).ok();
                Token::Address(ethabi::Address::from(bytes))
            }
            ("uint256" | "uint", serde_json::Value::Number(n)) => Token::Uint(n.as_u64().unwrap_or(0).into()),
            ("uint256" | "uint", serde_json::Value::String(s)) => Token::Uint(s.parse::<u64>().unwrap_or(0).into()),
            ("string", serde_json::Value::String(s)) => Token::String(s.clone()),
            ("bool", serde_json::Value::Bool(b)) => Token::Bool(*b),
            _ => Token::String(val.to_string()),
        }
    }).collect();

    let encoded_args = encode(&tokens);
    let mut calldata = Vec::with_capacity(4 + encoded_args.len());
    calldata.extend_from_slice(&real_selector.to_be_bytes());
    calldata.extend_from_slice(&encoded_args);

    // =================================================================
    // 3. CONSTRUCTION DES ARGS D'INTERPRÉTATION
    // =================================================================
    Ok(uvm_runtime::interpreter::InterpreterArgs {
        function_name: function_name.to_string(),
        contract_address: contract_address.to_string(),
        sender_address: sender.to_string(),
        args,
        state_data: calldata,
        gas_limit: if contract_address == "0xe3cf7102e5f8dfd6ec247daea8ca3e96579e8448"
            && ["initialize", "init", "constructor"].contains(&function_name) { 10_000_000 } else { function_meta.gas_limit },
        gas_price: if contract_address == "0xe3cf7102e5f8dfd6ec247daea8ca3e96579e8448"
            && ["initialize", "init", "constructor"].contains(&function_name) { 0 } else { self.gas_price },
        value: 0,
        call_depth: 0,
        block_number,
        timestamp: current_time,
        caller: sender.to_string(),
        origin: sender.to_string(),
        beneficiary: sender.to_string(),
        function_offset: None,
        base_fee: Some(0),
        blob_base_fee: Some(0),
        blob_hash: Some([0u8; 32]),
        is_view: function_meta.is_view,
        // LE SÉLECTEUR RÉEL EST POUSSÉ SUR LA PILE → LE CONTRAT SOLIDITY LE VOIT EN DUP1
        evm_stack_init: Some(vec![real_selector as u64]),
    })
}

    /// ✅ AJOUT: Formatage du résultat de fonction contrat
    fn format_contract_function_result(
        &self,
        result: serde_json::Value,
        _args: &uvm_runtime::interpreter::InterpreterArgs,
        function_meta: &FunctionMetadata,
    ) -> Result<NerenaValue, String> {
        if self.debug_mode {
            println!("🎨 FORMATAGE RÉSULTAT");
            println!("   Type retour: {}", function_meta.return_type);
            println!("   Résultat brut: {:?}", result);
        }

        // Si le résultat est un objet JSON avec champ "return", l'utiliser
        let raw = if let Some(ret) = result.get("return") {
            ret.clone()
        } else {
            result.clone()
        };

        // Helper: renvoie hex "0x..." pour un u128/u256 impossible à représenter en JSON number
        fn u64_to_hex(v: u64) -> String { format!("0x{:x}", v) }
        fn bytes_to_hex_vec(bytes: &[u8]) -> String { format!("0x{}", hex::encode(bytes)) }

        // Helper principal : convertit dynamiquement raw -> valeur Solidity conforme au type `t`
        fn parse_sol_value(raw: &serde_json::Value, t: &str) -> serde_json::Value {
            // normaliser le type (ex: uint => uint256)
            let t = if t == "uint" { "uint256" } else if t == "int" { "int256" } else { t };
            if t == "string" {
                if let Some(s) = raw.as_str() {
                    // Encode en ABI (offset, length, data)
                    let bytes = s.as_bytes();
                    let mut abi = vec![];
                    abi.extend_from_slice(&[0u8; 32]); // offset (toujours 0 pour un seul retour)
                    abi.extend_from_slice(&(bytes.len() as u128).to_be_bytes()); // length (32 bytes)
                    abi.extend_from_slice(bytes); // data
                    // Padding à 32 bytes
                    while abi.len() % 32 != 0 { abi.push(0); }
                    return serde_json::Value::String(format!("0x{}", hex::encode(abi)));
                }
            }
            // uint<M>
            if t.starts_with("uint") {
                let bits = t[4..].parse::<usize>().unwrap_or(256);
                // raw as number?
                if bits > 64 {
                    // renvoyer hex string pour >64 bits
                    if let Some(s) = raw.as_str() {
                        if s.starts_with("0x") { return serde_json::Value::String(s.to_string()); }
                        if let Ok(n) = s.parse::<u128>() { return serde_json::Value::String(format!("0x{:x}", n)); }
                    }
                    if let Some(n) = raw.as_u64() { return serde_json::Value::String(u64_to_hex(n)); }
                    return serde_json::Value::String("0x0".to_string());
                } else {
                    // <= 64 bits -> nombre JSON natif
                    let mask = if bits == 64 { u64::MAX } else { ((1u128 << bits) - 1) as u64 };
                    if let Some(n) = raw.as_u64() { return serde_json::Value::Number(serde_json::Number::from(n & mask)); }
                    if let Some(s) = raw.as_str() {
                        // accepte "0x..." ou décimal
                        if s.starts_with("0x") {
                            if let Ok(n) = u64::from_str_radix(s.trim_start_matches("0x"), 16) {
                                return serde_json::Value::Number(serde_json::Number::from(n & mask));
                            }
                        } else if let Ok(n) = s.parse::<u64>() {
                            return serde_json::Value::Number(serde_json::Number::from(n & mask));
                        }
                    }
                    serde_json::Value::Number(serde_json::Number::from(0u64))
                }
            }
            // int<M>
            else if t.starts_with("int") {
                let bits = t[3..].parse::<usize>().unwrap_or(256);
                if bits > 64 {
                    // renvoyer hex string pour grands int
                    if let Some(s) = raw.as_str() {
                        if s.starts_with("0x") { return serde_json::Value::String(s.to_string()); }
                        if let Ok(n) = s.parse::<i128>() { return serde_json::Value::String(format!("0x{:x}", n as i128)); }
                    }
                    if let Some(n) = raw.as_i64() { return serde_json::Value::Number(serde_json::Number::from(n)); }
                    if let Some(nu) = raw.as_u64() {
                        // tenter conversion deux's complement si nécessaire
                        let sign_bit = 1u128 << (bits - 1);
                        let val = if (nu as u128) & sign_bit != 0 {
                            // négatif en two's complement
                            let raw128 = nu as i128;
                            // approximatif : on renvoie hex si trop grand
                            return serde_json::Value::String(format!("0x{:x}", nu));
                        } else {
                            return serde_json::Value::Number(serde_json::Number::from(nu as i64));
                        };
                    }
                    serde_json::Value::String("0x0".to_string())
                } else {
                    // <=64 bits : convertir en i64 natif
                    if let Some(n) = raw.as_i64() { return serde_json::Value::Number(serde_json::Number::from(n)); }
                    if let Some(nu) = raw.as_u64() {
                        let bits = bits as u32;
                        let sign_bit = 1u64 << (bits - 1);
                        let mask = if bits == 64 { u64::MAX } else { (1u64 << bits) - 1 };
                        let rawmasked = nu & mask;
                        if rawmasked & sign_bit != 0 {
                            // négatif
                            let signed = (rawmasked as i128) - (1i128 << bits);
                            return serde_json::Value::Number(serde_json::Number::from(signed as i64));
                        } else {
                            return serde_json::Value::Number(serde_json::Number::from(rawmasked as i64));
                        }
                    }
                    if let Some(s) = raw.as_str() {
                        if s.starts_with("0x") {
                            if let Ok(n) = i64::from_str_radix(&s[2.min(s.len())..], 16) {
                                return serde_json::Value::Number(serde_json::Number::from(n));
                            }
                        } else if let Ok(n) = s.parse::<i64>() {
                            return serde_json::Value::Number(serde_json::Number::from(n));
                        }
                    }
                    serde_json::Value::Number(serde_json::Number::from(0i64))
                }
            }
            // address
            else if t == "address" {
                if let Some(s) = raw.as_str() {
                    // si déjà hex-like retourne tel quel
                    if s.starts_with("0x") || s.starts_with("*") { return serde_json::Value::String(s.to_string()); }
                    return serde_json::Value::String(s.to_string());
                }
                if let Some(n) = raw.as_u64() { return serde_json::Value::String(u64_to_hex(n)); }
                serde_json::Value::String("0x0".to_string())
            }
            // bool
            else if t == "bool" {
                if let Some(b) = raw.as_bool() { return serde_json::Value::Bool(b); }
                if let Some(n) = raw.as_u64() { return serde_json::Value::Bool(n != 0); }
                if let Some(s) = raw.as_str() {
                    return serde_json::Value::Bool(s != "0" && s != "false" && !s.is_empty());
                }
                serde_json::Value::Bool(false)
            }
            // fixed / ufixed: renvoyer string hex ou number si petit
            else if t.starts_with("fixed") || t.starts_with("ufixed") {
                if let Some(s) = raw.as_str() { return serde_json::Value::String(s.to_string()); }
                if let Some(n) = raw.as_u64() { return serde_json::Value::Number(serde_json::Number::from(n)); }
                serde_json::Value::String("0x0".to_string())
            }
            // bytes<M> (statiques)
            else if t.starts_with("bytes") && t != "bytes" {
                // bytesN, N from 1..32
                if let Some(s) = raw.as_str() {
                    if s.starts_with("0x") { return serde_json::Value::String(s.to_string()); }
                    return serde_json::Value::String(format!("0x{}", hex::encode(s.as_bytes())));
                }
                if let Some(n) = raw.as_u64() { return serde_json::Value::String(u64_to_hex(n)); }
                if raw.is_array() {
                    // join bytes
                    let mut b = Vec::new();
                    for el in raw.as_array().unwrap() {
                        if let Some(v) = el.as_u64() { b.push(v as u8); }
                    }
                    return serde_json::Value::String(bytes_to_hex_vec(&b));
                }
                serde_json::Value::String("0x".to_string())
            }
            // dynamic bytes
            else if t == "bytes" {
                if let Some(s) = raw.as_str() {
                    if s.starts_with("0x") { return serde_json::Value::String(s.to_string()); }
                    return serde_json::Value::String(format!("0x{}", hex::encode(s.as_bytes())));
                }
                if raw.is_array() {
                    let mut b = Vec::new();
                    for el in raw.as_array().unwrap() {
                        if let Some(v) = el.as_u64() { b.push(v as u8); }
                    }
                    return serde_json::Value::String(bytes_to_hex_vec(&b));
                }
                if let Some(n) = raw.as_u64() { return serde_json::Value::String(u64_to_hex(n)); }
                serde_json::Value::String("0x".to_string())
            }
            // arrays / tuples (detection simple)
            else if t.contains('[') || t.starts_with("tuple") {
                if raw.is_array() { return raw.clone(); }
                // si raw est string JSON, tenter parser
                if let Some(s) = raw.as_str() {
                    if let Ok(v) = serde_json::from_str::<serde_json::Value>(s) { return v; }
                }
                // fallback: wrap la valeur dans un array
                return serde_json::Value::Array(vec![raw.clone()]);
            }
            // default: retourner tel quel
            else {
                raw.clone()
            }
        }

        let parsed = parse_sol_value(&raw, function_meta.return_type.as_str());
        Ok(parsed)
    }

    /// ✅ NOUVEAU: Transfert de la supply initiale lors de l'initialisation
    fn transfer_initial_supply(
        &mut self,
        contract_address: &str,
        recipient_address: &str,
        amount: u64,
    ) -> Result<(), String> {
        if self.debug_mode {
            println!("💰 TRANSFERT SUPPLY INITIALE");
            println!("   De: {} (contrat)", contract_address);
            println!("   Vers: {}", recipient_address);
            println!("   Montant: {}", amount);
        }

        // Utilisation du verrou non bloquant
        if let Some(mut accounts) = try_accounts_write(&self.state.accounts) {
            if let Some(contract_account) = accounts.get_mut(contract_address) {
                if contract_account.balance >= amount as u128 {
                    contract_account.balance -= amount as u128;
                    contract_account.state_version += 1;
                } else {
                    return Err(format!("Supply insuffisante dans le contrat: {} < {}", 
                                     contract_account.balance, amount));
                }
            }

            let recipient_account = accounts.entry(recipient_address.to_string()).or_insert_with(|| AccountState {
                address: recipient_address.to_string(),
                balance: 0,
                contract_state: vec![0u8; 4096],
                resources: BTreeMap::new(),
                state_version: 0,
                last_block_number: 0,
                nonce: 0,
                code_hash: String::new(),
                storage_root: String::new(),
                is_contract: false,
                gas_used: 0,
            });
            
            recipient_account.balance += amount as u128;
            recipient_account.state_version += 1;
            recipient_account.resources.insert("is_initial_holder".to_string(), serde_json::Value::Bool(true));
            recipient_account.resources.insert("initial_amount".to_string(), serde_json::Value::Number(serde_json::Number::from(amount)));

            if let Some(vez_contract) = accounts.get_mut(contract_address) {
                let balance_key = format!("balance_{}", recipient_address);
                vez_contract.resources.insert(balance_key, serde_json::Value::Number(serde_json::Number::from(amount)));
            }
        } else {
            // Réponse immédiate si verrou non disponible
            return Ok(());
        }

        if self.debug_mode {
            println!("✅ Transfert supply initiale réussi: {} vers {}", amount, recipient_address);
        }

        Ok(())
    }

    /// ✅ AJOUT: Chargement de l'état d'un contrat
    pub fn load_contract_state(&self, contract_address: &str) -> Result<Vec<u8>, String> {
        if let Ok(accounts) = self.state.accounts.read() {
            if let Some(account) = accounts.get(contract_address) {
                return Ok(account.contract_state.clone());
            }
        }
        
        // État par défaut si contrat non trouvé
        Ok(vec![0u8; 4096])
    }

    /// Transfert natif VEZ via le contrat ERC20 proxy
    pub fn vez_native_transfer(&mut self, from: &str, to: &str, amount: u64) -> Result<(), String> {
        let vez_contract_addr = "0xe3cf7102e5f8dfd6ec247daea8ca3e96579e8448";
        let transfer_args = vec![
            serde_json::Value::String(to.to_string()),
            serde_json::Value::Number(serde_json::Number::from(amount)),
        ];
        self.execute_module(
            vez_contract_addr,
            "transfer",
            transfer_args,
            Some(from),
        )?;
        Ok(())
    }
}

/// ✅ NOUVEAU: Interpréteur spécialisé pour les fonctions VIEW
pub struct SimpleInterpreterWithView {
    pub base_interpreter: SimpleInterpreter,
    pub contract_view_data: BTreeMap<String, serde_json::Value>,
    pub is_view_mode: bool,
    pub contract_address: String,
}

impl SimpleInterpreterWithView {
    pub fn new(
        contract_view_data: BTreeMap<String, serde_json::Value>,
        is_view_mode: bool,
        contract_address: String,
    ) -> Self {
        SimpleInterpreterWithView {
            base_interpreter: SimpleInterpreter::new(),
            contract_view_data,
            is_view_mode,
            contract_address,
        }
    }

    /// ✅ Exécution avec support VIEW complet
    pub fn execute_program_with_view_support(
        &self,
        bytecode: &[u8],
        args: &uvm_runtime::interpreter::InterpreterArgs,
        stack_usage: Option<&uvm_runtime::stack::StackUsage>,
        _vm_state: Arc<RwLock<BTreeMap<String, AccountState>>>,
        _function_meta: &FunctionMetadata,
    ) -> Result<serde_json::Value, String> {
        // Utilise hashbrown::HashMap au lieu de std::collections::HashMap
        let exports: hashbrown::HashMap<u32, usize> = hashbrown::HashMap::new();
        uvm_runtime::interpreter::execute_program(
            Some(bytecode),
            stack_usage,
            &[0u8; 4096],
            &args.state_data,
            &self.base_interpreter.uvm_helpers,
            &self.base_interpreter.allowed_memory,
            Some(args.function_name.as_str()),
            &exports,
            args,
            None // No initial storage provided for view support
        ).map_err(|e| e.to_string())
    }
}

/// ✅ Structure pour les informations de module
#[derive(Clone, Debug)]
pub struct ModuleInfo {
    pub address: String,
    pub name: String,
    pub bytecode_size: usize,
    pub function_count: usize,
    pub functions: Vec<String>,
    pub events: Vec<EventDefinition>,
    pub is_deployed: bool,
    pub account_state: Option<AccountState>,
}

/// ✅ Structure mise à jour pour les fonctions détectées
#[derive(Clone, Debug)]
struct DetectedFunction {
    pub name: String,
    pub selector: u32,
    pub offset: usize,
    pub args_count: usize,
    pub is_view: bool,
    pub return_type: String,
    pub gas_estimate: u64,
    pub payable: bool,
}

/// ✅ Structure mise à jour pour les événements détectés
#[derive(Clone, Debug)]
struct DetectedEvent {
    pub name: String,
    pub signature: String,
    pub indexed_params: Vec<String>,
    pub data_params: Vec<String>,
}

// Helper pour accès immédiat, jamais bloquant
fn try_accounts_write(accounts: &Arc<RwLock<BTreeMap<String, AccountState>>>) -> Option<std::sync::RwLockWriteGuard<'_, BTreeMap<String, AccountState>>> {
    match accounts.try_write() {
        Ok(guard) => Some(guard),
        Err(TryLockError::WouldBlock) => None,
        Err(_) => None,
    }
}

/// Recherche l'offset d'un selector dans le bytecode EVM (pattern PUSH4 <selector>)
fn find_function_offset_in_bytecode(bytecode: &[u8], selector: u32) -> Option<usize> {
    let selector_bytes = selector.to_be_bytes();
    let len = bytecode.len();
    let mut i = 0;
    while i + 4 < len {
        // PUSH4 = 0x63
        if bytecode[i] == 0x63 && &bytecode[i + 1..i + 5] == selector_bytes {
            // On cherche le JUMPDEST qui suit (pattern EVM standard)
            let mut j = i + 5;
            while j < len {
                if bytecode[j] == 0x5b { // JUMPDEST
                    return Some(j);
                }
                j += 1;
            }
        }
        i += 1;
    }
    None
}

/// Vérifie la présence d'un compte dans l'état VM, retourne une erreur si absent
pub fn ensure_account_exists(accounts: &BTreeMap<String, AccountState>, address: &str) -> Result<(), String> {
    if !accounts.contains_key(address) {
        return Err(format!("Compte '{}' introuvable dans l'état VM", address));
    }
    Ok(())
}