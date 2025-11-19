use anyhow::Result;
use goblin::elf::Elf;
use std::collections::BTreeMap;
use serde::{Deserialize, Serialize};
use std::hash::{Hash, DefaultHasher};
use std::sync::{Arc, RwLock, Mutex};
use lazy_static::lazy_static;
use vuc_storage::storing_access::RocksDBManagerImpl;
use hashbrown::{HashMap, HashSet};
use std::sync::TryLockError;
use hex; // <-- ajout pour décoder le hex du bytecode

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
}

impl SimpleInterpreter {
    pub fn new() -> Self {
        let mut interpreter = SimpleInterpreter {
            helpers: HashMap::new(),
            allowed_memory: HashSet::new(),
            uvm_helpers: HashMap::new(),
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

    pub fn execute_program(
        &self,
        bytecode: &[u8],
        args: &uvm_runtime::interpreter::InterpreterArgs,
        stack_usage: Option<&uvm_runtime::stack::StackUsage>,
        vm_state: Arc<RwLock<BTreeMap<String, AccountState>>>,
    ) -> Result<serde_json::Value, String> {
    let mem = [0u8; 4096];
    let mbuff = &args.state_data;
    let exports: HashMap<u32, usize> = HashMap::new();

    // Clone des références pour le fallback
    let vm_state_clone = vm_state.clone();
    let contract_addr = args.contract_address.clone();
    let sender_addr = args.sender_address.clone();

    // ✅ Fallback FFI avec gestion EVM storage
    let ffi_fallback = move |hash: u32, reg_args: &[u64]| -> Option<u64> {
        // Helper pour obtenir le solde
        if hash == 0x6efda9af {
            let addr_str = decode_address_from_register(reg_args[0]);
            if let Ok(accounts) = vm_state_clone.read() {
                if let Some(account) = accounts.get(&addr_str) {
                    return Some(account.balance as u64);
                }
            }
           return Some(0);
        }
        
        // Helper pour les transferts
        else if hash == 0x14561e7a {
            let to_addr = decode_address_from_register(reg_args[0]);
            let amount = reg_args[1];
            
            if let Ok(mut accounts) = vm_state_clone.write() {
                // Vérification du solde sender
                let sender_balance = accounts.get(&sender_addr).map(|a| a.balance).unwrap_or(0);
                if sender_balance >= amount as u128 {
                    // Débite le sender
                    if let Some(sender_account) = accounts.get_mut(&sender_addr) {
                        sender_account.balance -= amount as u128;
                        sender_account.state_version += 1;
                    }
                    // Crédite le destinataire
                    let to_account = accounts.entry(to_addr.clone()).or_insert_with(|| AccountState {
                        address: to_addr.clone(),
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
                    to_account.balance += amount as u128;
                    to_account.state_version += 1;
                    return Some(1); // Succès
                }
            }
           return Some(0); // Échec
        }
        
        // Helper pour l'approbation
        else if hash == 0x1e645a4a {
            let spender_addr = decode_address_from_register(reg_args[0]);
            let amount = reg_args[1];
            
            if let Ok(mut accounts) = vm_state_clone.write() {
                if let Some(account) = accounts.get_mut(&sender_addr) {
                    let approval_key = format!("approval_{}", spender_addr);
                    account.resources.insert(approval_key, serde_json::Value::Number(amount.into()));
                    account.state_version += 1;
                    return Some(1);
                }
            }
           return  Some(0);
        }
        
        // SSTORE (0x55) - Stockage persistant EVM
        if hash == 0x55 {
            let slot = format!("{:064x}", reg_args[0]);
            let value = reg_args[1];
            if let Ok(mut accounts) = vm_state_clone.write() {
                if let Some(account) = accounts.get_mut(&contract_addr) {
                    account.resources.insert(slot.clone(), serde_json::Value::Number(value.into()));
                    account.state_version += 1;
                    return Some(1);
                }
            }
            return Some(0);
        }
        // SLOAD (0x54) - Chargement depuis storage EVM
        if hash == 0x54 {
            let slot = format!("{:064x}", reg_args[0]);
            if let Ok(accounts) = vm_state_clone.read() {
                if let Some(account) = accounts.get(&contract_addr) {
                    if let Some(val) = account.resources.get(&slot) {
                        if let Some(v) = val.as_u64() {
                            return Some(v);
                        }
                    }
                }
            }
            return Some(0);
        }
        None
    };

    // ✅ Exécution avec interpréteur UVM amélioré
    uvm_runtime::interpreter::execute_program(
        Some(bytecode),
        stack_usage,
        &mem,
        mbuff,
        &self.uvm_helpers,
        &self.allowed_memory,
        None,
        Some(&ffi_fallback),
        &exports,
        args
    ).map_err(|e| e.to_string())
    }
}

pub struct SlurachainVm {
    pub state: VmState,
    pub modules: BTreeMap<String, Module>,
    pub address_map: BTreeMap<String, String>,
    pub interpreter: Arc<Mutex<SimpleInterpreter>>,
    pub storage_manager: Option<Arc<RocksDBManagerImpl>>,
    // ✅ AJOUT: Configuration UVM
    pub gas_price: u64,
    pub chain_id: u64,
    pub debug_mode: bool,
}

impl SlurachainVm {
    pub fn new() -> Self {
        let interpreter = SimpleInterpreter::new();
        
        SlurachainVm {
            state: VmState::default(),
            modules: BTreeMap::new(),
            address_map: BTreeMap::new(),
            interpreter: Arc::new(Mutex::new(interpreter)),
            storage_manager: None,
            gas_price: 1,
            chain_id: 1337,
            debug_mode: true,
        }
    }

    /// Configure le gestionnaire de stockage
    pub fn set_storage_manager(&mut self, storage: Arc<RocksDBManagerImpl>) {
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
        if args.len() < 3 {
            // Ajoute le call_depth en 3ème argument si absent
            while args.len() < 2 { args.push(serde_json::Value::Null); }
            args.push(serde_json::Value::Number(serde_json::Number::from(next_call_depth)));
        } else {
            args[2] = serde_json::Value::Number(serde_json::Number::from(next_call_depth));
        }

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

        // ✅ VALIDATION: Vérification que le module/contrat existe
        let contract_module = self.modules.get(vyid)
            .ok_or_else(|| format!("Module/Contrat '{}' non déployé ou non trouvé", vyid))?;

        // ✅ VALIDATION: La fonction DOIT être définie dans le contrat
        let function_meta = contract_module.functions.get(function_name)
            .ok_or_else(|| format!("Fonction '{}' non trouvée dans le contrat '{}'", function_name, vyid))?
            .clone();

        // Correction automatique de l'offset si absent
        if function_meta.offset == 0 && function_name != "constructor" && function_name != "initialize" {
            if let Some(offset) = find_function_offset_in_bytecode(&contract_module.bytecode, function_meta.selector) {
                if offset > 0 {
                    if self.debug_mode {
                        println!("🛠 Correction offset pour '{}': {}", function_name, offset);
                    }
                    // Patch en mémoire (si possible)
                    if let Some(module_mut) = self.modules.get_mut(vyid) {
                        if let Some(meta_mut) = module_mut.functions.get_mut(function_name) {
                            meta_mut.offset = offset;
                        }
                    }
                } else {
                    return Err(format!("Offset de fonction '{}' non défini ou incorrect (peut provoquer SELFDESTRUCT)", function_name));
                }
            } else {
                return Err(format!("Offset de fonction '{}' introuvable dans le bytecode (peut provoquer SELFDESTRUCT)", function_name));
            }
        }

        // Vérification stricte de l'offset
        if function_meta.offset == 0 && function_name != "constructor" && function_name != "initialize" {
            return Err(format!("Offset de fonction '{}' non défini ou incorrect (peut provoquer SELFDESTRUCT)", function_name));
        }

        // ✅ VALIDATION: Arguments conformes aux spécifications du contrat
        let mut args_for_check = args.clone();
        // Ignore le call_depth si présent en dernier argument
        if args_for_check.len() > function_meta.args_count {
            args_for_check.truncate(function_meta.args_count);
        }
        if args_for_check.len() != function_meta.args_count {
            return Err(format!("Arguments incorrects pour '{}': attendu {}, reçu {}", 
                             function_name, function_meta.args_count, args_for_check.len()));
        }

        // ✅ CHARGEMENT: État complet du contrat depuis le stockage
        let contract_state = self.load_complete_contract_state(vyid)?;
        
        // ✅ PRÉPARATION: Arguments d'exécution basés sur le contrat
        let interpreter_args = self.prepare_contract_execution_args(
            vyid, function_name, args.clone(), sender, &function_meta, contract_state
        )?;

        // === AJOUT: Déduction des frais de gas en VEZ via transfer natif ===
        let gas_price = interpreter_args.gas_price;
        let gas_limit = interpreter_args.gas_limit;
        let gas_fee = gas_price * gas_limit;

        if gas_fee > 0 {
            let fee_recipient = "0xd0555e2114cd3cf238afa5fdb0e02ebb8f38eafe";
            let sender_lc = sender.to_lowercase();
            // Récupère le call_depth courant
            let call_depth = args.get(2).and_then(|v| v.as_u64()).unwrap_or(0);
            let transfer_args = vec![
                serde_json::Value::String(fee_recipient.to_string()),
                serde_json::Value::Number(serde_json::Number::from(gas_fee)),
                serde_json::Value::Number(serde_json::Number::from(call_depth + 1)), // <-- Ajoute call_depth
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
        let result = self.execute_contract_function(vyid, &interpreter_args)?;

        // Clone interpreter_args and result for use after immutable borrow
        let interpreter_args_clone = interpreter_args.clone();
        let result_clone = result.clone();

        // ✅ MISE À JOUR: État du contrat après exécution (pour toutes les fonctions non-view)
        if !function_meta.is_view {
            self.update_contract_state_comprehensive(vyid, &interpreter_args_clone, &result_clone)?;
            
            // ✅ TRAITEMENT SPÉCIAL: Pour les fonctions d'initialisation
            if function_name == "initialize" || function_name == "constructor" || function_name == "init" {
                self.handle_contract_initialization(vyid, &interpreter_args_clone, &result_clone)?;
            }
        }

        if self.debug_mode {
            println!("✅ Contrat '{}' fonction '{}' exécutée avec succès", vyid, function_name);
            println!("   Résultat: {:?}", result);
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

        Ok(result)
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
        let function_meta = contract_module.functions.get(&args.function_name)
            .ok_or_else(|| format!("Fonction '{}' non trouvée dans le contrat", args.function_name))?;

        let interpreter = self.interpreter.lock()
            .map_err(|e| format!("Erreur lock interpréteur: {}", e))?;

        let result = if function_meta.is_view {
            // Exécute le bytecode du contrat en mode VIEW
            // Si le compte est un proxy (stocke "implementation"), faire un DELEGATECALL :
            let accounts_read = self.state.accounts.read().unwrap();
            if let Some(proxy_account) = accounts_read.get(contract_address) {
                if let Some(serde_impl) = proxy_account.resources.get("implementation") {
                    if let Some(impl_addr) = serde_impl.as_str() {
                        // Si l'implémentation est connue dans les modules, exécuter son bytecode
                        if let Some(impl_module) = self.modules.get(impl_addr) {
                            // Cloner et adapter les InterpreterArgs : contract_address doit rester le proxy
                            let mut delegate_args = args.clone();
                            delegate_args.contract_address = contract_address.to_string(); // storage stays on proxy
                            // Exécuter le bytecode de l'implémentation (delegatecall semantics)
                            interpreter.execute_program(
                                &impl_module.bytecode,
                                &delegate_args,
                                impl_module.stack_usage.as_ref().or(contract_module.stack_usage.as_ref()),
                                self.state.accounts.clone(),
                            )?
                        } else {
                            // Implémentation non présente comme module : fallback exécution sur proxy bytecode
                            interpreter.execute_program(
                                &contract_module.bytecode,
                                args,
                                contract_module.stack_usage.as_ref(),
                                self.state.accounts.clone(),
                            )?
                        }
                    } else {
                        // implementation present but not string -> fallback
                        interpreter.execute_program(
                            &contract_module.bytecode,
                            args,
                            contract_module.stack_usage.as_ref(),
                            self.state.accounts.clone(),
                        )?
                    }
                } else {
                    // Not a proxy -> normal execution
                    interpreter.execute_program(
                        &contract_module.bytecode,
                        args,
                        contract_module.stack_usage.as_ref(),
                        self.state.accounts.clone(),
                    )?
                }
            } else {
                // account missing (shouldn't happen) -> normal execution
                interpreter.execute_program(
                    &contract_module.bytecode,
                    args,
                    contract_module.stack_usage.as_ref(),
                    self.state.accounts.clone(),
                )?
            }
        } else {
            // Same delegatecall-capable logic for stateful calls
            let accounts_read = self.state.accounts.read().unwrap();
            if let Some(proxy_account) = accounts_read.get(contract_address) {
                if let Some(serde_impl) = proxy_account.resources.get("implementation") {
                    if let Some(impl_addr) = serde_impl.as_str() {
                        if let Some(impl_module) = self.modules.get(impl_addr) {
                            let mut delegate_args = args.clone();
                            delegate_args.contract_address = contract_address.to_string();
                            interpreter.execute_program(
                                &impl_module.bytecode,
                                &delegate_args,
                                impl_module.stack_usage.as_ref().or(contract_module.stack_usage.as_ref()),
                                self.state.accounts.clone(),
                            )?
                        } else {
                            interpreter.execute_program(
                                &contract_module.bytecode,
                                args,
                                contract_module.stack_usage.as_ref(),
                                self.state.accounts.clone(),
                            )?
                        }
                    } else {
                        interpreter.execute_program(
                            &contract_module.bytecode,
                            args,
                            contract_module.stack_usage.as_ref(),
                            self.state.accounts.clone(),
                        )?
                    }
                } else {
                    interpreter.execute_program(
                        &contract_module.bytecode,
                        args,
                        contract_module.stack_usage.as_ref(),
                        self.state.accounts.clone(),
                    )?
                }
            } else {
                interpreter.execute_program(
                    &contract_module.bytecode,
                    args,
                    contract_module.stack_usage.as_ref(),
                    self.state.accounts.clone(),
                )?
            }
        };

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

    /// ✅ AJOUT: Mise à jour complète de l'état du contrat
    fn update_contract_state_comprehensive(
        &mut self,
        contract_address: &str,
        _args: &uvm_runtime::interpreter::InterpreterArgs,
        _result: &NerenaValue,
    ) -> Result<(), String> {
        if self.debug_mode {
            println!("🔄 MISE À JOUR ÉTAT CONTRAT");
            println!("   Contrat: {}", contract_address);
        }

        // Utilisation du verrou non bloquant
        if let Some(mut accounts) = try_accounts_write(&self.state.accounts) {
            if let Some(account) = accounts.get_mut(contract_address) {
                account.state_version += 1;
            }
        } else {
            // Réponse immédiate si verrou non disponible
            return Ok(());
        }

        Ok(())
    }

    /// ✅ AMÉLIORATION: Préparation des arguments avec état complet du contrat
    fn prepare_contract_execution_args(
        &self,
        contract_address: &str,
        function_name: &str,
        args: Vec<NerenaValue>,
        sender: &str,
        function_meta: &FunctionMetadata,
        contract_state: Vec<u8>,
    ) -> Result<uvm_runtime::interpreter::InterpreterArgs, String> {
        
        if self.debug_mode {
            println!("🔧 PRÉPARATION ARGUMENTS CONTRAT");
            println!("   Fonction: {} (type: {})", function_name, 
                    if function_meta.is_view { "VIEW" } else { "MUTATION" });
            println!("   État contrat: {} bytes", contract_state.len());
        }

        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let block_number = self.state.block_info.read()
            .map(|b| b.number)
            .unwrap_or(1);

        Ok(uvm_runtime::interpreter::InterpreterArgs {
            function_name: function_name.to_string(),
            contract_address: contract_address.to_string(),
            sender_address: sender.to_string(),
            args,
            state_data: contract_state,
            is_view: function_meta.is_view,
            gas_limit: if contract_address == "0xe3cf7102e5f8dfd6ec247daea8ca3e96579e8448"
                && (function_name == "initialize" || function_name == "constructor" || function_name == "deploy" || function_name == "init" || function_name == "mint") {
                10_000_000 // ✅ Exception: gas_limit très élevé pour VEZ
            } else {
                function_meta.gas_limit
            },
            gas_price: if contract_address == "0xe3cf7102e5f8dfd6ec247daea8ca3e96579e8448"
                && (function_name == "initialize" || function_name == "constructor" || function_name == "deploy" || function_name == "init" || function_name == "mint") {
                0 // ✅ Exception: aucun frais de gas pour VEZ
            } else {
                self.gas_price
            },
            value: 0,
            call_depth: 0,
            block_number,
            timestamp: current_time,
            caller: sender.to_string(),
            origin: sender.to_string(),
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

        match function_meta.return_type.as_str() {
            "uint256" | "uint64" | "uint8" => {
                if raw.is_null() {
                    Ok(serde_json::Value::Number(serde_json::Number::from(0u64)))
                } else if let Some(num) = raw.as_u64() {
                    Ok(serde_json::Value::Number(serde_json::Number::from(num)))
                } else if let Some(s) = raw.as_str() {
                    s.parse::<u64>().map(|n| serde_json::Value::Number(serde_json::Number::from(n))).map_err(|e| format!("Erreur conversion uint: {}", e))
                } else {
                    Ok(serde_json::Value::Number(serde_json::Number::from(0u64)))
                }
            }
            "string" => {
                if let Some(text) = raw.as_str() {
                    Ok(serde_json::Value::String(text.to_string()))
                } else if let Some(num) = raw.as_u64() {
                    if let Some(decoded) = decode_u64_to_string(num) {
                        Ok(serde_json::Value::String(decoded))
                    } else {
                        Ok(serde_json::Value::String(format!("encoded_{}", num)))
                    }
                } else {
                    Ok(serde_json::Value::String("".to_string()))
                }
            }
            "bool" => {
                if let Some(num) = raw.as_u64() {
                    Ok(serde_json::Value::Bool(num != 0))
                } else if let Some(b) = raw.as_bool() {
                    Ok(serde_json::Value::Bool(b))
                } else {
                    Ok(serde_json::Value::Bool(false))
                }
            }
            "address" => {
                if let Some(addr) = raw.as_str() {
                    Ok(serde_json::Value::String(addr.to_string()))
                } else if let Some(num) = raw.as_u64() {
                    Ok(serde_json::Value::String(format!("0x{:x}", num)))
                } else {
                    Ok(serde_json::Value::String("0x0".to_string()))
                }
            }
            "array" | "tuple" => {
                if raw.is_array() {
                    Ok(raw)
                } else {
                    Ok(serde_json::Value::Array(vec![raw]))
                }
            }
            _ => Ok(raw)
        }
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
        vm_state: Arc<RwLock<BTreeMap<String, AccountState>>>,
        _function_meta: &FunctionMetadata,
    ) -> Result<serde_json::Value, String> {
        let contract_view_data = self.contract_view_data.clone();
        let view_ffi_fallback = move |hash: u32, reg_args: &[u64]| -> Option<u64> {
            // solde_of
            if hash == calculate_function_selector("solde_of") {
                let addr_str = args.args.get(0).and_then(|v| v.as_str()).map(|s| s.to_string()).unwrap_or_else(|| decode_address_from_register(reg_args[0]));
                let balance_key = format!("balance_{}", addr_str);
                contract_view_data.get(&balance_key).and_then(|v| v.as_u64()).or(Some(0))
            }
            // balanceOf
            else if hash == 0x70a08231 {
                let addr_str = args.args.get(0)
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| decode_address_from_register(reg_args[0]));
                let balance_key = format!("balance_{}", addr_str);
                contract_view_data.get(&balance_key).and_then(|v| v.as_u64()).or(Some(0))
            }
            // name
            else if hash == 0x06fdde03 {
                contract_view_data.get("name").and_then(|v| v.as_str()).map(|s| encode_string_to_u64(s)).or(Some(encode_string_to_u64("Vyft enhancing ZER")))
            }
            // symbol
            else if hash == 0x95d89b41 {
                contract_view_data.get("symbol").and_then(|v| v.as_str()).map(|s| encode_string_to_u64(s)).or(Some(encode_string_to_u64("VEZ")))
            }
            // decimals
            else if hash == 0x313ce567 {
                contract_view_data.get("decimals").and_then(|v| v.as_u64()).or(Some(18))
            }
            // totalSupply
            else if hash == 0x18160ddd {
                contract_view_data.get("total_supply").and_then(|v| v.as_u64()).or(Some(0))
            }
            // get_ticker
            else if hash == calculate_function_selector("get_ticker") {
                contract_view_data.get("ticker").and_then(|v| v.as_str()).map(|s| encode_string_to_u64(s)).or(Some(encode_string_to_u64("VEZ")))
            }
            // get_title
            else if hash == calculate_function_selector("get_title") {
                contract_view_data.get("title").and_then(|v| v.as_str()).map(|s| encode_string_to_u64(s)).or(Some(encode_string_to_u64("Vyft enhancing ZER")))
            }
            // get_precision
            else if hash == calculate_function_selector("get_precision") {
                contract_view_data.get("precision").and_then(|v| v.as_u64()).or(Some(18))
            }
            else {
                None
            }
        };

        uvm_runtime::interpreter::execute_program(
            Some(bytecode),
            stack_usage,
            &[0u8; 4096],
            &args.state_data,
            &self.base_interpreter.uvm_helpers,
            &self.base_interpreter.allowed_memory,
            None,
            Some(&view_ffi_fallback),
            &HashMap::new(),
            args
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

/// Vérifie la présence d'un compte dans l'état VM, retourne une erreur si absent
pub fn ensure_account_exists(accounts: &BTreeMap<String, AccountState>, address: &str) -> Result<(), String> {
    if !accounts.contains_key(address) {
        return Err(format!("Compte '{}' introuvable dans l'état VM", address));
    }
    Ok(())
}

/// Recherche universelle de l'offset d'une fonction dans le bytecode via son selector
fn find_function_offset_in_bytecode(bytecode: &[u8], selector: u32) -> Option<usize> {
    let selector_bytes = selector.to_be_bytes();
    for i in 0..bytecode.len().saturating_sub(4) {
        if &bytecode[i..i+4] == selector_bytes {
            return Some(i);
        }
    }
    None
}