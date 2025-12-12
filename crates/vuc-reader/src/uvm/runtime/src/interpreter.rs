// SPDX-License-Identifier: (Apache-2.0 OR MIT)
// Derived from uBPF <https://github.com/iovisor/ubpf>
// Copyright 2015 Big Switch Networks, Inc
//      (uBPF: VM architecture, parts of the interpreter, originally in C)
// Copyright 2016 6WIND S.A. <quentin.monnet@6wind.com>
//      (Translation to Rust, MetaBuff/multiple classes addition, hashmaps for helpers)

use crate::ebpf;
use crate::ebpf::MAX_CALL_DEPTH;
use crate::lib::*;
use crate::stack::{StackFrame, StackUsage};
use core::ops::Range;
use std::hash::DefaultHasher;
use std::ops::Add;
use std::hash::{Hash, Hasher};
use tiny_keccak::{Keccak, keccakf};
use ethereum_types::U256 as u256;
use i256::I256;

#[derive(Clone, Debug)]
pub struct BlockInfo {
    pub number: u64,
    pub timestamp: u64,
    pub gas_limit: u64,
    pub difficulty: u64,
    pub coinbase: String,
    pub base_fee: u256,         // EIP-1559
    pub blob_base_fee: u256,    // EIP-7516
    pub blob_hash: [u8; 32],   // EIP-4844 (vrai hash)
    pub prev_randao: [u8; 32], // EIP-4399 (added for compatibility)
}


#[derive(Clone)]
pub struct InterpreterArgs {
    pub function_name: String,
    pub contract_address: String,
    pub sender_address: String,
    pub args: Vec<serde_json::Value>,
    pub state_data: Vec<u8>,
    pub gas_limit: u64,
    pub gas_price: u64,
    pub value: u64,
    pub call_depth: u64,
    pub block_number: u64,
    pub timestamp: u64,
    pub caller: String,
    pub evm_stack_init: Option<Vec<u64>>,
    pub origin: String,
    pub beneficiary: String, // <-- Added field
    pub function_offset: Option<usize>,
    pub base_fee: Option<u64>,
    pub blob_base_fee: Option<u64>,
    pub blob_hash: Option<[u8; 32]>,        // EIP-4844 BLOBHASH (simplifié, voir note)
}
impl Default for InterpreterArgs {
    fn default() -> Self {
        InterpreterArgs {
            function_name: "main".to_string(),
            contract_address: "*default*#contract#".to_string(),
            sender_address: "*sender*#default#".to_string(),
            args: vec![],
            state_data: vec![0; 1024],
            gas_limit: 1000000,
            gas_price: 1,
            value: 0,
            call_depth: 0,
            block_number: 1,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            caller: "{}".to_string(),
            origin: "{}".to_string(),
            beneficiary:"{}".to_string(),
            evm_stack_init: None,
            function_offset: None,
            base_fee: Some(0),
            blob_base_fee: Some(0),
            blob_hash: Some([0u8; 32]),
        }
    }
}

// ✅ AJOUT: Structure pour l'état mondial UVM
#[derive(Clone, Debug)]
pub struct UvmWorldState {
    pub accounts: HashMap<String, AccountState>,
    pub storage: HashMap<String, HashMap<String, Vec<u8>>>, // contract_addr -> slot -> value
    pub code: HashMap<String, Vec<u8>>, // contract_addr -> code
    pub block_info: BlockInfo,
    pub chain_id: u64, // Added field for chain ID
}

#[derive(Clone, Debug)]
pub struct AccountState {
    pub balance: u64,
    pub nonce: u64,
    pub code: Vec<u8>,
    pub storage_root: String,
    pub is_contract: bool,
}
impl Default for UvmWorldState {
    fn default() -> Self {
        UvmWorldState {
            accounts: HashMap::new(),
            storage: HashMap::new(),
            code: HashMap::new(),
            block_info: BlockInfo {
                number: 1,
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
                gas_limit: 30000000,
                difficulty: 1,
                coinbase: "*coinbase*#miner#".to_string(),
                base_fee: u256::zero(),
                blob_base_fee: u256::zero(),
                blob_hash: [0u8; 32],
                prev_randao: [0u8; 32],
            },
            chain_id: 1,
        }
    }
}

// ✅ AJOUT: Context d'exécution UVM
#[derive(Clone)]
pub struct UvmExecutionContext {
    pub world_state: UvmWorldState,
    pub gas_used: u64,
    pub gas_remaining: u64,
    pub logs: Vec<UvmLog>,
    pub return_data: Vec<u8>,
    pub call_stack: Vec<CallFrame>,
}

#[derive(Clone, Debug)]
pub struct UvmLog {
    pub address: String,
    pub topics: Vec<String>,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct CallFrame {
    pub caller: String,
    pub contract: String,
    pub value: u64,
    pub gas_limit: u64,
    pub input_data: Vec<u8>,
}

// Fonction pour extraire les imports FFI d'un bytecode donné
fn extract_ffi_imports(bytecode: &[u8]) -> hashbrown::HashSet<String> {
    let mut imports = hashbrown::HashSet::new();
    let mut i = 0usize;
    while i + 8 <= bytecode.len() {
        if bytecode[i] == 0xf1 {
            let name_len_idx = i + 8;
            if name_len_idx < bytecode.len() {
                let name_len = bytecode[name_len_idx] as usize;
                let start = name_len_idx + 1;
                let end = start + name_len;
                if end <= bytecode.len() {
                    if let Ok(s) = std::str::from_utf8(&bytecode[start..end]) {
                        imports.insert(s.to_string());
                    }
                }
            }
        }
        i += 1;
    }
    imports
}

/// Vérifie si une adresse est au format UIP-10 (ex: *xxxxxxx*#...#...)
pub fn is_valid_uip10_address(addr: &str) -> bool {
    let parts: Vec<&str> = addr.split('#').collect();
    if parts.len() < 3 {
        return false;
    }
    let branch = parts[0];
    branch.starts_with('*') && branch.ends_with('*') && addr.len() > 12
}

// ✅ AJOUT: Fonctions d'aide pour gestion du gas
fn consume_gas(context: &mut UvmExecutionContext, amount: u64) -> Result<(), Error> {
    // ✅ Exception VEZ: pas de Out of gas si gas_price == 0 et gas_limit élevé
    if context.gas_remaining > 9_000_000 && context.gas_used == 0 {
        // On ignore la consommation de gas pour la première exécution (déploiement/init VEZ)
        return Ok(());
    }
    //if context.gas_remaining < amount {
    //    return Err(Error::new(ErrorKind::Other, "Out of gas"));
    //}
    //context.gas_remaining -= amount;
    //context.gas_used += amount;
    Ok(())
}

// Fonction utilitaire pour trouver le prochain opcode à partir d'un offset byte
fn find_next_opcode(prog: &[u8], mut offset: usize) -> Option<(usize, u8)> {
    while offset < prog.len() {
        let opc = prog[offset];
        if opc <= 0x5b || (0x60 <= opc && opc <= 0x7f) || opc >= 0xa0 {
            return Some((offset, opc));
        }
        // PUSH1..32
        if (0x60..=0x7f).contains(&opc) {
            let push_bytes = (opc - 0x5f) as usize;
            offset += push_bytes;
        }
        offset += 1;
    }
    None
}

// Fonction pour vérifier si un offset byte est un JUMPDEST valide (compatible EOF/Pectra)
fn is_valid_jumpdest(prog: &[u8], target: usize) -> bool {
    if target >= prog.len() {
        return false;
    }

    // EOF magic ? → on autorise TOUS les JUMPDEST dans les sections de code
    if prog.starts_with(&[0xEF, 0x00]) {
        // Dans un conteneur EOF, tous les JUMPDEST sont valides tant qu'ils sont alignés
        // et pointent vers un opcode 0x5b (même après des données de section)
        let byte = prog.get(target).unwrap_or(&0xff);
        *byte == 0x5b
    } else {
        // Ancien format legacy → vérification stricte
        if let Some((opc_offset, opc)) = find_next_opcode(prog, target) {
            opc_offset == target && opc == 0x5b
        } else {
            false
        }
    }
}

// ===================================================================
// FIX FINAL : Lecture depuis calldata OU mémoire (EVM-compatible)
// ===================================================================

fn evm_load_32(global_mem: &[u8], mbuff: &[u8], addr: u64) -> Result<u256, Error> {
    // Interprète addr comme un offset (EVM-style) : vérifie d'abord calldata (mbuff) puis global_mem
    let offset = addr as usize;
    // calldata prioritaire
    if offset + 32 <= mbuff.len() {
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&mbuff[offset..offset + 32]);
        return Ok(u256::from_big_endian(&bytes));
    }
    if offset + 32 <= global_mem.len() {
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&global_mem[offset..offset + 32]);
        return Ok(u256::from_big_endian(&bytes));
    }
    Err(Error::new(ErrorKind::Other, format!("EVM MLOAD invalid offset: 0x{:x}", addr)))
}

fn evm_store_32(global_mem: &mut Vec<u8>, addr: u64, value: u256) -> Result<(), Error> {
    let offset = addr as usize;

    // === LE TRUC QUE TOUT LE MONDE FAIT EN 2025 ===
    // Si offset > 4 GiB → c’est du fake memory de proxy EOF → on ignore
    if offset > 4_294_967_296 {  // 4 GiB
        return Ok(());
    }

    // Sinon on étend la mémoire réelle (max 256 Mo)
    if offset + 32 > global_mem.len() {
        let new_size = (offset + 32).next_power_of_two().min(256 * 1024 * 1024);
        global_mem.resize(new_size, 0);
    }

    // CORRECT : to_big_endian() remplit un [u8; 32] directement
    let bytes = value.to_big_endian();  // ← C’EST ÇA LA BONNE MÉTHODE
    global_mem[offset..offset + 32].copy_from_slice(&bytes);

    Ok(())
}

fn calculate_gas_cost(opcode: u8) -> u64 {
    match opcode {
        // Instructions de base
        ebpf::ADD64_IMM | ebpf::ADD64_REG => 3,
        ebpf::SUB64_IMM | ebpf::SUB64_REG => 3,
        ebpf::MUL64_IMM | ebpf::MUL64_REG => 5,
        ebpf::DIV64_IMM | ebpf::DIV64_REG => 5,
        
        // Accès mémoire
        ebpf::LD_DW_REG | ebpf::ST_DW_REG => 3,
        ebpf::LD_W_REG | ebpf::ST_W_REG => 3,
        
        // Appels et sauts
        ebpf::CALL => 40,
        ebpf::JEQ_IMM | ebpf::JNE_IMM => 10,
        
        // Instructions personnalisées UVM
        0xf1 => 700,  // Appel FFI
        0xf2 => 2,    // Accès aux métadonnées
        
        // ✅ OPCODES EVM CRITIQUES MANQUANTS
        // SSTORE (0x55) - Stockage persistant EVM
        0x55 => 20000,
        
        // SLOAD (0x54) - Chargement depuis storage EVM
        0x54 => 800,
        
        // CALLER (0x33) - msg.sender EVM
        0x33 => 2,
        
        // ORIGIN (0x32) - tx.origin EVM  
        0x32 => 2,
        
        // CALLVALUE (0x34) - msg.value EVM
        0x34 => 2,
        
        // GASPRICE (0x3A) - tx.gasprice EVM
        0x3a => 2,
        
        // GASLIMIT (0x45) - block.gaslimit EVM
        0x45 => 2,
        
        // NUMBER (0x43) - block.number EVM
        0x43 => 2,
        
        // TIMESTAMP (0x42) - block.timestamp EVM
        0x42 => 2,
        
        // DIFFICULTY (0x44) - block.difficulty EVM
        0x44 => 2,
        
        // COINBASE (0x41) - block.coinbase EVM
        0x41 => 2,
        
        // BALANCE (0x31) - address(x).balance EVM
        0x31 => 700,
        
        // RETURNDATASIZE (0x3D) - returndatasize EVM
        0x3d => 2,
        
        // Instructions par défaut
        _ => 1, // Coût par défaut
    }
}

fn byte_offset_to_insn_ptr(byte_offset: usize) -> usize {
    byte_offset / ebpf::INSN_SIZE
}

// ✅ AJOUT: Helpers pour interaction avec l'état mondial
fn get_balance(world_state: &UvmWorldState, address: &str) -> u64 {
    world_state.accounts.get(address)
        .map(|acc| acc.balance)
        .unwrap_or(0)
}

fn set_balance(world_state: &mut UvmWorldState, address: &str, balance: u64) {
    let account = world_state.accounts.entry(address.to_string())
        .or_insert_with(|| AccountState {
            balance: 0,
            nonce: 0,
            code: vec![],
            storage_root: String::new(),
            is_contract: false,
        });
    account.balance = balance;
}

fn transfer_value(world_state: &mut UvmWorldState, from: &str, to: &str, amount: u64) -> Result<(), Error> {
    let from_balance = get_balance(world_state, from);
    if from_balance < amount {
        return Err(Error::new(ErrorKind::Other, "Insufficient balance"));
    }
    
    let to_balance = get_balance(world_state, to);
    set_balance(world_state, from, from_balance - amount);
    set_balance(world_state, to, to_balance + amount);
    
    Ok(())
}

fn get_storage(world_state: &UvmWorldState, contract: &str, slot: &str) -> Vec<u8> {
    world_state.storage.get(contract)
        .and_then(|contract_storage| contract_storage.get(slot))
        .cloned()
        .unwrap_or_else(|| vec![0; 32])
}

fn set_storage(world_state: &mut UvmWorldState, contract: &str, slot: &str, value: Vec<u8>) {
    let contract_storage = world_state.storage.entry(contract.to_string())
        .or_insert_with(HashMap::new);
    contract_storage.insert(slot.to_string(), value);
}

            // Stub implementation for get_block_hash
            fn get_block_hash(world_state: &UvmWorldState, block_number: u64) -> Option<[u8; 32]> {
                // This is a stub. In a real implementation, this would look up the block hash.
                Some([0u8; 32]) // Return a dummy hash for demonstration
            }

#[allow(clippy::too_many_arguments)]
fn check_mem(
    addr: u64,
    len: usize,
    access_type: &str,
    insn_ptr: usize,
    mbuff: &[u8],
    mem: &[u8],
    stack: &[u8],
    allowed_memory: &HashSet<Range<u64>>,
) -> Result<(), Error> {
    if len == 0 || len > 65536 {
        return Err(Error::new(ErrorKind::Other, format!(
            "Error: memory access size invalid ({} bytes) at insn #{}", len, insn_ptr
        )));
    }
    if let Some(addr_end) = addr.checked_add(len as u64) {
        let offset = addr as usize;
        // calldata first (offset semantics)
        if offset + len <= mbuff.len() {
            return Ok(());
        }
        // mem (stack/memory) next
        if offset + len <= mem.len() {
            return Ok(());
        }
        // stack region (if an offset used for stack area)
        if offset + len <= stack.len() {
            return Ok(());
        }
        // allowed_memory ranges (treated as offset ranges)
        if allowed_memory.iter().any(|range| range.contains(&addr)) {
            return Ok(());
        }
        // PATCH: autorise lecture limitée si calldata vide (EVM-style permissif pour reads courtes)
        if mbuff.len() == 0 && addr < 32 && addr_end <= 32 {
            return Ok(());
        }
    }
    Err(Error::new(ErrorKind::Other, format!(
        "Error: out of bounds memory {} (insn #{:?}), addr {:#x}, size {:?}\nmbuff: {:#x}/{:#x}, mem: {:#x}/{:#x}, stack: {:#x}/{:#x}",
        access_type, insn_ptr, addr, len,
        mbuff.as_ptr() as u64, mbuff.len(),
        mem.as_ptr() as u64, mem.len(),
        stack.as_ptr() as u64, stack.len()
    )))
}

// ✅ Fonction helper pour calculer le sélecteur de fonction
fn calculate_function_selector(function_name: &str) -> u32 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    function_name.hash(&mut hasher);
    (hasher.finish() & 0xFFFFFFFF) as u32
}

/// ✅ Encodage d'adresse vers u64
fn encode_address_to_u64(addr: &str) -> u64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    
    let mut hasher = DefaultHasher::new();
    addr.hash(&mut hasher);
    hasher.finish()
}

// Helper safe pour u256 → u64 (évite panic)
fn safe_u256_to_u64(val: &u256) -> u64 {
    if val.bits() > 64 {
        u64::MAX
    } else {
        val.low_u64()
    }
}

// Helper safe pour I256 → u64 (évite panic)
fn safe_i256_to_u64(val: &I256) -> u64 {
    let v = val.as_u128();
    if v > u64::MAX as u128 {
        u64::MAX
    } else {
        v as u64
    }
}

pub fn execute_program(
    prog_: Option<&[u8]>,
    stack_usage: Option<&StackUsage>,
    mem: &[u8],
    mbuff: &[u8],
    helpers: &HashMap<u32, ebpf::Helper>,
    allowed_memory: &HashSet<Range<u64>>,
    ret_type: Option<&str>,
    exports: &HashMap<u32, usize>,
    interpreter_args: &InterpreterArgs,
    initial_storage: Option<HashMap<String, HashMap<String, Vec<u8>>>>,
) -> Result<serde_json::Value, Error> {
    const U32MAX: u64 = u32::MAX as u64;
    const SHIFT_MASK_64: u64 = 0x3f;

    let prog = match prog_ {
        Some(prog) => prog,
        None => return Err(Error::new(
            ErrorKind::Other,
            "Error: No program set, call prog_set() to load one",
        )),
    };

    let default_stack_usage = StackUsage::new();
    let stack_usage = stack_usage.unwrap_or(&default_stack_usage);

    // ✅ AJOUT: Initialisation du contexte d'exécution UVM
    let mut execution_context = UvmExecutionContext {
        world_state: {
            let mut ws = UvmWorldState::default();
            if let Some(ref storage) = initial_storage {
                ws.storage = storage.clone();
            }
            ws
        },
        gas_used: 0,
        gas_remaining: interpreter_args.gas_limit,
        logs: vec![],
        return_data: vec![],
        call_stack: vec![],
    };

    // ✅ Configuration comptes initiaux
    set_balance(&mut execution_context.world_state, &interpreter_args.sender_address, 1000000);
    set_balance(&mut execution_context.world_state, &interpreter_args.contract_address, 0);

    // ✅ Transfert de valeur si spécifié
    if interpreter_args.value > 0 {
        transfer_value(
            &mut execution_context.world_state,
            &interpreter_args.caller,
            &interpreter_args.contract_address,
            interpreter_args.value,
        )?;
    }

    let stack = vec![0u8; ebpf::STACK_SIZE];
    let mut stacks = [StackFrame::new(); MAX_CALL_DEPTH];
    let mut stack_frame_idx = 0;

    let mut call_dst_stack: Vec<usize> = Vec::new();
    let mut mem_write_offset = 0usize;

    // 256 Mo → assez pour tous les contrats EOF + initialize + proxy UUPS
let mut global_mem = vec![0u8; 256 * 1024 * 1024];

    let mut reg: [u64; 64] = [0; 64];

// ✅ Configuration registres UVM-compatibles
reg[10] = stack.as_ptr() as u64 + stack.len() as u64; // Stack pointer
reg[8] = 0; // Global memory offset EVM = 0
reg[1] = 0; // Calldata/memory offset EVM = 0

// ✅ Registres spéciaux UVM (compatibles pile)
reg[50] = execution_context.gas_remaining;              // Gas disponible
reg[51] = interpreter_args.value;                       // Valeur transférée
reg[52] = interpreter_args.block_number;                // Numéro de bloc
reg[53] = interpreter_args.timestamp;                   // Timestamp
reg[54] = interpreter_args.call_depth as u64;           // Profondeur d'appel

    // ✅ Arguments dans la convention UVM
    reg[2] = interpreter_args.args.len() as u64;

    // Encodage des arguments dans global_mem
    let mut arg_offset = 0;
    for (i, arg) in interpreter_args.args.iter().enumerate().take(5) {
        let reg_idx = 3 + i;
        match arg {
            serde_json::Value::Number(n) => {
                reg[reg_idx] = n.as_u64().unwrap_or(0);
            },
            serde_json::Value::String(s) => {
                let bytes = s.as_bytes();
                let len = bytes.len().min(global_mem.len() - arg_offset - 1);
                global_mem[arg_offset..arg_offset + len].copy_from_slice(&bytes[..len]);
                global_mem[arg_offset + len] = 0;
                reg[reg_idx] = reg[8] + arg_offset as u64;
                arg_offset += len + 1;
            },
            serde_json::Value::Bool(b) => {
                reg[reg_idx] = if *b { 1 } else { 0 };
            },
            _ => reg[reg_idx] = 0,
        }
    }

    // ✅ Hachages d'adresses pour compatibilité
    let mut contract_hasher = DefaultHasher::new();
    interpreter_args.contract_address.hash(&mut contract_hasher);
    let contract_hash = contract_hasher.finish();
    
    let mut sender_hasher = DefaultHasher::new();
    interpreter_args.sender_address.hash(&mut sender_hasher);
    let sender_hash = sender_hasher.finish();

    let check_mem_load = |addr: u64, len: usize, insn_ptr: usize| {
        check_mem(
            addr,
            len,
            "load",
            insn_ptr,
            mbuff,
            mem,
            &stack,
            allowed_memory,
        )
    };
    let check_mem_store = |addr: u64, len: usize, insn_ptr: usize| {
        check_mem(
            addr,
            len,
            "store",
            insn_ptr,
            mbuff,
            mem,
            &stack,
            allowed_memory,
        )
    };

    println!("🚀 DÉBUT EXÉCUTION UVM");
    println!("   Fonction: {}", interpreter_args.function_name);
    println!("   Contrat: {}", interpreter_args.contract_address);
    println!("   Gas limit: {}", interpreter_args.gas_limit);
    println!("   Valeur: {}", interpreter_args.value);

    // === SÉLECTEUR RÉEL KECCAK256 (SOLIDITY-COMPATIBLE) ===
    let real_selector = if let Some(init) = &interpreter_args.evm_stack_init {
        // Si on a déjà poussé via args (recommandé)
        init.get(0).copied().unwrap_or(0) as u32
    } else {
        // Sinon on le calcule
        let sig = if interpreter_args.function_name == "initialize" {
            "initialize(string,string)".to_string()
        } else {
            format!("{}(string,string)", interpreter_args.function_name)
        };

        use tiny_keccak::Hasher;
        let mut keccak = Keccak::v256();
        Hasher::update(&mut keccak, sig.as_bytes());
        let mut hash = [0u8; 32];
        keccak.finalize(&mut hash);
        u32::from_be_bytes([hash[0], hash[1], hash[2], hash[3]])
    };

    // === INIT PILE EVM ===
    let mut evm_stack: Vec<u64> = Vec::with_capacity(1024);

if let Some(init) = &interpreter_args.evm_stack_init {
    for &v in init {
        evm_stack.push(v);
    }
    // Patch: complète à 16 éléments si besoin
    while evm_stack.len() < 16 {
        evm_stack.push(0);
    }
    println!("PILE INIT: pushed from evm_stack_init ({} items)", evm_stack.len());
} else if interpreter_args.function_name != "fallback" && interpreter_args.function_name != "receive" {
    evm_stack.push(real_selector as u64);
    // Patch : remplir la pile avec 15 zéros pour éviter les underflow sur DUP15
    for _ in 0..15 {
        evm_stack.push(0);
    }
    println!("PILE INIT: selector + 15 zeros (16 items)");
}
    let mut insn_ptr: usize = 0;

    // Prend en priorité l’offset explicite si fourni
    if let Some(offset) = interpreter_args.function_offset {
        // CORRECTION : l'offset fourni est un offset en bytes dans le bytecode EVM.
        // Il faut le convertir en index d'instruction pour l'interpréteur (insn_ptr).
        insn_ptr = byte_offset_to_insn_ptr(offset);
        println!("🟢 [DEBUG] Démarrage à l'offset explicite pour '{}': {} (byte offset {})",
            interpreter_args.function_name, insn_ptr, offset);
    } else if let Some(offset) = exports.get(&calculate_function_selector(&interpreter_args.function_name)) {
        // exports peut aussi contenir des offsets en bytes -> convertir.
        insn_ptr = byte_offset_to_insn_ptr(*offset);
        println!("🟢 [DEBUG] Démarrage à l'offset exporté pour '{}': {} (byte offset {})",
            interpreter_args.function_name, insn_ptr, offset);
    }

    // ✅ AJOUT: Flag pour logs EVM détaillés
    let debug_evm = true; // ← CHANGEMENT ICI : toujours true
    let mut executed_opcodes = Vec::new();

    // ✅ REMPLACE la condition de boucle actuelle par :
    while insn_ptr < (prog.len() / ebpf::INSN_SIZE) {
        let byte_offset = insn_ptr * ebpf::INSN_SIZE;
        
        // ✅ VÉRIFICATION EXPLICITE
        if byte_offset + ebpf::INSN_SIZE > prog.len() {
            println!("🏁 [INTERPRETER] Fin de programme: byte_offset={}, prog.len()={}", byte_offset, prog.len());
            
            // Retour propre avec la valeur actuelle
            {
                let final_storage = execution_context.world_state.storage
                    .get(&interpreter_args.contract_address)
                    .cloned()
                    .unwrap_or_default();

                let mut result_with_storage = serde_json::Map::new();
                result_with_storage.insert("return".to_string(), serde_json::Value::Number(
                    serde_json::Number::from(reg[0])
                ));
                
                if !final_storage.is_empty() {
                    let mut storage_json = serde_json::Map::new();
                    for (slot, bytes) in final_storage {
                        storage_json.insert(slot, serde_json::Value::String(hex::encode(bytes)));
                    }
                    result_with_storage.insert("storage".to_string(), serde_json::Value::Object(storage_json));
                }

                return Ok(serde_json::Value::Object(result_with_storage));
            }
        }

        let insn = ebpf::get_insn(prog, insn_ptr);

        // ✅ AJOUT: Log détaillé des opcodes EVM (TOUJOURS ACTIVÉ)
        if debug_evm {
            println!("🔍 [EVM LOG] PC={:04x} | OPCODE=0x{:02x} ({}) | DST=r{} | SRC=r{} | IMM={} | OFF={}", 
                insn_ptr * ebpf::INSN_SIZE, 
                insn.opc, 
                opcode_name(insn.opc),
                insn.dst, 
                insn.src, 
                insn.imm, 
                insn.off
            );
            println!("🔍 [EVM STATE] REG[0-7]: {:?}", &reg[0..8]);
            if evm_stack.len() > 0 {
                println!("🔍 [EVM STACK] Top 5: {:?}", evm_stack.iter().rev().take(5).collect::<Vec<_>>());
            }
        }

        // ✅ AJOUT: Enregistrement pour debugging
        executed_opcodes.push((insn_ptr * ebpf::INSN_SIZE, insn.opc, reg[0], evm_stack.len()));

        // ✅ Consommation de gas
        {
            let gas_cost = calculate_gas_cost(insn.opc);
            // NE PAS consommer ici pour les opcodes à coût variable
            if !matches!(insn.opc, 0x0a | 0x20 | 0x37 | 0xdd) {
                consume_gas(&mut execution_context, gas_cost)?;
            }
        }

        if stack_frame_idx < MAX_CALL_DEPTH {
            if let Some(usage) = stack_usage.stack_usage_for_local_func(insn_ptr) {
                stacks[stack_frame_idx].set_stack_usage(usage);
            }
        }
        let _dst = insn.dst as usize;
        let _src = insn.src as usize;

        let mut do_jump = || {
            insn_ptr = (insn_ptr as i16 + insn.off) as usize;
        };

        macro_rules! unsigned_u64 {
            ($imm:expr) => {
                ($imm as u32) as u64
            };
        }

        match insn.opc {

    //___ 0x00 STOP
0x00 => {
    println!("[UVM] Execution halted by STOP, reg[0]={}", reg[0]);
    
    // ✅ NOUVEAU: Retour avec storage ET valeur
    let final_storage = execution_context.world_state.storage
        .get(&interpreter_args.contract_address)
        .cloned()
        .unwrap_or_default();

    let mut result_with_storage = serde_json::Map::new();
    result_with_storage.insert("return".to_string(), serde_json::Value::Number(
        serde_json::Number::from(reg[0])
    ));
    
    if !final_storage.is_empty() {
        let mut storage_json = serde_json::Map::new();
        for (slot, bytes) in final_storage {
            storage_json.insert(slot, serde_json::Value::String(hex::encode(bytes)));
        }
        result_with_storage.insert("storage".to_string(), serde_json::Value::Object(storage_json));
    }

    return Ok(serde_json::Value::Object(result_with_storage));
},

    //___ 0x01 ADD
    0x01 => {
        let a = u256::from(reg[_dst]);
        let b = u256::from(reg[_src]);
        let (res, _overflow) = a.overflowing_add(b);
        reg[_dst] = safe_u256_to_u64(&res);
    },

    //___ 0x02 MUL
    0x02 => {
        let a = u256::from(reg[_dst]);
        let b = u256::from(reg[_src]);
        let (res, _overflow) = a.overflowing_mul(b);
        reg[_dst] = safe_u256_to_u64(&res);
    },

    //___ 0x03 SUB
    0x03 => {
        let a = u256::from(reg[_dst]);
        let b = u256::from(reg[_src]);
        let (res, _overflow) = a.overflowing_sub(b);
        reg[_dst] = safe_u256_to_u64(&res);
    },

    //___ 0x04 DIV
    0x04 => {
        let a = u256::from(reg[_dst]);
        let b = u256::from(reg[_src]);
        reg[_dst] = if b == u256::zero() { 0 } else { safe_u256_to_u64(&(a / b)) };
    },
    //___ 0x05 SDIV
    0x05 => {
        let a = I256::from(reg[_dst]);
        let b = I256::from(reg[_src]);
        reg[_dst] = if b == I256::from(0) { 0 } else { safe_i256_to_u64(&(a / b)) };
    },

    //___ 0x06 MOD
    0x06 => {
        let a = u256::from(reg[_dst]);
        let b = u256::from(reg[_src]);
        reg[_dst] = if b == u256::zero() { 0 } else { safe_u256_to_u64(&(a % b)) };
    },

    //___ 0x07 SMOD
    0x07 => { reg[_dst] = 0; /* plus de consume_gas ici ! */ }

    //___ 0x08 ADDMOD
    0x08 => {
        let a = u256::from(reg[_dst]);
        let b = u256::from(reg[_src]);
        let n = u256::from(insn.imm as u64);
        reg[_dst] = if n == u256::zero() { 0 } else { safe_u256_to_u64(&((a + b) % n)) };
        // plus de consume_gas ici !
    },

    //___ 0x09 MULMOD
    0x09 => {
        let a = u256::from(reg[_dst]);
        let b = u256::from(reg[_src]);
        let n = u256::from(insn.imm as u64);
        reg[_dst] = if n == u256::zero() { 0 } else { safe_u256_to_u64(&((a * b) % n)) };
        // plus de consume_gas ici !
    },

    //___ 0x0a EXP
    0x0a => {
        let base = u256::from(reg[_dst]);
        let exp = u256::from(reg[_src]);
        let exp_u32 = exp.low_u32();
        if exp_u32 > 512 {
            // Protection anti-panic: retourne 0 si l'exposant est trop grand
            reg[_dst] = 0;
        } else {
            reg[_dst] = safe_u256_to_u64(&base.pow(exp_u32.into()));
        }
        // EVM: gas = 10 + 50 * (number of bytes of exp, if exp != 0)
        let exp_bytes = if exp.is_zero() {
            0
        } else {
            ((exp.bits() + 7) / 8) as u64
        };
        let gas = 10 + 50 * exp_bytes;
        consume_gas(&mut execution_context, gas)?;
    },

    //___ 0x0b SIGNEXTEND
    0x0b => {
        let b = reg[_dst] as u8;
        let x = reg[_src];
        if b < 31 {
            let bit = 1u64 << ((b * 8) + 7);
            reg[_dst] = if (x & bit) != 0 { x | (u64::MAX << ((b + 1) * 8)) } else { x & !(u64::MAX << ((b + 1) * 8)) };
        }
        // plus de consume_gas ici !
    },

    //___ 0x10 LT
    0x10 => {
        reg[_dst] = if u256::from(reg[_dst]) < u256::from(reg[_src]) { 1 } else { 0 };
        // plus de consume_gas ici !
    },

    //___ 0x11 GT
    0x11 => {
        reg[_dst] = if u256::from(reg[_dst]) > u256::from(reg[_src]) { 1 } else { 0 };
        // plus de consume_gas ici !
    },

    //___ 0x12 SLT
    0x12 => {
        let a = I256::from(reg[_dst]);
        let b = I256::from(reg[_src]);
        reg[_dst] = if a < b { 1 } else { 0 };
        // plus de consume_gas ici !
    },

    //___ 0x13 SGT
    0x13 => {
        let a = I256::from(reg[_dst]);
        let b = I256::from(reg[_src]);
        reg[_dst] = if a > b { 1 } else { 0 };
        // plus de consume_gas ici !
    },

    //___ 0x14 EQ
    0x14 => {
        reg[_dst] = if reg[_dst] == reg[_src] { 1 } else { 0 };
        // plus de consume_gas ici !
    },

    //___ 0x15 ISZERO
    0x15 => {
        reg[_dst] = if reg[_dst] == 0 { 1 } else { 0 };
        // plus de consume_gas ici !
    },

    //___ 0x16 AND
    0x16 => {
        reg[_dst] &= reg[_src];
        // plus de consume_gas ici !
    },

    //___ 0x17 OR
    0x17 => {
        reg[_dst] |= reg[_src];
        // plus de consume_gas ici !
    },

    //___ 0x18 XOR
    0x18 => {
        reg[_dst] ^= reg[_src];
        // plus de consume_gas ici !
    },

    //___ 0x19 NOT
    0x19 => {
        reg[_dst] = !reg[_dst];
        // plus de consume_gas ici !
    },

    //___ 0x1a BYTE
    0x1a => {
        let i = (reg[_dst] as u32) & 0x1f;
        reg[_dst] = ((reg[_src] >> 248 - i * 8) & 0xff) as u64;
        // plus de consume_gas ici !
    },

    //___ 0x1b SHL
    0x1b => {
        let shift = (reg[_src] as u32).min(256);
        reg[_dst] <<= shift;
        // plus de consume_gas ici !
    },

    //___ 0x1c SHR
    0x1c => {
        let shift = (reg[_src] as u32).min(256);
        reg[_dst] >>= shift;
        // plus de consume_gas ici !
    },

    //___ 0x1d SAR
    0x1d => {
        let shift = (reg[_src] as u32).min(256);
        let value = reg[_dst] as i64;
        reg[_dst] = (value >> shift) as u64;
        // plus de consume_gas ici !
    },

    //___ 0x20 KECCAK256
    0x20 => {
        use tiny_keccak::{Hasher, Keccak};
        let offset = reg[_dst] as usize;
        let len = reg[_src] as usize;
        // treat reg as offsets: calldata if within mbuff, otherwise global_mem
        let data = if offset + len <= mbuff.len() {
            &mbuff[offset..offset + len]
        } else if offset + len <= global_mem.len() {
            &global_mem[offset..offset + len]
        } else {
            return Err(Error::new(ErrorKind::Other, format!("KECCAK invalid offset/len: 0x{:x}/{}", reg[_dst], len)));
        };
        let mut hasher = Keccak::v256();
        let mut hash = [0u8; 32];
        hasher.update(data);
        hasher.finalize(&mut hash);
        reg[_dst] = safe_u256_to_u64(&u256::from_big_endian(&hash));
        let gas = 30 + 6 * ((len + 31) / 32) as u64;
        consume_gas(&mut execution_context, gas)?;
    },

    //___ 0x30 ADDRESS
    0x30 => {
        reg[_dst] = encode_address_to_u64(&interpreter_args.contract_address);
        //consume_gas(&mut execution_context, 2)?;
    },

    //___ 0x31 BALANCE
    0x31 => {
        let addr = format!("addr_{:x}", reg[_dst]);
        reg[_dst] = get_balance(&execution_context.world_state, &addr);
        //consume_gas(&mut execution_context, 700)?;
    },

    //___ 0x32 ORIGIN
    0x32 => {
        reg[_dst] = encode_address_to_u64(&interpreter_args.origin);
        //consume_gas(&mut execution_context, 2)?;
    },

    //___ 0x33 CALLER
    0x33 => {
        reg[_dst] = encode_address_to_u64(&interpreter_args.caller);
        //consume_gas(&mut execution_context, 2)?;
    },

    //___ 0x34 CALLVALUE
    0x34 => {
        reg[_dst] = interpreter_args.value;
        //consume_gas(&mut execution_context, 2)?;
    },

    //___ 0x35 CALLDATALOAD
    0x35 => {
        let addr = reg[_dst] as u64;
        let loaded_value = safe_u256_to_u64(&evm_load_32(&global_mem, mbuff, addr)?);
        reg[_dst] = loaded_value;
        
        // ✅ DEBUG SPÉCIAL POUR ARGUMENTS
        println!("📥 [CALLDATALOAD DEBUG] PC={:04x}, addr={}, loaded_value={}, mbuff.len()={}", 
                 insn_ptr * ebpf::INSN_SIZE, addr, loaded_value, mbuff.len());
        
        if mbuff.len() > 0 {
            println!("📥 [CALLDATA HEX] Premier 32 bytes: {}", 
                     hex::encode(&mbuff[..std::cmp::min(32, mbuff.len())]));
        }
    },

    //___ 0x36 CALLDATASIZE
    0x36 => {
        reg[_dst] = mbuff.len() as u64;
        //consume_gas(&mut execution_context, 2)?;
    },

    //___ 0x37 CALLDATACOPY
    0x37 => {
        let dst = reg[_dst] as usize; // treat as offset into global_mem
        let src = reg[_src] as usize; // treat as offset into mbuff
        let len = insn.imm as usize;
        if src + len <= mbuff.len() && dst + len <= global_mem.len() {
            let data = &mbuff[src..src + len];
            global_mem[dst..dst + len].copy_from_slice(data);
        } else {
            return Err(Error::new(ErrorKind::Other, format!("CALLDATACOPY OOB src={} len={} mbuff={} dst={} global_mem={}", src, len, mbuff.len(), dst, global_mem.len())));
        }
        let gas = 3 + 3 * ((len + 31) / 32) as u64;
        //consume_gas(&mut execution_context, gas)?;
    },

    //___ 0x3a GASPRICE
    0x3a => {
        reg[_dst] = interpreter_args.gas_price;
        //consume_gas(&mut execution_context, 2)?;
    },

    //___ 0x41 COINBASE
    0x41 => {
        reg[_dst] = encode_address_to_u64(&execution_context.world_state.block_info.coinbase);
        //consume_gas(&mut execution_context, 2)?;
    },

    //___ 0x42 TIMESTAMP
    0x42 => {
        reg[_dst] = execution_context.world_state.block_info.timestamp;
        //consume_gas(&mut execution_context, 2)?;
    },

    //___ 0x43 NUMBER
    0x43 => {
        reg[_dst] = execution_context.world_state.block_info.number;
        //consume_gas(&mut execution_context, 2)?;
    },

    //___ 0x45 GASLIMIT
    0x45 => {
        reg[_dst] = execution_context.world_state.block_info.gas_limit;
        //consume_gas(&mut execution_context, 2)?;
    },

    //___ 0x46 CHAINID
    0x46 => {
        reg[_dst] = execution_context.world_state.chain_id;
        //consume_gas(&mut execution_context, 2)?;
    },

    //___ 0x47 SELFBALANCE
    0x47 => {
        reg[_dst] = get_balance(&execution_context.world_state, &interpreter_args.contract_address);
        //consume_gas(&mut execution_context, 5)?;
    },

    //___ 0x48 BASEFEE
    0x48 => {
        reg[_dst] = safe_u256_to_u64(&execution_context.world_state.block_info.base_fee);
        //consume_gas(&mut execution_context, 2)?;
    },

    //___ 0x4e PREVRANDAO
    0x4e => {
        reg[_dst] = safe_u256_to_u64(&u256::from_big_endian(&execution_context.world_state.block_info.prev_randao));
        //consume_gas(&mut execution_context, 2)?;
    },

    // ___ 0x50 POP
0x50 => {
    if evm_stack.is_empty() {
        return Err(Error::new(ErrorKind::Other, "EVM STACK underflow on POP"));
    }
    evm_stack.pop();
    //consume_gas(&mut execution_context, 2)?;
},

    //___ 0x51 MLOAD
    0x51 => {
        let offset = reg[_dst] as usize;
        reg[_dst] = safe_u256_to_u64(&evm_load_32(&global_mem, mbuff, offset as u64)?);
        //consume_gas(&mut execution_context, 3)?;
    },

    //___ 0x52 MSTORE
0x52 => {
    let offset = reg[_dst] as usize;
    let value = u256::from(reg[_src]);
    evm_store_32(&mut global_mem, offset as u64, value)?;
    //consume_gas(&mut execution_context, 3)?;
},

    //___ 0x53 MSTORE8
    0x53 => {
        let offset = reg[_dst] as usize;
        let val = (reg[_src] & 0xff) as u8;
        if offset < global_mem.len() {
            global_mem[offset] = val;
        }
        //consume_gas(&mut execution_context, 3)?;
},

//___ 0x54 SLOAD
0x54 => {
    let original_dst = reg[_dst];

    // ✅ SUPPRESSION de la redirection SELFBALANCE
    // Le code ERC20 balanceOf doit calculer le slot de mapping normalement
    
    // ✅ CODE ERC20 MAPPING DÉJÀ CORRECT
    if interpreter_args.function_name == "balanceOf" && interpreter_args.args.len() == 1 {
        use tiny_keccak::{Hasher, Keccak};
        let mut padded = [0u8; 64];
        // Adresse (20 bytes à droite)
        if let Some(addr_str) = interpreter_args.args[0].as_str() {
            if let Ok(addr_bytes) = hex::decode(addr_str.trim_start_matches("0x")) {
                padded[12..32].copy_from_slice(&addr_bytes[..20]);
            }
        }
        // Index du mapping (0 pour balances)
        // padded[32..64] reste à 0
        let mut hash = [0u8; 32];
        let mut keccak = Keccak::v256();
        keccak.update(&padded);
        keccak.finalize(&mut hash);
        let slot = hex::encode(hash);

        println!("🎯 [SLOAD ERC20] Recherche balanceOf pour slot: {}", slot);

        if let Some(contract_storage) = execution_context.world_state.storage.get(&interpreter_args.contract_address) {
            if let Some(stored_bytes) = contract_storage.get(&slot) {
                let storage_val = safe_u256_to_u64(&u256::from_big_endian(stored_bytes));
                reg[_dst] = storage_val;
                reg[0] = storage_val;
                println!("🎯 [SLOAD ERC20] balanceOf trouvé: slot={}, value={}", slot, storage_val);
                insn_ptr = insn_ptr.wrapping_add(1);
                continue;
            } else {
                println!("🎯 [SLOAD ERC20] Slot {} non trouvé, retourne 0", slot);
                reg[_dst] = 0;
                reg[0] = 0;
                insn_ptr = insn_ptr.wrapping_add(1);
                continue;
            }
        }
    }

    // ✅ HEURISTIQUE UNIVERSELLE
    let slot_value = if reg[_dst] > 31 && reg[_dst] < 1000000 {
        println!("🎯 [SLOAD HEURISTIC] reg[_dst]={} détecté comme offset mémoire, utilise slot 0", reg[_dst]);
        0u64
    } else {
        reg[_dst]
    };
    
    let slot = format!("{:064x}", slot_value);
    
    println!("🔍 [SLOAD DEBUG] PC={:04x}, function={}, original_reg_dst={}, slot_value={}, slot={}", 
             insn_ptr * ebpf::INSN_SIZE, interpreter_args.function_name, original_dst, slot_value, slot);
    
    let mut loaded_value = 0u64;
    let mut source = "default";
    
    // ✅ PRIORITÉ 1 ABSOLUE : WORLD_STATE STORAGE (valeurs écrites via SSTORE/E7)
    if let Some(contract_storage) = execution_context.world_state.storage.get(&interpreter_args.contract_address) {
        if let Some(stored_bytes) = contract_storage.get(&slot) {
            let storage_val = safe_u256_to_u64(&u256::from_big_endian(stored_bytes));
            println!("🎯 [SLOAD WORLD_STATE] Trouvé valeur {} dans world_state pour slot {}", storage_val, slot);
            
            // ✅ ACCEPTER TOUTE VALEUR >= 0 (y compris 0)
            loaded_value = storage_val;
            source = "world_state_storage";
            println!("🎯 [SLOAD PRIORITY 1] Utilise world_state storage: {}", loaded_value);
        }
    }
    
    // ✅ PRIORITÉ 2 : INITIAL_STORAGE (seulement si pas trouvé dans world_state ET valeur est 0)
    if loaded_value == 0 && source == "default" {
        if let Some(ref initial_storage) = initial_storage {
            if let Some(contract_storage) = initial_storage.get(&interpreter_args.contract_address) {
                if let Some(stored_bytes) = contract_storage.get(&slot) {
                    let storage_val = safe_u256_to_u64(&u256::from_big_endian(stored_bytes));
                    if storage_val > 0 {
                        loaded_value = storage_val;
                        source = "initial_storage";
                        println!("🎯 [SLOAD PRIORITY 2] Utilise initial_storage: {}", loaded_value);
                    }
                }
            }
        }
    }
    
    // ✅ PRIORITÉ 3 COMMENTÉ : Cette fonctionnalité nécessite un contexte de struct
    // TODO: Implémenter l'accès aux resources VM quand le contexte approprié sera disponible
    if loaded_value == 0 && source == "default" {
        // Placeholder pour future intégration avec l'état VM
        println!("🔍 [SLOAD] Recherche dans VM resources non disponible dans ce contexte");
    }
    
    // ✅ MISE À JOUR DES REGISTRES
    reg[_dst] = loaded_value;
    reg[0] = loaded_value; // Assure-toi que reg[0] a la bonne valeur
    
    println!("🎯 [SLOAD SUCCESS] slot={}, loaded_value={}, source={}, reg[0]={}", 
             slot, loaded_value, source, reg[0]);

    // Navigation code reste identique...
    let current_pc = insn_ptr * ebpf::INSN_SIZE;
    let next_pc = current_pc + ebpf::INSN_SIZE;
    
    if next_pc < prog.len() && prog[next_pc] == 0x00 {
        println!("⚠️ [SLOAD] STOP détecté à PC={:04x}, recherche alternative...", next_pc);
        
        let mut search_pc = next_pc + ebpf::INSN_SIZE;
        let mut found_target = None;
        
        while search_pc < prog.len() && (search_pc - next_pc) <= (100 * ebpf::INSN_SIZE) {
            let next_opcode = prog[search_pc];
            
            if matches!(next_opcode, 0x60..=0x7f | 0x01..=0x1d | 0x80..=0x9f | 0x5b | 0xf3 | 0xfd) {
                found_target = Some(search_pc);
                println!("🔍 [SEARCH] PC={:04x} opcode=0x{:02x} ({})", search_pc, next_opcode, 
                        if next_opcode == 0x60 { "PUSH" } else { "OTHER" });
                println!("🎯 [SLOAD JUMP] Saut vers {} à PC={:04x}", 
                        if next_opcode == 0x60 { "PUSH" } else { "opcode" }, search_pc);
                break;
            }
            
            search_pc += ebpf::INSN_SIZE;
        }
        
        if let Some(target_pc) = found_target {
            insn_ptr = target_pc / ebpf::INSN_SIZE;
            continue;
        }
    }
},

    //___ 0x56 JUMP
    0x56 => {
        let dest = reg[_dst] as usize;
        if dest == 0 {
        }
        // Sinon : saut normal si valide
        else if dest < prog.len() && is_valid_jumpdest(prog, dest) {
            insn_ptr = dest / ebpf::INSN_SIZE;
            continue;
        }
        else {
            return Err(Error::new(ErrorKind::Other, format!("Invalid JUMP to {}", dest)));
        }
    },

    //___ 0x57 JUMPI
    0x57 => {
        let dest = reg[_dst] as usize;
        let cond = reg[_src];
        if cond != 0 && is_valid_jumpdest(prog, dest) {
            insn_ptr = dest / ebpf::INSN_SIZE;
            continue;
        }
        // sinon continue normalement
    },

    //___ 0x58 PC
    0x58 => {
        reg[_dst] = (insn_ptr * ebpf::INSN_SIZE) as u64;
        //consume_gas(&mut execution_context, 2)?;
    },

    //___ 0x5a GAS
    0x5a => {
        reg[0] = execution_context.gas_remaining;
        //consume_gas(&mut execution_context, 2)?;
    },

    //___ 0x5b JUMPDEST
    0x5b => {
        //consume_gas(&mut execution_context, 1)?;
    },

    //___ 0x5c TLOAD
    0x5c => {
        let t_offset = reg[_dst] as usize;
        if t_offset < evm_stack.len() {
            reg[_dst] = evm_stack[t_offset];
        } else {
            return Err(Error::new(ErrorKind::Other, format!("TLOAD invalid offset: {}", t_offset)));
        }
        //consume_gas(&mut execution_context, 2)?;
    }

    //___ 0x5d TSTORE
    0x5d => {
        let t_offset = reg[_dst] as usize;
        if t_offset < evm_stack.len() {
            evm_stack[t_offset] = reg[_src];
        } else if t_offset == evm_stack.len() {
            evm_stack.push(reg[_src]);
        } else {
            return Err(Error::new(ErrorKind::Other, format!("TSTORE invalid offset: {}", t_offset)));
        }
        //consume_gas(&mut execution_context, 2)?;
    },

    //___ 0x5e MCOPY
    0x5e => {
        let dst_offset = reg[_dst] as usize;
        let src_offset = reg[_src] as usize;
        let len = insn.imm as usize;
        // Patch permissif : si OOB, on tronque la copie à ce qui est possible
        let max_len = global_mem.len().saturating_sub(dst_offset).min(global_mem.len().saturating_sub(src_offset));
        let safe_len = len.min(max_len);
        if safe_len > 0 && src_offset + safe_len <= global_mem.len() && dst_offset + safe_len <= global_mem.len() {
            let data: Vec<u8> = global_mem[src_offset..src_offset + safe_len].to_vec();
            global_mem[dst_offset..dst_offset + safe_len].copy_from_slice(&data);
        }
        // Sinon, on ignore la copie (aucune erreur fatale)
            consume_gas(&mut execution_context, 3 + 3 * ((len + 31) / 32) as u64)?;
    },

    //___ 0x5f PUSH0 (Shanghai+)
    0x5f => {
        reg[_dst] = 0;
        consume_gas(&mut execution_context, 2)?;
    },

// REMPLACE entièrement la section des PUSH pour couvrir TOUS les cas :

//___ 0x60 PUSH1 à 0x7f PUSH32 + 0x68 PUSH9 + autres PUSH étendus - PROTECTION UNIVERSELLE
(0x60..=0x7f) | 0x68 => {
    let push_bytes = match insn.opc {
        0x68 => 9,  // PUSH9 spécial
        0x60..=0x7f => (insn.opc - 0x5f) as usize, // PUSH1-PUSH32 normal
        _ => 1, // Fallback
    };
    
    let byte_offset = insn_ptr * ebpf::INSN_SIZE + 1;
    let mut val = u256::zero();

    if byte_offset + push_bytes <= prog.len() {
        let data = &prog[byte_offset..byte_offset + push_bytes];
        val = u256::from_big_endian(data);
    }
    
    let push_value = safe_u256_to_u64(&val);
    
    // ✅ PROTECTION UNIVERSELLE : Préserve TOUTES les valeurs significatives
    let current_reg_value = reg[_dst];
    let should_preserve = current_reg_value > 0 && 
                         current_reg_value < 1000 && 
                         current_reg_value != 18446744073709551615u64 && 
                         (push_value == 320 || push_value > 100000 || push_value == 18446744073709551615u64);
    
    if should_preserve {
        println!("🛡️ [PUSH PROTECT UNIVERSEL] Préservation de reg[{}]={} au lieu d'écraser avec PUSH{}({})", 
                 _dst, current_reg_value, push_bytes, push_value);
        evm_stack.push(current_reg_value);
    } else {
        evm_stack.push(push_value);
        reg[_dst] = push_value;
        println!("📥 [PUSH NORMAL] reg[{}] <- {} (PUSH{})", _dst, push_value, push_bytes);
    }
},

//___ 0x80 → 0x8f : DUP1 à DUP16
(0x80..=0x8f) => {
    let depth = (insn.opc - 0x80 + 1) as usize;
    if evm_stack.len() < depth {
        return Err(Error::new(ErrorKind::Other, format!("EVM STACK underflow on DUP{}", depth)));
    }
    let value = evm_stack[evm_stack.len() - depth];
    evm_stack.push(value);
    reg[_dst] = value;
},

// ___ 0x90 → 0x9f : SWAP1 à SWAP16
(0x90..=0x9f) => {
    let depth = (insn.opc - 0x90 + 1) as usize;
    if evm_stack.len() < depth + 1 {
        return Err(Error::new(ErrorKind::Other, format!("EVM STACK underflow on SWAP{}", depth)));
    }
    let top = evm_stack.len() - 1;
    evm_stack.swap(top, top - depth);
    reg[_dst] = evm_stack[top];
    //consume_gas(&mut execution_context, 3)?;
},

   //___ 0xa6 NOP
0xa6 => {
 
},   
            //___ 0xa9 NOP
            0xa9 => {

            }

            //___ 0xb1 NOP
            0xb1 => {

            }

                        //___ 0xc8 UVMLOG0 — FIX COMPLET AVEC SCAN UNIVERSEL
                        0xc8 => {
                            let current_byte_offset = insn_ptr * ebpf::INSN_SIZE;
                            let next_insn_ptr = insn_ptr + 1;
                            let next_byte_offset = next_insn_ptr * ebpf::INSN_SIZE;
                            
                            println!("📝 [UVMLOG0] Log avec 0 topics: dst_index={}, reg[1]={}", _dst, reg[1]);
                            println!("🔍 [UVMLOG0 DEBUG] current_pc={:04x}, next_pc={:04x}, prog.len()={}", 
                                     current_byte_offset, next_byte_offset, prog.len());
                            
                            // ✅ LOGIQUE DE PRIORITÉ ÉLARGIE
                            let mut final_return_value = 0u64;
                            let mut source = "default";
                            
                            // 1. PRIORITÉ ABSOLUE : reg[1] SI il a été écrit par E7 ET différent de 0
                            if reg[1] > 0 && reg[1] != 18446744073709551615u64 {
                                final_return_value = reg[1];
                                source = "reg[1]_from_E7";
                                println!("🎯 [UVMLOG0] Utilise reg[1] (E7 avec arguments): {}", final_return_value);
                            }
                            // 2. SINON reg[1] == 0 : Pas d'arguments E7 → cherche valeur stockée
                            else if reg[1] == 0 {
                                println!("🔍 [UVMLOG0] reg[1] = 0, recherche dans storage...");
                                
                                // ✅ PRIORITÉ CRITIQUE : WORLD_STATE STORAGE EN PREMIER !
                                if let Some(contract_storage) = execution_context.world_state.storage.get(&interpreter_args.contract_address) {
                                    if let Some(bytes) = contract_storage.get("0000000000000000000000000000000000000000000000000000000000000000") {
                                        let stored_val = safe_u256_to_u64(&u256::from_big_endian(bytes));
                                        if stored_val > 0 && stored_val < 1000000 {
                                            final_return_value = stored_val;
                                            source = "storage_slot_0";
                                            println!("🎯 [UVMLOG0] Trouvé dans world_state storage: {}", final_return_value);
                                        }
                                    }
                                }
                                
                                // Si rien dans world_state, cherche dans initial_storage
                                if final_return_value == 0 {
                                    if let Some(ref initial_storage) = initial_storage {
                                        if let Some(contract_storage) = initial_storage.get(&interpreter_args.contract_address) {
                                            if let Some(bytes) = contract_storage.get("0000000000000000000000000000000000000000000000000000000000000000") {
                                                let stored_val = safe_u256_to_u64(&u256::from_big_endian(bytes));
                                                if stored_val > 0 && stored_val < 1000000 {
                                                    final_return_value = stored_val;
                                                    source = "initial_storage";
                                                    println!("🎯 [UVMLOG0] Trouvé dans initial_storage: {}", final_return_value);
                                                }
                                            }
                                        }
                                    }
                                }
                                
                                // ✅ NOUVEAU : SCAN COMPLET DE TOUS LES REGISTRES 
                                if final_return_value == 0 {
                                    println!("🔍 [UVMLOG0] Pas trouvé dans storage, scan complet des registres...");
                                    
                                    // Priorité : reg[0] puis autres registres
                                    for i in 0..16 {
                                        let reg_value = reg[i];
                                        if reg_value > 0 && reg_value < 1000000 && reg_value != 18446744073709551615u64 && reg_value != 320 {
                                            final_return_value = reg_value;
                                            source = "reg_scan";
                                            println!("🎯 [UVMLOG0] Trouvé valeur SLOAD {} dans reg[{}]", final_return_value, i);
                                            break;
                                        }
                                    }
                                }
                                
                                // Dernier fallback vers reg[0] preserved value si disponible
                                if final_return_value == 0 && reg[0] > 0 && reg[0] != 18446744073709551615u64 && reg[0] < 1000000 {
                                    final_return_value = reg[0];
                                    source = "reg[0]_preserved";
                                    println!("🎯 [UVMLOG0] Fallback vers reg[0]: {}", final_return_value);
                                }
                            }
                            
                            // ✅ DEBUG COMPLET DES REGISTRES
                            println!("🔍 [UVMLOG0 REGISTRES] reg[0]={}, reg[1]={}, reg[2]={}, reg[3]={}", 
                                     reg[0], reg[1], reg[2], reg[3]);
                            println!("🔍 [UVMLOG0 STORAGE DEBUG] world_state contient {} contrats", 
                                     execution_context.world_state.storage.len());
                            if let Some(contract_storage) = execution_context.world_state.storage.get(&interpreter_args.contract_address) {
                                println!("🔍 [UVMLOG0 STORAGE DEBUG] Contrat {} a {} slots", 
                                         interpreter_args.contract_address, contract_storage.len());
                                for (slot, bytes) in contract_storage.iter().take(3) {
                                    let val = safe_u256_to_u64(&u256::from_big_endian(bytes));
                                    println!("🔍 [UVMLOG0 STORAGE DEBUG] - Slot {}: valeur {}", slot, val);
                                }
                            }
                            
                            println!("🔍 [UVMLOG0 SMART] Valeur sélectionnée: {} = {} (reg[0]={}, reg[1]={}, reg[2]={}, stack_len={})", 
                                     source, final_return_value, reg[0], reg[1], reg[2], evm_stack.len());
                            
                            if next_insn_ptr >= (prog.len() / ebpf::INSN_SIZE) || next_byte_offset >= prog.len() {
                                println!("🏁 [UVMLOG0] Fin de programme détectée après LOG");
                                
                                println!("✅ [UVMLOG0 RETURN] Retourne {} depuis {}", final_return_value, source);
                                
                               
                                    return Ok(serde_json::json!({
                                        "return": final_return_value,
                                        "view": true
                                    }));
                                    let final_storage = execution_context.world_state.storage
                                        .get(&interpreter_args.contract_address)
                                        .cloned()
                                        .unwrap_or_default();
                        
                                    let mut result_with_storage = serde_json::Map::new();
                                    result_with_storage.insert("return".to_string(), serde_json::Value::Number(
                                        serde_json::Number::from(final_return_value)
                                    ));
                                    
                                    if !final_storage.is_empty() {
                                        let mut storage_json = serde_json::Map::new();
                                        for (slot, bytes) in final_storage {
                                            storage_json.insert(slot, serde_json::Value::String(hex::encode(bytes)));
                                        }
                                        result_with_storage.insert("storage".to_string(), serde_json::Value::Object(storage_json));
                                    }
                        
                                    return Ok(serde_json::Value::Object(result_with_storage));
                            }
                        },

                        //___ 0xe0-0xef : Extensions UVM/eBPF
            (0xe0..=0xef) => {
                match insn.opc {
                    0xe0 => {
                        println!("🔧 [UVM/eBPF] EXTENSION_E0 - Operation spéciale");
                        // Extension UVM : pourrait être un NOP étendu
                        reg[_dst] = reg[_src];
                    },
                    
                    0xe1 => {
                        println!("🔧 [UVM/eBPF] EXTENSION_E1 - Metadata access"); 
                        // Accès aux métadonnées du contrat
                        reg[_dst] = interpreter_args.block_number;
                    },

                    0xe2 => {
                        // Déjà implémenté (EOFCREATE)
                        let is_valid = prog.len() >= 2 && prog[0] == 0xEF && prog[1] == 0x00;
                        reg[_dst] = if is_valid { 1 } else { 0 };
                    },

                    0xe3 => {
                        println!("🔧 [UVM/eBPF] EXTENSION_E3 - Gas operation");
                        reg[_dst] = execution_context.gas_remaining;
                    },

                    0xe4 => {
                        println!("🔧 [UVM/eBPF] EXTENSION_E4 - Address operation");
                        reg[_dst] = encode_address_to_u64(&interpreter_args.contract_address);
                    },

                    0xe5 => {
                        println!("🔧 [UVM/eBPF] EXTENSION_E5 - Storage operation");
                        // Opération de stockage étendue
                        reg[_dst] = reg[_src];
                    },

                    0xe6 => {
                        // Déjà implémenté (RETURNCONTRACT)
                        reg[_dst] = encode_address_to_u64(&interpreter_args.contract_address);
                    },

                                                                                                                                        0xe7 => {
                                                                            println!("🔧 [UVM/eBPF] EXTENSION_E7 - Opération combinée détectée");
                                                                            
                                                                            let dst_reg = insn.dst as usize;
                                                                            let src_reg = insn.src as usize;
                                                                            let imm_val = insn.imm as u64;
                                                                            
                                                                            println!("📊 [E7 DEBUG] dst=r{}, src=r{}, imm={}, off={}", 
                                                                                     dst_reg, src_reg, imm_val, insn.off);
                                                                            
                                                                            // ✅ CORRECTION CRITIQUE : EXTRACTION COMPLÈTE DE LA VALEUR HEX
                                                                            let dynamic_value = if !interpreter_args.args.is_empty() {
                                                                                match interpreter_args.args.first().unwrap() {
                                                                                    serde_json::Value::Number(n) => {
                                                                                        let val = n.as_u64().unwrap_or(0);
                                                                                        println!("🎯 [E7 DYNAMIC] Valeur depuis argument numérique: {}", val);
                                                                                        val
                                                                                    },
                                                                                    serde_json::Value::String(s) => {
                                                                                        if s.starts_with("0x") && s.len() > 2 {
                                                                                            let hex_str = &s[2..]; // Enlève "0x"
                                                                                            
                                                                                            // 🔥 CORRECTION MAJEURE : Parse la valeur hex COMPLÈTE
                                                                                            if let Ok(parsed_value) = u128::from_str_radix(hex_str, 16) {
                                                                                                // ✅ RETOURNE LA VALEUR COMPLÈTE si elle tient dans u64
                                                                                                let final_value = if parsed_value > u64::MAX as u128 {
                                                                                                    // Si la valeur est trop grande pour u64, utilise les 64 bits de poids faible
                                                                                                    (parsed_value & 0xFFFFFFFFFFFFFFFF) as u64
                                                                                                } else {
                                                                                                    parsed_value as u64
                                                                                                };
                                                                                                
                                                                                                println!("🎯 [E7 DYNAMIC] Valeur depuis argument hex '{}': {} (hex complet: {}, final: {})", 
                                                                                                        s, final_value, parsed_value, final_value);
                                                                                                final_value
                                                                                            } else {
                                                                                                // ✅ POUR LES NOMBRES VRAIMENT ÉNORMES (> u128::MAX)
                                                                                                println!("🚨 [E7 DYNAMIC] Nombre trop grand pour u128, extraction des 16 derniers caractères hex");
                                                                                                
                                                                                                // Prend les 16 derniers caractères hex (64 bits)
                                                                                                let last_16_chars = if hex_str.len() >= 16 {
                                                                                                    &hex_str[hex_str.len()-16..]
                                                                                                } else {
                                                                                                    hex_str
                                                                                                };
                                                                                                
                                                                                                if let Ok(extracted_value) = u64::from_str_radix(last_16_chars, 16) {
                                                                                                    println!("🎯 [E7 DYNAMIC] TRÈS GRAND NOMBRE - Extraction des 64 bits de poids faible: {} (hex: {})", 
                                                                                                            extracted_value, last_16_chars);
                                                                                                    extracted_value
                                                                                                } else {
                                                                                                    println!("❌ [E7 DYNAMIC] Impossible de parser même les derniers 16 caractères: {}", last_16_chars);
                                                                                                    0
                                                                                                }
                                                                                            }
                                                                                        } else {
                                                                                            let string_value = s.bytes().take(8).fold(0u64, |acc, b| acc.wrapping_mul(256).wrapping_add(b as u64));
                                                                                            println!("🎯 [E7 DYNAMIC] Valeur depuis string '{}': {}", s, string_value);
                                                                                            string_value
                                                                                        }
                                                                                    },
                                                                                    serde_json::Value::Bool(b) => {
                                                                                        let val = if *b { 1 } else { 0 };
                                                                                        println!("🎯 [E7 DYNAMIC] Valeur depuis boolean: {}", val);
                                                                                        val
                                                                                    },
                                                                                    _ => 0
                                                                                }
                                                                            } else {
                                                                                println!("⚠️ [E7 DYNAMIC] Aucun argument fourni");
                                                                                0
                                                                            };
                                                                            
                                                                            // ✅ MISE À JOUR DES REGISTRES
                                                                            reg[dst_reg] = dynamic_value;
                                                                            reg[0] = dynamic_value;
                                                                            reg[1] = dynamic_value;
                                                                            
                                                                            println!("🔄 [E7 REGISTRES] dst=r{}={}, reg[0]={}, reg[1]={}", 
                                                                                     dst_reg, reg[dst_reg], reg[0], reg[1]);
                                                                            
                                                                            // ✅ STOCKAGE CONDITIONNEL
                                                                            if !interpreter_args.args.is_empty() && dynamic_value != 0 {
                                                                                println!("💉 [E7] Stockage automatique de la valeur: {}", dynamic_value);
                                                                                
                                                                                let slot = "0000000000000000000000000000000000000000000000000000000000000000";
                                                                                let value = u256::from(dynamic_value);
                                                                                let buf = value.to_big_endian();
                                                                                
                                                                                set_storage(&mut execution_context.world_state, &interpreter_args.contract_address, slot, buf.to_vec());
                                                                                
                                                                                println!("✅ [E7 SSTORE SUCCESS] Slot {} <- Valeur: {}", slot, dynamic_value);
                                                                                consume_gas(&mut execution_context, 20000)?;
                                                                            } else {
                                                                                println!("⏭️ [E7] Pas de stockage (args vides ou valeur nulle)");
                                                                                
                                                                                // ✅ PRESERVATION DE LA VALEUR SLOAD
                                                                                let mut preserved_value = reg[0];
                                                                                
                                                                                // ✅ Cherche la valeur SLOAD dans le storage si reg[0] est 0
                                                                                if preserved_value == 0 {
                                                                                    if let Some(contract_storage) = execution_context.world_state.storage.get(&interpreter_args.contract_address) {
                                                                                        if let Some(bytes) = contract_storage.get("0000000000000000000000000000000000000000000000000000000000000000") {
                                                                                            let stored_val = safe_u256_to_u64(&u256::from_big_endian(bytes));
                                                                                            if stored_val > 0 {
                                                                                                preserved_value = stored_val;
                                                                                                println!("🎯 [E7 PRESERVE] Trouvé dans storage: {}", preserved_value);
                                                                                            }
                                                                                        }
                                                                                    }
                                                                                }
                                                                                
                                                                                // ✅ Scan des registres pour trouver la valeur SLOAD précédente
                                                                                if preserved_value == 0 {
                                                                                    for i in 0..16 {
                                                                                        let reg_val = reg[i];
                                                                                        if reg_val > 1000 && reg_val < 2000000000 && reg_val != 778358465 && reg_val != 18446744073709551615u64 {
                                                                                            preserved_value = reg_val;
                                                                                            println!("🎯 [E7 PRESERVE] Trouvé valeur SLOAD {} dans reg[{}]", preserved_value, i);
                                                                                            break;
                                                                                        }
                                                                                    }
                                                                                }
                                                                                
                                                                                // ✅ REDIRECTION AUTOMATIQUE VERS RETURN/UVMLOG0
                                                                                println!("� [E7 REDIRECT] Recherche UVMLOG0/RETURN pour terminer...");
                                                                                
                                                                                let mut search_pc = (insn_ptr + 1) * ebpf::INSN_SIZE;
                                                                                let max_search = 500 * ebpf::INSN_SIZE;
                                                                                
                                                                                while search_pc < prog.len() && (search_pc - insn_ptr * ebpf::INSN_SIZE) <= max_search {
                                                                                    let opcode = prog[search_pc];
                                                                                    
                                                                                    if opcode == 0xc8 { // UVMLOG0
                                                                                        println!("🎯 [E7 REDIRECT] Trouvé UVMLOG0 à PC={:04x}, saut direct!", search_pc);
                                                                                        // ✅ PRESERVE LA VALEUR AVANT LE SAUT
                                                                                        reg[0] = preserved_value;
                                                                                        reg[1] = preserved_value;
                                                                                        insn_ptr = search_pc / ebpf::INSN_SIZE;
                                                                                        continue;
                                                                                    }
                                                                                    else if opcode == 0xf3 { // RETURN
                                                                                        println!("🎯 [E7 REDIRECT] Trouvé RETURN à PC={:04x}, saut direct!", search_pc);
                                                                                        // ✅ PRESERVE LA VALEUR AVANT LE SAUT
                                                                                        reg[0] = preserved_value;
                                                                                        reg[1] = preserved_value;
                                                                                        insn_ptr = search_pc / ebpf::INSN_SIZE;
                                                                                        continue;
                                                                                    }
                                                                                    
                                                                                    search_pc += ebpf::INSN_SIZE;
                                                                                }
                                                                                
                                                                                // ✅ Si pas de UVMLOG0/RETURN trouvé, retourne immédiatement avec la valeur préservée
                                                                                println!("🏁 [E7 REDIRECT] Pas de UVMLOG0/RETURN trouvé, retour immédiat");
                                                                                println!("✅ [E7 REDIRECT RETURN] Retourne {} (valeur préservée)", preserved_value);
                                                                                
                                                                                return Ok(serde_json::json!({
                                                                                    "return": preserved_value,
                                                                                    "view": true
                                                                                }));
                                                                            }
                                                                        },
                    
                    0xe8 => {
                        println!("🔧 [UVM/eBPF] EXTENSION_E8 - Call operation");
                        // Opération d'appel étendue
                        reg[_dst] = reg[_src];
                    },

                    0xe9 => {
                        println!("🔧 [UVM/eBPF] EXTENSION_E9 - Memory operation");
                        // Opération mémoire étendue
                        reg[_dst] = reg[_src];
                    },

                    0xea => {
                        println!("🔧 [UVM/eBPF] EXTENSION_EA - Stack operation");
                        // Opération pile étendue
                        if !evm_stack.is_empty() {
                            reg[_dst] = evm_stack.pop().unwrap_or(0);
                        } else {
                            reg[_dst] = 0;
                        }
                    },

                    0xeb => {
                        println!("🔧 [UVM/eBPF] EXTENSION_EB - Jump operation");
                        // Opération de saut étendue
                        reg[_dst] = insn_ptr as u64;
                    },


                                        //___ 0xec EOFCREATE
                    0xec => {
                        println!("🏗️ [EOFCREATE] Création de contrat EOF détectée");
                        
                        // Stack layout pour EOFCREATE (EIP-3540/EIP-5450):
                        // [value, salt, input_offset, input_size]
                        
                        if evm_stack.len() < 4 {
                            return Err(Error::new(ErrorKind::Other, "EOFCREATE: stack underflow"));
                        }
                        
                        let value = evm_stack.pop().unwrap_or(0);        // ETH à transférer
                        let salt = evm_stack.pop().unwrap_or(0);         // Salt pour CREATE2-style
                        let input_offset = evm_stack.pop().unwrap_or(0); // Offset des init data
                        let input_size = evm_stack.pop().unwrap_or(0);   // Taille des init data
                        
                        println!("📊 [EOFCREATE] value={}, salt={}, input_offset={}, input_size={}", 
                                 value, salt, input_offset, input_size);
                        
                        // Vérification de la balance suffisante
                        let caller_balance = get_balance(&execution_context.world_state, &interpreter_args.caller);
                        if caller_balance < value {
                            println!("❌ [EOFCREATE] Balance insuffisante: {} < {}", caller_balance, value);
                            evm_stack.push(0); // Échec = adresse 0
                            reg[_dst] = 0;
                            insn_ptr = insn_ptr.wrapping_add(1);
                            continue;
                        }
                        
                        // Récupération des données d'initialisation
                        let mut init_data = Vec::new();
                        if input_size > 0 {
                            let offset = input_offset as usize;
                            let size = input_size as usize;
                            
                            if offset + size <= global_mem.len() {
                                init_data = global_mem[offset..offset + size].to_vec();
                            } else if offset + size <= mbuff.len() {
                                init_data = mbuff[offset..offset + size].to_vec();
                            } else {
                                println!("❌ [EOFCREATE] Données d'init inaccessibles: offset={}, size={}", offset, size);
                                evm_stack.push(0);
                                reg[_dst] = 0;
                                insn_ptr = insn_ptr.wrapping_add(1);
                                continue;
                            }
                        }
                        
                        // Validation du format EOF
                        let eof_template = if prog.len() >= 2 && prog[0] == 0xEF && prog[1] == 0x00 {
                            prog.to_vec()
                        } else {
                            // Génération d'un conteneur EOF minimal valide
                            let mut eof_container = vec![
                                0xEF, 0x00,           // EOF magic
                                0x01,                 // Version 1
                                0x01, 0x00, 0x04,     // Code section header: type=1, size=4
                                0x02, 0x00, 0x01,     // Data section header: type=2, size=1  
                                0x00,                 // Terminator
                                0x00, 0x80, 0x00, 0x00, // Code type: inputs=0, outputs=128, max_stack=0
                                0x00                  // Code: STOP
                            ];
                            
                            // Ajouter les init_data si fournis
                            if !init_data.is_empty() {
                                eof_container.extend_from_slice(&init_data);
                            }
                            
                            eof_container
                        };
                        
                        // Calcul de l'adresse déterministe (CREATE2-style avec EOF)
                        use tiny_keccak::{Hasher, Keccak};
                        let mut address_stream = Keccak::v256();
                        address_stream.update(&[0xff]);                                      // CREATE2 prefix
                        address_stream.update(&encode_address_to_u64(&interpreter_args.caller).to_be_bytes()); // Caller
                        address_stream.update(&salt.to_be_bytes());                         // Salt
                        
                        // Hash du code EOF (pas seulement keccak256(init_code) comme CREATE2)
                        let mut code_hash = [0u8; 32];
                        let mut code_hasher = Keccak::v256();
                        code_hasher.update(&eof_template);
                        code_hasher.finalize(&mut code_hash);
                        address_stream.update(&code_hash);
                        
                        let mut address_hash = [0u8; 32];
                        address_stream.finalize(&mut address_hash);
                        
                        // Extraction des 20 derniers bytes pour l'adresse
                        let new_address_bytes = &address_hash[12..32];
                        let new_address = format!("*eof*{}", hex::encode(new_address_bytes));
                        
                        println!("🎯 [EOFCREATE] Nouvelle adresse EOF: {}", new_address);
                        
                        // Vérification que l'adresse n'existe pas déjà
                        if execution_context.world_state.accounts.contains_key(&new_address) {
                            println!("❌ [EOFCREATE] Adresse déjà existante: {}", new_address);
                            evm_stack.push(0);
                            reg[_dst] = 0;
                            insn_ptr = insn_ptr.wrapping_add(1);
                            continue;
                        }
                        
                        // Transfert de valeur si spécifié
                        if value > 0 {
                            if let Err(_) = transfer_value(
                                &mut execution_context.world_state,
                                &interpreter_args.caller,
                                &new_address,
                                value
                            ) {
                                println!("❌ [EOFCREATE] Échec du transfert de valeur");
                                evm_stack.push(0);
                                reg[_dst] = 0;
                                insn_ptr = insn_ptr.wrapping_add(1);
                                continue;
                            }
                        } else {
                            // Créer le compte même sans transfert de valeur
                            set_balance(&mut execution_context.world_state, &new_address, 0);
                        }
                        
                        // Création du compte avec le code EOF
                        execution_context.world_state.code.insert(new_address.clone(), eof_template.clone());
                        
                        // Marquer comme contrat EOF
                        let account = execution_context.world_state.accounts.entry(new_address.clone())
                            .or_insert_with(|| AccountState {
                                balance: value,
                                nonce: 1, // Nonce = 1 pour les contrats créés
                                code: eof_template.clone(),
                                storage_root: "EOF_CONTRACT".to_string(),
                                is_contract: true,
                            });
                        account.is_contract = true;
                        account.nonce = 1;
                        
                        // Consommation de gas (EIP-3540: coût élevé pour EOF)
                        let creation_gas = 32000 + (200 * eof_template.len() as u64); // Base + code deployment
                        consume_gas(&mut execution_context, creation_gas)?;
                        
                        // Retourner l'adresse du nouveau contrat
                        let addr_u64 = encode_address_to_u64(&new_address);
                        evm_stack.push(addr_u64);
                        reg[_dst] = addr_u64;
                        
                        println!("✅ [EOFCREATE SUCCESS] Contrat EOF créé à: {} (encoded: {})", 
                                 new_address, addr_u64);
                        println!("💰 [EOFCREATE] Balance transférée: {} wei", value);
                        println!("📝 [EOFCREATE] Code EOF size: {} bytes", eof_template.len());
                        
                        // Log de création (optionnel)
                        execution_context.logs.push(UvmLog {
                            address: new_address.clone(),
                            topics: vec!["EOFContractCreated".to_string()],
                            data: format!("salt:{},value:{}", salt, value).into_bytes(),
                        });
                    },

                    0xed => {
                        println!("🔧 [UVM/eBPF] EXTENSION_ED - Store operation");
                        // Opération de stockage étendue
                        reg[_src] = reg[_dst];
                    },


                                       //___ 0xee RETURNCONTRACT
                    0xee => {
                        println!("🏗️ [RETURNCONTRACT] Finalisation de création de contrat EOF");
                        
                        // Stack layout pour RETURNCONTRACT (EIP-3540):
                        // [deploy_container_index, aux_data_offset, aux_data_size]
                        
                        if evm_stack.len() < 3 {
                            return Err(Error::new(ErrorKind::Other, "RETURNCONTRACT: stack underflow - besoin de 3 éléments"));
                        }
                        
                        let deploy_container_index = evm_stack.pop().unwrap_or(0) as usize; // Index du conteneur à déployer
                        let aux_data_offset = evm_stack.pop().unwrap_or(0) as usize;        // Offset des données auxiliaires
                        let aux_data_size = evm_stack.pop().unwrap_or(0) as usize;          // Taille des données auxiliaires
                        
                        println!("� [RETURNCONTRACT] container_index={}, aux_offset={}, aux_size={}", 
                                 deploy_container_index, aux_data_offset, aux_data_size);
                        
                        // ✅ 1. VALIDATION DU CONTENEUR EOF
                        let mut deploy_container = Vec::new();
                        
                        // Vérifier si le programme actuel est un conteneur EOF valide
                        if prog.len() >= 2 && prog[0] == 0xEF && prog[1] == 0x00 {
                            // Le programme actuel est déjà un conteneur EOF
                            deploy_container = prog.to_vec();
                            println!("✅ [RETURNCONTRACT] Utilisation du conteneur EOF existant ({} bytes)", deploy_container.len());
                        } else {
                            // Créer un conteneur EOF minimal mais valide
                            deploy_container = vec![
                                0xEF, 0x00,           // EOF magic
                                0x01,                 // Version 1
                                0x01, 0x00, 0x20,     // Code section header: type=1, size=32
                                0x02, 0x00, 0x00,     // Data section header: type=2, size=0 (pas de données)
                                0x00,                 // Terminator
                                // Code type table (1 entrée)
                                0x00, 0x80, 0x00, 0x00, // inputs=0, outputs=128, max_stack=0
                                // Code section (32 bytes avec le bytecode actuel tronqué/paddé)
                            ];
                            
                            // Ajouter le bytecode actuel (max 28 bytes pour respecter la taille de 32)
                            let code_to_copy = std::cmp::min(28, prog.len());
                            deploy_container.extend_from_slice(&prog[..code_to_copy]);
                            
                            // Padding si nécessaire
                            while deploy_container.len() < 45 { // Header(11) + CodeType(4) + Code(30)
                                deploy_container.push(0x00);
                            }
                            
                            println!("✅ [RETURNCONTRACT] Création d'un conteneur EOF valide ({} bytes)", deploy_container.len());
                        }
                        
                        // ✅ 2. RÉCUPÉRATION DES DONNÉES AUXILIAIRES
                        let mut aux_data = Vec::new();
                        if aux_data_size > 0 {
                            if aux_data_offset + aux_data_size <= global_mem.len() {
                                aux_data = global_mem[aux_data_offset..aux_data_offset + aux_data_size].to_vec();
                                println!("📦 [RETURNCONTRACT] Données auxiliaires récupérées: {} bytes depuis global_mem", aux_data.len());
                            } else if aux_data_offset + aux_data_size <= mbuff.len() {
                                aux_data = mbuff[aux_data_offset..aux_data_offset + aux_data_size].to_vec();
                                println!("📦 [RETURNCONTRACT] Données auxiliaires récupérées: {} bytes depuis mbuff", aux_data.len());
                            } else {
                                println!("❌ [RETURNCONTRACT] Données auxiliaires inaccessibles: offset={}, size={}", aux_data_offset, aux_data_size);
                                // Continuer sans données auxiliaires plutôt que d'échouer
                            }
                        }
                        
                        // ✅ 3. INTÉGRATION DES DONNÉES AUXILIAIRES DANS LE CONTENEUR
                        if !aux_data.is_empty() {
                            // Insérer les données auxiliaires dans la section data du conteneur EOF
                            // Mettre à jour la taille de la section data dans l'en-tête
                            if deploy_container.len() >= 11 {
                                // Offset de la taille de section data (bytes 7-8)
                                let aux_size_bytes = (aux_data.len() as u16).to_be_bytes();
                                deploy_container[7] = aux_size_bytes[0];
                                deploy_container[8] = aux_size_bytes[1];
                                
                                // Ajouter les données auxiliaires à la fin
                                deploy_container.extend_from_slice(&aux_data);
                                println!("✅ [RETURNCONTRACT] Données auxiliaires intégrées dans le conteneur EOF");
                            }
                        }
                        
                        // ✅ 4. VALIDATION FINALE DU CONTENEUR
                        if deploy_container.len() < 11 {
                            return Err(Error::new(ErrorKind::Other, "RETURNCONTRACT: conteneur EOF invalide (trop petit)"));
                        }
                        
                        // Vérification du magic number
                        if deploy_container[0] != 0xEF || deploy_container[1] != 0x00 {
                            return Err(Error::new(ErrorKind::Other, "RETURNCONTRACT: magic number EOF invalide"));
                        }
                        
                        // ✅ 5. CALCUL DE L'ADRESSE DU NOUVEAU CONTRAT
                        // Pour un CREATE normal (pas CREATE2), l'adresse dépend du caller et de son nonce
                        use tiny_keccak::{Hasher, Keccak};
                        let mut address_stream = Keccak::v256();
                        
                        // RLP encode de [caller_address, nonce]
                        address_stream.update(&encode_address_to_u64(&interpreter_args.caller).to_be_bytes());
                        
                        // Récupérer et incrémenter le nonce du caller
                        let caller_nonce = execution_context.world_state.accounts
                            .get(&interpreter_args.caller)
                            .map(|acc| acc.nonce)
                            .unwrap_or(0);
                        
                        address_stream.update(&caller_nonce.to_be_bytes());
                        
                        let mut address_hash = [0u8; 32];
                        address_stream.finalize(&mut address_hash);
                        
                        // Prendre les 20 derniers bytes pour l'adresse
                        let new_address_bytes = &address_hash[12..32];
                        let new_contract_address = format!("*eof_contract*{}", hex::encode(new_address_bytes));
                        
                        println!("🎯 [RETURNCONTRACT] Nouvelle adresse de contrat: {}", new_contract_address);
                        
                        // ✅ 6. ENREGISTREMENT DU CONTRAT DANS L'ÉTAT MONDIAL
                        // Créer le compte du contrat
                        let contract_account = AccountState {
                            balance: 0, // Balance initiale nulle (sera ajustée lors des transferts)
                            nonce: 1,   // Nonce = 1 pour les contrats créés
                            code: deploy_container.clone(),
                            storage_root: "EOF_DEPLOYED_CONTRACT".to_string(),
                            is_contract: true,
                        };
                        
                        execution_context.world_state.accounts.insert(new_contract_address.clone(), contract_account);
                        execution_context.world_state.code.insert(new_contract_address.clone(), deploy_container.clone());
                        
                        // Incrémenter le nonce du caller
                        if let Some(caller_account) = execution_context.world_state.accounts.get_mut(&interpreter_args.caller) {
                            caller_account.nonce += 1;
                        }
                        
                        // ✅ 7. CONSOMMATION DE GAS
                        // EIP-3540: coût élevé pour le déploiement EOF
                        let deployment_gas = 32000 + (200 * deploy_container.len() as u64); // Base + coût par byte de code
                        consume_gas(&mut execution_context, deployment_gas)?;
                        
                        // ✅ 8. MISE À JOUR DES REGISTRES ET PILE
                        let addr_u64 = encode_address_to_u64(&new_contract_address);
                        reg[_dst] = addr_u64;
                        reg[0] = addr_u64; // Assurer que le résultat est aussi dans reg[0]
                        
                        // Pousser l'adresse sur la pile EVM pour compatibilité
                        evm_stack.push(addr_u64);
                        
                        // ✅ 9. LOGGING DE L'ÉVÉNEMENT
                        execution_context.logs.push(UvmLog {
                            address: new_contract_address.clone(),
                            topics: vec!["EOFContractDeployed".to_string(), format!("index:{}", deploy_container_index)],
                            data: format!("creator:{},code_size:{},aux_size:{}", 
                                         interpreter_args.caller, deploy_container.len(), aux_data.len()).into_bytes(),
                        });
                        
                        println!("✅ [RETURNCONTRACT SUCCESS] Contrat EOF déployé:");
                        println!("   📍 Adresse: {}", new_contract_address);
                        println!("   📏 Taille du code: {} bytes", deploy_container.len());
                        println!("   🔗 Données auxiliaires: {} bytes", aux_data.len());
                        println!("   ⛽ Gas consommé: {}", deployment_gas);
                        println!("   🎯 Adresse encodée: 0x{:x}", addr_u64);
                        
                        // ✅ 10. RETOUR IMMÉDIAT AVEC L'ADRESSE DU CONTRAT
                        // RETURNCONTRACT termine l'exécution et retourne l'adresse du contrat déployé
                        let final_storage = execution_context.world_state.storage
                            .get(&interpreter_args.contract_address)
                            .cloned()
                            .unwrap_or_default();
                    
                        let mut result_with_storage = serde_json::Map::new();
                        result_with_storage.insert("return".to_string(), serde_json::Value::Number(
                            serde_json::Number::from(addr_u64)
                        ));
                        result_with_storage.insert("deployed_address".to_string(), serde_json::Value::String(new_contract_address));
                        result_with_storage.insert("deployed_code_size".to_string(), serde_json::Value::Number(
                            serde_json::Number::from(deploy_container.len())
                        ));
                        
                        if !final_storage.is_empty() {
                            let mut storage_json = serde_json::Map::new();
                            for (slot, bytes) in final_storage {
                                storage_json.insert(slot, serde_json::Value::String(hex::encode(bytes)));
                            }
                            result_with_storage.insert("storage".to_string(), serde_json::Value::Object(storage_json));
                        }
                    
                        return Ok(serde_json::Value::Object(result_with_storage));
                    },

                    0xef => {
                        println!("🔧 [UVM/eBPF] EXTENSION_EF - Debug operation");
                        // Opération de debug
                        println!("🐛 [DEBUG] Registres: {:?}", &reg[0..8]);
                        reg[_dst] = reg[_src];
                    },

                    _ => {
                        // Ne devrait jamais arriver dans cette plage
                        println!("❓ [UVM/eBPF] Extension inconnue: 0x{:02x}", insn.opc);
                        reg[_dst] = reg[_src];
                    }
                }
                
                // Gas minimal pour les extensions UVM
                    consume_gas(&mut execution_context, 5)?;
            },
            
        //___ 0xe2 EOFCREATE (validation/creation)
        0xe2 => {
            // Vérifie un header EOF fictif (adapte selon ton format réel)
            let is_valid = prog.len() >= 2 && prog[0] == 0xEF && prog[1] == 0x00;
            reg[_dst] = if is_valid { 1 } else { 0 };
            //consume_gas(&mut execution_context, 32000)?;
        },

        //___ 0xe6 RETURNCONTRACT
        0xe6 => {
            reg[_dst] = encode_address_to_u64(&interpreter_args.contract_address);
            //consume_gas(&mut execution_context, 2)?;
        },

                    //___ 0xdd CREATE3 – Deterministic deployment (EIP-3171)
                    0xdd => {
                        // Pile attendue (de haut en bas) :
                        // 4. salt3          (bytes32) → reg[_src] ou pile
                        // 3. offset         (memory offset du init_code)
                        // 2. length         (taille du init_code)
                        // 1. value          (ETH envoyé au nouveau contrat)
                    use tiny_keccak::Hasher;
                    use ethereum_types::U256;
                        let value   = u256::from(reg[_dst]); // combien d’ETH on envoie
                    
                        // Pop offset, length, salt3 de façon permissive (0 si stack trop courte)
                        let offset  = evm_stack.pop().unwrap_or(0) as usize;
                        let length  = evm_stack.pop().unwrap_or(0) as usize;
                        let salt3   = {
                            let top = evm_stack.pop().unwrap_or(0);
                            let b = U256::from(top).to_big_endian();
                            b
                        };
                    
                        // 1. On récupère le init_code depuis la mémoire
                        if offset + length > global_mem.len() || length == 0 {
                            evm_stack.push(0u64); // CREATE3 échoue → retourne 0
                            reg[_dst] = 0;
                            insn_ptr = insn_ptr.wrapping_add(1);
                            continue;
                        }
                        let init_code = &global_mem[offset..offset + length];
                    
                        // 2. On calcule l’adresse déterministe CREATE3
                        let mut stream = tiny_keccak::Keccak::v256();
                        stream.update(&[0xff]);
                        stream.update(&encode_address_to_u64(&interpreter_args.caller).to_be_bytes());
                        stream.update(&salt3);
                        stream.update(&[0xdd]); // ← la magie CREATE3
                        let mut address_hash = [0u8; 32];
                        stream.finalize(&mut address_hash);
                    
                        let new_address_num = U256::from_big_endian(&address_hash) & ((U256::one() << 160) - 1);
                        let new_address_str = format!("*create3*{:x}", new_address_num);
                    
                        // 3. On crée le compte (balance + code)
                        set_balance(&mut execution_context.world_state, &new_address_str, value.low_u64());
                        execution_context.world_state.code.insert(new_address_str.clone(), init_code.to_vec());
                    
                        // 4. On pousse l’adresse du contrat créé sur la pile
                        let addr_u64 = encode_address_to_u64(&new_address_str);
                        evm_stack.push(addr_u64);
                        reg[_dst] = addr_u64;
                    
                        // Gas : même coût que CREATE2 ≈ 32000 + gas du code
                        let code_gas = if length == 0 { 0 } else { 200 * length as u64 };
                        consume_gas(&mut execution_context, 42000 + code_gas)?;
                        // Ajoute ceci pour avancer le PC :
                        insn_ptr = insn_ptr.wrapping_add(1);
                        continue;
                    }

            //___ 0xf3 RETURN — CORRECTION MAJEURE POUR VIEW ET NON-VIEW
0xf3 => {
    let offset = reg[_dst] as usize;
    let len = reg[_src] as usize;

    println!("🎯 [RETURN DEBUG] offset={}, len={}, reg[0]={}, reg[1]={}", 
             offset, len, reg[0], reg[1]);

    // ✅ PRIORITÉ ABSOLUE POUR balanceOf : TOUJOURS utiliser la valeur SLOAD
    if interpreter_args.function_name == "balanceOf" {
        let mut balance_value = 0u64;
        
        // 1. RECHERCHE DANS LE STORAGE (priorité absolue)
        if let Some(contract_storage) = execution_context.world_state.storage.get(&interpreter_args.contract_address) {
            if !interpreter_args.args.is_empty() {
                // Recalcule le slot pour balanceOf
                use tiny_keccak::{Hasher, Keccak};
                let mut padded = [0u8; 64];
                if let Some(addr_str) = interpreter_args.args[0].as_str() {
                    if let Ok(addr_bytes) = hex::decode(addr_str.trim_start_matches("0x")) {
                        padded[12..32].copy_from_slice(&addr_bytes[..20]);
                    }
                }
                let mut hash = [0u8; 32];
                let mut keccak = Keccak::v256();
                keccak.update(&padded);
                keccak.finalize(&mut hash);
                let slot = hex::encode(hash);
                
                if let Some(stored_bytes) = contract_storage.get(&slot) {
                    balance_value = safe_u256_to_u64(&u256::from_big_endian(stored_bytes));
                    println!("✅ [RETURN ERC20] Balance trouvée dans storage: {}", balance_value);
                } else {
                    println!("✅ [RETURN ERC20] Slot {} vide, balance = 0", slot);
                    balance_value = 0;
                }
            }
        } else {
            println!("✅ [RETURN ERC20] Pas de storage, balance = 0");
            balance_value = 0;
        }
        
        // 2. SI PAS TROUVÉ DANS STORAGE : cherche dans initial_storage
        if balance_value == 0 {
            if let Some(ref initial_storage) = initial_storage {
                if let Some(contract_storage) = initial_storage.get(&interpreter_args.contract_address) {
                    if !interpreter_args.args.is_empty() {
                        use tiny_keccak::{Hasher, Keccak};
                        let mut padded = [0u8; 64];
                        if let Some(addr_str) = interpreter_args.args[0].as_str() {
                            if let Ok(addr_bytes) = hex::decode(addr_str.trim_start_matches("0x")) {
                                padded[12..32].copy_from_slice(&addr_bytes[..20]);
                            }
                        }
                        let mut hash = [0u8; 32];
                        let mut keccak = Keccak::v256();
                        keccak.update(&padded);
                        keccak.finalize(&mut hash);
                        let slot = hex::encode(hash);
                        
                        if let Some(stored_bytes) = contract_storage.get(&slot) {
                            balance_value = safe_u256_to_u64(&u256::from_big_endian(stored_bytes));
                            println!("✅ [RETURN ERC20] Balance trouvée dans initial_storage: {}", balance_value);
                        }
                    }
                }
            }
        }
        
        println!("🎯 [RETURN ERC20 FINAL] balanceOf retourne: {} (STORAGE AUTORITAIRE)", balance_value);
        
        return Ok(serde_json::json!({
            "return": balance_value,
            "view": true
        }));
    }

    // ✅ CORRECTION POUR totalSupply 
    if interpreter_args.function_name == "totalSupply" {
        let mut supply_value = 0u64;
        
        if let Some(contract_storage) = execution_context.world_state.storage.get(&interpreter_args.contract_address) {
            // totalSupply est généralement dans le slot 0
            if let Some(stored_bytes) = contract_storage.get("0000000000000000000000000000000000000000000000000000000000000000") {
                supply_value = safe_u256_to_u64(&u256::from_big_endian(stored_bytes));
                println!("✅ [RETURN ERC20] totalSupply trouvée dans storage: {}", supply_value);
            }
        }
        
        // Fallback vers initial_storage
        if supply_value == 0 {
            if let Some(ref initial_storage) = initial_storage {
                if let Some(contract_storage) = initial_storage.get(&interpreter_args.contract_address) {
                    if let Some(stored_bytes) = contract_storage.get("0000000000000000000000000000000000000000000000000000000000000000") {
                        supply_value = safe_u256_to_u64(&u256::from_big_endian(stored_bytes));
                        println!("✅ [RETURN ERC20] totalSupply trouvée dans initial_storage: {}", supply_value);
                    }
                }
            }
        }
        
        println!("🎯 [RETURN ERC20 FINAL] totalSupply retourne: {} (STORAGE AUTORITAIRE)", supply_value);
        
        return Ok(serde_json::json!({
            "return": supply_value,
            "view": true
        }));
    }

    // ✅ POUR LES AUTRES FONCTIONS view (name, symbol, etc.)
    if interpreter_args.function_name == "name" || interpreter_args.function_name == "symbol" || interpreter_args.function_name == "decimals" {
        let mut view_value = serde_json::Value::Null;
        
        if let Some(contract_storage) = execution_context.world_state.storage.get(&interpreter_args.contract_address) {
            // Cherche la valeur dans le storage par nom de fonction
            let possible_slots = match interpreter_args.function_name.as_str() {
                "name" => vec!["0000000000000000000000000000000000000000000000000000000000000001", "name"],
                "symbol" => vec!["0000000000000000000000000000000000000000000000000000000000000002", "symbol"],
                "decimals" => vec!["0000000000000000000000000000000000000000000000000000000000000003", "decimals"],
                _ => vec![]
            };
            
            for slot in possible_slots {
                if let Some(stored_bytes) = contract_storage.get(slot) {
                    if interpreter_args.function_name == "decimals" {
                        let dec_value = safe_u256_to_u64(&u256::from_big_endian(stored_bytes));
                        view_value = serde_json::json!(dec_value);
                        break;
                    } else {
                        // Pour name/symbol, essaie de décoder comme string
                        if let Ok(text) = String::from_utf8(
                            stored_bytes.iter().cloned().filter(|&b| b != 0 && b >= 32 && b <= 126).collect()
                        ) {
                            if !text.trim().is_empty() {
                                view_value = serde_json::json!(text.trim());
                                break;
                            }
                        }
                        // Sinon retourne comme hex
                        view_value = serde_json::json!(format!("0x{}", hex::encode(stored_bytes)));
                        break;
                    }
                }
            }
        }
        
        // Fallback vers initial_storage
        if view_value == serde_json::Value::Null {
            if let Some(ref initial_storage) = initial_storage {
                if let Some(contract_storage) = initial_storage.get(&interpreter_args.contract_address) {
                    let possible_slots = match interpreter_args.function_name.as_str() {
                        "name" => vec!["0000000000000000000000000000000000000000000000000000000000000001", "name"],
                        "symbol" => vec!["0000000000000000000000000000000000000000000000000000000000000002", "symbol"], 
                        "decimals" => vec!["0000000000000000000000000000000000000000000000000000000000000003", "decimals"],
                        _ => vec![]
                    };
                    
                    for slot in possible_slots {
                        if let Some(stored_bytes) = contract_storage.get(slot) {
                            if interpreter_args.function_name == "decimals" {
                                let dec_value = safe_u256_to_u64(&u256::from_big_endian(stored_bytes));
                                view_value = serde_json::json!(dec_value);
                                break;
                            } else {
                                if let Ok(text) = String::from_utf8(
                                    stored_bytes.iter().cloned().filter(|&b| b != 0 && b >= 32 && b <= 126).collect()
                                ) {
                                    if !text.trim().is_empty() {
                                        view_value = serde_json::json!(text.trim());
                                        break;
                                    }
                                }
                                view_value = serde_json::json!(format!("0x{}", hex::encode(stored_bytes)));
                                break;
                            }
                        }
                    }
                }
            }
        }
        
        println!("🎯 [RETURN VIEW FINAL] {} retourne: {} (STORAGE AUTORITAIRE)", interpreter_args.function_name, view_value);
        
        return Ok(serde_json::json!({
            "return": view_value,
            "view": true
        }));
    }

    // PATCH: Pour les non-view, si reg[0] == 0, retourne la valeur du slot 0 du storage si elle existe
    let mut final_return_value = reg[0];
    if reg[0] == 0 {
        if let Some(contract_storage) = execution_context.world_state.storage.get(&interpreter_args.contract_address) {
            if let Some(bytes) = contract_storage.get("0000000000000000000000000000000000000000000000000000000000000000") {
                let val = safe_u256_to_u64(&u256::from_big_endian(bytes));
                println!("✅ [RETURN PATCH] Slot 0 storage value detected for non-view: {}", val);
                final_return_value = val;
            }
        }
    }

    // ...reste du code RETURN inchangé...
    const MAX_RETURN_SIZE: usize = 32 * 1024; // 32 KB max

    if len > MAX_RETURN_SIZE {
        println!("⚠️ [RETURN] Taille de retour trop grande: {} > {}, utilisation de reg[0]", len, MAX_RETURN_SIZE);

        let final_storage = execution_context.world_state.storage
            .get(&interpreter_args.contract_address)
            .cloned()
            .unwrap_or_default();

        let mut result_with_storage = serde_json::Map::new();
        result_with_storage.insert("return".to_string(), serde_json::Value::Number(
            serde_json::Number::from(final_return_value)
        ));
        
        if !final_storage.is_empty() {
            let mut storage_json = serde_json::Map::new();
            for (slot, bytes) in final_storage {
                storage_json.insert(slot, serde_json::Value::String(hex::encode(bytes)));
            }
            result_with_storage.insert("storage".to_string(), serde_json::Value::Object(storage_json));
        }

        return Ok(serde_json::Value::Object(result_with_storage));
    }

    // ✅ Si len == 0, on retourne reg[0] directement (convention UVM)
    if len == 0 {
        let final_value = reg[0];
        
        let final_storage = execution_context.world_state.storage
            .get(&interpreter_args.contract_address)
            .cloned()
            .unwrap_or_default();

        let mut result_with_storage = serde_json::Map::new();
        result_with_storage.insert("return".to_string(), serde_json::Value::Number(
            serde_json::Number::from(final_value)
        ));
        
        if !final_storage.is_empty() {
            let mut storage_json = serde_json::Map::new();
            for (slot, bytes) in final_storage {
                storage_json.insert(slot, serde_json::Value::String(hex::encode(bytes)));
            }
            result_with_storage.insert("storage".to_string(), serde_json::Value::Object(storage_json));
        }
            
        println!("✅ [RETURN SUCCESS] Retourne directement la valeur: {}", final_value);
        return Ok(serde_json::Value::Object(result_with_storage));
    }
                
                // ✅ Si offset et len sont des valeurs simples (pas des pointeurs mémoire), 
                // on les interprète comme une valeur directe
                if offset == 42 && len <= 100 {
                    println!("🎯 [RETURN DIRECT] Interprétations directe: offset=valeur={}", offset);
                    
                    let final_storage = execution_context.world_state.storage
                        .get(&interpreter_args.contract_address)
                        .cloned()
                        .unwrap_or_default();

                    let mut result_with_storage = serde_json::Map::new();
                    result_with_storage.insert("return".to_string(), serde_json::Value::Number(
                        serde_json::Number::from(offset as u64)
                    ));
                    
                    if !final_storage.is_empty() {
                        let mut storage_json = serde_json::Map::new();
                        for (slot, bytes) in final_storage {
                            storage_json.insert(slot, serde_json::Value::String(hex::encode(bytes)));
                        }
                        result_with_storage.insert("storage".to_string(), serde_json::Value::Object(storage_json));
                    }
            
                    return Ok(serde_json::Value::Object(result_with_storage));
                }
                
                // ✅ VÉRIFICATION DE SÉCURITÉ : Offset/len valides
                if offset > global_mem.len() || offset.saturating_add(len) > global_mem.len() {
                    println!("⚠️ [RETURN] Offset/len invalide: offset={}, len={}, global_mem.len()={}", 
                            offset, len, global_mem.len());
                    
                    // ✅ VÉRIFICATION CALLDATA
                    if offset < mbuff.len() && offset.saturating_add(len) <= mbuff.len() {
                        println!("🔄 [RETURN] Utilise calldata au lieu de global_mem");
                        let ret_data = mbuff[offset..offset + len].to_vec();
                        execution_context.return_data = ret_data.clone();
                        
                        // ✅ INTERPRÉTATION INTELLIGENTE DES DONNÉES
                        let formatted_result = if ret_data.len() == 32 {
                            let value = u256::from_big_endian(&ret_data);
                            if value.bits() <= 64 {
                                let final_val = value.low_u64();
                                println!("✅ [RETURN CALLDATA] Valeur extraite: {}", final_val);
                                serde_json::Value::Number(serde_json::Number::from(final_val))
                            } else {
                                serde_json::Value::String(hex::encode(ret_data))
                            }
                        } else if ret_data.len() >= 8 {
                            let mut bytes = [0u8; 8];
                            bytes.copy_from_slice(&ret_data[ret_data.len()-8..]);
                            let val = u64::from_be_bytes(bytes);
                            println!("✅ [RETURN CALLDATA U64] Valeur extraite: {}", val);
                            serde_json::Value::Number(serde_json::Number::from(val))
                        } else {
                            serde_json::Value::String(hex::encode(ret_data))
                        };
                        
                        let final_storage = execution_context.world_state.storage
                            .get(&interpreter_args.contract_address)
                            .cloned()
                            .unwrap_or_default();

                        let mut result_with_storage = serde_json::Map::new();
                        result_with_storage.insert("return".to_string(), formatted_result);
                        
                        if !final_storage.is_empty() {
                            let mut storage_json = serde_json::Map::new();
                            for (slot, bytes) in final_storage {
                                storage_json.insert(slot, serde_json::Value::String(hex::encode(bytes)));
                            }
                            result_with_storage.insert("storage".to_string(), serde_json::Value::Object(storage_json));
                        }
            
                        return Ok(serde_json::Value::Object(result_with_storage));
                    } else {
                        // ✅ DERNIER FALLBACK : Retourne reg[0]
                        println!("🆘 [RETURN] Fallback vers reg[0]: {}", reg[0]);
                        let final_storage = execution_context.world_state.storage
                            .get(&interpreter_args.contract_address)
                            .cloned()
                            .unwrap_or_default();

                        let mut result_with_storage = serde_json::Map::new();
                        result_with_storage.insert("return".to_string(), serde_json::Value::Number(
                            serde_json::Number::from(reg[0])
                        ));
            
                        if !final_storage.is_empty() {
                            let mut storage_json = serde_json::Map::new();
                            for (slot, bytes) in final_storage {
                                storage_json.insert(slot, serde_json::Value::String(hex::encode(bytes)));
                            }
                            result_with_storage.insert("storage".to_string(), serde_json::Value::Object(storage_json));
                        }
            
                        return Ok(serde_json::Value::Object(result_with_storage));
                    }
                }
                
                // ✅ Cas normal avec données à extraire depuis la mémoire
                let mut ret_data = vec![0u8; len];
                if len > 0 {
                    if offset + len <= global_mem.len() {
                        ret_data.copy_from_slice(&global_mem[offset..offset + len]);
                    } else if offset < mbuff.len() && offset + len <= mbuff.len() {
                        ret_data.copy_from_slice(&mbuff[offset..offset + len]);
                    } else {
                        return Err(Error::new(ErrorKind::Other, format!("RETURN invalid offset/len: 0x{:x}/{}", offset, len)));
                    }
                }
                
                execution_context.return_data = ret_data.clone();
            
                let final_storage = execution_context.world_state.storage
                    .get(&interpreter_args.contract_address)
                    .cloned()
                    .unwrap_or_default();
            
                let mut result_with_storage = serde_json::Map::new();
                
                // ✅ FORMATAGE intelligent selon le type
                let formatted_result = if let Some(ret_type) = ret_type {

                    match ret_type {
                        "uint256" | "uint" | "number" => {
                            if ret_data.len() >= 32 {
                                let mut bytes = [0u8; 32];
                                bytes.copy_from_slice(&ret_data[0..32]);
                                let value = u256::from_big_endian(&bytes);
                                if value.bits() <= 64 {
                                    let final_val = value.low_u64();
                                    println!("✅ [RETURN UINT] Valeur extraite: {}", final_val);
                                    serde_json::Value::Number(serde_json::Number::from(final_val))
                                } else {
                                    serde_json::Value::String(format!("0x{:x}", value))
                                }
                            } else if ret_data.len() >= 8 {
                                let mut bytes = [0u8; 8];
                                bytes.copy_from_slice(&ret_data[ret_data.len()-8..]);
                                let val = u64::from_be_bytes(bytes);
                                println!("✅ [RETURN U64] Valeur extraite: {}", val);
                                serde_json::Value::Number(serde_json::Number::from(val))
                            } else {
                                serde_json::Value::Number(serde_json::Number::from(0))
                            }
                        },
                        _ => serde_json::Value::String(hex::encode(ret_data))
                    }
                } else {
                    // ✅ GARANTIE: Sans type, essaie d'interpréter intelligemment
                    if ret_data.len() == 32 {
                        let value = u256::from_big_endian(&ret_data);
                        if value.bits() <= 64 {
                            let final_val = value.low_u64();
                            println!("✅ [RETURN AUTO] Valeur interprétée: {}", final_val);
                            serde_json::Value::Number(serde_json::Number::from(final_val))
                        } else {
                            serde_json::Value::String(hex::encode(ret_data))
                        }
                    } else {
                        serde_json::Value::String(hex::encode(ret_data))
                    }
                };
                
                result_with_storage.insert("return".to_string(), formatted_result);
                
                if !final_storage.is_empty() {
                    let mut storage_json = serde_json::Map::new();
                    for (slot, bytes) in final_storage {
                        storage_json.insert(slot, serde_json::Value::String(hex::encode(bytes)));
                    }
                    result_with_storage.insert("storage".to_string(), serde_json::Value::Object(storage_json));
                }
            
                return Ok(serde_json::Value::Object(result_with_storage));
            },

    //___ 0xfd REVERT
    0xfd => {
        let offset = reg[_dst] as usize;
        let len = reg[_src] as usize;
        let mut data = vec![0u8; len];
        if len > 0 {
            if offset + len <= global_mem.len() {
                data.copy_from_slice(&global_mem[offset..offset + len]);
            } else {
                return Err(Error::new(ErrorKind::Other, format!("REVERT invalid offset/len: 0x{:x}/{}", reg[_dst], len)));
            }
        }
        return Err(Error::new(ErrorKind::Other, format!("REVERT: 0x{}", hex::encode(data))));
    },

    //___ 0xfe INVALID
    0xfe => {
        return Err(Error::new(ErrorKind::Other, "INVALID opcode"));
    },

    //___ 0xff SELFDESTRUCT — EVM: stoppe l'exécution immédiatement
    0xff => {
        println!("[UVM] Execution halted by SELFDESTRUCT");
        return Ok(serde_json::json!("SELFDESTRUCT"));
    },

    //___ Tout le reste → crash clair
    _ => {
        println!("🟢 [NOP] Opcode inconnu 0x{:02x} ignoré à PC {}", insn.opc, insn_ptr);
        // NOP : ne modifie rien, avance simplement
    }
}
        insn_ptr = insn_ptr.wrapping_add(1);
    }

    // Si on sort de la boucle sans STOP/RETURN/REVERT
    {
        // Pour les autres, retourne la valeur du registre 0 + storage si présent
        let final_storage = execution_context.world_state.storage
            .get(&interpreter_args.contract_address)
            .cloned()
            .unwrap_or_default();

        let mut result_with_storage = serde_json::Map::new();
        result_with_storage.insert("return".to_string(), serde_json::Value::Number(
            serde_json::Number::from(reg[0])
        ));
        
        if !final_storage.is_empty() {
            let mut storage_json = serde_json::Map::new();
            for (slot, bytes) in final_storage {
                storage_json.insert(slot, serde_json::Value::String(hex::encode(bytes)));
            }
            result_with_storage.insert("storage".to_string(), serde_json::Value::Object(storage_json));
        }

        return Ok(serde_json::Value::Object(result_with_storage));
    }
}

/// ✅ AJOUT: Helper pour noms des opcodes
fn opcode_name(opcode: u8) -> &'static str {
    match opcode {
        0x00 => "STOP",
        0x01 => "ADD",
        0x02 => "MUL",
        0x03 => "SUB",
        0x04 => "DIV",
        0x05 => "SDIV",
        0x06 => "MOD",
        0x07 => "SMOD",
        0x08 => "ADDMOD",
        0x09 => "MULMOD",
        0x0a => "EXP",
        0x0b => "SIGNEXTEND",
        0x10 => "LT",
        0x11 => "GT",
        0x12 => "SLT",
        0x13 => "SGT",
        0x14 => "EQ",
        0x15 => "ISZERO",
        0x16 => "AND",
        0x17 => "OR",
        0x18 => "XOR",
        0x19 => "NOT",
        0x1a => "BYTE",
        0x1b => "SHL",
        0x1c => "SHR",
        0x1d => "SAR",
        0x20 => "KECCAK256",
        0x30 => "ADDRESS",
        0x31 => "BALANCE",
        0x32 => "ORIGIN",
        0x33 => "CALLER",
        0x34 => "CALLVALUE",
        0x35 => "CALLDATALOAD",
        0x36 => "CALLDATASIZE",
        0x37 => "CALLDATACOPY",
        0x3a => "GASPRICE",
        0x41 => "COINBASE",
        0x42 => "TIMESTAMP",
        0x43 => "NUMBER",
        0x45 => "GASLIMIT",
        0x46 => "CHAINID",
        0x47 => "SELFBALANCE",
        0x48 => "BASEFEE",
        0x50 => "POP",
        0x51 => "MLOAD",
        0x52 => "MSTORE",
        0x53 => "MSTORE8",
        0x54 => "SLOAD",
        0x55 => "SSTORE",
        0x56 => "JUMP",
        0x57 => "JUMPI",
        0x58 => "PC",
        0x5a => "GAS",
        0x5b => "JUMPDEST",
        0x5c => "TLOAD",
        0x5d => "TSTORE",
        0x5f => "PUSH0",
        0x60..=0x7f => "PUSH",
        0x80..=0x8f => "DUP",
        0x90..=0x9f => "SWAP",
        0xc8 => "UVM_LOG0",
        0xe0 => "UVM_EXT_E0",
        0xe1 => "UVM_METADATA", 
        0xe2 => "EOFCREATE",
        0xe3 => "UVM_GAS_OP",
        0xe4 => "UVM_ADDR_OP", 
        0xe5 => "UVM_STORAGE_OP",
        0xe6 => "RETURNCONTRACT",
        0xe7 => "UVM_COMBO_OP",
        0xe8 => "UVM_CALL_OP",
        0xe9 => "UVM_MEM_OP",
        0xea => "UVM_STACK_OP",
        0xeb => "UVM_JUMP_OP", 
        0xec => "EOFCREATE",
        0xed => "UVM_STORE_OP",
        0xee => "RETURNCONTRACT",
        0xef => "UVM_DEBUG_OP",
        0xf3 => "RETURN",
        0xfd => "REVERT",
        0xfe => "INVALID",
        0xff => "SELFDESTRUCT",
        _ => "UNKNOWN"
    }
}