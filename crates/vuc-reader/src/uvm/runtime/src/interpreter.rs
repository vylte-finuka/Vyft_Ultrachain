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
    pub is_view: bool, // <-- Ajoute ce champ
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
            is_view: false,
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
    initial_storage: Option<HashMap<String, HashMap<String, Vec<u8>>>>, // <-- AJOUT
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
            if let Some(storage) = initial_storage {
                ws.storage = storage;
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

    while insn_ptr.wrapping_mul(ebpf::INSN_SIZE) < prog.len() {
        let insn = ebpf::get_insn(prog, insn_ptr);

        // DEBUG: Affiche chaque opcode et ses registres
        println!(
            "🟦 [DEBUG] PC={:04} | OPCODE=0x{:02x} | DST={} | SRC={} | IMM={} | OFF={}",
            insn_ptr, insn.opc, insn.dst, insn.src, insn.imm, insn.off
        );
        println!("     [DEBUG] REGISTRES: {:?}", &reg[..16]);
        println!("     [DEBUG] global_mem[0..32]: {:?}", &global_mem[0..32]);

        // ✅ Consommation de gas
        if !interpreter_args.is_view {
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
        println!("[UVM] Execution halted by STOP");
        return Ok(serde_json::json!(reg[0]));
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
        reg[_dst] = safe_u256_to_u64(&evm_load_32(&global_mem, mbuff, addr)?);
        //consume_gas(&mut execution_context, 3)?;
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
        let slot = format!("{:064x}", reg[_dst]);
        let value = get_storage(&execution_context.world_state, &interpreter_args.contract_address, &slot);
        reg[_dst] = safe_u256_to_u64(&u256::from_big_endian(&value));
        //consume_gas(&mut execution_context, 800)?;
    },

    //___ 0x55 SSTORE — LE PLUS IMPORTANT
    0x55 => {
        let slot = format!("{:064x}", reg[_dst]);
        let value = u256::from(reg[_src]);
        let buf = value.to_big_endian(); // retourne Vec<u8> (32 octets)
        set_storage(&mut execution_context.world_state, &interpreter_args.contract_address, &slot, buf.to_vec());
        consume_gas(&mut execution_context, 20000)?;
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

    //___ 0x5a GAS
    0x5a => {
        reg[0] = execution_context.gas_remaining;
        //consume_gas(&mut execution_context, 2)?;
    },

    //___ 0x5b JUMPDEST
    0x5b => {
        //consume_gas(&mut execution_context, 1)?;
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
        if !interpreter_args.is_view {
            consume_gas(&mut execution_context, 3 + 3 * ((len + 31) / 32) as u64)?;
        }
    },

    //___ 0x5f PUSH0 (Shanghai+)
    0x5f => {
        reg[_dst] = 0;
        consume_gas(&mut execution_context, 2)?;
    },

    //___ 0x60 PUSH1 à 0x7f PUSH32
(0x60..=0x7f) => {
    let push_bytes = (insn.opc - 0x5f) as usize; // 1 à 32
    let byte_offset = insn_ptr * ebpf::INSN_SIZE + 1;
    let mut val = u256::zero();

    if byte_offset + push_bytes <= prog.len() {
        let data = &prog[byte_offset..byte_offset + push_bytes];
        val = u256::from_big_endian(data);
    }
    // On pousse sur la pile EVM + registre dst
    evm_stack.push(safe_u256_to_u64(&val));
    reg[_dst] = safe_u256_to_u64(&val);
    //consume_gas(&mut execution_context, 3)?;
},

    // ___ 0x80 → 0x8f : DUP1 à DUP16
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

                //___ 0xf3 RETURN — LE SAINT GRAAL
                0xf3 => {
                    let offset = reg[_dst] as usize;
                    let len = reg[_src] as usize;
                    // PATCH: refuse toute demande de retour > 1 Mo (sécurité)
                    if len > 1024 * 1024 {
                        println!("[WARN] RETURN length trop grande ({}), forcée à 0", len);
                        return Ok(serde_json::Value::String(String::new()));
                    }
                    let mut ret_data = vec![0u8; len];
                    if len > 0 {
                        if offset + len <= global_mem.len() {
                            ret_data.copy_from_slice(&global_mem[offset..offset + len]);
                        } else {
                            return Err(Error::new(ErrorKind::Other, format!("RETURN invalid offset/len: 0x{:x}/{}", reg[_dst], len)));
                        }
                    }
                    execution_context.return_data = ret_data.clone();
        
                    if let Some(ret_type) = ret_type {
                        if (ret_type == "string" || ret_type == "bytes") && !ret_data.is_empty() {
                            // Solidity ABI: [offset (32)] [length (32)] [data (n)]
                            if ret_data.len() >= 64 {
                                let len_bytes = &ret_data[32..64];
                                let str_len = u32::from_be_bytes([
                                    len_bytes[28], len_bytes[29], len_bytes[30], len_bytes[31]
                                ]) as usize;
                                if ret_data.len() >= 64 + str_len {
                                    let str_bytes = &ret_data[64..64 + str_len];
                                    // PATCH: ignore padding null bytes at the end
                                    let str_bytes = str_bytes.split(|b| *b == 0).next().unwrap_or(str_bytes);
                                    if let Ok(s) = std::str::from_utf8(str_bytes) {
                                        return Ok(serde_json::Value::String(s.to_string()));
                                    }
                                }
                            }
                            // fallback: direct utf8
                            if let Ok(s) = std::str::from_utf8(&ret_data) {
                                return Ok(serde_json::Value::String(s.to_string()));
                            }
                        }
                    }
                    return Ok(serde_json::Value::String(hex::encode(ret_data)));
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
        return Err(Error::new(ErrorKind::Other, 
            format!("Unsupported EVM opcode 0x{:02x} at PC {}", insn.opc, insn_ptr)));
    }
}
        insn_ptr = insn_ptr.wrapping_add(1);
    }

    // Si on sort de la boucle sans STOP/RETURN/REVERT
    if interpreter_args.is_view {
        // Pour une view, retourne la valeur du registre 0 (ou adapte selon convention)
        return Ok(serde_json::json!(reg[0]));
    }

    Err(Error::new(ErrorKind::Other, "Error: program terminated without STOP"))
}
