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
    if context.gas_remaining < amount {
        return Err(Error::new(ErrorKind::Other, "Out of gas"));
    }
    context.gas_remaining -= amount;
    context.gas_used += amount;
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

// Fonction pour vérifier si un offset byte est un JUMPDEST valide
fn is_valid_jumpdest(prog: &[u8], target: usize) -> bool {
    if target >= prog.len() {
        return false;
    }
    // On cherche le prochain opcode réel à partir de target
    if let Some((opc_offset, opc)) = find_next_opcode(prog, target) {
        // Pour être valide, l'opcode doit être JUMPDEST (0x5b)
        // ET il doit être exactement à l'endroit où on atterrit ou juste après des données PUSH
        opc == 0x5b
    } else {
        false
    }
}

// ===================================================================
// FIX FINAL : Lecture depuis calldata OU mémoire (EVM-compatible)
// ===================================================================

fn evm_load_32(global_mem: &[u8], mbuff: &[u8], addr: u64) -> Result<u256, Error> {
    // 1. Si l'adresse pointe dans le calldata → on lit là
    let mbuff_start = mbuff.as_ptr() as u64;
    let mbuff_end = mbuff_start + mbuff.len() as u64;

    if addr >= mbuff_start && addr + 32 <= mbuff_end {
        let offset = (addr - mbuff_start) as usize;
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&mbuff[offset..offset + 32]);
        return Ok(u256::from_big_endian(&bytes));
    }

    // 2. Sinon, lecture dans la mémoire globale
    let mem_start = global_mem.as_ptr() as u64;
    let mem_end = mem_start + global_mem.len() as u64;

    if addr >= mem_start && addr + 32 <= mem_end {
        let offset = (addr - mem_start) as usize;
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&global_mem[offset..offset + 32]);
        return Ok(u256::from_big_endian(&bytes));
    }

    // 3. Sinon → erreur claire
    Err(Error::new(ErrorKind::Other, format!("EVM MLOAD invalid address: {:#x}", addr)))
}

fn evm_store_32(global_mem: &mut [u8], addr: u64, value: u256) -> Result<(), Error> {
    let mem_start = global_mem.as_ptr() as u64;
    let mem_end = mem_start + global_mem.len() as u64;

    if addr >= mem_start && addr + 32 <= mem_end {
        let offset = (addr - mem_start) as usize;
        let mut bytes = [0u8; 32];
        value.to_big_endian();
        global_mem[offset..offset + 32].copy_from_slice(&bytes);
        Ok(())
    } else {
        Err(Error::new(ErrorKind::Other, format!("EVM MSTORE invalid address: {:#x}", addr)))
    }
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
        if mbuff.as_ptr() as u64 <= addr && addr_end <= mbuff.as_ptr() as u64 + mbuff.len() as u64 {
            return Ok(());
        }
        if mem.as_ptr() as u64 <= addr && addr_end <= mem.as_ptr() as u64 + mem.len() as u64 {
            return Ok(());
        }
        if stack.as_ptr() as u64 <= addr && addr_end <= stack.as_ptr() as u64 + stack.len() as u64 {
            return Ok(());
        }
        if allowed_memory.iter().any(|range| range.contains(&addr)) {
            return Ok(());
        }
        // PATCH EVM: autorise lecture jusqu'à 32 octets après la fin de mbuff (EVM-style)
        // On autorise si addr >= mbuff.as_ptr() et addr_end <= mbuff.as_ptr() + mbuff.len() + 32
        if mbuff.as_ptr() as u64 <= addr
            && addr_end <= mbuff.as_ptr() as u64 + mbuff.len() as u64 + 32
        {
            return Ok(());
        }
        // Correction : autorise aussi lecture totalement hors du buffer (ex: calldata vide)
        if mbuff.len() == 0
            && addr >= mbuff.as_ptr() as u64
            && addr_end <= mbuff.as_ptr() as u64 + 32
        {
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
        world_state: UvmWorldState::default(),
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

    // Mémoire globale étendue pour UVM
    let mut global_mem = vec![0u8; 1024 * 1024]; // 1MB pour l'état

    let mut reg: [u64; 64] = [0; 64];
    
    // ✅ Configuration registres UVM-compatibles
    reg[10] = stack.as_ptr() as u64 + stack.len() as u64; // Stack pointer
    reg[8] = global_mem.as_ptr() as u64;                  // Global memory
    
    // ✅ Registres spéciaux UVM (compatibles pile)
    reg[50] = execution_context.gas_remaining;              // Gas disponible
    reg[51] = interpreter_args.value;                       // Valeur transférée
    reg[52] = interpreter_args.block_number;                // Numéro de bloc
    reg[53] = interpreter_args.timestamp;                   // Timestamp
    reg[54] = interpreter_args.call_depth as u64;           // Profondeur d'appel

    // ✅ Arguments dans la convention UVM
    if !mbuff.is_empty() {
        reg[1] = mbuff.as_ptr() as u64;
    } else if !mem.is_empty() {
        reg[1] = mem.as_ptr() as u64;
    }

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

    // Setup état initial dans global_mem
    let state_offset = 65536; // Offset pour l'état contractuel
    let state_data = &mut global_mem[state_offset..state_offset + 4096];
    if interpreter_args.state_data.len() <= 4096 {
        state_data[..interpreter_args.state_data.len()].copy_from_slice(&interpreter_args.state_data);
    }

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

    let mut insn_ptr: usize = 0;

    // Prend en priorité l’offset explicite si fourni
    if let Some(offset) = interpreter_args.function_offset {
        insn_ptr = offset;
        println!("🟢 [DEBUG] Démarrage à l'offset explicite pour '{}': {}", interpreter_args.function_name, insn_ptr);
    } else if let Some(offset) =     exports.get(&calculate_function_selector(&interpreter_args.function_name)) {
        insn_ptr = *offset;
        println!("🟢 [DEBUG] Démarrage à l'offset exporté pour '{}': {}", interpreter_args.function_name, insn_ptr);
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
        let gas_cost = calculate_gas_cost(insn.opc);
        consume_gas(&mut execution_context, gas_cost)?;

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
        reg[_dst] = res.low_u64();
        consume_gas(&mut execution_context, 3)?;
    },

    //___ 0x02 MUL
    0x02 => {
        let a = u256::from(reg[_dst]);
        let b = u256::from(reg[_src]);
        let (res, _overflow) = a.overflowing_mul(b);
        reg[_dst] = res.low_u64();
        consume_gas(&mut execution_context, 5)?;
    },

    //___ 0x03 SUB
    0x03 => {
        let a = u256::from(reg[_dst]);
        let b = u256::from(reg[_src]);
        let (res, _overflow) = a.overflowing_sub(b);
        reg[_dst] = res.low_u64();
        consume_gas(&mut execution_context, 3)?;
    },

    //___ 0x04 DIV
    0x04 => {
        let a = u256::from(reg[_dst]);
        let b = u256::from(reg[_src]);
        reg[_dst] = if b == u256::zero() { 0 } else { (a / b).low_u64() };
        consume_gas(&mut execution_context, 5)?;
    },
    //___ 0x05 SDIV
    0x05 => {
        let a = I256::from(reg[_dst]);
        let b = I256::from(reg[_src]);
        reg[_dst] = if b == I256::from(0) { 0 } else { (a / b).as_u64() };
        consume_gas(&mut execution_context, 5)?;
    },

    //___ 0x06 MOD
    0x06 => {
        let a = u256::from(reg[_dst]);
        let b = u256::from(reg[_src]);
        reg[_dst] = if b == u256::zero() { 0 } else { (a % b).low_u64() };
        consume_gas(&mut execution_context, 5)?;
    },

    //___ 0x07 SMOD (à implémenter si besoin, sinon stub)
    0x07 => { reg[_dst] = 0; consume_gas(&mut execution_context, 5)?; }

    //___ 0x08 ADDMOD
    0x08 => {
        let a = u256::from(reg[_dst]);
        let b = u256::from(reg[_src]);
        let n = u256::from(insn.imm as u64);
        reg[_dst] = if n == u256::zero() { 0 } else { ((a + b) % n).low_u64() };
        consume_gas(&mut execution_context, 8)?;
    },

    //___ 0x09 MULMOD
    0x09 => {
        let a = u256::from(reg[_dst]);
        let b = u256::from(reg[_src]);
        let n = u256::from(insn.imm as u64);
        reg[_dst] = if n == u256::zero() { 0 } else { ((a * b) % n).low_u64() };
        consume_gas(&mut execution_context, 8)?;
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
                reg[_dst] = base.pow(exp_u32.into()).low_u64();
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
        consume_gas(&mut execution_context, 5)?;
    },

    //___ 0x10 LT
    0x10 => {
        reg[_dst] = if u256::from(reg[_dst]) < u256::from(reg[_src]) { 1 } else { 0 };
        consume_gas(&mut execution_context, 3)?;
    },

    //___ 0x11 GT
    0x11 => {
        reg[_dst] = if u256::from(reg[_dst]) > u256::from(reg[_src]) { 1 } else { 0 };
        consume_gas(&mut execution_context, 3)?;
    },

    //___ 0x12 SLT
    0x12 => {
        let a = I256::from(reg[_dst]);
        let b = I256::from(reg[_src]);
        reg[_dst] = if a < b { 1 } else { 0 };
        consume_gas(&mut execution_context, 3)?;
    },

    //___ 0x13 SGT
    0x13 => {
        let a = I256::from(reg[_dst]);
        let b = I256::from(reg[_src]);
        reg[_dst] = if a > b { 1 } else { 0 };
        consume_gas(&mut execution_context, 3)?;
    },

    //___ 0x14 EQ
    0x14 => {
        reg[_dst] = if reg[_dst] == reg[_src] { 1 } else { 0 };
        consume_gas(&mut execution_context, 3)?;
    },

    //___ 0x15 ISZERO
    0x15 => {
        reg[_dst] = if reg[_dst] == 0 { 1 } else { 0 };
        consume_gas(&mut execution_context, 3)?;
    },

    //___ 0x16 AND
    0x16 => {
        reg[_dst] &= reg[_src];
        consume_gas(&mut execution_context, 3)?;
    },

    //___ 0x17 OR
    0x17 => {
        reg[_dst] |= reg[_src];
        consume_gas(&mut execution_context, 3)?;
    },

    //___ 0x18 XOR
    0x18 => {
        reg[_dst] ^= reg[_src];
        consume_gas(&mut execution_context, 3)?;
    },

    //___ 0x19 NOT
    0x19 => {
        reg[_dst] = !reg[_dst];
        consume_gas(&mut execution_context, 3)?;
    },

    //___ 0x1a BYTE
    0x1a => {
        let i = (reg[_dst] as u32) & 0x1f;
        reg[_dst] = ((reg[_src] >> (248 - i * 8)) & 0xff) as u64;
        consume_gas(&mut execution_context, 3)?;
    },

    //___ 0x1b SHL
    0x1b => {
        let shift = (reg[_src] as u32).min(256);
        reg[_dst] <<= shift;
        consume_gas(&mut execution_context, 3)?;
    },

    //___ 0x1c SHR
    0x1c => {
        let shift = (reg[_src] as u32).min(256);
        reg[_dst] >>= shift;
        consume_gas(&mut execution_context, 3)?;
    },

    //___ 0x1d SAR
    0x1d => {
        let shift = (reg[_src] as u32).min(256);
        let value = reg[_dst] as i64;
        reg[_dst] = (value >> shift) as u64;
        consume_gas(&mut execution_context, 3)?;
    },

    //___ 0x20 KECCAK256
    0x20 => {
        use tiny_keccak::{Hasher, Keccak};
        let offset = reg[_dst] as u64;
        let len = reg[_src] as usize;
        let data = if offset >= mbuff.as_ptr() as u64 && offset + len as u64 <= mbuff.as_ptr() as u64 + mbuff.len() as u64 {
            let off = (offset - mbuff.as_ptr() as u64) as usize;
            &mbuff[off..off + len]
        } else {
            let off = (offset - global_mem.as_ptr() as u64) as usize;
            &global_mem[off..off + len]
        };
        let mut hasher = Keccak::v256();
        let mut hash = [0u8; 32];
        hasher.update(data);
        hasher.finalize(&mut hash);
        reg[_dst] = u256::from_big_endian(&hash).as_u64();
        let gas = 30 + 6 * ((len + 31) / 32) as u64;
        consume_gas(&mut execution_context, gas)?;
    },

    //___ 0x30 ADDRESS
    0x30 => {
        reg[_dst] = encode_address_to_u64(&interpreter_args.contract_address);
        consume_gas(&mut execution_context, 2)?;
    },

    //___ 0x31 BALANCE
    0x31 => {
        let addr = format!("addr_{:x}", reg[_dst]);
        reg[_dst] = get_balance(&execution_context.world_state, &addr);
        consume_gas(&mut execution_context, 700)?;
    },

    //___ 0x32 ORIGIN
    0x32 => {
        reg[_dst] = encode_address_to_u64(&interpreter_args.origin);
        consume_gas(&mut execution_context, 2)?;
    },

    //___ 0x33 CALLER
    0x33 => {
        reg[_dst] = encode_address_to_u64(&interpreter_args.caller);
        consume_gas(&mut execution_context, 2)?;
    },

    //___ 0x34 CALLVALUE
    0x34 => {
        reg[_dst] = interpreter_args.value;
        consume_gas(&mut execution_context, 2)?;
    },

    //___ 0x35 CALLDATALOAD
    0x35 => {
        let addr = reg[_dst] as u64;
        reg[_dst] = evm_load_32(&global_mem, mbuff, addr)?.as_u64();
        consume_gas(&mut execution_context, 3)?;
    },

    //___ 0x36 CALLDATASIZE
    0x36 => {
        reg[_dst] = mbuff.len() as u64;
        consume_gas(&mut execution_context, 2)?;
    },

    //___ 0x37 CALLDATACOPY
    0x37 => {
        let dst = reg[_dst] as u64;
        let src = reg[_src] as u64;
        let len = insn.imm as usize;
        if src + len as u64 <= mbuff.len() as u64 {
            let data = &mbuff[src as usize..src as usize + len];
            let offset = (dst - global_mem.as_ptr() as u64) as usize;
            global_mem[offset..offset + len].copy_from_slice(data);
        }
        let gas = 3 + 3 * ((len + 31) / 32) as u64;
        consume_gas(&mut execution_context, gas)?;
    },

    //___ 0x3a GASPRICE
    0x3a => {
        reg[_dst] = interpreter_args.gas_price;
        consume_gas(&mut execution_context, 2)?;
    },

    //___ 0x41 COINBASE
    0x41 => {
        reg[_dst] = encode_address_to_u64(&execution_context.world_state.block_info.coinbase);
        consume_gas(&mut execution_context, 2)?;
    },

    //___ 0x42 TIMESTAMP
    0x42 => {
        reg[_dst] = execution_context.world_state.block_info.timestamp;
        consume_gas(&mut execution_context, 2)?;
    },

    //___ 0x43 NUMBER
    0x43 => {
        reg[_dst] = execution_context.world_state.block_info.number;
        consume_gas(&mut execution_context, 2)?;
    },

    //___ 0x45 GASLIMIT
    0x45 => {
        reg[_dst] = execution_context.world_state.block_info.gas_limit;
        consume_gas(&mut execution_context, 2)?;
    },

    //___ 0x46 CHAINID
    0x46 => {
        reg[_dst] = execution_context.world_state.chain_id;
        consume_gas(&mut execution_context, 2)?;
    },

    //___ 0x47 SELFBALANCE
    0x47 => {
        reg[_dst] = get_balance(&execution_context.world_state, &interpreter_args.contract_address);
        consume_gas(&mut execution_context, 5)?;
    },

    //___ 0x48 BASEFEE
    0x48 => {
        reg[_dst] = execution_context.world_state.block_info.base_fee.low_u64();
        consume_gas(&mut execution_context, 2)?;
    },

    //___ 0x50 POP
    0x50 => {
        consume_gas(&mut execution_context, 2)?;
    },

    //___ 0x51 MLOAD
    0x51 => {
        let addr = reg[_dst] as u64;
        reg[_dst] = evm_load_32(&global_mem, mbuff, addr)?.as_u64();
        consume_gas(&mut execution_context, 3)?;
    },

    //___ 0x52 MSTORE
    0x52 => {
        let addr = reg[_dst] as u64;
        let value = u256::from(reg[_src]);
        evm_store_32(&mut global_mem, addr, value)?;
        consume_gas(&mut execution_context, 3)?;
    },

    //___ 0x53 MSTORE8
    0x53 => {
        let addr = reg[_dst] as u64;
        let val = (reg[_src] & 0xff) as u8;
        let offset = (addr - global_mem.as_ptr() as u64) as usize;
        if offset < global_mem.len() {
            global_mem[offset] = val;
        }
        consume_gas(&mut execution_context, 3)?;
    },

    //___ 0x54 SLOAD
    0x54 => {
        let slot = format!("{:064x}", reg[_dst]);
        let value = get_storage(&execution_context.world_state, &interpreter_args.contract_address, &slot);
        reg[_dst] = u256::from_big_endian(&value).as_u64();
        consume_gas(&mut execution_context, 800)?;
    },

    //___ 0x55 SSTORE — LE PLUS IMPORTANT
    0x55 => {
        let slot = format!("{:064x}", reg[_dst]);
        let mut value = [0u8; 32];
        u256::from(reg[_src]).to_big_endian();
        set_storage(&mut execution_context.world_state, &interpreter_args.contract_address, &slot, value.to_vec());
        consume_gas(&mut execution_context, 20000)?;
    },

    //___ 0x56 JUMP
    0x56 => {
        let dest = reg[_dst] as usize;
        if is_valid_jumpdest(prog, dest) {
            insn_ptr = dest / ebpf::INSN_SIZE;
            continue;
        } else {
            return Err(Error::new(ErrorKind::Other, "Invalid JUMP"));
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

    //___ 0x5b JUMPDEST
    0x5b => {
        consume_gas(&mut execution_context, 1)?;
    },

    //___ 0x5f PUSH0 (Shanghai+)
    0x5f => {
        reg[_dst] = 0;
        consume_gas(&mut execution_context, 2)?;
    },

    //___ 0x60 PUSH1
    0x60 => {
        // PUSH1: push 1 octet (immédiat) sur la pile
        let byte_offset = insn_ptr * ebpf::INSN_SIZE;
        if byte_offset + 1 < prog.len() {
            reg[_dst] = prog[byte_offset + 1] as u64;
        } else {
            reg[_dst] = 0;
        }
        consume_gas(&mut execution_context, 2)?;
    },
    
    //___ 0x69 PUSH10
    0x69 => {
        // PUSH10: push 10 octets sur la pile (on ne peut stocker que 8 octets dans u64)
        let byte_offset = insn_ptr * ebpf::INSN_SIZE;
        let mut val: u64 = 0;
        for i in 0..8 {
            if byte_offset + 1 + i < prog.len() {
                val = (val << 8) | (prog[byte_offset + 1 + i] as u64);
            }
        }
        reg[_dst] = val;
        consume_gas(&mut execution_context, 2)?;
    },

    //___ 0xf3 RETURN — LE SAINT GRAAL
    0xf3 => {
        let offset = reg[_dst] as u64;
        let len = reg[_src] as usize;
        let mut ret_data = vec![0u8; len];
        if len > 0 {
            let start = (offset - global_mem.as_ptr() as u64) as usize;
            if start + len <= global_mem.len() {
                ret_data.copy_from_slice(&global_mem[start..start + len]);
            }
        }
        execution_context.return_data = ret_data.clone();

        if let Some(ret_type) = ret_type {
            if (ret_type == "string" || ret_type == "bytes") && !ret_data.is_empty() {
                if let Ok(s) = std::str::from_utf8(&ret_data) {
                    return Ok(serde_json::Value::String(s.to_string()));
                }
            }
        }
        return Ok(serde_json::Value::String(hex::encode(ret_data)));
    },

    //___ 0xfd REVERT
    0xfd => {
        let offset = reg[_dst] as u64;
        let len = reg[_src] as usize;
        let mut data = vec![0u8; len];
        if len > 0 {
            let start = (offset - global_mem.as_ptr() as u64) as usize;
            data.copy_from_slice(&global_mem[start..start + len]);
        }
        return Err(Error::new(ErrorKind::Other, format!("REVERT: 0x{}", hex::encode(data))));
    },

    //___ 0xfe INVALID
    0xfe => {
        return Err(Error::new(ErrorKind::Other, "INVALID opcode"));
    },

    //___ 0xff SELFDESTRUCT — autorisé uniquement dans le dispatcher UUPS
    0xff => {
        if insn_ptr < 120 {
            // On est dans le dispatcher du proxy → 0xff = padding → on skip
            // continue;   // <-- À remplacer
            insn_ptr = insn_ptr.wrapping_add(1);
            continue;
        } else {
            return Err(Error::new(ErrorKind::Other, "SELFDESTRUCT forbidden"));
        }
    },

    //___ Tout le reste → crash clair
    _ => {
        return Err(Error::new(ErrorKind::Other, 
            format!("Unsupported EVM opcode 0x{:02x} at PC {}", insn.opc, insn_ptr)));
    }
}
        insn_ptr = insn_ptr.wrapping_add(1);
    }

    Err(Error::new(ErrorKind::Other, "Error: program terminated without STOP"))
}