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

#[derive(Clone)]
pub struct InterpreterArgs {
    pub function_name: String,
    pub contract_address: String,
    pub sender_address: String,
    pub args: Vec<serde_json::Value>,
    pub state_data: Vec<u8>,
    pub is_view: bool,
    // ✅ AJOUT: Champs compatibles architecture basée sur pile
    pub gas_limit: u64,
    pub gas_price: u64,
    pub value: u64,          // Montant transféré avec l'appel
    pub call_depth: u32,     // Profondeur d'appel actuelle
    pub block_number: u64,
    pub timestamp: u64,
    pub caller: String,      // Adresse de l'appelant direct
    pub origin: String,      // Adresse de l'initiateur de la transaction
}

impl Default for InterpreterArgs {
    fn default() -> Self {
        InterpreterArgs {
            function_name: "main".to_string(),
            contract_address: "*default*#contract#".to_string(),
            sender_address: "*sender*#default#".to_string(),
            args: vec![],
            state_data: vec![0; 1024],
            is_view: false,
            gas_limit: 1000000,
            gas_price: 1,
            value: 0,
            call_depth: 0,
            block_number: 1,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            caller: "*caller*#default#".to_string(),
            origin: "*origin*#default#".to_string(),
        }
    }
}

// ✅ AJOUT: Structure pour l'état mondial UVM
#[derive(Clone, Debug)]
pub struct UvmWorldState {
    pub accounts: HashMap<String, AccountState>,
    pub storage: HashMap<String, HashMap<String, Vec<u8>>>, // contract_addr -> slot -> value
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

#[derive(Clone, Debug)]
pub struct BlockInfo {
    pub number: u64,
    pub timestamp: u64,
    pub gas_limit: u64,
    pub difficulty: u64,
    pub coinbase: String,
}
impl Default for UvmWorldState {
    fn default() -> Self {
        UvmWorldState {
            accounts: HashMap::new(),
            storage: HashMap::new(),
            block_info: BlockInfo {
                number: 1,
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
                gas_limit: 30000000,
                difficulty: 1,
                coinbase: "*coinbase*#miner#".to_string(),
            },
            chain_id: 1, // Default chain ID
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
        
        // EXTCODESIZE (0x3B) - address(x).code.length EVM
        0x3b => 700,
        
        // RETURNDATASIZE (0x3D) - returndatasize EVM
        0x3d => 2,
        
        // Instructions par défaut
        _ => 1, // Coût par défaut
    }
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
    }

    Err(Error::new(ErrorKind::Other, format!(
        "Error: out of bounds memory {} (insn #{:?}), addr {:#x}, size {:?}\nmbuff: {:#x}/{:#x}, mem: {:#x}/{:#x}, stack: {:#x}/{:#x}",
        access_type, insn_ptr, addr, len,
        mbuff.as_ptr() as u64, mbuff.len(),
        mem.as_ptr() as u64, mem.len(),
        stack.as_ptr() as u64, stack.len()
    )))
}

pub fn execute_program(
    prog_: Option<&[u8]>,
    stack_usage: Option<&StackUsage>,
    mem: &[u8],
    mbuff: &[u8],
    helpers: &HashMap<u32, ebpf::Helper>,
    allowed_memory: &HashSet<Range<u64>>,
    ret_type: Option<&str>,
    ffi_fallback: Option<&dyn Fn(u32, &[u64]) -> Option<u64>>,
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
    if interpreter_args.value > 0 && !interpreter_args.is_view {
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
    while insn_ptr * ebpf::INSN_SIZE < prog.len() {
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
            // ✅ Instructions UVM étendues pour gestion d'état
            0xf2 => {
                match insn.imm {
                    0 => reg[_dst] = interpreter_args.args.len() as u64,
                    1 => reg[_dst] = contract_hash,
                    2 => reg[_dst] = sender_hash,
                    3 => reg[_dst] = interpreter_args.state_data.len() as u64,
                    4 => reg[_dst] = if interpreter_args.is_view { 1 } else { 0 },
                    5 => reg[_dst] = execution_context.gas_remaining, // Gas restant
                    6 => reg[_dst] = get_balance(&execution_context.world_state, &interpreter_args.contract_address), // Balance contrat
                    7 => reg[_dst] = get_balance(&execution_context.world_state, &interpreter_args.sender_address), // Balance sender
                    8 => reg[_dst] = interpreter_args.block_number,
                    9 => reg[_dst] = interpreter_args.timestamp,
                    10 => reg[_dst] = interpreter_args.call_depth as u64,
                    _ => reg[_dst] = 0,
                }
            },

            0xbb => {
                // Instruction CALLVALUE (0x34) - msg.value EVM
                reg[_dst] = interpreter_args.value;
            },

            0x03 => {
                // Instruction GASLIMIT (0x45) - block.gaslimit EVM
                reg[_dst] = execution_context.world_state.block_info.gas_limit;
            },

            0x01 => {
                // Instruction NUMBER (0x43) - block.number EVM
                reg[_dst] = execution_context.world_state.block_info.number;
            },

            0xa9 => {
                // Instruction CALLER (0x33) - msg.sender EVM
                let caller_bytes = interpreter_args.caller.as_bytes();
                let len = caller_bytes.len().min(32);
                let mut caller_value = 0u64;
                for i in 0..len.min(8) {
                    caller_value |= (caller_bytes[i] as u64) << (8 * i);
                }
                reg[_dst] = caller_value;
            },

            0x2 => {
                // Instruction ORIGIN (0x32) - tx.origin EVM
                let origin_bytes = interpreter_args.origin.as_bytes();
                let len = origin_bytes.len().min(32);
                let mut origin_value = 0u64;
                for i in 0..len.min(8) {
                    origin_value |= (origin_bytes[i] as u64) << (8 * i);
                }
                reg[_dst] = origin_value;
            },

            0xd1 => {
                // ✅ SUPPORT OPCODE 0xd1 (GASPRICE)
                reg[_dst] = interpreter_args.gas_price;
            }

            // ✅ Instruction de stockage d'état (SSTORE équivalent)
            0xf3 => {
                if !interpreter_args.is_view {
                    let slot = format!("{:064x}", reg[_dst]);
                    let value = reg[_src].to_le_bytes().to_vec();
                    set_storage(&mut execution_context.world_state, &interpreter_args.contract_address, &slot, value);
                    consume_gas(&mut execution_context, 20000)?; // Coût SSTORE
                }
            },

            // ✅ Instruction de chargement d'état (SLOAD équivalent)
            0xf4 => {
                let slot = format!("{:064x}", reg[_src]);
                let value = get_storage(&execution_context.world_state, &interpreter_args.contract_address, &slot);
                if value.len() >= 8 {
                    reg[_dst] = u64::from_le_bytes(value[..8].try_into().unwrap_or([0; 8]));
                } else {
                    reg[_dst] = 0;
                }
                consume_gas(&mut execution_context, 800)?; // Coût SLOAD

                reg[0] = reg[_dst];
                println!("🟩 [DEBUG] r0 mis à jour (SLOAD 0xf4): {}", reg[0]);
            },

            // ✅ Instruction de log (LOG équivalent)
            0xf5 => {
                if !interpreter_args.is_view {
                    let topic = format!("{:016x}", reg[_src]);
                    let data_ptr = reg[_dst] as usize;
                    let data_len = insn.imm as usize;
                    
                    let log_data = if data_ptr < global_mem.len() && data_ptr + data_len <= global_mem.len() {
                        global_mem[data_ptr..data_ptr + data_len].to_vec()
                    } else {
                        vec![]
                    };

                    execution_context.logs.push(UvmLog {
                        address: interpreter_args.contract_address.clone(),
                        topics: vec![topic],
                        data: log_data,
                    });
                    
                    consume_gas(&mut execution_context, 375 + (data_len as u64 * 8))?; // Coût LOG
                }
            },

            // Instructions eBPF standard avec consommation de gas...
            ebpf::LD_B_REG => {
                reg[_dst] = unsafe {
                    let orig_addr = (reg[_src] as *const u8).wrapping_offset(insn.off as isize) as u64;
                    let addr = check_mem_load(orig_addr, 1, insn_ptr);
                    match addr {
                        Ok(_) => (orig_addr as *const u8).read_unaligned() as u64,
                        Err(_) => 0,
                    }
                };
            },
            ebpf::LD_H_REG => {
                reg[_dst] = unsafe {
                    let orig_addr = (reg[_src] as *const u8).wrapping_offset(insn.off as isize) as u64;
                    let addr = check_mem_load(orig_addr, 2, insn_ptr);
                    match addr {
                        Ok(_) => (orig_addr as *const u16).read_unaligned() as u64,
                        Err(_) => 0,
                    }
                };
            },
            ebpf::LD_W_REG => {
                reg[_dst] = unsafe {
                    let orig_addr = (reg[_src] as *const u8).wrapping_offset(insn.off as isize) as u64;
                    let addr = check_mem_load(orig_addr, 4, insn_ptr);
                    match addr {
                        Ok(_) => (orig_addr as *const u32).read_unaligned() as u64,
                        Err(_) => 0,
                    }
                };
            },
            ebpf::LD_DW_REG => {
                reg[_dst] = unsafe {
                    let orig_addr = (reg[_src] as *const u8).wrapping_offset(insn.off as isize) as u64;
                    let addr = check_mem_load(orig_addr, 8, insn_ptr);
                    match addr {
                        Ok(_) => (orig_addr as *const u64).read_unaligned(),
                        Err(_) => 0,
                    }
                };
            },

            // Instructions de stockage avec vérification gas
            ebpf::ST_B_IMM => unsafe {
                let orig_addr = (reg[_dst] as *const u8).wrapping_offset(insn.off as isize) as u64;
                if check_mem_store(orig_addr, 1, insn_ptr).is_ok() {
                    (orig_addr as *mut u8).write_unaligned(insn.imm as u8);
                }
            },
            ebpf::ST_H_IMM => unsafe {
                let orig_addr = (reg[_dst] as *const u8).wrapping_offset(insn.off as isize) as u64;
                if check_mem_store(orig_addr, 2, insn_ptr).is_ok() {
                    (orig_addr as *mut u16).write_unaligned(insn.imm as u16);
                }
            },
            ebpf::ST_W_IMM => unsafe {
                let orig_addr = (reg[_dst] as *const u8).wrapping_offset(insn.off as isize) as u64;
                if check_mem_store(orig_addr, 4, insn_ptr).is_ok() {
                    (orig_addr as *mut u32).write_unaligned(insn.imm as u32);
                }
            },
            ebpf::ST_DW_IMM => unsafe {
                let orig_addr = (reg[_dst] as *const u8).wrapping_offset(insn.off as isize) as u64;
                if check_mem_store(orig_addr, 8, insn_ptr).is_ok() {
                    (orig_addr as *mut u64).write_unaligned(insn.imm as u64);
                }
            },
            ebpf::ST_B_REG => unsafe {
                let orig_addr = (reg[_dst] as *const u8).wrapping_offset(insn.off as isize) as u64;
                if check_mem_store(orig_addr, 1, insn_ptr).is_ok() {
                    (orig_addr as *mut u8).write_unaligned(reg[_src] as u8);
                }
            },
            ebpf::ST_H_REG => unsafe {
                let orig_addr = (reg[_dst] as *const u8).wrapping_offset(insn.off as isize) as u64;
                if check_mem_store(orig_addr, 2, insn_ptr).is_ok() {
                    (orig_addr as *mut u16).write_unaligned(reg[_src] as u16);
                }
            },
            ebpf::ST_W_REG => unsafe {
                let orig_addr = (reg[_dst] as *const u8).wrapping_offset(insn.off as isize) as u64;
                if check_mem_store(orig_addr, 4, insn_ptr).is_ok() {
                    (orig_addr as *mut u32).write_unaligned(reg[_src] as u32);
                }
            },
            ebpf::ST_DW_REG => unsafe {
                if _dst == 8 || _dst == 10 {
                    return Err(Error::new(
                        ErrorKind::Other,
                        format!("Erreur: tentative d'écriture mémoire via r{} (réservé UVM)", _dst)
                    ));
                }
                let orig_addr = (reg[_dst] as *const u8).wrapping_offset(insn.off as isize) as u64;
                if check_mem_store(orig_addr, 8, insn_ptr).is_ok() {
                    (orig_addr as *mut u64).write_unaligned(reg[_src]);
                }
            },

            // Instructions arithmétiques ALU32
            ebpf::ADD32_IMM  => reg[_dst] = (reg[_dst] as i32).wrapping_add(insn.imm) as u64,
            ebpf::ADD32_REG  => reg[_dst] = (reg[_dst] as i32).wrapping_add(reg[_src] as i32) as u64,
            ebpf::SUB32_IMM  => reg[_dst] = (reg[_dst] as i32).wrapping_sub(insn.imm) as u64,
            ebpf::SUB32_REG  => reg[_dst] = (reg[_dst] as i32).wrapping_sub(reg[_src] as i32) as u64,
            ebpf::MUL32_IMM  => reg[_dst] = (reg[_dst] as i32).wrapping_mul(insn.imm) as u64,
            ebpf::MUL32_REG  => reg[_dst] = (reg[_dst] as i32).wrapping_mul(reg[_src] as i32) as u64,
            ebpf::DIV32_IMM if insn.imm as u32 == 0 => reg[_dst] = 0,
            ebpf::DIV32_IMM  => reg[_dst] = (reg[_dst] as u32 / insn.imm as u32) as u64,
            ebpf::DIV32_REG if reg[_src] as u32 == 0 => reg[_dst] = 0,
            ebpf::DIV32_REG  => reg[_dst] = (reg[_dst] as u32 / reg[_src] as u32) as u64,
            ebpf::OR32_IMM   => reg[_dst] = (reg[_dst] as u32 | insn.imm as u32) as u64,
            ebpf::OR32_REG   => reg[_dst] = (reg[_dst] as u32 | reg[_src] as u32) as u64,
            ebpf::AND32_IMM  => reg[_dst] = (reg[_dst] as u32 & insn.imm as u32) as u64,
            ebpf::AND32_REG  => reg[_dst] = (reg[_dst] as u32 & reg[_src] as u32) as u64,
            ebpf::LSH32_IMM  => reg[_dst] = (reg[_dst] as u32).wrapping_shl(insn.imm as u32) as u64,
            ebpf::LSH32_REG  => reg[_dst] = (reg[_dst] as u32).wrapping_shl(reg[_src] as u32) as u64,
            ebpf::RSH32_IMM  => reg[_dst] = (reg[_dst] as u32).wrapping_shr(insn.imm as u32) as u64,
            ebpf::RSH32_REG  => reg[_dst] = (reg[_dst] as u32).wrapping_shr(reg[_src] as u32) as u64,
            ebpf::NEG32      => { reg[_dst] = (reg[_dst] as i32).wrapping_neg() as u64; reg[_dst] &= U32MAX; },
            ebpf::MOD32_IMM if insn.imm as u32 == 0 => (),
            ebpf::MOD32_IMM  => reg[_dst] = (reg[_dst] as u32 % insn.imm as u32) as u64,
            ebpf::MOD32_REG if reg[_src] as u32 == 0 => (),
            ebpf::MOD32_REG  => reg[_dst] = (reg[_dst] as u32 % reg[_src] as u32) as u64,
            ebpf::XOR32_IMM  => reg[_dst] = (reg[_dst] as u32 ^ insn.imm as u32) as u64,
            ebpf::XOR32_REG  => reg[_dst] = (reg[_dst] as u32 ^ reg[_src] as u32) as u64,
            ebpf::MOV32_IMM  => reg[_dst] = insn.imm as u32 as u64,
            ebpf::MOV32_REG  => {
                if _dst == 8 || _dst == 10 || _dst >= 50 {
                    return Err(Error::new(
                        ErrorKind::Other,
                        format!("Erreur: tentative d'écraser r{} (réservé UVM)", _dst)
                    ));
                }
                reg[_dst] = (reg[_src] as u32) as u64;
            },
            ebpf::ARSH32_IMM => { reg[_dst] = (reg[_dst] as i32).wrapping_shr(insn.imm as u32) as u64; reg[_dst] &= U32MAX; },
            ebpf::ARSH32_REG => { reg[_dst] = (reg[_dst] as i32).wrapping_shr(reg[_src] as u32) as u64; reg[_dst] &= U32MAX; },

            // Instructions de conversion d'endianness
            ebpf::LE => {
                reg[_dst] = match insn.imm {
                    16 => (reg[_dst] as u16).to_le() as u64,
                    32 => (reg[_dst] as u32).to_le() as u64,
                    64 => reg[_dst].to_le(),
                    _ => unreachable!(),
                };
            },
            ebpf::BE => {
                reg[_dst] = match insn.imm {
                    16 => (reg[_dst] as u16).to_be() as u64,
                    32 => (reg[_dst] as u32).to_be() as u64,
                    64 => reg[_dst].to_be(),
                    _ => unreachable!(),
                };
            },

            // Instructions arithmétiques ALU64
            ebpf::ADD64_IMM  => reg[_dst] = reg[_dst].wrapping_add(insn.imm as u64),
            ebpf::ADD64_REG  => reg[_dst] = reg[_dst].wrapping_add(reg[_src]),
            ebpf::SUB64_IMM  => reg[_dst] = reg[_dst].wrapping_sub(insn.imm as u64),
            ebpf::SUB64_REG  => reg[_dst] = reg[_dst].wrapping_sub(reg[_src]),
            ebpf::MUL64_IMM  => reg[_dst] = reg[_dst].wrapping_mul(insn.imm as u64),
            ebpf::MUL64_REG  => reg[_dst] = reg[_dst].wrapping_mul(reg[_src]),
            ebpf::DIV64_IMM if insn.imm == 0 => reg[_dst] = 0,
            ebpf::DIV64_IMM  => reg[_dst] /= insn.imm as u64,
            ebpf::DIV64_REG if reg[_src] == 0 => reg[_dst] = 0,
            ebpf::DIV64_REG  => reg[_dst] /= reg[_src],
            ebpf::OR64_IMM   => reg[_dst] |= insn.imm as u64,
            ebpf::OR64_REG   => reg[_dst] |= reg[_src],
            ebpf::AND64_IMM  => reg[_dst] &= insn.imm as u64,
            ebpf::AND64_REG  => reg[_dst] &= reg[_src],
            ebpf::LSH64_IMM  => reg[_dst] <<= insn.imm as u64 & SHIFT_MASK_64,
            ebpf::LSH64_REG  => reg[_dst] <<= reg[_src] & SHIFT_MASK_64,
            ebpf::RSH64_IMM  => reg[_dst] >>= insn.imm as u64 & SHIFT_MASK_64,
            ebpf::RSH64_REG  => reg[_dst] >>= reg[_src] & SHIFT_MASK_64,
            ebpf::NEG64      => reg[_dst] = (-(reg[_dst] as i64)) as u64,
            ebpf::MOD64_IMM if insn.imm == 0 => (),
            ebpf::MOD64_IMM  => reg[_dst] %= insn.imm as u64,
            ebpf::MOD64_REG if reg[_src] == 0 => (),
            ebpf::MOD64_REG  => reg[_dst] %= reg[_src],
            ebpf::XOR64_IMM  => reg[_dst] ^= insn.imm as u64,
            ebpf::XOR64_REG  => reg[_dst] ^= reg[_src],
            ebpf::MOV64_IMM  => reg[_dst] = insn.imm as u64,
            ebpf::MOV64_REG  => {
                if _dst == 8 || _dst == 10 || _dst >= 50 {
                    return Err(Error::new(
                        ErrorKind::Other,
                        format!("Erreur: tentative d'écraser r{} (réservé UVM)", _dst)
                    ));
                }
                reg[_dst] = reg[_src];
            },

            // Instructions de saut
            ebpf::JA         => do_jump(),
            ebpf::JEQ_IMM    => if reg[_dst] == unsigned_u64!(insn.imm) { do_jump(); },
            ebpf::JEQ_REG    => if reg[_dst] == reg[_src] { do_jump(); },
            ebpf::JGT_IMM    => if reg[_dst] > unsigned_u64!(insn.imm) { do_jump(); },
            ebpf::JGT_REG    => if reg[_dst] > reg[_src] { do_jump(); },
            ebpf::JGE_IMM    => if reg[_dst] >= unsigned_u64!(insn.imm) { do_jump(); },
            ebpf::JGE_REG    => if reg[_dst] >= reg[_src] { do_jump(); },
            ebpf::JLT_IMM    => if reg[_dst] < unsigned_u64!(insn.imm) { do_jump(); },
            ebpf::JLT_REG    => if reg[_dst] < reg[_src] { do_jump(); },
            ebpf::JLE_IMM    => if reg[_dst] <= unsigned_u64!(insn.imm) { do_jump(); },
            ebpf::JLE_REG    => if reg[_dst] <= reg[_src] { do_jump(); },
            ebpf::JSET_IMM   => if reg[_dst] & insn.imm as u64 != 0 { do_jump(); },
            ebpf::JSET_REG   => if reg[_dst] & reg[_src] != 0 { do_jump(); },
            ebpf::JNE_IMM    => if reg[_dst] != unsigned_u64!(insn.imm) { do_jump(); },
            ebpf::JNE_REG    => if reg[_dst] != reg[_src] { do_jump(); },
            ebpf::JSGT_IMM   => if reg[_dst] as i64 > insn.imm as i64 { do_jump(); },
            ebpf::JSGT_REG   => if reg[_dst] as i64 > reg[_src] as i64 { do_jump(); },
            ebpf::JSGE_IMM   => if reg[_dst] as i64 >= insn.imm as i64 { do_jump(); },
            ebpf::JSGE_REG   => if reg[_dst] as i64 >= reg[_src] as i64 { do_jump(); },
            ebpf::JSLT_IMM   => if (reg[_dst] as i64) < insn.imm as i64 { do_jump(); },
            ebpf::JSLT_REG   => if (reg[_dst] as i64) < reg[_src] as i64 { do_jump(); },
            ebpf::JSLE_IMM   => if reg[_dst] as i64 <= insn.imm as i64 { do_jump(); },
            ebpf::JSLE_REG   => if reg[_dst] as i64 <= reg[_src] as i64 { do_jump(); },
            // Instructions de saut 32-bit
            ebpf::JEQ_IMM32  => if reg[_dst] as u32 == insn.imm as u32 { do_jump(); },
            ebpf::JEQ_REG32  => if reg[_dst] as u32 == reg[_src] as u32 { do_jump(); },
            ebpf::JGT_IMM32  => if reg[_dst] as u32 > insn.imm as u32 { do_jump(); },
            ebpf::JGT_REG32  => if reg[_dst] as u32 > reg[_src] as u32 { do_jump(); },
            ebpf::JGE_IMM32  => if reg[_dst] as u32 >= insn.imm as u32 { do_jump(); },
            ebpf::JGE_REG32  => if reg[_dst] as u32 >= reg[_src] as u32 { do_jump(); },
            ebpf::JLT_IMM32  => if (reg[_dst] as u32) < insn.imm as u32 { do_jump(); },
            ebpf::JLT_REG32  => if (reg[_dst] as u32) < reg[_src] as u32 { do_jump(); },
            ebpf::JLE_IMM32  => if reg[_dst] as u32 <= insn.imm as u32 { do_jump(); },
            ebpf::JLE_REG32  => if (reg[_dst] as u32) <= reg[_src] as u32 { do_jump(); },
            ebpf::JSET_IMM32 => if reg[_dst] as u32 & insn.imm as u32 != 0 { do_jump(); },
            ebpf::JSET_REG32 => if reg[_dst] as u32 & reg[_src] as u32 != 0 { do_jump(); },
            ebpf::JNE_IMM32  => if reg[_dst] as u32 != insn.imm as u32 { do_jump(); },
            ebpf::JNE_REG32  => if reg[_dst] as u32 != reg[_src] as u32 { do_jump(); },
            ebpf::JSGT_IMM32 => if reg[_dst] as i32 > insn.imm { do_jump(); },
            ebpf::JSGT_REG32 => if reg[_dst] as i32 > reg[_src] as i32 { do_jump(); },
            ebpf::JSGE_IMM32 => if reg[_dst] as i32 >= insn.imm { do_jump(); },
            ebpf::JSGE_REG32 => if reg[_dst] as i32 >= reg[_src] as i32 { do_jump(); },
            ebpf::JSLT_IMM32 => if (reg[_dst] as i32) < insn.imm { do_jump(); },
            ebpf::JSLT_REG32 => if (reg[_dst] as i32) < reg[_src] as i32 { do_jump(); },
            ebpf::JSLE_IMM32 => if reg[_dst] as i32 <= insn.imm { do_jump(); },
            ebpf::JSLE_REG32 => if reg[_dst] as i32 <= reg[_src] as i32 { do_jump(); },

            // Instructions d'appel
            ebpf::CALL => {
                match _src {
                    0 => {
                        if let Some(function) = helpers.get(&(insn.imm as u32)) {
                            consume_gas(&mut execution_context, 40)?;
                            reg[0] = function(reg[1], reg[2], reg[3], reg[4], reg[5]);
                        } else {
                            return Err(Error::new(
                                ErrorKind::Other,
                                format!("Error: unknown helper function (id: {:#x})", insn.imm as u32)
                            ));
                        }
                    }
                    1 => {
                        if stack_frame_idx >= MAX_CALL_DEPTH {
                            return Err(Error::new(
                                ErrorKind::Other,
                                format!("Error: too many nested calls (max: {MAX_CALL_DEPTH})")
                            ));
                        }
                        consume_gas(&mut execution_context, 40)?;
                        stacks[stack_frame_idx].save_registers(&reg[6..=9]);
                        stacks[stack_frame_idx].save_return_address(insn_ptr);
                        reg[10] -= stacks[stack_frame_idx].get_stack_usage().stack_usage() as u64;
                        stack_frame_idx += 1;
                        insn_ptr += insn.imm as usize;
                        continue;
                    }
                    _ => {
                        return Err(Error::new(
                            ErrorKind::Other,
                            format!("Error: unsupported call type #{} (insn #{})", _src, insn_ptr-1)
                        ));
                    }
                }
            }
    
            0x00 => {
                // NOP : ne rien faire, avance simplement
            },

            // 00 STOP
            0x00 => {
                println!("🟥 [DEBUG] STOP opcode atteint !");
                return Ok(serde_json::json!(reg[0]));
            },

            // 01 ADD
            0x01 => {
                reg[_dst] = reg[_dst].wrapping_add(reg[_src]);
                consume_gas(&mut execution_context, 3)?;
            },

            // 02 MUL
            0x02 => {
                reg[_dst] = reg[_dst].wrapping_mul(reg[_src]);
                consume_gas(&mut execution_context, 5)?;
            },

            // 03 SUB
            0x03 => {
                reg[_dst] = reg[_dst].wrapping_sub(reg[_src]);
                consume_gas(&mut execution_context, 3)?;
            },

            // 04 DIV
            0x04 => {
                reg[_dst] = if reg[_src] == 0 { 0 } else { reg[_dst] / reg[_src] };
                consume_gas(&mut execution_context, 5)?;
            },

            // 05 SDIV
            0x05 => {
                let a = reg[_dst] as i128;
                let b = reg[_src] as i128;
                reg[_dst] = if b == 0 { 0 } else { (a / b) as u64 };
                consume_gas(&mut execution_context, 5)?;
            },

            // 06 MOD
            0x06 => {
                reg[_dst] = if reg[_src] == 0 { 0 } else { reg[_dst] % reg[_src] };
                consume_gas(&mut execution_context, 5)?;
            },

            // 07 SMOD
            0x07 => {
                let a = reg[_dst] as i128;
                let b = reg[_src] as i128;
                reg[_dst] = if b == 0 { 0 } else { (a % b) as u64 };
                consume_gas(&mut execution_context, 5)?;
            },

            // 08 ADDMOD
            0x08 => {
                let n = reg[5];
                reg[_dst] = if n == 0 { 0 } else { (reg[_dst].wrapping_add(reg[_src])) % n };
                consume_gas(&mut execution_context, 8)?;
            },

            // 09 MULMOD
            0x09 => {
                let n = reg[5];
                reg[_dst] = if n == 0 { 0 } else { (reg[_dst].wrapping_mul(reg[_src])) % n };
                consume_gas(&mut execution_context, 8)?;
            },

            // 0A EXP
            0x0a => {
                let base = reg[_dst];
                let exp = reg[_src];
                reg[_dst] = base.checked_pow(exp as u32).unwrap_or(0);
                consume_gas(&mut execution_context, 10 + exp * 50)?; // estimation
            },

            // 0B SIGNEXTEND
            0x0b => {
                let b = reg[_dst] as u8;
                let x = reg[_src];
                if b < 32 {
                    let sign_bit = 1u64 << (8 * (b + 1) - 1);
                    let mask = (1u64 << (8 * (b + 1))) - 1;
                    reg[_dst] = if x & sign_bit != 0 {
                        x | (!mask)
                    } else {
                        x & mask
                    };
                }
                consume_gas(&mut execution_context, 5)?;
            },

            // 10 LT
            0x10 => {
                reg[_dst] = if reg[_dst] < reg[_src] { 1 } else { 0 };
                consume_gas(&mut execution_context, 3)?;
            },

            // 11 GT
            0x11 => {
                reg[_dst] = if reg[_dst] > reg[_src] { 1 } else { 0 };
                consume_gas(&mut execution_context, 3)?;
            },

            // 12 SLT
            0x12 => {
                let a = reg[_dst] as i128;
                let b = reg[_src] as i128;
                reg[_dst] = if a < b { 1 } else { 0 };
                consume_gas(&mut execution_context, 3)?;
            },

            // 13 SGT
            0x13 => {
                let a = reg[_dst] as i128;
                let b = reg[_src] as i128;
                reg[_dst] = if a > b { 1 } else { 0 };
                consume_gas(&mut execution_context, 3)?;
            },

            // 14 EQ
            0x14 => {
                reg[_dst] = if reg[_dst] == reg[_src] { 1 } else { 0 };
                consume_gas(&mut execution_context, 3)?;
            },

            // 15 ISZERO
            0x15 => {
                reg[_dst] = if reg[_dst] == 0 { 1 } else { 0 };
                consume_gas(&mut execution_context, 3)?;
            },

            // 16 AND
            0x16 => {
                reg[_dst] &= reg[_src];
                consume_gas(&mut execution_context, 3)?;
            },

            // 17 OR
            0x17 => {
                reg[_dst] |= reg[_src];
                consume_gas(&mut execution_context, 3)?;
            },

            // 18 XOR
            0x18 => {
                reg[_dst] ^= reg[_src];
                consume_gas(&mut execution_context, 3)?;
            },

            // 19 NOT
            0x19 => {
                reg[_dst] = !reg[_dst];
                consume_gas(&mut execution_context, 3)?;
            },

            // 1A BYTE
            0x1a => {
                let i = reg[_dst] as usize;
                let x = reg[_src];
                reg[_dst] = if i < 32 { (x >> (248 - i * 8)) & 0xFF } else { 0 };
                consume_gas(&mut execution_context, 3)?;
            },

            // 1B SHL
            0x1b => {
                reg[_dst] = reg[_src] << reg[_dst];
                consume_gas(&mut execution_context, 3)?;
            },

            // 1C SHR
            0x1c => {
                reg[_dst] = reg[_src] >> reg[_dst];
                consume_gas(&mut execution_context, 3)?;
            },

            // 1D SAR
            0x1d => {
                let shift = reg[_dst] as u32;
                let val = reg[_src] as i128;
                reg[_dst] = (val >> shift) as u64;
                consume_gas(&mut execution_context, 3)?;
            },

            // 40 BLOCKHASH
            0x40 => {
                let block_num = reg[_dst];
                if let Some(hash) = get_block_hash(&execution_context.world_state, block_num) {
                    // On copie le hash dans le registre (premiers 8 octets)
                    reg[_dst] = u64::from_le_bytes(hash[..8].try_into().unwrap_or([0; 8]));
                } else {
                    reg[_dst] = 0;
                }
                consume_gas(&mut execution_context, 20)?;
            },

            // 41 COINBASE
            0x41 => {
                // Adresse du mineur du bloc
                let coinbase_bytes = execution_context.world_state.block_info.coinbase.as_bytes();
                let mut val = 0u64;
                for i in 0..coinbase_bytes.len().min(8) {
                    val |= (coinbase_bytes[i] as u64) << (8 * i);
                }
                reg[_dst] = val;
                consume_gas(&mut execution_context, 2)?;
            },

            // 42 TIMESTAMP
            0x42 => {
                reg[_dst] = execution_context.world_state.block_info.timestamp;
                consume_gas(&mut execution_context, 2)?;
            },

            // 43 NUMBER
            0x43 => {
                reg[_dst] = execution_context.world_state.block_info.number;
                consume_gas(&mut execution_context, 2)?;
            },

            // 44 PREVRANDAO
            0x44 => {
                reg[_dst] = execution_context.world_state.block_info.difficulty;
                consume_gas(&mut execution_context, 2)?;
            },

            // 45 GASLIMIT
            0x45 => {
                reg[_dst] = execution_context.world_state.block_info.gas_limit;
                consume_gas(&mut execution_context, 2)?;
            },

            // 46 CHAINID
            0x46 => {
                reg[_dst] = execution_context.world_state.chain_id;
                consume_gas(&mut execution_context, 2)?;
            },

            // 48 BASEFEE
            0x48 => {
                // Si tu as une vraie basefee dans BlockInfo, utilise-la, sinon gas_price
                reg[_dst] = execution_context.world_state.block_info.gas_limit; // ou interpreter_args.gas_price
                consume_gas(&mut execution_context, 2)?;
            },

            // 49 BLOBHASH
            0x49 => {
                // EIP-4844: retourne 0 si non supporté
                reg[_dst] = 0;
                consume_gas(&mut execution_context, 3)?;
            },

            // 4A BLOBBASEFEE
            0x4a => {
                // EIP-7516: retourne 0 si non supporté
                reg[_dst] = 0;
                consume_gas(&mut execution_context, 2)?;
            },

            // 5C TLOAD / 5D TSTORE / 5E MCOPY : non supportés, stub
            0x5c | 0x5d | 0x5e => {
                reg[_dst] = 0;
                consume_gas(&mut execution_context, 100)?;
            },

            _ => {
                // Catch-all for unhandled opcodes; do nothing.
            }
        }
        insn_ptr += 1;
    }
    
    // Fin de programme sans EXIT explicite
    if let Some(&last) = prog.last() {
        if last == ebpf::EXIT {
            return Ok(serde_json::Value::Null);
        }
    }
    
    println!("🏁 UVM fin de programme (gas: {})", execution_context.gas_used);
    println!("🟨 [DEBUG] Fin sans EXIT explicite, global_mem[0..32]: {:?}", &global_mem[0..32]);
    println!("🟨 [DEBUG] r0 final: {}", reg[0]);

    // === AJOUT : Construction du résultat brut du flow of fund ===
    let mut balances = serde_json::Map::new();
    for (addr, acc) in &execution_context.world_state.accounts {
        balances.insert(addr.clone(), serde_json::json!(acc.balance));
    }
    let mut events = Vec::new();
    for log in &execution_context.logs {
        events.push(serde_json::json!({
            "address": log.address,
            "topics": log.topics,
            "data": hex::encode(&log.data)
        }));
    }
    let result_type = if interpreter_args.is_view {
        "view"
    } else if interpreter_args.function_name.contains("mint") {
        "mint"
    } else if interpreter_args.function_name.contains("burn") {
        "burn"
    } else if interpreter_args.function_name.contains("deliver") || interpreter_args.function_name.contains("transfer") {
        "transfer"
    } else {
        "other"
    };

    let result_json = serde_json::json!({
        "result_type": result_type,
        "function": interpreter_args.function_name,
        "balances": balances,
        "events": events,
        "gas_used": execution_context.gas_used,
        "return": reg[0]
    });

    Ok(result_json)
}

// ✅ Fonction helper pour décoder les adresses depuis les registres
fn decode_address_from_register(reg_value: u64) -> String {
    if reg_value == 0 {
        return "*system*#default#".to_string();
    }
    
    if reg_value > 0x1000 {
        unsafe {
            let ptr = reg_value as *const u8;
            let mut bytes = Vec::new();
            let mut offset = 0;
            
            while offset < 64 {
                let byte = *ptr.add(offset);
                if byte == 0 { break; }
                bytes.push(byte);
                offset += 1;
            }
            
            if let Ok(addr) = String::from_utf8(bytes) {
                if is_valid_uip10_address(&addr) {
                    return addr;
                }
            }
        }
    }
    
    format!("*addr_{}*#generated#", reg_value)
}

/// ✅ Encodage d'adresse vers u64
fn encode_address_to_u64(addr: &str) -> u64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    
    let mut hasher = DefaultHasher::new();
    addr.hash(&mut hasher);
    hasher.finish()
}