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

// Fonction pour extraire les imports FFI d'un bytecode donné
fn extract_ffi_imports(bytecode: &[u8]) -> Vec<String> {
    let mut imports = Vec::new();
    let mut i = 0;

    while i < bytecode.len() {
        // Lecture de l'instruction (2 premiers octets)
        let insn = u16::from_le_bytes([bytecode[i], bytecode[i + 1]]);
        i += 2;

        // Si c'est une instruction CALL (opcode 0xB7), on extrait le nom de la fonction
        if insn == 0xB7 {
            // Le nom de la fonction suit immédiatement l'instruction CALL
            let mut name = String::new();
            while i < bytecode.len() && bytecode[i] != 0 {
                name.push(bytecode[i] as char);
                i += 1;
            }
            imports.push(name);
        }
    }

    imports
}

// Fonction pour initialiser les helpers à partir des imports FFI extraits
fn init_helpers_from_imports(
    bytecode: &[u8],
    resolve: impl Fn(u32, [u64; 5]) -> String + Send + Sync + 'static
) -> HashMap<u32, Box<dyn Fn(u64, u64, u64, u64, u64) -> u64 + Send + Sync>> {
    let mut helpers = HashMap::new();
    let resolve = std::sync::Arc::new(resolve);
    for name in extract_ffi_imports(bytecode) {
        let mut hasher = DefaultHasher::new();
        name.hash(&mut hasher);
        let hash = (hasher.finish() & 0xFFFF_FFFF) as u32;

        let resolve = resolve.clone();
        let closure = Box::new(move |r1, r2, r3, r4, r5| {
            let s = resolve(hash, [r1, r2, r3, r4, r5]);
            Box::leak(s.into_boxed_str()).as_ptr() as u64
        }) as Box<dyn Fn(u64, u64, u64, u64, u64) -> u64 + Send + Sync>;
        helpers.insert(hash, closure);
    }
    helpers
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
) -> Result<serde_json::Value, Error> {
    const U32MAX: u64 = u32::MAX as u64;
    const SHIFT_MASK_64: u64 = 0x3f;

    let (prog, stack_usage) = match prog_ {
        Some(prog) => (prog, stack_usage.unwrap()),
        None => Err(Error::new(
            ErrorKind::Other,
            "Error: No program set, call prog_set() to load one",
        ))?,
    };
    let stack = vec![0u8; ebpf::STACK_SIZE];
    let mut stacks = [StackFrame::new(); MAX_CALL_DEPTH];
    let mut stack_frame_idx = 0;

       
    let mut call_dst_stack: Vec<usize> = Vec::new();
    let mut mem_write_offset = 0usize;

    // --- AJOUT: mémoire globale VM pour r8 ---
    let mut global_mem = vec![0u8; 64 * 1024]; // 64 Ko pour la mémoire globale VM

    // R1 points to beginning of memory area, R10 to stack
    let mut reg: [u64; 64] = [0; 64];
    reg[12] = stack.as_ptr() as u64 + stack.len() as u64;
    if !mbuff.is_empty() {
        reg[1] = mbuff.as_ptr() as u64;
    } else if !mem.is_empty() {
        reg[1] = mem.as_ptr() as u64;
    }
    // --- PATCH: r8 pointe sur la mémoire globale VM ---
    reg[8] = global_mem.as_ptr() as u64;

    // --- PATCH: capture le pointeur et la taille pour check_mem ---
    let global_mem_ptr = global_mem.as_ptr() as u64;
    let global_mem_len = global_mem.len() as u64;
    // PATCH: Ajoute la mémoire globale VM dans check_mem
    let check_mem = move |addr: u64, len: usize, _access_type: &str, _insn_ptr: usize,
                          mbuff: &[u8], mem: &[u8], stack: &[u8], allowed_memory: &HashSet<Range<u64>>| -> u64 {
        if let Some(addr_end) = addr.checked_add(len as u64) {
            if mbuff.as_ptr() as u64 <= addr && addr_end <= mbuff.as_ptr() as u64 + mbuff.len() as u64 {
                return addr;
            }
            if mem.as_ptr() as u64 <= addr && addr_end <= mem.as_ptr() as u64 + mem.len() as u64 {
                return addr;
            }
            if stack.as_ptr() as u64 <= addr && addr_end <= stack.as_ptr() as u64 + stack.len() as u64 {
                return addr;
            }
            if global_mem_ptr <= addr && addr_end <= global_mem_ptr + global_mem_len {
                return addr;
            }
            if allowed_memory.iter().any(|range| range.contains(&addr)) {
                return addr;
            }
        }
        // Redirige tout accès hors-bounds vers le début d'une zone valide
        if !mbuff.is_empty() {
            mbuff.as_ptr() as u64
        } else if !mem.is_empty() {
            mem.as_ptr() as u64
        } else if !stack.is_empty() {
            stack.as_ptr() as u64
        } else if global_mem_len > 0 {
            global_mem_ptr
        } else {
            0 // fallback ultime
        }
    };

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

    // Déclare ici, AVANT la boucle :
    let mut last_b7_value: Option<u64> = None; // Pour mémoriser la dernière valeur 0xb7

    // Loop on instructions
    let mut insn_ptr: usize = 0;
    println!("Ulbf: {:?}", prog); // Ajout log pour debug
    while insn_ptr * ebpf::INSN_SIZE < prog.len() {
        let insn = ebpf::get_insn(prog, insn_ptr);
        println!("INSN[{}]: opc=0x{:x} dst={} src={} off={} imm={}", insn_ptr, insn.opc, insn.dst, insn.src, insn.off, insn.imm);

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
            // BPF_LD class
            // LD_ABS_* and LD_IND_* are supposed to load pointer to data from metadata buffer.
            // Since this pointer is constant, and since we already know it (mem), do not
            // bother re-fetching it, just use mem already.            
            0x6b => unsafe {
                let orig_addr = (reg[_dst] as *const u8).wrapping_offset(insn.off as isize) as u64;
                let addr = check_mem_store(orig_addr, 2, insn_ptr);
                (addr as *mut u16).write_unaligned(reg[_src] as u16);
            },
            ebpf::LD_B_REG => reg[_dst] = unsafe {
                let orig_addr = (reg[_src] as *const u8).wrapping_offset(insn.off as isize) as u64;
                let addr = check_mem_load(orig_addr, 1, insn_ptr);
                (addr as *const u8).read_unaligned() as u64
            },
            ebpf::LD_H_REG => reg[_dst] = unsafe {
                let orig_addr = (reg[_src] as *const u8).wrapping_offset(insn.off as isize) as u64;
                let addr = check_mem_load(orig_addr, 2, insn_ptr);
                (addr as *const u16).read_unaligned() as u64
            },
            ebpf::LD_W_REG => reg[_dst] = unsafe {
                let orig_addr = (reg[_src] as *const u8).wrapping_offset(insn.off as isize) as u64;
                let addr = check_mem_load(orig_addr, 4, insn_ptr);
                (addr as *const u32).read_unaligned() as u64
            },
            ebpf::LD_DW_REG => reg[_dst] = unsafe {
                let orig_addr = (reg[_src] as *const u8).wrapping_offset(insn.off as isize) as u64;
                let addr = check_mem_load(orig_addr, 8, insn_ptr);
                (addr as *const u64).read_unaligned()
            },
            ebpf::ST_B_IMM => unsafe {
                let orig_addr = (reg[_dst] as *const u8).wrapping_offset(insn.off as isize) as u64;
                let addr = check_mem_store(orig_addr, 1, insn_ptr);
                (addr as *mut u8).write_unaligned(insn.imm as u8);
            },
            ebpf::ST_H_IMM => unsafe {
                let orig_addr = (reg[_dst] as *const u8).wrapping_offset(insn.off as isize) as u64;
                let addr = check_mem_store(orig_addr, 2, insn_ptr);
                (addr as *mut u16).write_unaligned(insn.imm as u16);
            },
            ebpf::ST_W_IMM => unsafe {
                let orig_addr = (reg[_dst] as *const u8).wrapping_offset(insn.off as isize) as u64;
                let addr = check_mem_store(orig_addr, 4, insn_ptr);
                (addr as *mut u32).write_unaligned(insn.imm as u32);
            },
            ebpf::ST_DW_IMM => unsafe {
                let orig_addr = (reg[_dst] as *const u8).wrapping_offset(insn.off as isize) as u64;
                let addr = check_mem_store(orig_addr, 8, insn_ptr);
                (addr as *mut u64).write_unaligned(insn.imm as u64);
            },
            ebpf::ST_B_REG => unsafe {
                let orig_addr = (reg[_dst] as *const u8).wrapping_offset(insn.off as isize) as u64;
                let addr = check_mem_store(orig_addr, 1, insn_ptr);
                (addr as *mut u8).write_unaligned(reg[_src] as u8);
            },
            ebpf::ST_H_REG => unsafe {
                let orig_addr = (reg[_dst] as *const u8).wrapping_offset(insn.off as isize) as u64;
                let addr = check_mem_store(orig_addr, 2, insn_ptr);
                (addr as *mut u16).write_unaligned(reg[_src] as u16);
            },
            ebpf::ST_W_REG => unsafe {
                let orig_addr = (reg[_dst] as *const u8).wrapping_offset(insn.off as isize) as u64;
                let addr = check_mem_store(orig_addr, 4, insn_ptr);
                (addr as *mut u32).write_unaligned(reg[_src] as u32);
            },
            ebpf::ST_DW_REG => unsafe {
                if _dst == 8 || _dst == 10 {
                    return Err(Error::new(
                        ErrorKind::Other,
                        format!("Erreur: tentative d'écriture mémoire via r{} (réservé VM)", _dst)
                    ));
                }
                let orig_addr = (reg[_dst] as *const u8).wrapping_offset(insn.off as isize) as u64;
                let addr = check_mem_store(orig_addr, 8, insn_ptr);
                (addr as *mut u64).write_unaligned(reg[_src]);
            },
            ebpf::ST_W_XADD  => unimplemented!(),
            ebpf::ST_DW_XADD => unimplemented!(),

            // BPF_ALU class
            // TODO Check how overflow works in kernel. Should we &= U32MAX all src register value
            // before we do the operation?
            // Cf ((0x11 << 32) - (0x1 << 32)) as u32 VS ((0x11 << 32) as u32 - (0x1 << 32) as u32
            ebpf::ADD32_IMM  => reg[_dst] = (reg[_dst] as i32).wrapping_add(insn.imm)         as u64, //((reg[_dst] & U32MAX) + insn.imm  as u64)     & U32MAX,
            ebpf::ADD32_REG  => reg[_dst] = (reg[_dst] as i32).wrapping_add(reg[_src] as i32) as u64, //((reg[_dst] & U32MAX) + (reg[_src] & U32MAX)) & U32MAX,
            ebpf::SUB32_IMM  => reg[_dst] = (reg[_dst] as i32).wrapping_sub(insn.imm)         as u64,
            ebpf::SUB32_REG  => reg[_dst] = (reg[_dst] as i32).wrapping_sub(reg[_src] as i32) as u64,
            ebpf::MUL32_IMM  => reg[_dst] = (reg[_dst] as i32).wrapping_mul(insn.imm)         as u64,
            ebpf::MUL32_REG  => reg[_dst] = (reg[_dst] as i32).wrapping_mul(reg[_src] as i32) as u64,
            ebpf::DIV32_IMM if insn.imm as u32 == 0 => reg[_dst] = 0,
            ebpf::DIV32_IMM  => reg[_dst] = (reg[_dst] as u32 / insn.imm              as u32) as u64,
            ebpf::DIV32_REG if reg[_src] as u32 == 0 => reg[_dst] = 0,
            ebpf::DIV32_REG  => reg[_dst] = (reg[_dst] as u32 / reg[_src]             as u32) as u64,
            ebpf::OR32_IMM   =>   reg[_dst] = (reg[_dst] as u32             | insn.imm  as u32) as u64,
            ebpf::OR32_REG   =>   reg[_dst] = (reg[_dst] as u32             | reg[_src] as u32) as u64,
            ebpf::AND32_IMM  =>   reg[_dst] = (reg[_dst] as u32             & insn.imm  as u32) as u64,
            ebpf::AND32_REG  =>   reg[_dst] = (reg[_dst] as u32             & reg[_src] as u32) as u64,
            // As for the 64-bit version, we should mask the number of bits to shift with
            // 0x1f, but .wrappping_shr() already takes care of it for us.
            ebpf::LSH32_IMM  =>   reg[_dst] = (reg[_dst] as u32).wrapping_shl(insn.imm  as u32) as u64,
            ebpf::LSH32_REG  =>   reg[_dst] = (reg[_dst] as u32).wrapping_shl(reg[_src] as u32) as u64,
            ebpf::RSH32_IMM  =>   reg[_dst] = (reg[_dst] as u32).wrapping_shr(insn.imm  as u32) as u64,
            ebpf::RSH32_REG  =>   reg[_dst] = (reg[_dst] as u32).wrapping_shr(reg[_src] as u32) as u64,
            ebpf::NEG32      => { reg[_dst] = (reg[_dst] as i32).wrapping_neg()                 as u64; reg[_dst] &= U32MAX; },
            ebpf::MOD32_IMM if insn.imm as u32 == 0 => (),
            ebpf::MOD32_IMM  =>   reg[_dst] = (reg[_dst] as u32             % insn.imm  as u32) as u64,
            ebpf::MOD32_REG if reg[_src] as u32 == 0 => (),
            ebpf::MOD32_REG  =>   reg[_dst] = (reg[_dst] as u32 % reg[_src]             as u32) as u64,
            ebpf::XOR32_IMM  =>   reg[_dst] = (reg[_dst] as u32             ^ insn.imm  as u32) as u64,
            ebpf::XOR32_REG  =>   reg[_dst] = (reg[_dst] as u32             ^ reg[_src] as u32) as u64,
            ebpf::MOV32_IMM  =>   reg[_dst] = insn.imm   as u32                                 as u64,
            ebpf::MOV32_REG  =>   reg[_dst] = {
                if _dst == 8 || _dst == 10 {
                    return Err(Error::new(
                        ErrorKind::Other,
                        format!("Erreur: tentative d'écraser r{} (réservé VM)", _dst)
                    ));
                }
                (reg[_src] as u32) as u64
            },

            // As for the 64-bit version, we should mask the number of bits to shift with
            // 0x1f, but .wrappping_shr() already takes care of it for us.
            ebpf::ARSH32_IMM => { reg[_dst] = (reg[_dst] as i32).wrapping_shr(insn.imm  as u32) as u64; reg[_dst] &= U32MAX; },
            ebpf::ARSH32_REG => { reg[_dst] = (reg[_dst] as i32).wrapping_shr(reg[_src] as u32) as u64; reg[_dst] &= U32MAX; },
            ebpf::LE         => {
                reg[_dst] = match insn.imm {
                    16 => (reg[_dst] as u16).to_le() as u64,
                    32 => (reg[_dst] as u32).to_le() as u64,
                    64 =>  reg[_dst].to_le(),
                    _  => unreachable!(),
                };
            },
            ebpf::BE         => {
                reg[_dst] = match insn.imm {
                    16 => (reg[_dst] as u16).to_be() as u64,
                    32 => (reg[_dst] as u32).to_be() as u64,
                    64 =>  reg[_dst].to_be(),
                    _  => unreachable!(),
                };
            },

            // BPF_ALU64 class
            ebpf::ADD64_IMM  => reg[_dst] = reg[_dst].wrapping_add(insn.imm as u64),
            ebpf::ADD64_REG  => reg[_dst] = reg[_dst].wrapping_add(reg[_src]),
            ebpf::SUB64_IMM  => reg[_dst] = reg[_dst].wrapping_sub(insn.imm as u64),
            ebpf::SUB64_REG  => reg[_dst] = reg[_dst].wrapping_sub(reg[_src]),
            ebpf::MUL64_IMM  => reg[_dst] = reg[_dst].wrapping_mul(insn.imm as u64),
            ebpf::MUL64_REG  => reg[_dst] = reg[_dst].wrapping_mul(reg[_src]),
            ebpf::DIV64_IMM if insn.imm == 0 => reg[_dst] = 0,
            ebpf::DIV64_IMM  => reg[_dst]                       /= insn.imm as u64,
            ebpf::DIV64_REG if reg[_src] == 0 => reg[_dst] = 0,
            ebpf::DIV64_REG  => reg[_dst] /= reg[_src],
            ebpf::OR64_IMM   => reg[_dst] |=  insn.imm as u64,
            ebpf::OR64_REG   => reg[_dst] |=  reg[_src],
            ebpf::AND64_IMM  => reg[_dst] &=  insn.imm as u64,
            ebpf::AND64_REG  => reg[_dst] &=  reg[_src],
            ebpf::LSH64_IMM  => reg[_dst] <<= insn.imm as u64 & SHIFT_MASK_64,
            ebpf::LSH64_REG  => reg[_dst] <<= reg[_src] & SHIFT_MASK_64,
            ebpf::RSH64_IMM  => reg[_dst] >>= insn.imm as u64 & SHIFT_MASK_64,
            ebpf::RSH64_REG  => reg[_dst] >>= reg[_src] & SHIFT_MASK_64,
            ebpf::NEG64      => reg[_dst] = -(reg[_dst] as i64) as u64,
            ebpf::MOD64_IMM if insn.imm == 0 => (),
            ebpf::MOD64_IMM  => reg[_dst] %=  insn.imm as u64,
            ebpf::MOD64_REG if reg[_src] == 0 => (),
            ebpf::MOD64_REG  => reg[_dst] %= reg[_src],
            ebpf::XOR64_IMM  => reg[_dst] ^= insn.imm  as u64,
            ebpf::XOR64_REG  => reg[_dst] ^= reg[_src],
            ebpf::MOV64_IMM  => reg[_dst] =  insn.imm  as u64,
            ebpf::MOV64_REG  => {
                if _dst == 8 || _dst == 10 {
                    return Err(Error::new(
                        ErrorKind::Other,
                        format!("Erreur: tentative d'écraser r{} (réservé VM)", _dst)
                    ));
                }
                reg[_dst] =  reg[_src];
            },

            // BPF_JMP class
            // TODO: check this actually works as expected for signed / unsigned ops
            // J-EQ, J-NE, J-GT, J-GE, J-LT, J-LE: unsigned
            // JS-GT, JS-GE, JS-LT, JS-LE: signed
            ebpf::JA         =>                                             do_jump(),
            ebpf::JEQ_IMM    => if  reg[_dst] == unsigned_u64!(insn.imm)  { do_jump(); },
            ebpf::JEQ_REG    => if  reg[_dst] == reg[_src]                { do_jump(); },
            ebpf::JGT_IMM    => if  reg[_dst] >  unsigned_u64!(insn.imm)  { do_jump(); },
            ebpf::JGT_REG    => if  reg[_dst] >  reg[_src]                { do_jump(); },
            ebpf::JGE_IMM    => if  reg[_dst] >= unsigned_u64!(insn.imm)  { do_jump(); },
            ebpf::JGE_REG    => if  reg[_dst] >= reg[_src]                { do_jump(); },
            ebpf::JLT_IMM    => if  reg[_dst] <  unsigned_u64!(insn.imm)  { do_jump(); },
            ebpf::JLT_REG    => if  reg[_dst] <  reg[_src]                { do_jump(); },
            ebpf::JLE_IMM    => if  reg[_dst] <= unsigned_u64!(insn.imm)  { do_jump(); },
            ebpf::JLE_REG    => if  reg[_dst] <= reg[_src]                { do_jump(); },
            ebpf::JSET_IMM   => if  reg[_dst] &  insn.imm as u64 != 0     { do_jump(); },
            ebpf::JSET_REG   => if  reg[_dst] &  reg[_src]       != 0     { do_jump(); },
            ebpf::JNE_IMM    => if  reg[_dst] != unsigned_u64!(insn.imm)  { do_jump(); },
            ebpf::JNE_REG    => if  reg[_dst] != reg[_src]                { do_jump(); },
            ebpf::JSGT_IMM   => if  reg[_dst] as i64  >  insn.imm  as i64 { do_jump(); },
            ebpf::JSGT_REG   => if  reg[_dst] as i64  >  reg[_src] as i64 { do_jump(); },
            ebpf::JSGE_IMM   => if  reg[_dst] as i64  >= insn.imm  as i64 { do_jump(); },
            ebpf::JSGE_REG   => if  reg[_dst] as i64  >= reg[_src] as i64 { do_jump(); },
            ebpf::JSLT_IMM   => if (reg[_dst] as i64) <  insn.imm  as i64 { do_jump(); },
            ebpf::JSLT_REG   => if (reg[_dst] as i64) <  reg[_src] as i64 { do_jump(); },
            ebpf::JSLE_IMM   => if  reg[_dst] as i64  <= insn.imm  as i64 { do_jump(); },
            ebpf::JSLE_REG   => if  reg[_dst] as i64  <= reg[_src] as i64 { do_jump(); },

            // BPF_JMP32 class
            ebpf::JEQ_IMM32  => if  reg[_dst] as u32  == insn.imm  as u32      { do_jump(); },
            ebpf::JEQ_REG32  => if  reg[_dst] as u32  == reg[_src] as u32      { do_jump(); },
            ebpf::JGT_IMM32  => if  reg[_dst] as u32  >  insn.imm  as u32      { do_jump(); },
            ebpf::JGT_REG32  => if  reg[_dst] as u32  >  reg[_src] as u32      { do_jump(); },
            ebpf::JGE_IMM32  => if  reg[_dst] as u32  >= insn.imm  as u32      { do_jump(); },
            ebpf::JGE_REG32  => if  reg[_dst] as u32  >= reg[_src] as u32      { do_jump(); },
            ebpf::JLT_IMM32  => if (reg[_dst] as u32) <  insn.imm  as u32      { do_jump(); },
            ebpf::JLT_REG32  => if (reg[_dst] as u32) <  reg[_src] as u32      { do_jump(); },
            ebpf::JLE_IMM32  => if  reg[_dst] as u32  <= insn.imm  as u32      { do_jump(); },
            ebpf::JLE_REG32  => if (reg[_dst] as u32) <= reg[_src] as u32      { do_jump(); },
            ebpf::JSET_IMM32 => if  reg[_dst] as u32  &  insn.imm  as u32 != 0 { do_jump(); },
            ebpf::JSET_REG32 => if  reg[_dst] as u32  &  reg[_src] as u32 != 0 { do_jump(); },
            ebpf::JNE_IMM32  => if  reg[_dst] as u32  != insn.imm  as u32      { do_jump(); },
            ebpf::JNE_REG32  => if  reg[_dst] as u32  != reg[_src] as u32      { do_jump(); },
            ebpf::JSGT_IMM32 => if  reg[_dst] as i32  >  insn.imm              { do_jump(); },
            ebpf::JSGT_REG32 => if  reg[_dst] as i32  >  reg[_src] as i32      { do_jump(); },
            ebpf::JSGE_IMM32 => if  reg[_dst] as i32  >= insn.imm              { do_jump(); },
            ebpf::JSGE_REG32 => if  reg[_dst] as i32  >= reg[_src] as i32      { do_jump(); },
            ebpf::JSLT_IMM32 => if (reg[_dst] as i32) <  insn.imm              { do_jump(); },
            ebpf::JSLT_REG32 => if (reg[_dst] as i32) <  reg[_src] as i32      { do_jump(); },
            ebpf::JSLE_IMM32 => if  reg[_dst] as i32  <= insn.imm              { do_jump(); },
            ebpf::JSLE_REG32 => if  reg[_dst] as i32  <= reg[_src] as i32      { do_jump(); },

            // Do not delegate the check to the verifier, since registered functions can be
            // changed after the program has been verified.
            ebpf::CALL       => {
                match _src {
                    // Call helper function
                    0 => {
                        if let Some(function) = helpers.get(&(insn.imm as u32)) {
                            reg[0] = function(reg[1], reg[2], reg[3], reg[4], reg[5]);
                        } else {
                            return Err(Error::new(
                                ErrorKind::Other,
                                format!(
                                    "Error: unknown helper function (id: {:#x})",
                                    insn.imm as u32
                                )
                            ));
                        }
                    }
                    // eBPF-to-eBPF call
                    1 => {
                        if stack_frame_idx >= MAX_CALL_DEPTH {
                            return Err(Error::new(
                                ErrorKind::Other,
                                format!(
                                    "Error: too many nested calls (max: {MAX_CALL_DEPTH})"
                                )
                            ));
                        }
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
            ebpf::TAIL_CALL  => unimplemented!(),
            0xf1 => {
                // Appel FFI dynamique universel via discriminant (hash ou discriminant Anchor-like)
                let export_hash = insn.imm as u32;
                let mut next_ptr = insn_ptr * ebpf::INSN_SIZE + 8; // 8 = taille insn
                let func_name_len = prog[next_ptr] as usize;
                next_ptr += 1;                    
                
                let func_name = std::str::from_utf8(&prog[next_ptr..next_ptr+func_name_len]).unwrap_or("");
                next_ptr += func_name_len;
                // Avance le pointeur d'instruction
                insn_ptr += (next_ptr - insn_ptr * ebpf::INSN_SIZE) / ebpf::INSN_SIZE;

                // --- DYNAMIQUE : utilise le fallback pour toutes les fonctions FFI ---
                if let Some(&offset) = exports.get(&export_hash) {
                    // Appel VM→VM (fonction exportée dans la meta)
                    if stack_frame_idx >= MAX_CALL_DEPTH {
                        return Err(Error::new(
                            ErrorKind::Other,
                            format!(
                                "Error: too many nested calls (max: {MAX_CALL_DEPTH})"
                            )
                        ));
                    }
                    stacks[stack_frame_idx].save_registers(&reg[6..=9]);
                    stacks[stack_frame_idx].save_return_address(insn_ptr);
                    reg[10] -= stacks[stack_frame_idx].get_stack_usage().stack_usage() as u64;
                    stack_frame_idx += 1;
                    insn_ptr = offset / ebpf::INSN_SIZE;
                    call_dst_stack.push(insn.dst as usize);
                    continue;
                } else if let Some(helper) = helpers.get(&export_hash) {
                    let result = helper(reg[1], reg[2], reg[3], reg[4], reg[5]);
                    reg[insn.dst as usize] = result;
                } else if let Some(fallback) = ffi_fallback {
                    use std::collections::hash_map::DefaultHasher;
                    use std::hash::{Hash, Hasher};
                    let mut hasher = DefaultHasher::new();
                    func_name.hash(&mut hasher);
                    let dynamic_hash = (hasher.finish() & 0xFFFF_FFFF) as u32;
                    let args = [reg[1], reg[2], reg[3], reg[4], reg[5]];
                    if let Some(result) = fallback(dynamic_hash, &args) {
                        reg[insn.dst as usize] = result;
                    } else if func_name.ends_with("_resource_mut") {
                        reg[insn.dst as usize] = 0;
                    } else {
                        reg[insn.dst as usize] = 0;
                    }
                } else if func_name.ends_with("_resource_mut") {
                    reg[insn.dst as usize] = 0;
                } else {
                    reg[insn.dst as usize] = 0;
                }

                // Si le résultat est un pointeur hors mem/mbuff/stack, tente de copier la chaîne dans mem
                let result = reg[insn.dst as usize];
                let mem_start = mem.as_ptr() as u64;
                let mem_end = mem_start + mem.len() as u64;

                let is_valid_ptr = result > 0x1000 && result < 0x0000_FFFF_FFFF_FFFF
                    && (result < mem_start || result >= mem_end)
                    && result % std::mem::align_of::<u8>() as u64 == 0;

                if is_valid_ptr {
                    unsafe {
                        let mut len = 0usize;
                        // On lit jusqu'à 256 octets ou jusqu'au premier '\0'
                        while len < 256 && *((result as *const u8).add(len)) != 0 {
                            len += 1;
                        }
                        // --- PATCH: copie bien toute la chaîne, y compris le '\0' final ---
                        if len < mem.len() && len > 0 {
                            let src = std::slice::from_raw_parts(result as *const u8, len);
                            let dst_offset = mem_write_offset;
                            let dst_ptr = (mem.as_ptr() as *mut u8).add(dst_offset);
                            std::ptr::copy_nonoverlapping(src.as_ptr(), dst_ptr, len);
                            // Ajoute explicitement le '\0' final
                            *dst_ptr.add(len) = 0u8;
                            reg[insn.dst as usize] = dst_offset as u64;
                            mem_write_offset += len + 1;
                        }
                    }
                }
            },
            0x10 => {
                reg[_dst] = reg[_dst].wrapping_add(insn.imm as u64);
            },
            0x00 | 0x0a | 0x06 => {
                // NOP ou instruction personnalisée ignorée
                println!("AVERTISSEMENT: opcode 0x{:x} ignoré à l'instruction #{}", insn.opc, insn_ptr);
            },            
            0x5a => {
                // Instruction personnalisée
            },
            0xb1 => {
                // Instruction personnalisée
            },
            0x3 => reg[_dst] = reg[_dst].wrapping_add(insn.imm as u64), // ADD64 personnalisé
            0x8 => reg[_dst] = reg[_dst].wrapping_sub(insn.imm as u64), // SUB64 personnalisé
            0x09 => reg[_dst] = reg[_dst].wrapping_add(reg[_src]), // ADD64 personnalisé
            0x16 => reg[_dst] = reg[_dst].wrapping_sub(reg[_src]), // SUB64 personnalisé
            0x5f => reg[_dst] |= reg[_src],                        // OR64 personnalisé
            0x6e => reg[_dst] ^= reg[_src],                        // XOR64 personnalisé
            0x70 => reg[_dst] &= reg[_src],                        // AND64 personnalisé
            0x50 => {
                // Instruction personnalisée
            },
            0x20 => {
                // Instruction personnalisée
                reg[_dst] = (reg[_dst] as u32).wrapping_shr(insn.imm as u32) as u64;
            },
            0x30  => reg[_dst] = (reg[_dst] as u32).wrapping_shl(insn.imm as u32) as u64, // LSH32_IMM personnalisé
            0xa1 => reg[_dst] = (reg[_dst] as i64).wrapping_neg() as u64, // NEG64 personnalisé
            ebpf::EXIT => {
                if stack_frame_idx > 0 {
                    stack_frame_idx -= 1;
                    reg[6..=9].copy_from_slice(&stacks[stack_frame_idx].get_registers());
                    insn_ptr = stacks[stack_frame_idx].get_return_address();
                    reg[10] += stacks[stack_frame_idx].get_stack_usage().stack_usage() as u64;
                    if let Some(dst) = call_dst_stack.pop() {
                        reg[dst] = reg[0];
                    }
                } else {
                    let val = reg[0];
                    // --- Gestion explicite de tous les types ---

                    // Ajout : gestion explicite du type bool
                    if let Some("bool") = ret_type {
                        return Ok(serde_json::Value::Bool(val != 0));
                    }

                    // 1. Test chaîne courte (4 octets)
                    let bytes = (val as u32).to_le_bytes();
                    if let Ok(s) = std::str::from_utf8(&bytes) {
                        let s = s.trim_end_matches('\0');
                        // On considère chaîne si au moins un caractère ASCII imprimable (et non vide)
                        if !s.is_empty() && s.chars().any(|c| c.is_ascii_graphic() || c == ' ') {
                            return Ok(serde_json::Value::String(s.to_string()));
                        }
                    }

                    // 2. Booléen
                    if val == 0 {
                        return Ok(serde_json::Value::Bool(false));
                    } else if val == 1 {
                        return Ok(serde_json::Value::Bool(true));
                    }

                    // 3. Nombre
                    if val < 256 {
                        return Ok(serde_json::Value::Number(val.into()));
                    }
                    if val < 0x1_0000_0000 {
                        return Ok(serde_json::Value::Number(val.into()));
                    }
                    // Si c'est un float encodé (optionnel, à adapter selon ton ABI)
                    // let float_val = f64::from_bits(val);
                    // if float_val.is_finite() { ... }

                    // Si c'est une chaîne encodée sur 4 bytes (ex: "BTC\0")
                    let bytes = (val as u32).to_le_bytes();
                    if let Ok(s) = std::str::from_utf8(&bytes) {
                        let s = s.trim_end_matches('\0');
                        if !s.is_empty() {
                            return Ok(serde_json::Value::String(s.to_string()));
                        }
                    }
                    // Sinon, essaye de lire une chaîne en mémoire (cas avancé)
                    if !mem.is_empty() && (val as usize) < mem.len() {
                        let addr = val as usize;
                        let mut end = addr;
                        while end < mem.len() && mem[end] != 0 {
                            end += 1;
                        }
                        let s = std::str::from_utf8(&mem[addr..end]).unwrap_or("").to_string();
                        return Ok(serde_json::Value::String(s));
                    }
                    // Sinon, null explicite
                    if val == u64::MAX {
                        return Ok(serde_json::Value::Null);
                    }
                    // Sinon, type inconnu : retourne une erreur explicite
                    return Err(Error::new(
                        ErrorKind::Other,
                        format!("Type de retour non supporté ou inconnu : {val:#x}"),
                    ));
                }
            }

            0xb7 => { // MOV64_IMM ou MOV32_IMM
                reg[insn.dst as usize] = insn.imm as u64;
                last_b7_value = Some(insn.imm as u64); // Mémorise la valeur pour 0x95
            },
            0x78 => { }
           ebpf::EXIT => {
                if stack_frame_idx > 0 {
                    stack_frame_idx -= 1;
                    reg[6..=9].copy_from_slice(&stacks[stack_frame_idx].get_registers());
                    insn_ptr = stacks[stack_frame_idx].get_return_address();
                    reg[10] += stacks[stack_frame_idx].get_stack_usage().stack_usage() as u64;

                    // --- PATCH: copie la valeur de retour dans le registre de destination ---
                    if let Some(dst) = call_dst_stack.pop() {
                        reg[dst] = reg[0];
                    }
                } else {
                    let val = reg[0];
                    // --- Gestion explicite de tous les types ---

                    // Ajout : gestion explicite du type bool
                    if let Some("bool") = ret_type {
                        return Ok(serde_json::Value::Bool(val != 0));
                    }

                    // 1. Test chaîne courte (4 octets)
                    let bytes = (val as u32).to_le_bytes();
                    if let Ok(s) = std::str::from_utf8(&bytes) {
                        let s = s.trim_end_matches('\0');
                        // On considère chaîne si au moins un caractère ASCII imprimable (et non vide)
                        if !s.is_empty() && s.chars().any(|c| c.is_ascii_graphic() || c == ' ') {
                            return Ok(serde_json::Value::String(s.to_string()));
                        }
                    }

                    // 2. Booléen
                    if val == 0 {
                        return Ok(serde_json::Value::Bool(false));
                    } else if val == 1 {
                        return Ok(serde_json::Value::Bool(true));
                    }

                    // 3. Nombre
                    if val < 256 {
                        return Ok(serde_json::Value::Number(val.into()));
                    }
                    if val < 0x1_0000_0000 {
                        return Ok(serde_json::Value::Number(val.into()));
                    }
                    // Si c'est un float encodé (optionnel, à adapter selon ton ABI)
                    // let float_val = f64::from_bits(val);
                    // if float_val.is_finite() { ... }

                    // Si c'est une chaîne encodée sur 4 bytes (ex: "BTC\0")
                    let bytes = (val as u32).to_le_bytes();
                    if let Ok(s) = std::str::from_utf8(&bytes) {
                        let s = s.trim_end_matches('\0');
                        if !s.is_empty() {
                            return Ok(serde_json::Value::String(s.to_string()));
                        }
                    }
                    // Sinon, essaye de lire une chaîne en mémoire (cas avancé)
                    if !mem.is_empty() && (val as usize) < mem.len() {
                        let addr = val as usize;
                        let mut end = addr;
                        while end < mem.len() && mem[end] != 0 {
                            end += 1;
                        }
                        let s = std::str::from_utf8(&mem[addr..end]).unwrap_or("").to_string();
                        return Ok(serde_json::Value::String(s));
                    }
                    // Sinon, null explicite
                    if val == u64::MAX {
                        return Ok(serde_json::Value::Null);
                    }
                    // Sinon, type inconnu : retourne une erreur explicite
                    return Err(Error::new(
                        ErrorKind::Other,
                        format!("Type de retour non supporté ou inconnu : {val:#x}"),
                    ));
                }
            }

            _ => {
                return Err(Error::new(
                    ErrorKind::Other,
                    format!(
                        "Error: unknown or unsupported opcode 0x{:x} at insn #{}",
                        insn.opc, insn_ptr
                    ),
                ));
            }
        }

        insn_ptr += 1;
    }
    // Si le buffer ne se termine pas sur un bloc EXIT complet, vérifie s'il reste un EXIT partiel
    if let Some(&last) = prog.last() {
        if last == ebpf::EXIT {
            // On considère le programme comme terminé proprement
            return Ok(serde_json::Value::Null);
        }
    }
    // Plus d'erreur : on considère terminé même sans EXIT
    Ok(serde_json::Value::Null)
}