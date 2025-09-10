use anyhow::Result;
use goblin::elf::Elf;
use hashbrown::{HashMap as HbHashMap, HashSet as HbHashSet};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::ops::Range;
use std::sync::{Arc, RwLock};

pub type NerenaValue = serde_json::Value;

#[derive(Clone)]
pub struct Module {
    pub name: String,
    pub address: String,
    pub bytecode: Vec<u8>,
    pub elf_buffer: Vec<u8>,
    pub context: uvm_runtime::UbfContext,
    pub stack_usage: Option<uvm_runtime::stack::StackUsage>, // Ajoute ce champ
}

#[derive(Clone, Debug)]
pub struct AccountState {
    pub address: String,
    pub balance: u64,
    pub resources: BTreeMap<String, serde_json::Value>,
}

#[derive(Default)]
pub struct VmState {
    pub accounts: Arc<RwLock<BTreeMap<String, AccountState>>>,
}

pub struct UltrachainVm {
    pub state: VmState,
    pub modules: BTreeMap<String, Module>, // clé: nom logique du module
    pub address_map: BTreeMap<String, String>, // clé: nom logique, valeur: adresse publique
}

impl UltrachainVm {
    pub fn new() -> Self {
        UltrachainVm {
            state: VmState::default(),
            modules: BTreeMap::new(),
            address_map: BTreeMap::new(),
        }
    }

    /// ____Charge tous les modules ELF ulBF et les enregistre avec leur adresse
    pub fn initialize_all_modules(&mut self, so_dir: &str) -> Result<(), String> {
        for entry in std::fs::read_dir(so_dir).map_err(|e| e.to_string())? {
            let entry = entry.map_err(|e| e.to_string())?;
            let path = entry.path();
            if !path.extension().map_or(false, |ext| ext == "so") {
                continue;
            }
            let file_content = fs::read(&path).map_err(|e| format!("Erreur lecture ELF '{}': {}", path.display(), e))?;
            let ctx = uvm_runtime::EbpfVmMbuff::load_ubf_context(&file_content)?;
            // Extraction de l'adresse depuis .ubf_meta
            let meta_str = String::from_utf8_lossy(&ctx.meta);
            let address = meta_str
                .lines()
                .find_map(|line| line.strip_prefix("address="))
                .ok_or("Adresse non trouvée dans .ubf_meta")?
                .trim()
                .to_string();

            // Extraction du nom du module (optionnel)
            let module_name = meta_str
                .lines()
                .find_map(|line| line.strip_prefix("module="))
                .unwrap_or("unknown")
                .trim()
                .to_string();

            // Extraction du bytecode (section .text)
            let elf = Elf::parse(&file_content).map_err(|e| e.to_string())?;
            let text_section = elf.section_headers.iter()
                .find(|sh| elf.shdr_strtab.get(sh.sh_name).expect("REASON").ok().map(|s| s == ".text").unwrap_or(false))
                .ok_or("Section .text non trouvée")?;
            let mut bytecode = file_content[text_section.sh_offset as usize
                ..text_section.sh_offset as usize + text_section.sh_size as usize].to_vec();

            // Vérification d'alignement du bytecode sur 8 octets
            if bytecode.len() % 8 != 0 {
                return Err(format!(
                    "Bytecode du module '{}' non aligné (taille = {}, attendu multiple de 8)",
                    module_name, bytecode.len()
                ));
            }

            // Enregistrement dans la VM
            let stack_usage = {
                let mut verifier = uvm_runtime::stack::StackVerifier::default();
                verifier.stack_validate(&bytecode).ok()
            };
            self.modules.insert(module_name.clone(), Module {
                name: module_name.clone(),
                address: address.clone(),
                bytecode,
                elf_buffer: file_content.clone(),
                context: ctx,
                stack_usage,
            });
            self.address_map.insert(module_name, address);
        }
        Ok(())
    }

    /// Résout un module à partir de son nom ou de son adresse
    pub fn resolve_module(&self, key: &str) -> Option<&Module> {
        let parts: Vec<&str> = key.split("::").collect();

        // Cas chemin complet : adresse::module::fonction
        if parts.len() >= 2 {
            let module_name = parts[1];
            if let Some(module) = self.modules.get(module_name) {
                return Some(module);
            }
        }

        // Cas chemin partiel : adresse::module
        if parts.len() == 2 {
            let module_name = parts[1];
            if let Some(module) = self.modules.get(module_name) {
                return Some(module);
            }
        }

        // Cas nom logique seul
        if let Some(module) = self.modules.get(key) {
            return Some(module);
        }

        // Cas recherche par adresse publique
        if let Some(addr) = parts.get(0) {
            for module in self.modules.values() {
                if &module.address == addr {
                    return Some(module);
                }
            }
        }

        None
    }

    /// Extrait les fonctions disponibles dans un module ELF
    pub fn extract_functions(&self, module_name: &str) -> Result<Vec<String>, String> {
        let module = self.resolve_module(module_name)
            .ok_or_else(|| format!("Module '{}' non trouvé", module_name))?;

        let meta_str = String::from_utf8_lossy(&module.context.meta);
        let mut functions = Vec::new();
        for line in meta_str.lines() {
            if let Some(rest) = line.strip_prefix("fn_") {
                if let Some(fname) = rest.strip_suffix("=1") {
                    functions.push(fname.to_string());
                }
            }
        }
        Ok(functions)
    }

    /// Vérifie si un module et une fonction existent dans le bytecode ELF
    pub fn verify_module_and_function(
        &self,
        module_name: &str,
        function_name: &str,
    ) -> Result<(), String> {
        let functions = self.extract_functions(module_name)?;
        if !functions.contains(&function_name.to_string()) {
            return Err(format!(
                "Erreur : Fonction '{}' non trouvée dans le module '{}'. Fonctions disponibles : {:?}",
                function_name, module_name, functions
            ));
        }
        Ok(())
    }

    /// Exécute dynamiquement une fonction d'un module ELF    
    pub fn execute_module(
        &self,
        module_name: &str,
        function_names: Vec<String>,
        args: Vec<NerenaValue>,
    ) -> Result<NerenaValue, String> {
        let function_name = function_names.get(0)
            .ok_or("Aucune fonction spécifiée")?;
        let module = self.resolve_module(module_name)
            .ok_or_else(|| format!("Module '{}' non trouvé", module_name))?;
    
        // Vérifie que la fonction existe
        self.verify_module_and_function(module_name, function_name)?;
    
        // Récupère l'offset de la fonction dans le bytecode
        let offset = self.get_function_offset(module_name, function_name)?;
    
        // Récupère la section .text du module
        let elf = Elf::parse(&module.elf_buffer).map_err(|e| e.to_string())?;
        let text_section = elf.section_headers.iter()
            .find(|sh| elf.shdr_strtab.get(sh.sh_name).expect("REASON").ok().map(|s| s == ".text").unwrap_or(false))
            .ok_or("Section .text non trouvée")?;
        let text_start = text_section.sh_offset as usize;
        let text_size = text_section.sh_size as usize;
        let bytecode = &module.elf_buffer[text_start..text_start + text_size];
    
        // Découpe le bytecode à partir de l'offset de la fonction
        if offset >= bytecode.len() {
            return Err(format!("Offset {} hors limites du bytecode (taille {})", offset, bytecode.len()));
        }
        let func_bytecode = &bytecode[offset..];
    
        // Prépare le buffer mémoire (mem) à passer au programme (exemple : à partir des args)
        // Ici, on supporte jusqu'à 5 arguments u64 (r1 à r5) pour eBPF
        let mut mem = vec![];
        let mut reg_args = [0u64; 5];
        for (i, arg) in args.iter().take(5).enumerate() {
            reg_args[i] = match arg {
                serde_json::Value::Number(n) => n.as_u64().unwrap_or(0),
                serde_json::Value::String(s) => s.parse::<u64>().unwrap_or(0),
                serde_json::Value::Array(arr) => {
                    // Si tableau, on copie dans mem et on passe le pointeur
                    mem.clear();
                    for v in arr {
                        if let Some(b) = v.as_u64() {
                            mem.extend_from_slice(&b.to_le_bytes());
                        }
                    }
                    mem.as_ptr() as u64
                }
                _ => 0,
            };
        }
    
        // Prépare le buffer métadonnées (mbuff) si besoin (ici vide ou à adapter selon usage)
        let mbuff: Vec<u8> = vec![];
        let mem = vec![0u8; 4096]; // ou plus selon besoin
        if mem.is_empty() {
            return Err(std::io::Error::new(std::io::ErrorKind::Other, "Mémoire globale VM (mem) non allouée").to_string());
        }
        // Appelle directement l'interpréteur eBPF sur le bytecode de la fonction
        let stack_usage = module.stack_usage.as_ref().ok_or("Stack usage non initialisé pour ce module")?;
        let helpers: HbHashMap<u32, uvm_runtime::ebpf::Helper> = HbHashMap::new();
        let allowed_memory: HbHashSet<Range<u64>> = HbHashSet::new();

        // 1. Construction de la table des exports (hash -> offset)
        let mut exports: HashMap<u32, usize> = HashMap::new();

        let exports_hb: hashbrown::HashMap<u32, usize> = exports.clone().into_iter().collect();

        let meta_str = String::from_utf8_lossy(&module.context.meta);
        for line in meta_str.lines() {
            if let Some(rest) = line.strip_prefix("fn_") {
                // Ex: fn_insert_hash=0x74568380 offset=1234
                if let Some((name_hash, offset)) = rest.split_once("_hash=") {
                    let (hash_str, offset_part) = offset.split_once(" offset=").unwrap_or((offset, ""));
                    if let (Ok(hash), Ok(offset)) = (u32::from_str_radix(hash_str.trim_start_matches("0x"), 16), offset_part.trim().parse::<usize>()) {
                        exports.insert(hash, offset);
                    }
                }
                // Ou ex: fn_insert=1 hash=0x74568380 offset=1234
                else if let Some((name, rest2)) = rest.split_once("=") {
                    if let Some(hash_str) = rest2.split("hash=").nth(1).and_then(|s| s.split_whitespace().next()) {
                        if let Some(offset_str) = rest2.split("offset=").nth(1).and_then(|s| s.split_whitespace().next()) {
                            if let (Ok(hash), Ok(offset)) = (u32::from_str_radix(hash_str.trim_start_matches("0x"), 16), offset_str.trim().parse::<usize>()) {
                                exports.insert(hash, offset);
                            }
                        }
                    }
                }
            }
        }

        // 2. Passe exports à execute_program
        uvm_runtime::interpreter::execute_program(
            Some(func_bytecode),
            Some(stack_usage),
            &mem,
            &mbuff,
            &helpers,
            &allowed_memory,
            None,
            None,
            &exports_hb, // <-- Utilise la version hashbrown ici
        ).map_err(|e| format!("Erreur exécution bytecode: {}", e))
    }

    pub fn configure_fees(
        &mut self,
        signer: &str,
        fee_percentage: u64,
        fee_recipient: &str,
    ) -> Result<()> {
        let module_address = self.address_map.get("Frameline")
            .ok_or_else(|| anyhow::anyhow!("Adresse du module Frameline non trouvée"))?;
        let module_name = "fee_caption";
        let function_name = "initialize_fee_caption";
        let module_path = format!("{}::{}", module_address, module_name);

        let args = vec![
            serde_json::Value::String(signer.to_string()),
            serde_json::Value::Number(fee_percentage.into()),
            serde_json::Value::String(fee_recipient.to_string()),
        ];

        self.execute_module(
            &module_path,
            vec![function_name.to_string()],
            args,
        ).map_err(anyhow::Error::msg)?;

        Ok(())
    }

    pub fn configure_governance(
        &mut self,
        signer: &str,
        min_voting_power: u64,
        voting_duration_secs: u64,
    ) -> Result<()> {
        let module_address = self.address_map.get("Frameline")
            .ok_or_else(|| anyhow::anyhow!("Adresse du module Frameline non trouvée"))?;
        let module_name = "vez_std_gov";
        let function_name = "initialize_governance";
        let module_path = format!("{}::{}::{}", module_address, module_name, function_name);

        let args = vec![
            serde_json::Value::String(signer.to_string()),
            serde_json::Value::Number(min_voting_power.into()),
            serde_json::Value::Number(voting_duration_secs.into()),
        ];

        self.execute_module(
            &module_path,
            vec![function_name.to_string()],
            args,
        ).map_err(anyhow::Error::msg)?;

        Ok(())
    }

    pub fn print_functions(&self, module_name: &str) {
        match self.extract_functions(module_name) {
            Ok(funcs) => println!("Fonctions disponibles : {:?}", funcs),
            Err(e) => println!("Erreur : {}", e),
        }
    }

    pub fn get_function_offset(&self, module_name: &str, function_name: &str) -> Result<usize, String> {
        let module = self.resolve_module(module_name)
            .ok_or_else(|| format!("Module '{}' non trouvé", module_name))?;
        let meta_str = String::from_utf8_lossy(&module.context.meta);
        for line in meta_str.lines() {
            if let Some(rest) = line.strip_prefix(&format!("fn_{}_offset=", function_name)) {
                return rest.trim().parse::<usize>().map_err(|e| format!("Offset invalide: {}", e));
            }
        }
        Err(format!("Offset de la fonction '{}' non trouvé dans le module '{}'", function_name, module_name))
    }
}

/// Types natifs Nerena pour VM (interopérables avec les adresses string Nerena)
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Address(pub String);

impl Address {
    pub fn new(addr: &str) -> Self {
        Address(addr.to_string())
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Signer {
    pub address: Address,
}

impl Signer {
    pub fn new(addr: &str) -> Self {
        Signer { address: Address::new(addr) }
    }
    pub fn address(&self) -> &Address {
        &self.address
    }
}