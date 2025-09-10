use std::sync::Arc;
use log::error;
use serde::{Serialize, Deserialize};
use base64::{self, Engine};

use vuc_types::tx_op::TxOpPart;
use vuc_storage::storing_access::RocksDBManager;
use crate::ultrachain_vm::UltrachainVm;
use serde_json::Value;

//___ Field structure for ultrachain transactions
pub struct HookOp {
    pub refresh_solde: fn(&str, i64) -> Result<(), Box<dyn std::error::Error>>,
    pub agent: fn(TxOpPart) -> Result<(), Box<dyn std::error::Error>>,
    pub fetch_solde: fn(&str) -> Result<i64, Box<dyn std::error::Error>>,
    pub sender: String
    }

impl Default for HookOp {
    fn default() -> Self {
        Self {
            refresh_solde: |_, _| Ok(()),
            agent: |_| Ok(()),
            fetch_solde: |_| Ok(0),
            sender: "default_sender".to_string(),
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub enum ValueTx {
    Str(String),
    Num(u64),
    Bool(bool),
    VecU8(Vec<u8>),
    List(Vec<ValueTx>),
}

impl ValueTx {
    pub fn is_value_empty(&self) -> bool {
        match self {
            ValueTx::Str(s) => s.is_empty(),
            ValueTx::Num(n) => *n == 0,
            ValueTx::Bool(b) => !*b,
            ValueTx::VecU8(v) => v.is_empty(),
            ValueTx::List(l) => l.is_empty(),
        }
    }
}

impl Default for ValueTx {
    fn default() -> Self {
        ValueTx::Str(String::new())
    }
}

#[derive(Serialize, Clone, Default)]
pub struct UltrachainTx {
    pub from_op: String,
    pub receiver_op: String,
    pub fees_tx: u64,
    pub value_tx: ValueTx,
    pub arguments: Vec<Value>,
    pub nonce_tx: u64,
    pub hash_tx: String,
    pub func_tx: String,
}

//___ Field structure for ultrachain transactions

impl UltrachainTx {
    pub async fn functiontx_impl(
        &self,
        vm: &mut UltrachainVm,
        consensus: HookOp,
        db_manager: Arc<dyn RocksDBManager>,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let _ = consensus;

        println!("[UltrachainTx] func_tx reçu : '{}'", self.func_tx);

        if self.func_tx.is_empty() {
            return Err("Erreur : Aucune fonction spécifiée dans func_tx.".into());
        }

        let parts: Vec<&str> = self.func_tx.split("::").collect();
        if parts.len() != 3 {
            return Err(
                "Erreur : Format de la fonction Nerena invalide. Utilisez 'module_address::module_name::function_name'."
                    .into(),
            );
        }

        let module_address = parts[0];
        let module_name = parts[1];
        let function_name = parts[2];

        println!(
            "Exécution de la fonction dynamique : {}::{}::{}",
            module_address, module_name, function_name
        );

        // Vérifier si le module et la fonction existent
        vm.verify_module_and_function(&format!("{}::{}", module_address, module_name), function_name)?;

        // Exécution de la fonction
        let result = vm
            .execute_module(
                &format!("{}::{}", module_address, module_name),
                vec![function_name.to_string()],
                self.arguments.clone(),
            );
        match result {
            Ok(response) => {
                println!(
                    "La fonction Nerena '{}' a été exécutée avec succès : {:?}",
                    function_name, response
                );
                Ok(format!("{{ {} }}", response))
            }
            Err(e) => {
                error!(
                    "Erreur lors de l'exécution de la fonction Nerena '{}': {}",
                    function_name, e
                );
                Err(format!("Erreur Nerena : {}", e).into())
            }
        }
    }
}