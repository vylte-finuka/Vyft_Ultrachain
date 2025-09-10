use serde::{Deserialize, Serialize};
use vuc_tx::ultrachain_vm::UltrachainVm;

#[derive(Debug, Serialize, Deserialize)]
pub struct UltrachainGovernance {
    pub vez_stacking_locked: u64,
    pub vez_stacking_unlocked: u64,
    pub vez_stacking_totalvalue: u64,
    pub vez_stacking_allocated: u64,
    pub account_address: String,
}

impl Default for UltrachainGovernance {
    fn default() -> Self {
        UltrachainGovernance {
            vez_stacking_locked: 0,
            vez_stacking_unlocked: 0,
            vez_stacking_totalvalue: 0,
            vez_stacking_allocated: 0,
            account_address: String::new(),
        }
    }
}

impl UltrachainGovernance {
    pub async fn stake_vez(
        &mut self,
        vm: &mut UltrachainVm,
        amount: u64,
    ) -> Result<(), anyhow::Error> {
        let module_address = vm.address_map.get("vezcur")
            .ok_or_else(|| anyhow::anyhow!("Adresse du module vezcur non trouvée"))?;
        let module_path = format!("{}::vez_std_gov", module_address);
        let function_name = "stake";
        vm.execute_module(
            &module_path,
            vec![function_name.to_string()],
            vec![], // Ajoute ici les arguments si besoin
        ).map_err(anyhow::Error::msg)?;
        self.vez_stacking_locked += amount;
        self.vez_stacking_unlocked = self.vez_stacking_unlocked.saturating_sub(amount);
        Ok(())
    }

    pub async fn unstake_vez(
        &mut self,
        vm: &mut UltrachainVm,
        amount: u64,
    ) -> Result<(), anyhow::Error> {
        let module_address = vm.address_map.get("vezcur")
            .ok_or_else(|| anyhow::anyhow!("Adresse du module vezcur non trouvée"))?;
        let module_path = format!("{}::vez_std_gov", module_address);
        let function_name = "unstake";
        vm.execute_module(
            &module_path,
            vec![function_name.to_string()],
            vec![], // Ajoute ici les arguments si besoin
        ).map_err(anyhow::Error::msg)?;
        self.vez_stacking_locked = self.vez_stacking_locked.saturating_sub(amount);
        self.vez_stacking_unlocked += amount;
        Ok(())
    }

    pub async fn vote_proposal(
        &self,
        vm: &mut UltrachainVm,
        proposal_id: u64,
        support: bool,
        voting_power: u64,
    ) -> Result<(), anyhow::Error> {
        let module_address = vm.address_map.get("vezcur")
            .ok_or_else(|| anyhow::anyhow!("Adresse du module vezcur non trouvée"))?;
        let module_path = format!("{}::vez_std_gov", module_address);
        let function_name = "vote";
        vm.execute_module(
            &module_path,
            vec![function_name.to_string()],
            vec![], // Ajoute ici les arguments si besoin
        ).map_err(anyhow::Error::msg)?;
        Ok(())
    }

    pub fn get_locked_amount(&self) -> u64 {
        self.vez_stacking_locked
    }
}