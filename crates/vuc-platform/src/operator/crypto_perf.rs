use std::collections::BTreeMap;
use fastcrypto::ed25519::Ed25519KeyPair;
use sha3::{Digest, Sha3_256};
use hex;
use fastcrypto::traits::KeyPair;
use rand::{Rng, distributions::Alphanumeric};
use vuc_tx::ultrachain_vm::{AccountState, UltrachainVm};

/// Génère une adresse UIP-10 flexible avec des branches dynamiques
pub fn generate_uip10_address(contract_info: &str, num_branches: usize) -> String {
    // 1. Branche principale : hash du contrat Rust (nom/module/etc)
    let mut hasher = Sha3_256::new();
    hasher.update(contract_info.as_bytes());
    let branch = &hex::encode(&hasher.finalize_reset())[0..7];

    // 2. Génère des branches dynamiques séparées par #
    let mut rng = rand::thread_rng();
    let mut parts = vec![format!("*{}*", branch)];
    for _ in 0..num_branches {
        let len = rng.gen_range(5..=12);
        let part: String = (0..len).map(|_| rng.sample(Alphanumeric) as char).collect();
        parts.push(format!("#{}", part));
    }

    // 3. Clé de validité : hash de contrôle sur la concaténation précédente
    let mut hasher = Sha3_256::new();
    let pre_checksum = parts.join("");
    hasher.update(pre_checksum.as_bytes());
    let checksum = &hex::encode(&hasher.finalize())[0..3]; // 3 caractères

    // 4. Format final
    format!("{}#{}", pre_checksum, checksum)
}

// Exemple d'utilisation
pub async fn generate_and_create_account(vm: &mut UltrachainVm, contract_info: &str) -> Result<(String, String), anyhow::Error> {
    let keypair = Ed25519KeyPair::generate(&mut rand::thread_rng());
    let privkey_hex = hex::encode(keypair.private().0.to_bytes());

    // Génère l'adresse UIP-10 flexible
    let address_custom = generate_uip10_address(contract_info, 3);

    // Ajout dans le state VM
    {
        let mut state_guard = vm.state.accounts.write().unwrap();
        let accounts = &mut *state_guard;
        accounts.insert(
            address_custom.clone(),
            AccountState {
                address: address_custom.clone(),
                balance: 0,
                resources: BTreeMap::new(),
            },
        );
    }

    // Récupère l'adresse du module vezcur depuis la VM
    let vezcur_address = vm.address_map.get("vezcur")
        .ok_or_else(|| anyhow::anyhow!("Adresse du module vezcur non trouvée"))?;

    // Appel dynamique avec l'adresse réelle
    let module_path = format!("{}::vezcur::init_vez", vezcur_address);

    vm.execute_module(
        &module_path,
        vec!["init_vez".to_string()],
        vec![serde_json::Value::String(address_custom.clone())],
    ).map_err(anyhow::Error::msg)?;

    Ok((address_custom, privkey_hex))
}