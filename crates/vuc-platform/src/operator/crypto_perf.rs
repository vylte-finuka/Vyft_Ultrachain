use std::collections::BTreeMap;
use fastcrypto::ed25519::Ed25519KeyPair;
use hex;
 use sha3::Sha3_256;
use fastcrypto::traits::KeyPair;
use rand::{Rng, distributions::Alphanumeric};
use vuc_tx::slurachain_vm::{AccountState, SlurachainVm};
use k256::ecdsa::{SigningKey, VerifyingKey};
use k256::elliptic_curve::SecretKey;
use sha3::{Digest, Keccak256};

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
pub async fn generate_and_create_account(vm: &mut SlurachainVm, _contract_info: &str) -> Result<(String, String), anyhow::Error> {
    // 1. Génère une clé privée secp256k1
    let signing_key = SigningKey::random(&mut rand::thread_rng());
    let secret_key = signing_key.to_bytes();
    let privkey_hex = hex::encode(secret_key);

    // 2. Calcule la clé publique
    let verifying_key = VerifyingKey::from(&signing_key);
    let encoded_point = verifying_key.to_encoded_point(false);
    let pubkey_bytes = encoded_point.as_bytes(); // non compressé

    // 3. Calcule l'adresse Ethereum
    let mut hasher = Keccak256::new();
    hasher.update(&pubkey_bytes[1..]); // ignore le premier octet (format EC)
    let hash = hasher.finalize();
    let eth_address = format!("0x{}", hex::encode(&hash[12..])); // derniers 20 octets

    // 4. Ajoute le compte dans la VM
    {
        let mut state_guard = vm.state.accounts.write().unwrap();
        state_guard.insert(
            eth_address.clone(),
            AccountState {
                address: eth_address.clone(),
                balance: 0,
                resources: BTreeMap::new(),
                contract_state: Vec::new(),
                state_version: 0,
                last_block_number: 0,
                nonce: 0,
                code_hash: String::new(),
                storage_root: String::new(),
                is_contract: false,
                gas_used: 0,
            },
        );
    }

    // Initialisation du contrat VEZ si nécessaire
    let vezcur_address = vm.address_map.get("vezcur")
        .ok_or_else(|| anyhow::anyhow!("Adresse du module vezcur non trouvée"))?
        .clone();

    let vez_contract = vm.state.accounts.read().unwrap().get(&vezcur_address).cloned();
    let already_initialized = vez_contract
        .and_then(|acc| acc.resources.get("initialized").cloned())
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    if !already_initialized {
        // Appelle initialize avant le mint (si pas déjà fait)
        vm.execute_module(
            &vezcur_address,
            "initialize",
            vec![],
            Some("system")
        ).ok();
    }

    // Mint 10_000_000 VEZ pour le nouveau compte
    vm.execute_module(
        &vezcur_address,
        "mint",
        vec![serde_json::Value::String(eth_address.clone()), serde_json::Value::Number(10_000_000u64.into())],
        Some("system") // doit être owner !
    ).map_err(anyhow::Error::msg)?;

    Ok((eth_address, privkey_hex))
}

/// Mint des tokens VEZ pour le compte courant
pub async fn mint_act(vm: &mut SlurachainVm, value: u64, sender: &str) -> Result<(), anyhow::Error> {
    let vezcur_address = vm.address_map.get("vezcur")
        .ok_or_else(|| anyhow::anyhow!("Adresse du module vezcur non trouvée"))?
        .clone();
    vm.execute_module(
        &vezcur_address,
        "mint",
        vec![serde_json::Value::Number(value.into())],
        Some(sender)
    ).map_err(anyhow::Error::msg)?;
    Ok(())
}

/// Brûle des tokens VEZ pour le compte courant
pub async fn burn_act(vm: &mut SlurachainVm, value: u64, sender: &str) -> Result<(), anyhow::Error> {
    let vezcur_address = vm.address_map.get("vezcur")
        .ok_or_else(|| anyhow::anyhow!("Adresse du module vezcur non trouvée"))?
        .clone();
    vm.execute_module(
        &vezcur_address,
        "burn",
        vec![serde_json::Value::Number(value.into())],
        Some(sender)
    ).map_err(anyhow::Error::msg)?;
    Ok(())
}

/// Transfert des tokens VEZ à un autre compte
pub async fn deliver(vm: &mut SlurachainVm, to: &str, value: u64, sender: &str) -> Result<(), anyhow::Error> {
    let vezcur_address = vm.address_map.get("vezcur")
        .ok_or_else(|| anyhow::anyhow!("Adresse du module vezcur non trouvée"))?
        .clone();
    vm.execute_module(
        &vezcur_address,
        "transfer",
        vec![
            serde_json::Value::String(to.to_string()),
            serde_json::Value::Number(value.into())
        ],
        Some(sender)
    ).map_err(anyhow::Error::msg)?;
    Ok(())
}

/// Transfert des tokens VEZ depuis un compte autorisé
pub async fn deliver_from(vm: &mut SlurachainVm, from: &str, to: &str, value: u64, sender: &str) -> Result<(), anyhow::Error> {
    let vezcur_address = vm.address_map.get("vezcur")
        .ok_or_else(|| anyhow::anyhow!("Adresse du module vezcur non trouvée"))?
        .clone();
    vm.execute_module(
        &vezcur_address,
        "transferFrom",
        vec![
            serde_json::Value::String(from.to_string()),
            serde_json::Value::String(to.to_string()),
            serde_json::Value::Number(value.into())
        ],
        Some(sender)
    ).map_err(anyhow::Error::msg)?;
    Ok(())
}

/// Autorise un compte à utiliser VEZ
pub async fn allow(vm: &mut SlurachainVm, account: &str, sender: &str) -> Result<(), anyhow::Error> {
    let vezcur_address = vm.address_map.get("vezcur")
        .ok_or_else(|| anyhow::anyhow!("Adresse du module vezcur non trouvée"))?
        .clone();
    vm.execute_module(
        &vezcur_address,
        "unBlacklist",
        vec![serde_json::Value::String(account.to_string())],
        Some(sender)
    ).map_err(anyhow::Error::msg)?;
    Ok(())
}

/// Désautorise un compte
pub async fn disallow(vm: &mut SlurachainVm, account: &str, sender: &str) -> Result<(), anyhow::Error> {
    let vezcur_address = vm.address_map.get("vezcur")
        .ok_or_else(|| anyhow::anyhow!("Adresse du module vezcur non trouvée"))?
        .clone();
    vm.execute_module(
        &vezcur_address,
        "blacklist",
        vec![serde_json::Value::String(account.to_string())],
        Some(sender)
    ).map_err(anyhow::Error::msg)?;
    Ok(())
}

/// Vérifie le solde VEZ d'un compte
pub async fn solde_of(vm: &mut SlurachainVm, account: &str) -> Result<u64, anyhow::Error> {
    let vezcur_address = vm.address_map.get("vezcur")
        .ok_or_else(|| anyhow::anyhow!("Adresse du module vezcur non trouvée"))?
        .clone();
    let res = vm.execute_module(
        &vezcur_address,
        "balanceOf",
        vec![serde_json::Value::String(account.to_string())],
        Some("system")
    ).map_err(anyhow::Error::msg)?;
    match res {
        serde_json::Value::Number(n) => Ok(n.as_u64().unwrap_or(0)),
        _ => Ok(0),
    }
}