use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use rand::Rng;
use sha2::{Sha256, Digest};
use chrono::Utc;
use tracing::info;

use vuc_events::timestamp_release::TimestampRelease;
use vuc_events::time_warp::TimeWarp;
use vuc_types::committee::committee::EpochId;
use vuc_types::supported_protocol_versions::SupportedProtocolVersions;
use vuc_gov::slurachain_gov::slurachainGovernance;
use crate::service::slurachain_service::slurachainService;

pub struct LurosonieManager {
    pub epoch_id: EpochId,
    pub committee: Vec<String>,
    pub supported_protocol_versions: SupportedProtocolVersions,
    pub from_op: String,
    pub governance: slurachainGovernance,
    pub balances: Arc<RwLock<HashMap<String, u64>>>,
    pub time_warp: TimeWarp,
}

impl LurosonieManager {
    pub async fn lurosonie_protocole_impl(&self, block: &TimestampRelease) -> Result<(), String> {
        if !self.verify_block_creator(&block.vyfties_id) {
            return Err("Block creator identity verification failed.".to_string());
        }

        let timestamp_release = TimestampRelease {
            timestamp: Utc::now(),
            log: format!("Block processed successfully: {:?}.", block),
            block_number: block.block_number,
            vyfties_id: "vyft_id".to_string(),
        };

        info!("TimestampRelease: {} - Block Number: {}.", timestamp_release.timestamp, timestamp_release.block_number);

        Ok(())
    }

    pub async fn process_block(&self, block: TimestampRelease) -> Result<(), String> {
        if !self.verify_block_creator(&block.vyfties_id) {
            return Err("Block creator identity verification failed.".to_string());
        }

        let blocked: String = block.block_number.to_string();
        let clockfeed: &str = &block.timestamp.to_string();

        let validator_stake = self.get_validator_stake(&block.vyfties_id, blocked, clockfeed);
        if validator_stake < self.required_stake() {
            return Err("Validator does not have enough stake.".to_string());
        }

        let timestamp_release = TimestampRelease {
            timestamp: Utc::now(),
            log: format!("Block processed successfully: {:?}.", block),
            block_number: block.block_number,
            vyfties_id: "vyft_id".to_string(),
        };

        info!("TimestampRelease: {} - Block Number: {}", timestamp_release.timestamp, timestamp_release.block_number);

        Ok(())
    }

    pub async fn build_block(&self) -> Result<slurachainService, String> {
        let mut rng = rand::thread_rng();
        let nonce: u64 = rng.gen();

        let block = slurachainService {
            tx_op: Vec::new(), // Liste vide de transactions pour simplifier l'exemple
            nonce_tx: nonce,
            sign_op: String::new(),
            creator_id: self.from_op.clone(),
        };

        let mut hasher = Sha256::new();
        hasher.update(block.to_string().as_bytes());
        let _block_hash = hasher.finalize();

        // Ajoutez la logique pour diffuser le bloc aux autres nœuds

        Ok(block)
    }

    fn verify_block_creator(&self, creator_id: &str) -> bool {
        creator_id == self.from_op
    }

    fn required_stake(&self) -> u64 {
        500
    }

    fn get_validator_stake(&self, creator_id: &str, blocked: String, clockfeed: &str) -> u64 {
        100
    }

    pub async fn select_delegates(&self) -> Vec<String> {
        let mut delegates = Vec::new();
        let balances = self.balances.read().unwrap();
        for (account, balance) in balances.iter() {
            if *balance >= self.required_stake() {
                delegates.push(account.clone());
            }
        }
        delegates
    }

    pub async fn produce_block(&self) -> Result<(), String> {
        let _block = self.build_block().await?;
        info!("Block produced by Lurosonie consensus.");

        Ok(())
    }

    pub async fn start_time_warp(&'static self) {
        let mut rx = self.time_warp.sync_in_warp();
        tokio::spawn(async move {
            while let Some(timestamp_release) = rx.recv().await {
                match self.lurosonie_protocole_impl(&timestamp_release).await {
                    Ok(_) => info!("Block processed successfully."),
                    Err(e) => info!("Failed to process block: {}.", e),
                }
            }
        });
    }
}