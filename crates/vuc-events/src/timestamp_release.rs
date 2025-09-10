use std::fmt::Debug;
use chrono::{DateTime, Utc}; // Pour la manipulation des dates et heures
use serde::{Deserialize, Serialize}; // Pour la sérialisation et la désérialisation
use tokio::sync::mpsc; // Pour les canaux asynchrones
use tracing::info; // Pour les logs

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TimestampRelease {
    pub timestamp: DateTime<Utc>,
    pub log: String,
    pub block_number: u64,
    pub vyfties_id: String,
}

impl TimestampRelease {
    pub fn counter_moment(&self) -> () {
        const REFRESH_PER_SECONDE: u64 = 30;
        let mut clock = tokio::time::interval(std::time::Duration::from_secs(REFRESH_PER_SECONDE));
        let (tx, rx) = mpsc::channel(1);
        let mut block_number = self.block_number;

        tokio::spawn(async move {
            loop {
                clock.tick().await;
                block_number += 1;
                let new_release = TimestampRelease {
                    timestamp: Utc::now(),
                    log: format!("New block created: {}", block_number),
                    block_number,
                    vyfties_id: "vyft_id".to_string(),
                };
                tx.send(new_release.clone()).await.unwrap();
                info!("Latest period: {} - Bloc number: {}", new_release.timestamp, new_release.block_number);
            }
        }); 
    }
}
