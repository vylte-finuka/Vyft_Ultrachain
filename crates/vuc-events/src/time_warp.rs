use serde::{Deserialize, Serialize};
use tracing::info;
use tokio::sync::mpsc;
use crate::timestamp_release::TimestampRelease;
use chrono::Utc;

#[derive(Serialize, Deserialize)]
pub struct TimeWarp {
    pub warping_blocks: Vec<u64>,
}

impl Default for TimeWarp {
    fn default() -> Self {
        TimeWarp {
            warping_blocks: vec![],
        }
    }
}

impl TimeWarp {
    pub fn sync_in_warp(&self) -> mpsc::Receiver<TimestampRelease> {
        let (sync_counter, rx) = mpsc::channel(1);
        tokio::spawn(async move {
            let mut block_number = 0;
            loop {
                let timestamp_release = TimestampRelease {
                    timestamp: Utc::now(),
                    log: String::from("Bloc synchronisé"),
                    block_number,
                    vyfties_id: String::from("vyft_id"),
                };
                sync_counter.send(timestamp_release.clone()).await.unwrap();
                info!("TimeWarp: Bloc synchronisé : {}", block_number);
                block_number += 1;
                tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;
            }
        });
        rx
    }
}