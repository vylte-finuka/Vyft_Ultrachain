use serde::{Deserialize, Serialize};

use crate::committee::committee::EpochId;
use crate::messages_checkpoint::messages_checkpoint::CheckpointSequenceNumber;

#[derive(Debug, Serialize, Deserialize)]
pub struct SupportedProtocolVersions {
    pub epoch_id: EpochId,
    pub messages_checkpoint: CheckpointSequenceNumber,
    pub supported_protocol_versions: Vec<String>,
}

impl SupportedProtocolVersions {
    pub fn new(
        epoch_id: EpochId,
        messages_checkpoint: CheckpointSequenceNumber,
        supported_protocol_versions: Vec<String>,
    ) -> Self {
        Self {
            epoch_id,
            messages_checkpoint,
            supported_protocol_versions,
        }
    }
}

impl Default for SupportedProtocolVersions {
    fn default() -> Self {
        Self {
            epoch_id: EpochId::default(),
            messages_checkpoint: CheckpointSequenceNumber::default(),
            supported_protocol_versions: vec![],
        }
    }
}