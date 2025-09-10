pub mod messages_checkpoint {
    pub type CheckpointSequenceNumber = u64;

    pub struct Checkpoint {
        data: Vec<u8>, // Les données du checkpoint sous forme de bytes
    }

    impl Checkpoint {
        pub fn new(sequence_number: CheckpointSequenceNumber, data: Vec<u8>) -> Self {
            Self {
                data,
            }
        }

        pub fn validate(&self) -> bool {
            // Logique de validation des données du checkpoint
            !self.data.is_empty()
        }
    }
}
