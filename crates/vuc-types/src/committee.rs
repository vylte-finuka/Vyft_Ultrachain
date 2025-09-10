pub mod committee {
    use std::collections::HashMap;

    pub type EpochId = u64;

    pub struct Committee {
        epoch_id: EpochId,
        members: HashMap<String, u64>, // Nom du membre et son poids
    }

    impl Committee {
        pub fn new(epoch_id: EpochId) -> Self {
            Self {
                epoch_id,
                members: HashMap::new(),
            }
        }

        pub fn add_member(&mut self, name: String, weight: u64) {
            self.members.insert(name, weight);
        }

        pub fn get_member_weight(&self, name: &str) -> Option<&u64> {
            self.members.get(name)
        }
    }
}