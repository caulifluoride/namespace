/// Consensus parameters. All heights are namespace block heights, not
/// Bitcoin heights: a block's validity must not depend on which Bitcoin block
/// its anchor happens to land in.
#[derive(Clone, Debug)]
pub struct Params {
    /// Registrations allowed per block at height 1.
    pub initial_registrations_per_block: u32,
    /// The registration cap doubles every this many blocks...
    pub registration_doubling_interval: u64,
    /// ...until it reaches this ceiling.
    pub max_registrations_per_block: u32,
    /// Commits allowed per block, as a multiple of the registration cap.
    /// Commits are free, so they need their own limit.
    pub commits_per_registration: u32,
    /// Hard limit on transactions of any kind per block.
    pub max_txs_per_block: u32,
    /// A commitment can be revealed this many blocks after it was included at
    /// the earliest. At least 1, so a reveal seen in the mempool can't be
    /// front-run by committing to the same name in the same block.
    pub min_commit_age: u64,
    /// Commitments older than this can't be revealed anymore and are dropped.
    pub max_commit_age: u64,
    /// A name expires this many blocks after it was registered or last renewed.
    pub expiry_period: u64,
}

impl Params {
    pub fn mainnet() -> Self {
        Self {
            initial_registrations_per_block: 16,
            // Namespace blocks are at most one per Bitcoin block, so this is
            // at least ~1 year.
            registration_doubling_interval: 52_560,
            max_registrations_per_block: 4_096,
            commits_per_registration: 4,
            max_txs_per_block: 20_000,
            min_commit_age: 6,
            max_commit_age: 1_008,
            expiry_period: 52_560,
        }
    }

    /// Small values for tests and local development.
    pub fn regtest() -> Self {
        Self {
            initial_registrations_per_block: 2,
            registration_doubling_interval: 10,
            max_registrations_per_block: 16,
            commits_per_registration: 4,
            max_txs_per_block: 1_000,
            min_commit_age: 1,
            max_commit_age: 20,
            expiry_period: 50,
        }
    }

    /// The registration cap for a block at `height`: starts at the initial
    /// value and doubles every `registration_doubling_interval` blocks, up
    /// to the ceiling.
    pub fn registration_cap(&self, height: u64) -> u32 {
        let doublings = height.saturating_sub(1) / self.registration_doubling_interval;
        let cap = u64::from(self.initial_registrations_per_block)
            .checked_shl(u32::try_from(doublings).unwrap_or(u32::MAX))
            .unwrap_or(u64::MAX);
        u32::try_from(cap)
            .unwrap_or(u32::MAX)
            .min(self.max_registrations_per_block)
    }

    pub fn commit_cap(&self, height: u64) -> u32 {
        self.registration_cap(height)
            .saturating_mul(self.commits_per_registration)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registration_cap_doubles_then_saturates() {
        let p = Params::regtest();
        assert_eq!(p.registration_cap(1), 2);
        assert_eq!(p.registration_cap(10), 2);
        assert_eq!(p.registration_cap(11), 4);
        assert_eq!(p.registration_cap(21), 8);
        assert_eq!(p.registration_cap(31), 16);
        assert_eq!(p.registration_cap(41), 16);
        assert_eq!(p.registration_cap(u64::MAX), 16);
    }
}
