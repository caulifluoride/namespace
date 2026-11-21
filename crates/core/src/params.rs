use serde::{Deserialize, Serialize};

/// Consensus parameters. All heights are namespace block heights, not
/// Bitcoin heights: a block's validity must not depend on which Bitcoin block
/// its anchor happens to land in.
///
/// # Announcement tiers
///
/// A name must be announced before it can be registered, and announcements
/// are rate-limited by tier. Shorter names are scarcer, so they open later and
/// slowly. A name's *tier*
/// is how many characters shorter than `long_name_len` it is: names at least
/// that long are tier 0, one character shorter is tier 1, and so on.
///
/// Every tier follows the same ramp, advancing one stage every
/// `stage_length` blocks. With `f = ramp_factor` and `k = ramp_slow_stages`,
/// stage `s` allows `f^(s - k)` announcements per block, capped at
/// `max_announcements_per_tier`. Below one per block, stage `s` allows one
/// announcement in blocks whose height is a multiple of `f^(k - s)`. With
/// the mainnet values (f = 3, k = 2, cap 16) a tier goes through
///
/// ```text
/// 1 every 9 blocks, 1 every 3, 1 per block, 3, 9, 16 per block
/// ```
///
/// A tier opens when the one before it reaches the cap. Tier 0 opens at
/// launch already at `f` per block. So at global stage
/// `c = (height - 1) / stage_length`, tier `t` is at stage
///
/// ```text
/// c + (k + 1) - t * stages_per_tier
/// ```
///
/// and is closed while that is negative.
#[derive(Clone, Debug)]
pub struct Params {
    /// Names this long or longer are tier 0, the first to open.
    pub long_name_len: usize,
    /// Blocks per ramp stage.
    pub stage_length: u64,
    /// Each stage allows this many times more announcements than the last.
    pub ramp_factor: u32,
    /// Stages below one announcement per block at the start of each tier.
    pub ramp_slow_stages: u32,
    /// Where each tier's ramp stops.
    pub max_announcements_per_tier: u32,
    /// Hard limit on transactions of any kind per block.
    pub max_txs_per_block: u32,
    /// An announced name can be registered this many blocks after the
    /// announcement at the earliest. This is the auction: everyone has this
    /// long to see the name is coming up and bid for the slot that opens it.
    pub announce_delay: u64,
    /// A name expires this many blocks after it was registered or last renewed.
    pub expiry_period: u64,
}

/// How many announcements a tier allows at some height.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TierRate {
    /// Not open yet.
    Closed {
        opens_at: u64,
    },
    /// One announcement in blocks whose height is a multiple of `blocks`.
    Every {
        blocks: u64,
    },
    PerBlock {
        count: u32,
    },
}

impl Params {
    pub fn mainnet() -> Self {
        Self {
            long_name_len: 10,
            // Namespace blocks come every 3 Bitcoin blocks, so this is about
            // three months: a tier takes about 18 months to ramp up, and
            // 1-character names open after about 13 years.
            stage_length: 4_380,
            ramp_factor: 3,
            ramp_slow_stages: 2,
            max_announcements_per_tier: 16,
            max_txs_per_block: 20_000,
            // About a week.
            announce_delay: 336,
            // About three years.
            expiry_period: 52_560,
        }
    }

    /// Small values for tests and local development. Every name is in the
    /// first tier, so any name can be announced right away.
    pub fn regtest() -> Self {
        Self {
            long_name_len: 1,
            stage_length: 10,
            ramp_factor: 3,
            ramp_slow_stages: 2,
            max_announcements_per_tier: 16,
            max_txs_per_block: 1_000,
            announce_delay: 2,
            expiry_period: 50,
        }
    }

    /// The tier of a name of `len` characters.
    pub fn tier(&self, len: usize) -> u32 {
        u32::try_from(self.long_name_len.saturating_sub(len)).unwrap_or(u32::MAX)
    }

    /// Number of tiers: one per length from 1 up to `long_name_len`.
    pub fn tiers(&self) -> u32 {
        self.tier(1) + 1
    }

    /// The name lengths in tier `t`, for display: `"10+"`, `"9"`, ...
    pub fn tier_lengths(&self, tier: u32) -> String {
        let len = self.long_name_len.saturating_sub(tier as usize);
        if tier == 0 {
            format!("{len}+")
        } else {
            len.to_string()
        }
    }

    /// Stages from a tier's first announcement to its cap.
    pub fn stages_per_tier(&self) -> u64 {
        let factor = u64::from(self.ramp_factor.max(2));
        let mut fast = 0;
        let mut rate = 1u64;
        while rate < u64::from(self.max_announcements_per_tier) {
            rate = rate.saturating_mul(factor);
            fast += 1;
        }
        u64::from(self.ramp_slow_stages) + 1 + fast
    }

    /// Tier 0 starts past the slow stages, at `ramp_factor` per block.
    fn head_start(&self) -> u64 {
        u64::from(self.ramp_slow_stages) + 1
    }

    /// The height at which tier `t` opens.
    pub fn tier_opens_at(&self, tier: u32) -> u64 {
        let first_stage =
            (u64::from(tier) * self.stages_per_tier()).saturating_sub(self.head_start());
        first_stage
            .saturating_mul(self.stage_length)
            .saturating_add(1)
    }

    pub fn tier_rate(&self, height: u64, tier: u32) -> TierRate {
        let clock = height.saturating_sub(1) / self.stage_length.max(1);
        let Some(stage) =
            (clock + self.head_start()).checked_sub(u64::from(tier) * self.stages_per_tier())
        else {
            return TierRate::Closed {
                opens_at: self.tier_opens_at(tier),
            };
        };
        let factor = u64::from(self.ramp_factor);
        let slow = u64::from(self.ramp_slow_stages);
        if stage < slow {
            let blocks = factor.saturating_pow(u32::try_from(slow - stage).unwrap_or(u32::MAX));
            return TierRate::Every { blocks };
        }
        let rate = factor.saturating_pow(u32::try_from(stage - slow).unwrap_or(u32::MAX));
        let count = rate.min(u64::from(self.max_announcements_per_tier));
        TierRate::PerBlock {
            count: u32::try_from(count).unwrap_or(u32::MAX),
        }
    }

    /// Announcements of tier `t` names allowed in the block at `height`.
    pub fn tier_cap(&self, height: u64, tier: u32) -> u32 {
        match self.tier_rate(height, tier) {
            TierRate::Closed { .. } => 0,
            TierRate::Every { blocks } => u32::from(height % blocks.max(1) == 0),
            TierRate::PerBlock { count } => count,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params() -> Params {
        Params {
            stage_length: 1,
            ..Params::mainnet()
        }
    }

    #[test]
    fn tiers_by_length() {
        let p = Params::mainnet();
        assert_eq!(p.tier(63), 0);
        assert_eq!(p.tier(10), 0);
        assert_eq!(p.tier(9), 1);
        assert_eq!(p.tier(1), 9);
        assert_eq!(p.tiers(), 10);
        assert_eq!(p.tier_lengths(0), "10+");
        assert_eq!(p.tier_lengths(9), "1");
        assert_eq!(Params::regtest().tiers(), 1);
    }

    #[test]
    fn each_tier_ramps_then_the_next_opens() {
        use TierRate::*;
        let p = params();
        assert_eq!(p.stages_per_tier(), 6);
        // With one block per stage, height h is global stage h - 1.
        let rates = |tier| (1..=13).map(|h| p.tier_rate(h, tier)).collect::<Vec<_>>();
        let n = |count| PerBlock { count };
        assert_eq!(
            rates(0),
            [
                n(3),
                n(9),
                n(16),
                n(16),
                n(16),
                n(16),
                n(16),
                n(16),
                n(16),
                n(16),
                n(16),
                n(16),
                n(16)
            ]
        );
        let closed = Closed { opens_at: 4 };
        assert_eq!(
            rates(1),
            [
                closed,
                closed,
                closed,
                Every { blocks: 9 },
                Every { blocks: 3 },
                n(1),
                n(3),
                n(9),
                n(16),
                n(16),
                n(16),
                n(16),
                n(16)
            ]
        );
        assert_eq!(p.tier_rate(9, 2), Closed { opens_at: 10 });
        assert_eq!(p.tier_rate(10, 2), Every { blocks: 9 });
    }

    #[test]
    fn slow_stages_allow_one_on_multiples() {
        let p = Params::mainnet();
        let opens = p.tier_opens_at(1);
        // 6 stages per tier, tier 0 starts 3 stages in.
        assert_eq!(opens, 3 * 4_380 + 1);
        let caps: Vec<_> = (opens..opens + 18).map(|h| p.tier_cap(h, 1)).collect();
        assert_eq!(caps.iter().sum::<u32>(), 2);
        assert!(
            (opens..opens + 18)
                .filter(|h| p.tier_cap(*h, 1) == 1)
                .all(|h| h % 9 == 0)
        );
        assert_eq!(p.tier_cap(opens - 1, 1), 0);
    }

    #[test]
    fn far_future_saturates() {
        let p = Params::mainnet();
        for t in 0..p.tiers() {
            assert_eq!(p.tier_cap(u64::MAX, t), 16);
        }
    }
}
