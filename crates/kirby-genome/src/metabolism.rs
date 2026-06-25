//! The shared life-gating METABOLISM: the earn-or-die classification of a THINK and a WRITE
//! receipt, plus the cmdline-knob set every cognition workload rides. This lives in ONE place so
//! the CAPABLE workload (and any future agent loop) maps a receipt the SAME way — the
//! life-gating logic is never duplicated across workloads (D-1).
//!
//! Originally factored out of the Diarist; the cmdline knob NAMES (`kirby.brain_*`,
//! `kirby.memory_*`, `kirby.diarist_*`) are the genome's existing cmdline contract and are kept
//! as-is so a bare daemon config and the cmdline path still agree.

use std::time::Duration;

use kirby_proto::{CapabilityReceipt, Outcome};

// Defaults when the daemon set no `kirby.diarist_*=`/`kirby.brain_*=`/`kirby.memory_*=` on
// the cmdline. They MATCH `kirby_node::config`'s defaults (AgentConfig/BrainConfig/
// MemoryConfig) so a bare config and the cmdline path agree.
const DEFAULT_DIARIST_TICK_SECS: u64 = 60;
const DEFAULT_DIARIST_RECALL_COUNT: usize = 5;
const DEFAULT_BRAIN_MODEL: &str = "anthropic/claude-sonnet-4.6";
const DEFAULT_BRAIN_MAX_COST_SATS: u64 = 64;
const DEFAULT_MEMORY_MAX_COST_SATS: u64 = 64;

/// The agent's runtime knobs, read from the kernel command line. It REUSES the brain knobs
/// (model + per-think ceiling) and the memory knob (per-write ceiling), and adds its own
/// cadence + recall depth; the brain/memory `tick_secs` are unused (the agent has ONE loop).
///
/// `pub(crate)` so the CAPABLE workload reuses the EXACT same knob set (D-1, D-7): a capable
/// agent rides the existing `kirby.brain_*`/`kirby.memory_*`/`kirby.diarist_*` cmdline knobs (no
/// new daemon plumbing, charter "genome-side composition ONLY").
pub(crate) struct DiaristParams {
    /// The model the THINK uses (cosmetic for the stub; load-bearing for RoutstrBrain).
    pub(crate) model: String,
    /// The per-THINK budget ceiling (from `[brain].max_cost_sats`).
    pub(crate) brain_max_cost: u64,
    /// The per-REMEMBER budget ceiling (from `[memory].max_cost_sats`).
    pub(crate) memory_max_cost: u64,
    /// The one loop cadence (think + remember per tick).
    pub(crate) tick: Duration,
    /// How many recent journal entries to RECALL into each reflection prompt.
    pub(crate) recall_count: usize,
}

/// Parse the agent knobs from `/proc/cmdline`, falling back to the defaults for any absent
/// or unparseable value (so a bare config still runs). Mirrors brain.rs/memory.rs.
pub(crate) fn diarist_params_from_cmdline() -> DiaristParams {
    let cmdline = std::fs::read_to_string("/proc/cmdline").unwrap_or_default();
    let get = |key: &str| {
        cmdline
            .split_whitespace()
            .find_map(|tok| tok.strip_prefix(key))
            .map(|s| s.to_string())
    };
    let model = get("kirby.brain_model=").unwrap_or_else(|| DEFAULT_BRAIN_MODEL.to_string());
    let brain_max_cost = get("kirby.brain_max_cost_sats=")
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_BRAIN_MAX_COST_SATS);
    let memory_max_cost = get("kirby.memory_max_cost_sats=")
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_MEMORY_MAX_COST_SATS);
    let tick_secs = get("kirby.diarist_tick_secs=")
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_DIARIST_TICK_SECS);
    let recall_count = get("kirby.diarist_recall_count=")
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_DIARIST_RECALL_COUNT);
    DiaristParams {
        model,
        brain_max_cost,
        memory_max_cost,
        // At least one second so a misconfigured 0 cannot busy-spin the loop.
        tick: Duration::from_secs(tick_secs.max(1)),
        recall_count,
    }
}

/// What a THINK resolved to, for the loop's control flow.
///
/// `pub(crate)` so the CAPABLE workload reuses the SAME metabolism semantics (D-1): it maps a
/// receipt through the shared [`classify_think`] and matches these variants verbatim, so the
/// life-gating earn-or-die logic lives in ONE place, never duplicated across workloads.
pub(crate) enum ThinkOutcome {
    /// The reflection came back (PERFORMED, or a DUPLICATE_IGNORED resume-replay that returns
    /// the SAME persisted words). The agent keeps living; `cost`/`treasury_remaining` feed the
    /// next prompt's runway.
    Performed {
        reply: String,
        cost_sats: u64,
        treasury_remaining: u64,
    },
    /// The treasury can no longer cover a think (DENIED, either reason). DEATH (F4): the
    /// genome parks and the daemon halts the VM. Mirrors brain.rs's `brain_dead`.
    Broke,
    /// A transient hiccup (re-dialed channel or an unexpected outcome); drop the turn, keep
    /// ticking.
    Transient,
}

/// What a REMEMBER (write) resolved to. The two DENIED reasons are SPLIT (F5): an over-budget
/// write is a permanent CONFIG error (loud), an insufficient-treasury write is genuinely broke
/// (a soft "can recall, can't record" skip). Neither is death — the THINK is the one death gate.
pub(crate) enum RememberOutcome {
    /// The reflection was recorded (PERFORMED or a DUPLICATE_IGNORED resume-replay).
    Recorded,
    /// DENIED_INSUFFICIENT_TREASURY: broke enough to think but not to record. Soft skip — a
    /// broke mind still RECALLs its past (reads are free), it just cannot FORM new memories.
    Broke,
    /// DENIED_OVER_BUDGET: the `[memory].max_cost_sats` ceiling is below the host-computed
    /// storage cost — a PERMANENT misconfiguration, not brokeness. Fail LOUD so the deploy
    /// raises the ceiling (F5).
    ConfigError,
    /// A transient hiccup (re-dialed channel or an unexpected outcome).
    Transient,
}

/// Classify a THINK receipt into a [`ThinkOutcome`], the shared life-gating metabolism (D-1).
/// PURE (no IO, no logging) so BOTH a diarist-style `think` and the capable loop map a receipt
/// the SAME way, in ONE place: a PERFORMED or a DUPLICATE_IGNORED resume-replay (which carries
/// the SAME persisted completion bytes, F2) is Performed; EITHER denial is Broke (earn-or-die
/// applied to the mind, the one death gate, F4); anything else is a transient hiccup.
pub(crate) fn classify_think(receipt: &CapabilityReceipt) -> ThinkOutcome {
    match Outcome::try_from(receipt.outcome).unwrap_or(Outcome::Unspecified) {
        Outcome::AuthorizedAndPerformed | Outcome::DuplicateIgnored => ThinkOutcome::Performed {
            reply: String::from_utf8_lossy(&receipt.completion).into_owned(),
            cost_sats: receipt.cost_sats,
            treasury_remaining: receipt.treasury_remaining,
        },
        Outcome::DeniedInsufficientTreasury | Outcome::DeniedOverBudget => ThinkOutcome::Broke,
        _ => ThinkOutcome::Transient,
    }
}

/// Classify a REMEMBER (write) receipt into a [`RememberOutcome`], shared metabolism (D-1).
/// PURE: the two DENIED reasons stay SPLIT (F5) so the caller treats over-budget as a LOUD
/// config error and insufficient-treasury as a SOFT broke-skip, while a PERFORMED or a
/// DUPLICATE_IGNORED replay is Recorded (exactly-once, F1). Shared by the capable loop.
pub(crate) fn classify_remember(receipt: &CapabilityReceipt) -> RememberOutcome {
    match Outcome::try_from(receipt.outcome).unwrap_or(Outcome::Unspecified) {
        Outcome::AuthorizedAndPerformed | Outcome::DuplicateIgnored => RememberOutcome::Recorded,
        Outcome::DeniedOverBudget => RememberOutcome::ConfigError,
        Outcome::DeniedInsufficientTreasury => RememberOutcome::Broke,
        _ => RememberOutcome::Transient,
    }
}
