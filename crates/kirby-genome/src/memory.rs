//! The durable-mind-state workload (memory-stub, Chunk-1): the in-VM harness loop that
//! exercises the `Memory` brokered act -- the SIBLING of the brain's `Completion`. Each
//! WRITE (SET/RM) drains the treasury by a HOST-computed storage cost; each READ (GET/LS)
//! is FREE. The genome never speaks to a relay; the daemon's `StubMemory` performs the
//! store op (Chunk-2 swaps in the real NIP-AE engram store, same wire).
//!
//! The loop proves the seam, then lives on it:
//!   1. SET `core` (a write -> drains), then GET it back (the contract returns the VALUE,
//!      not just a hash), then LS (both free), then RE-ISSUE the SET under the SAME
//!      write-seq -> DUPLICATE_IGNORED with NO second debit (idempotent replay, F1).
//!   2. then keep forming memories on a tick (each a fresh write -> drains), recalling
//!      each (a free read), and PARK (`idle_forever`) when a write can no longer be
//!      afforded -- the daemon then halts the VM. Death is the host halt, NOT the loop
//!      breaking (PID 1 must never exit, F4).
//!
//! Dependency-free (F5): the request carries STRUCTURED prost fields, so the genome needs
//! no JSON encoder. WRITES key on a MONOTONIC write-seq (`mem-write-{wseq}`) so a resume
//! retry reuses the seq = exactly-once debit (design doc 10 F1 -- NOT a content hash,
//! which would falsely dedupe a legitimate future re-write); READS key uniquely per call
//! (`mem-get-{slug}-{tick}` / `mem-ls-{tick}`) so each is a fresh, free fetch.

use kirby_proto::node_gateway_client::NodeGatewayClient;
use kirby_proto::CheckpointBlob;

use super::boot_log;

/// The memory checkpoint blob format (Chunk-2 wseq-persist): a 5-byte magic followed by
/// the monotonic `wseq` as 8 big-endian bytes. Dep-free (no JSON, F5) -- the daemon
/// stores it opaquely (content-addressed) and serves it back inline on resume
/// (`SessionContext.restore_checkpoint_blob`), the SAME run-agent restore path the
/// app-checkpoint workload uses. The magic guards against decoding a foreign blob.
const MEM_CKPT_MAGIC: &[u8] = b"KMEM1";

/// Encode the wseq checkpoint blob (magic ‖ wseq big-endian).
fn encode_wseq_checkpoint(wseq: u64) -> Vec<u8> {
    let mut payload = Vec::with_capacity(MEM_CKPT_MAGIC.len() + 8);
    payload.extend_from_slice(MEM_CKPT_MAGIC);
    payload.extend_from_slice(&wseq.to_be_bytes());
    payload
}

/// Restore the monotonic `wseq` from the session's inline checkpoint blob, or `0` for a
/// fresh boot (no/foreign/short blob). On resume this is the LAST wseq the genome
/// checkpointed, so the next write takes `wseq + 1` -- a NEW seq, never a reset-to-0 that
/// would re-issue `mem-write-1` and false-dedupe against the persistent ledger (the F1
/// bug on a durable store, design doc §16). The daemon's wseq_floor (R2-7) is the
/// authoritative backstop if this blob is ever stale.
///
/// `pub(super)` so the DIARIST workload reuses the EXACT checkpoint-blob contract (same
/// `KMEM1` format, same daemon `wseq_floor` backstop): the diarist drives its monotonic
/// `seq` off this on resume, so a restart continues past the last journal entry rather
/// than re-issuing an old write key (F1) or an old think key (F2). Behavior is unchanged.
pub(super) fn restore_wseq(ctx: &kirby_proto::SessionContext) -> u64 {
    let blob = &ctx.restore_checkpoint_blob;
    if blob.len() == MEM_CKPT_MAGIC.len() + 8 && blob.starts_with(MEM_CKPT_MAGIC) {
        let mut be = [0u8; 8];
        be.copy_from_slice(&blob[MEM_CKPT_MAGIC.len()..]);
        u64::from_be_bytes(be)
    } else {
        0
    }
}

/// Submit a checkpoint carrying the current `wseq` (Chunk-2). Called after a successful
/// write so the daemon always holds the highest issued seq for a resume. A submit failure
/// is logged, not fatal (the wseq_floor backstop still protects correctness on resume).
///
/// `pub(super)` so the DIARIST reuses the exact wseq-persist contract (see [`restore_wseq`]).
pub(super) async fn submit_wseq_checkpoint(
    client: &mut NodeGatewayClient<tonic::transport::Channel>,
    wseq: u64,
) {
    let payload = encode_wseq_checkpoint(wseq);
    match client
        .submit_checkpoint(CheckpointBlob { schema_version: kirby_proto::SCHEMA_VERSION, payload })
        .await
    {
        Ok(_) => boot_log(&format!("memory_checkpoint wseq={wseq} submitted")),
        Err(status) => {
            boot_log(&format!("memory_checkpoint wseq={wseq} submit failed: {status}"))
        }
    }
}

// (The `memory` workload loop and its private helpers were removed when Kirby collapsed to the
// single `capable` agent; only the shared `KMEM1` checkpoint contract above survives, reused by
// the capable loop's resume path.)
