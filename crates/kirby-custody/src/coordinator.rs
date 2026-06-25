//! In-process FROST coordinator (chunk C-2). Drives a single 2-of-(n) threshold
//! signing ceremony over ZF frost-secp256k1-tr, producing a 64-byte BIP-340
//! signature under the TWEAKED taproot output key Q (merkle_root = None, key-path
//! only). No transport/relay (that is the D-14 seam, filled at C-6); signers are
//! driven in-process.
//!
//! D-16 state machine: Idle -> Round1Collect -> PackageReady -> Round2Collect ->
//! Aggregate -> Done | Aborted. One ceremony = one fresh nonce per signer; the
//! round-1 secret nonce is single-use and zeroized on drop right after round-2
//! (frost SigningNonces derives ZeroizeOnDrop). No ROAST (v0 = abort-and-retry).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use frost_secp256k1_tr as frost;
use frost::keys::{KeyPackage, PublicKeyPackage};
use frost::round1::{SigningCommitments, SigningNonces};
use frost::round2::SignatureShare;
use frost::{Identifier, SigningPackage};

/// The D-16 coordinator state machine. A ceremony ends in Done or Aborted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    Idle,
    Round1Collect,
    PackageReady,
    Round2Collect,
    Aggregate,
    Done,
    Aborted,
}

/// Error surfaced toward the D-10 Signer seam. The coordinator NEVER panics; the
/// gateway maps QuorumUnavailable to its UPSTREAM_FAILED outcome (debit 0).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignError {
    /// Fewer than the threshold of signers participated, or aggregation could not
    /// form a valid group signature (sub-threshold / abort). No ROAST in v0.
    QuorumUnavailable(String),
    /// A signer produced a malformed or invalid round-2 signature share.
    BadShare(String),
    /// The quorum slice contained a repeated signer identifier (which would reuse
    /// a single-use nonce). Rejected up front, before any signing.
    DuplicateSigner(String),
    /// run() was invoked on a coordinator that already finished or aborted. One
    /// coordinator drives exactly one ceremony; create a new one per ceremony.
    InvalidState(String),
    /// An unexpected library or serialization error (should not happen in v0).
    Internal(String),
}

impl fmt::Display for SignError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SignError::QuorumUnavailable(m) => write!(f, "quorum unavailable: {m}"),
            SignError::BadShare(m) => write!(f, "bad signature share: {m}"),
            SignError::DuplicateSigner(m) => write!(f, "duplicate signer in quorum: {m}"),
            SignError::InvalidState(m) => write!(f, "invalid coordinator state: {m}"),
            SignError::Internal(m) => write!(f, "internal signing error: {m}"),
        }
    }
}

impl std::error::Error for SignError {}

/// Convert a dealer keyset's secret shares into per-guardian KeyPackages (the
/// signing material each guardian holds). The caller selects which >= threshold
/// guardians participate in a given ceremony.
pub fn key_packages(
    keyset: &crate::DealerKeyset,
) -> Result<BTreeMap<Identifier, KeyPackage>, SignError> {
    keyset
        .shares
        .iter()
        .map(|(id, share)| {
            KeyPackage::try_from(share.clone())
                .map(|kp| (*id, kp))
                .map_err(|e| SignError::Internal(e.to_string()))
        })
        .collect()
}

/// The in-process FROST coordinator. One instance drives one signing ceremony
/// (fresh nonces); create a new one per ceremony. This is the shape the D-10
/// async Signer seam wraps at convergence: Signer::sign(message) maps to
/// Coordinator::new(..).run(quorum, message).
pub struct Coordinator {
    pubkeys: PublicKeyPackage,
    min_signers: u16,
    state: SessionState,
}

impl Coordinator {
    /// Create a coordinator for a group (its PublicKeyPackage) with the given
    /// quorum threshold. Starts Idle.
    pub fn new(pubkeys: PublicKeyPackage, min_signers: u16) -> Self {
        Self {
            pubkeys,
            min_signers,
            state: SessionState::Idle,
        }
    }

    /// The current state machine position (observable for verification).
    pub fn state(&self) -> SessionState {
        self.state
    }

    /// Drive the full ceremony over `signers` (the participating guardians),
    /// signing `message` (a 32-byte digest at G1; a real BIP-341 sighash at C-3).
    /// Returns the 64-byte BIP-340 signature under the TWEAKED output key Q, or an
    /// error after moving to Aborted. Any failure aborts cleanly (never panics).
    /// Single-shot: a coordinator drives exactly one ceremony (terminal-state guard).
    pub fn run(
        &mut self,
        signers: &[KeyPackage],
        message: &[u8],
    ) -> Result<[u8; 64], SignError> {
        // Terminal-state guard: run() is single-shot (one ceremony per coordinator,
        // so a stale Done/Aborted coordinator cannot be re-driven). Leaves state
        // unchanged so the prior outcome stays observable.
        if self.state != SessionState::Idle {
            return Err(SignError::InvalidState(format!(
                "run() already used (state = {:?}); create a new Coordinator per ceremony",
                self.state
            )));
        }

        // Reject a quorum slice with a repeated signer identifier BEFORE round1: a
        // duplicate would collapse in the nonce/commitment maps yet be iterated
        // again in round2, reusing a single-use nonce. Not acceptable on custody.
        let mut seen: BTreeSet<Identifier> = BTreeSet::new();
        for kp in signers {
            if !seen.insert(*kp.identifier()) {
                self.state = SessionState::Aborted;
                return Err(SignError::DuplicateSigner(format!(
                    "identifier {:?} appears more than once",
                    kp.identifier()
                )));
            }
        }

        // Idle -> Round1Collect: each signer commits a FRESH single-use nonce.
        self.state = SessionState::Round1Collect;
        let mut rng = rand::rngs::OsRng;
        let mut nonces: BTreeMap<Identifier, SigningNonces> = BTreeMap::new();
        let mut commitments: BTreeMap<Identifier, SigningCommitments> = BTreeMap::new();
        for kp in signers {
            let (nonce, commitment) = frost::round1::commit(kp.signing_share(), &mut rng);
            nonces.insert(*kp.identifier(), nonce);
            commitments.insert(*kp.identifier(), commitment);
        }
        if commitments.len() < self.min_signers as usize {
            self.state = SessionState::Aborted;
            return Err(SignError::QuorumUnavailable(format!(
                "sub-threshold: {} of {} required signers participated",
                commitments.len(),
                self.min_signers
            )));
        }

        // Round1Collect -> PackageReady: build exactly ONE SigningPackage.
        self.state = SessionState::PackageReady;
        let package = SigningPackage::new(commitments, message);

        // PackageReady -> Round2Collect: each signer produces a TWEAKED share
        // (merkle_root = None, key-path only).
        self.state = SessionState::Round2Collect;
        let mut shares: BTreeMap<Identifier, SignatureShare> = BTreeMap::new();
        for kp in signers {
            // remove() CONSUMES the nonce: each is used at most once, and a stray
            // duplicate (defense in depth behind the up-front dedup) finds none.
            let Some(nonce) = nonces.remove(kp.identifier()) else {
                self.state = SessionState::Aborted;
                return Err(SignError::Internal(
                    "missing round-1 nonce for a signer (duplicate or internal error)".to_string(),
                ));
            };
            match frost::round2::sign_with_tweak(&package, &nonce, kp, None) {
                Ok(share) => {
                    shares.insert(*kp.identifier(), share);
                }
                Err(e) => {
                    self.state = SessionState::Aborted;
                    return Err(SignError::BadShare(e.to_string()));
                }
            }
            // `nonce` (owned) drops here: SigningNonces zeroizes the secret nonce
            // immediately after its single use. Nonces are never persisted (D-16).
        }

        // Round2Collect -> Aggregate -> Done: aggregate the tweaked shares.
        self.state = SessionState::Aggregate;
        let group_sig =
            match frost::aggregate_with_tweak(&package, &shares, &self.pubkeys, None) {
                Ok(sig) => sig,
                Err(e) => {
                    self.state = SessionState::Aborted;
                    return Err(SignError::QuorumUnavailable(e.to_string()));
                }
            };
        let bytes = match group_sig.serialize() {
            Ok(b) => b,
            Err(e) => {
                self.state = SessionState::Aborted;
                return Err(SignError::Internal(e.to_string()));
            }
        };
        let sig: [u8; 64] = match bytes.as_slice().try_into() {
            Ok(arr) => arr,
            Err(_) => {
                self.state = SessionState::Aborted;
                return Err(SignError::Internal(format!(
                    "expected a 64-byte BIP-340 signature, got {} bytes",
                    bytes.len()
                )));
            }
        };
        self.state = SessionState::Done;
        Ok(sig)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{generate_dealer_keyset_with_rng, taproot_address};
    use bitcoin::key::TapTweak;
    use bitcoin::secp256k1::{schnorr, Message, Secp256k1};
    use bitcoin::KnownHrp;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    // Non-secret, zero-funds Mutinynet fixture seed (reproducible C-2 G1 keyset).
    const G1_SEED: [u8; 32] = *b"kirby-custody-c2-g1-seed-mutiny!";

    fn keyset_and_signers(take: usize) -> (crate::DealerKeyset, Vec<KeyPackage>) {
        let mut rng = StdRng::from_seed(G1_SEED);
        let keyset = generate_dealer_keyset_with_rng(2, 3, &mut rng).expect("keygen");
        let all = key_packages(&keyset).expect("key packages");
        let signers: Vec<KeyPackage> = all.into_values().take(take).collect();
        (keyset, signers)
    }

    /// G1 (the money-path safety gate): a 2-of-3 quorum signs a fixed 32-byte
    /// digest; the aggregate VERIFIES under the tweaked output key Q and FAILS
    /// under the untweaked internal key P (the assertion that proves the taproot
    /// tweak is real), with merkle_root = None throughout (no script path).
    #[test]
    fn g1_verify_under_q_pass_under_p_fail() {
        let (keyset, signers) = keyset_and_signers(2);
        assert_eq!(signers.len(), 2);

        // Internal key P and the address: derived exactly as C-1 (merkle_root=None).
        let (_addr, internal_p) =
            taproot_address(&keyset.pubkeys, KnownHrp::Testnets).expect("address");

        // Fixed 32-byte test digest (a real BIP-341 tx sighash is C-3).
        let message = [0x42u8; 32];

        let mut coord = Coordinator::new(keyset.pubkeys.clone(), 2);
        let sig_bytes = coord.run(&signers, &message).expect("happy-path 2-of-3 sign");
        assert_eq!(coord.state(), SessionState::Done);
        assert_eq!(sig_bytes.len(), 64);

        // Derive Q = P tweaked with merkle_root = None (the C-1 derivation chain).
        let secp = Secp256k1::verification_only();
        let (q_tweaked, _parity) = internal_p.tap_tweak(&secp, None);
        let q_xonly = q_tweaked.to_x_only_public_key();

        let sig = schnorr::Signature::from_slice(&sig_bytes).expect("parse 64-byte sig");
        let msg = Message::from_digest(message);

        // (a) VERIFIES under the TWEAKED output key Q.
        let under_q = secp.verify_schnorr(&sig, &msg, &q_xonly);
        assert!(under_q.is_ok(), "aggregate must verify under tweaked Q: {under_q:?}");

        // (b) FAILS under the UNTWEAKED internal key P (proves the tweak is real).
        let under_p = secp.verify_schnorr(&sig, &msg, &internal_p);
        assert!(under_p.is_err(), "aggregate must NOT verify under untweaked P");

        // (c) merkle_root = None / no script path: Q derived and signed with None
        //     throughout, and Q != P (a non-trivial tweak, so no leaf was committed).
        assert_ne!(q_xonly, internal_p, "Q must differ from P (non-trivial tweak)");

        println!(
            "G1 PASS: verify under tweaked Q = OK; verify under untweaked P = REJECTED; merkle_root=None; Q != P"
        );
    }

    /// A sub-threshold ceremony (1 of a 2-of-3) aborts cleanly with
    /// QuorumUnavailable and never panics (toward G3; the dedicated G3 gate is C-4).
    #[test]
    fn sub_threshold_aborts_cleanly() {
        let (keyset, signers) = keyset_and_signers(1);
        let message = [0x42u8; 32];

        let mut coord = Coordinator::new(keyset.pubkeys.clone(), 2);
        let result = coord.run(&signers, &message);

        assert!(
            matches!(result, Err(SignError::QuorumUnavailable(_))),
            "sub-threshold must be QuorumUnavailable, got {result:?}"
        );
        assert_eq!(coord.state(), SessionState::Aborted);
        println!("ABORT PASS: 1-of-3 sub-threshold ceremony Aborted with QuorumUnavailable (no panic)");
    }

    /// A quorum slice containing a repeated signer identifier is rejected up front
    /// (before any signing), so no single-use nonce is ever reused.
    #[test]
    fn duplicate_signer_is_rejected() {
        let (keyset, signers) = keyset_and_signers(2);
        // Quorum [signer1, signer2, signer1]: a duplicate identifier.
        let with_dup = vec![signers[0].clone(), signers[1].clone(), signers[0].clone()];
        let message = [0x42u8; 32];

        let mut coord = Coordinator::new(keyset.pubkeys.clone(), 2);
        let result = coord.run(&with_dup, &message);

        assert!(
            matches!(result, Err(SignError::DuplicateSigner(_))),
            "a duplicate signer must be rejected, got {result:?}"
        );
        // Rejected before round1, so the ceremony aborted without signing at all.
        assert_eq!(coord.state(), SessionState::Aborted);
        println!("DUP PASS: quorum with a duplicate identifier rejected before signing (no nonce reuse)");
    }

    /// run() is single-shot: a coordinator that already reached a terminal state
    /// rejects re-invocation, and a rejected re-run leaves the prior state intact.
    #[test]
    fn run_is_single_shot() {
        let (keyset, signers) = keyset_and_signers(2);
        let message = [0x42u8; 32];

        let mut coord = Coordinator::new(keyset.pubkeys.clone(), 2);
        coord.run(&signers, &message).expect("first run succeeds");
        assert_eq!(coord.state(), SessionState::Done);

        // Second run on the SAME coordinator is rejected; state stays Done.
        let again = coord.run(&signers, &message);
        assert!(
            matches!(again, Err(SignError::InvalidState(_))),
            "re-run after Done must be InvalidState, got {again:?}"
        );
        assert_eq!(coord.state(), SessionState::Done, "rejected re-run must not change state");
        println!("TERMINAL PASS: run() is single-shot; re-invocation after Done rejected, state unchanged");
    }

    /// G3 (no single guardian can rug it): a sub-threshold quorum cannot produce a
    /// valid spend. Two layers: (a) the coordinator ABORTS a 1-of-3 ceremony; AND
    /// (b) even bypassing the coordinator and aggregating ZF directly from a LONE
    /// share, no signature valid under Q is producible (aggregate errors, or yields
    /// a non-Q signature). The funds are unspendable by any single node.
    #[test]
    fn g3_single_guardian_cannot_rug() {
        let (keyset, lone) = keyset_and_signers(1);
        let (_addr, internal_p) =
            taproot_address(&keyset.pubkeys, KnownHrp::Testnets).expect("address");
        let message = [0x42u8; 32];

        // (a) Operational: the coordinator refuses a sub-threshold ceremony.
        let mut coord = Coordinator::new(keyset.pubkeys.clone(), 2);
        let result = coord.run(&lone, &message);
        assert!(
            matches!(result, Err(SignError::QuorumUnavailable(_))),
            "1-of-3 must abort QuorumUnavailable, got {result:?}"
        );
        assert_eq!(coord.state(), SessionState::Aborted);

        // (b) Cryptographic floor: hand-drive ZF round1/round2/aggregate from the
        //     LONE share (bypassing the coordinator's threshold guard). ANY failure
        //     along the way (ZF refuses a sub-threshold share or aggregate, or the
        //     result is non-Q) means no Q-valid signature is producible from one share.
        //     In practice ZF round2::sign already refuses a sub-threshold package.
        let kp = &lone[0];
        let mut rng = rand::rngs::OsRng;
        let (nonces, commitments) = frost::round1::commit(kp.signing_share(), &mut rng);
        let mut commit_map = BTreeMap::new();
        commit_map.insert(*kp.identifier(), commitments);
        let package = SigningPackage::new(commit_map, &message);

        let q_valid = 'attempt: {
            let Ok(share) = frost::round2::sign_with_tweak(&package, &nonces, kp, None) else {
                break 'attempt false;
            };
            let mut share_map = BTreeMap::new();
            share_map.insert(*kp.identifier(), share);
            let Ok(sig) = frost::aggregate_with_tweak(&package, &share_map, &keyset.pubkeys, None)
            else {
                break 'attempt false;
            };
            let Ok(bytes) = sig.serialize() else { break 'attempt false; };
            let Ok(arr) = <[u8; 64]>::try_from(bytes.as_slice()) else { break 'attempt false; };
            let secp = Secp256k1::verification_only();
            let (q_tweaked, _parity) = internal_p.tap_tweak(&secp, None);
            let q_xonly = q_tweaked.to_x_only_public_key();
            let Ok(s) = schnorr::Signature::from_slice(&arr) else { break 'attempt false; };
            secp.verify_schnorr(&s, &Message::from_digest(message), &q_xonly).is_ok()
        };
        assert!(!q_valid, "a LONE share must NOT yield a signature valid under Q");
        println!("G3 PASS: 1-of-3 aborts AND a lone share yields no Q-valid signature (unspendable by one node)");
    }

    /// G4 (quorum is the only spend path, no privileged signer): ALL THREE distinct
    /// signer pairs {1,2}, {1,3}, {2,3} each produce an aggregate that VERIFIES
    /// under Q (and fails under P). Offline (verify-under-Q); on-chain spendability
    /// is covered by G2 for the {1,2} pair, so this does not re-spend.
    #[test]
    fn g4_all_three_pairs_verify_under_q() {
        let (keyset, kps) = keyset_and_signers(3);
        assert_eq!(kps.len(), 3);
        let (_addr, internal_p) =
            taproot_address(&keyset.pubkeys, KnownHrp::Testnets).expect("address");
        let message = [0x42u8; 32];

        let secp = Secp256k1::verification_only();
        let (q_tweaked, _parity) = internal_p.tap_tweak(&secp, None);
        let q_xonly = q_tweaked.to_x_only_public_key();
        let msg = Message::from_digest(message);

        // kps are sorted by identifier (1, 2, 3) -> indices 0, 1, 2.
        let pairs: [(usize, usize, &str); 3] =
            [(0, 1, "{1,2}"), (0, 2, "{1,3}"), (1, 2, "{2,3}")];
        for (a, b, label) in pairs {
            let signers = vec![kps[a].clone(), kps[b].clone()];
            let mut coord = Coordinator::new(keyset.pubkeys.clone(), 2);
            let sig_bytes = coord.run(&signers, &message).expect("pair sign");
            assert_eq!(coord.state(), SessionState::Done);
            let sig = schnorr::Signature::from_slice(&sig_bytes).expect("parse sig");
            assert!(
                secp.verify_schnorr(&sig, &msg, &q_xonly).is_ok(),
                "pair {label} aggregate must verify under Q"
            );
            assert!(
                secp.verify_schnorr(&sig, &msg, &internal_p).is_err(),
                "pair {label} aggregate must NOT verify under untweaked P"
            );
            println!("G4 pair {label}: aggregate verifies under Q (and fails under P)");
        }
        println!("G4 PASS: all 3 distinct pairs {{1,2}} {{1,3}} {{2,3}} co-sign valid-under-Q (no privileged signer)");
    }
}
