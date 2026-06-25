//! D-14 transport seam (C-6): the RelayAdapter trait, an in-memory same-host
//! carrier, and a coordinator that drives the 2-of-3 ceremony over the seam by
//! exchanging OPAQUE CoSignEvents. The carrier inspects ONLY session_id + round +
//! destination (routing/dedupe), NEVER the payload, so a real transport (the
//! kirby-nostr relay, nerve slice-2) drops in unchanged.
//!
//! This is ADDITIVE: the crypto is identical to the in-process Coordinator (C-2),
//! which is left untouched, so the existing gates G1-G5 stay green. The real
//! two-machine run (separate boxes over a Nostr relay at this seam) is OUT of C-6
//! (kirby-nostr nerve slice-2 + a 2nd box, gudnuf-gated); it retires the multi-node
//! custody claim by dropping into this same seam.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::rc::Rc;

use frost_secp256k1_tr as frost;
use frost::keys::{KeyPackage, PublicKeyPackage};
use frost::round1::{SigningCommitments, SigningNonces};
use frost::round2::SignatureShare;
use frost::{Identifier, SigningPackage};

use crate::coordinator::SignError;

/// A guardian's identity on the wire (the FROST identifier).
pub type GuardianId = Identifier;

/// CoSignEvent round discriminant. D-16 specifies 1 = commitment and 2 = share (the
/// signer -> coordinator partials). PACKAGE (3) is the coordinator's SigningPackage
/// fan-out (coordinator -> signers), added so the coordinator-centric flow runs
/// ENTIRELY over the opaque seam; the carrier routes by it and never reads the payload.
pub const ROUND_COMMITMENT: u8 = 1;
pub const ROUND_SHARE: u8 = 2;
pub const ROUND_PACKAGE: u8 = 3;

/// Reserved wire address for the coordinator/aggregator (never a signer identifier).
const COORDINATOR_ADDR: u16 = u16::MAX;

fn coordinator_id() -> GuardianId {
    GuardianId::try_from(COORDINATOR_ADDR).expect("reserved coordinator id is valid")
}

/// Transport error surfaced by the carrier (kept distinct from SignError).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportError {
    /// The destination endpoint is not registered on this carrier.
    Unreachable(String),
    /// The inbox is empty / no event is available.
    Closed,
}

/// The opaque co-sign envelope (D-14 / D-16). The carrier reads only session_id +
/// round (+ the destination on send); the payload is opaque serialized ZF bytes
/// (a SigningCommitments, a SigningPackage, or a SignatureShare).
#[derive(Debug, Clone)]
pub struct CoSignEvent {
    pub session_id: u64,
    pub from: GuardianId,
    pub round: u8,
    pub payload: Vec<u8>,
}

/// The D-14 transport seam. Coordinator-centric (FROST is aggregator-shaped):
/// send(to) covers the coordinator fanning out the SigningPackage and signers
/// returning partials. A real impl wraps and signs a Nostr event; the in-memory
/// impl below is the same-host carrier.
#[allow(async_fn_in_trait)]
pub trait RelayAdapter {
    async fn send(&self, to: GuardianId, event: CoSignEvent) -> Result<(), TransportError>;
    async fn recv(&self) -> Result<(GuardianId, CoSignEvent), TransportError>;
}

/// In-memory same-host carrier: per-endpoint inboxes keyed by GuardianId. It routes
/// purely by destination and NEVER deserializes a payload (proven by the opacity test).
#[derive(Default)]
struct Bus {
    inboxes: BTreeMap<GuardianId, VecDeque<CoSignEvent>>,
}

/// A shared in-memory relay; hand out one endpoint per party.
pub struct InMemoryRelay {
    bus: Rc<RefCell<Bus>>,
}

impl InMemoryRelay {
    pub fn new() -> Self {
        Self {
            bus: Rc::new(RefCell::new(Bus::default())),
        }
    }

    /// An endpoint bound to `me` (registers its inbox).
    pub fn endpoint(&self, me: GuardianId) -> InMemoryAdapter {
        self.bus.borrow_mut().inboxes.entry(me).or_default();
        InMemoryAdapter {
            me,
            bus: Rc::clone(&self.bus),
        }
    }

    /// The coordinator/aggregator endpoint (reserved address).
    pub fn coordinator(&self) -> InMemoryAdapter {
        self.endpoint(coordinator_id())
    }
}

impl Default for InMemoryRelay {
    fn default() -> Self {
        Self::new()
    }
}

/// An in-memory RelayAdapter endpoint bound to one GuardianId.
#[derive(Clone)]
pub struct InMemoryAdapter {
    me: GuardianId,
    bus: Rc<RefCell<Bus>>,
}

impl RelayAdapter for InMemoryAdapter {
    async fn send(&self, to: GuardianId, event: CoSignEvent) -> Result<(), TransportError> {
        // Route by destination ONLY; the payload is never inspected.
        let mut bus = self.bus.borrow_mut();
        match bus.inboxes.get_mut(&to) {
            Some(inbox) => {
                inbox.push_back(event);
                Ok(())
            }
            None => Err(TransportError::Unreachable(format!(
                "no endpoint registered for {to:?}"
            ))),
        }
    }

    async fn recv(&self) -> Result<(GuardianId, CoSignEvent), TransportError> {
        let event = self
            .bus
            .borrow_mut()
            .inboxes
            .get_mut(&self.me)
            .and_then(|q| q.pop_front());
        match event {
            Some(e) => Ok((e.from, e)),
            None => Err(TransportError::Closed),
        }
    }
}

fn transport_err(e: TransportError) -> SignError {
    SignError::QuorumUnavailable(format!("transport: {e:?}"))
}

fn codec_err(context: &str, e: impl std::fmt::Display) -> SignError {
    SignError::Internal(format!("{context}: {e}"))
}

/// Drive a 2-of-(n) FROST ceremony entirely over the RelayAdapter seam, exchanging
/// OPAQUE CoSignEvents, and return the 64-byte BIP-340 signature under the tweaked
/// key Q. `signers` are the participating guardians (each a (id, endpoint, key
/// package)); `coordinator` is the aggregator endpoint. Same crypto as the C-2
/// Coordinator; only the message transport differs. Secret nonces stay local and
/// are NEVER serialized onto the wire (D-16).
pub async fn coordinate_2of3_over_seam<A: RelayAdapter>(
    coordinator: &A,
    signers: &[(GuardianId, &A, &KeyPackage)],
    pubkeys: &PublicKeyPackage,
    message: &[u8],
    session_id: u64,
) -> Result<[u8; 64], SignError> {
    let threshold = signers.len();

    // Reject a duplicate signer identifier BEFORE round 1: a duplicate would reuse a
    // single-use round-1 nonce. This is the same guard C-2's Coordinator enforces; a
    // NEW signing entry point (this seam coordinator) needs it too.
    let mut seen: BTreeSet<GuardianId> = BTreeSet::new();
    for &(id, _ep, _kp) in signers {
        if !seen.insert(id) {
            return Err(SignError::DuplicateSigner(format!(
                "identifier {id:?} appears more than once in the quorum"
            )));
        }
    }

    // Round 1: each signer commits a FRESH nonce and sends its commitment (opaque)
    // to the coordinator. The secret nonces stay local; they are never serialized.
    let mut nonces: BTreeMap<GuardianId, SigningNonces> = BTreeMap::new();
    for &(id, ep, kp) in signers {
        let mut rng = rand::rngs::OsRng;
        let (nonce, commitments) = frost::round1::commit(kp.signing_share(), &mut rng);
        nonces.insert(id, nonce);
        let payload = serde_json::to_vec(&commitments).map_err(|e| codec_err("commitment", e))?;
        ep.send(
            coordinator_id(),
            CoSignEvent {
                session_id,
                from: id,
                round: ROUND_COMMITMENT,
                payload,
            },
        )
        .await
        .map_err(transport_err)?;
    }

    // Coordinator: collect >= threshold commitments, build ONE SigningPackage.
    let mut commitments_map: BTreeMap<GuardianId, SigningCommitments> = BTreeMap::new();
    for _ in 0..threshold {
        let (from, event) = coordinator.recv().await.map_err(transport_err)?;
        if event.session_id != session_id || event.round != ROUND_COMMITMENT {
            return Err(SignError::QuorumUnavailable(format!(
                "unexpected round-1 event (session {}, round {})",
                event.session_id, event.round
            )));
        }
        let commitments =
            serde_json::from_slice(&event.payload).map_err(|e| codec_err("commitment decode", e))?;
        commitments_map.insert(from, commitments);
    }
    let package = SigningPackage::new(commitments_map, message);

    // Coordinator: fan out the SigningPackage (opaque) to each signer.
    let package_payload = serde_json::to_vec(&package).map_err(|e| codec_err("package", e))?;
    for &(id, _ep, _kp) in signers {
        coordinator
            .send(
                id,
                CoSignEvent {
                    session_id,
                    from: coordinator_id(),
                    round: ROUND_PACKAGE,
                    payload: package_payload.clone(),
                },
            )
            .await
            .map_err(transport_err)?;
    }

    // Round 2: each signer receives the package, signs the tweaked share, sends it.
    for &(id, ep, kp) in signers {
        let (_from, event) = ep.recv().await.map_err(transport_err)?;
        if event.session_id != session_id || event.round != ROUND_PACKAGE {
            return Err(SignError::QuorumUnavailable(format!(
                "unexpected package event (session {}, round {})",
                event.session_id, event.round
            )));
        }
        let signing_package: SigningPackage =
            serde_json::from_slice(&event.payload).map_err(|e| codec_err("package decode", e))?;
        // remove() CONSUMES the nonce: each is used at most once and zeroizes on
        // drop after this single use (a stray duplicate would find none and abort).
        let nonce = nonces.remove(&id).ok_or_else(|| {
            SignError::Internal("missing local nonce for a signer (duplicate or internal error)".to_string())
        })?;
        let share = frost::round2::sign_with_tweak(&signing_package, &nonce, kp, None)
            .map_err(|e| SignError::BadShare(e.to_string()))?;
        let payload = serde_json::to_vec(&share).map_err(|e| codec_err("share", e))?;
        ep.send(
            coordinator_id(),
            CoSignEvent {
                session_id,
                from: id,
                round: ROUND_SHARE,
                payload,
            },
        )
        .await
        .map_err(transport_err)?;
    }

    // Coordinator: collect >= threshold shares, aggregate the tweaked signature.
    let mut shares_map: BTreeMap<GuardianId, SignatureShare> = BTreeMap::new();
    for _ in 0..threshold {
        let (from, event) = coordinator.recv().await.map_err(transport_err)?;
        if event.session_id != session_id || event.round != ROUND_SHARE {
            return Err(SignError::QuorumUnavailable(format!(
                "unexpected round-2 event (session {}, round {})",
                event.session_id, event.round
            )));
        }
        let share = serde_json::from_slice(&event.payload).map_err(|e| codec_err("share decode", e))?;
        shares_map.insert(from, share);
    }
    let group_sig = frost::aggregate_with_tweak(&package, &shares_map, pubkeys, None)
        .map_err(|e| SignError::QuorumUnavailable(e.to_string()))?;
    let bytes = group_sig.serialize().map_err(|e| codec_err("signature", e))?;
    <[u8; 64]>::try_from(bytes.as_slice())
        .map_err(|_| SignError::Internal(format!("expected 64-byte signature, got {}", bytes.len())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coordinator::key_packages;
    use crate::{generate_dealer_keyset_with_rng, taproot_address};
    use bitcoin::key::TapTweak;
    use bitcoin::secp256k1::{schnorr, Message, Secp256k1, XOnlyPublicKey};
    use bitcoin::KnownHrp;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    const SEAM_SEED: [u8; 32] = *b"kirby-custody-c6-seam-seed-mtny!";

    fn verifies_under_q(sig_bytes: &[u8; 64], message: &[u8; 32], internal_p: XOnlyPublicKey) -> bool {
        let secp = Secp256k1::verification_only();
        let (q_tweaked, _parity) = internal_p.tap_tweak(&secp, None);
        let q_xonly = q_tweaked.to_x_only_public_key();
        let Ok(sig) = schnorr::Signature::from_slice(sig_bytes) else {
            return false;
        };
        secp.verify_schnorr(&sig, &Message::from_digest(*message), &q_xonly)
            .is_ok()
    }

    /// G6 (same-host loopback, the first acceptance bar per D-7): run the 2-of-3
    /// ceremony over the in-memory RelayAdapter and assert a valid Q-signature.
    #[test]
    fn g6_same_host_seam_produces_q_sig() {
        let mut rng = StdRng::from_seed(SEAM_SEED);
        let keyset = generate_dealer_keyset_with_rng(2, 3, &mut rng).expect("keygen");
        let (_addr, internal_p) =
            taproot_address(&keyset.pubkeys, KnownHrp::Testnets).expect("address");
        let kps: Vec<KeyPackage> =
            key_packages(&keyset).expect("key packages").into_values().take(2).collect();

        let relay = InMemoryRelay::new();
        let coordinator = relay.coordinator();
        let endpoints: Vec<InMemoryAdapter> =
            kps.iter().map(|kp| relay.endpoint(*kp.identifier())).collect();
        let signers: Vec<(GuardianId, &InMemoryAdapter, &KeyPackage)> = kps
            .iter()
            .zip(endpoints.iter())
            .map(|(kp, ep)| (*kp.identifier(), ep, kp))
            .collect();

        let message = [0x42u8; 32];
        let sig = futures::executor::block_on(coordinate_2of3_over_seam(
            &coordinator,
            &signers,
            &keyset.pubkeys,
            &message,
            1,
        ))
        .expect("2-of-3 ceremony over the seam");

        assert!(
            verifies_under_q(&sig, &message, internal_p),
            "the seam-driven aggregate must verify under Q"
        );
        println!("G6 PASS: 2-of-3 over the in-memory RelayAdapter produced a Q-valid signature (same-host seam)");
    }

    /// A test-only RelayAdapter wrapper that records every event it SENDS, so a test
    /// can observe exactly what hit the wire.
    struct RecordingAdapter {
        inner: InMemoryAdapter,
        log: std::rc::Rc<std::cell::RefCell<Vec<CoSignEvent>>>,
    }
    impl RelayAdapter for RecordingAdapter {
        async fn send(&self, to: GuardianId, event: CoSignEvent) -> Result<(), TransportError> {
            self.log.borrow_mut().push(event.clone());
            self.inner.send(to, event).await
        }
        async fn recv(&self) -> Result<(GuardianId, CoSignEvent), TransportError> {
            self.inner.recv().await
        }
    }

    /// G7 (nonce single-use, forced session retry over the seam): running the FULL
    /// ceremony twice puts DISTINCT round-1 commitments on the wire across the two
    /// sessions, so a forced retry/restart never reuses a nonce (the spec's G7 letter,
    /// observed on the wire, not just at the commit() unit level).
    #[test]
    fn g7_forced_session_retry_distinct_wire_commitments() {
        use std::cell::RefCell;
        use std::rc::Rc;

        let mut rng = StdRng::from_seed(SEAM_SEED);
        let keyset = generate_dealer_keyset_with_rng(2, 3, &mut rng).expect("keygen");
        let kps: Vec<KeyPackage> =
            key_packages(&keyset).expect("key packages").into_values().take(2).collect();
        let message = [0x42u8; 32];

        let run_once = |session_id: u64| -> Vec<Vec<u8>> {
            let log = Rc::new(RefCell::new(Vec::<CoSignEvent>::new()));
            let relay = InMemoryRelay::new();
            let coordinator = RecordingAdapter {
                inner: relay.coordinator(),
                log: Rc::clone(&log),
            };
            let endpoints: Vec<RecordingAdapter> = kps
                .iter()
                .map(|kp| RecordingAdapter {
                    inner: relay.endpoint(*kp.identifier()),
                    log: Rc::clone(&log),
                })
                .collect();
            let signers: Vec<(GuardianId, &RecordingAdapter, &KeyPackage)> = kps
                .iter()
                .zip(endpoints.iter())
                .map(|(kp, ep)| (*kp.identifier(), ep, kp))
                .collect();
            futures::executor::block_on(coordinate_2of3_over_seam(
                &coordinator,
                &signers,
                &keyset.pubkeys,
                &message,
                session_id,
            ))
            .expect("ceremony over the seam");
            let mut commits: Vec<Vec<u8>> = log
                .borrow()
                .iter()
                .filter(|e| e.round == ROUND_COMMITMENT)
                .map(|e| e.payload.clone())
                .collect();
            commits.sort();
            commits
        };

        let run1 = run_once(1);
        let run2 = run_once(2); // a forced retry / restarted session
        assert_eq!(run1.len(), 2, "each ceremony puts two round-1 commitments on the wire");
        assert_ne!(
            run1, run2,
            "a forced session retry must put DISTINCT round-1 commitments on the wire (no nonce reuse)"
        );
        println!("G7 PASS: a forced session retry over the seam puts distinct round-1 commitments on the wire (single-use nonces, no reuse)");
    }

    /// The seam coordinator (a NEW signing entry point) rejects a duplicate GuardianId
    /// BEFORE round 1, like C-2's Coordinator, so no round-1 nonce can be reused.
    #[test]
    fn seam_rejects_duplicate_signer() {
        let mut rng = StdRng::from_seed(SEAM_SEED);
        let keyset = generate_dealer_keyset_with_rng(2, 3, &mut rng).expect("keygen");
        let kps: Vec<KeyPackage> =
            key_packages(&keyset).expect("key packages").into_values().take(2).collect();
        let relay = InMemoryRelay::new();
        let coordinator = relay.coordinator();
        let ep = relay.endpoint(*kps[0].identifier());
        // A quorum list containing the SAME signer twice.
        let signers: Vec<(GuardianId, &InMemoryAdapter, &KeyPackage)> = vec![
            (*kps[0].identifier(), &ep, &kps[0]),
            (*kps[0].identifier(), &ep, &kps[0]),
        ];
        let message = [0x42u8; 32];
        let result = futures::executor::block_on(coordinate_2of3_over_seam(
            &coordinator,
            &signers,
            &keyset.pubkeys,
            &message,
            9,
        ));
        assert!(
            matches!(result, Err(SignError::DuplicateSigner(_))),
            "the seam coordinator must reject a duplicate signer, got {result:?}"
        );
        println!("SEAM-DUP PASS: the seam coordinator rejects a duplicate GuardianId before round 1 (no nonce reuse)");
    }

    /// Transport-agnostic property: the carrier routes by destination and delivers
    /// ARBITRARY (even non-frost / garbage) payload bytes verbatim, NEVER parsing
    /// them. This is what lets kirby-nostr's relay drop into the seam unchanged.
    #[test]
    fn carrier_never_inspects_payload() {
        let relay = InMemoryRelay::new();
        let coordinator = relay.coordinator();
        let signer_id = GuardianId::try_from(1u16).unwrap();
        let signer = relay.endpoint(signer_id);

        let garbage = vec![0xde, 0xad, 0xbe, 0xef, 0x00, 0xff, 0x42];
        let event = CoSignEvent {
            session_id: 7,
            from: signer_id,
            round: ROUND_COMMITMENT,
            payload: garbage.clone(),
        };
        futures::executor::block_on(signer.send(coordinator_id(), event)).expect("send");
        let (from, got) = futures::executor::block_on(coordinator.recv()).expect("recv");

        assert_eq!(from, signer_id);
        assert_eq!(
            got.payload, garbage,
            "the carrier delivered the opaque payload verbatim (it never parsed it)"
        );
        println!("OPACITY PASS: the carrier routes by destination and delivers opaque payload bytes verbatim (never deserializes)");
    }
}
