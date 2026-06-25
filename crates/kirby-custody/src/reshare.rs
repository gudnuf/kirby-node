//! Proactive resharing (C-5, gate G5) via ZF keys::refresh. Re-randomizes the
//! share material over the SAME membership; the group verifying_key (and therefore
//! p2tr(Q) and the address) is PRESERVED, so no funds move and the address is
//! unchanged. The refreshed quorum can spend the same pre-existing UTXOs.
//!
//! HONEST framing (D-16, do NOT overclaim): this is rotate-the-shares plus
//! operationally-erase-old-shares, NOT cryptographic revocation. keys::refresh
//! preserves the group key, so a RETAINED pre-refresh share still reconstructs the
//! same group secret and can still sign. True revocation requires moving funds to a
//! fresh key, which is out of MVP scope.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use frost_secp256k1_tr as frost;
use frost::keys::refresh::{compute_refreshing_shares, refresh_share};
use frost::keys::{KeyPackage, PublicKeyPackage};
use frost::Identifier;
use serde::{Deserialize, Serialize};

use crate::DealerKeyset;

/// A refreshed keyset: the post-reshare per-guardian KeyPackages plus the group
/// PublicKeyPackage. The group verifying_key (the address) is preserved; only the
/// share material changes. Signing uses these KeyPackages directly via Coordinator.
pub struct RefreshedKeyset {
    pub key_packages: BTreeMap<Identifier, KeyPackage>,
    pub pubkeys: PublicKeyPackage,
}

/// Proactively reshare a dealer keyset over the SAME membership (same identifiers).
/// Dealer-style ZF refresh (D-8): compute zero-shares (a fresh sharing of zero),
/// then fold each into its member's current key package. The group key is preserved
/// (zero-secret), so the address and funds do not move.
pub fn reshare_same_membership(
    keyset: &DealerKeyset,
) -> Result<RefreshedKeyset, Box<dyn std::error::Error>> {
    // The authoritative membership is the group's verifying-share set. Reject a
    // truncated or mismatched keyset: ZF compute_refreshing_shares treats a SUBSET
    // as participant REMOVAL, which would silently refresh a SMALLER group under the
    // same Q (e.g. a 2-of-2 wearing the 2-of-3 address). Refuse rather than degrade.
    let group_ids: BTreeSet<Identifier> =
        keyset.pubkeys.verifying_shares().keys().copied().collect();
    let share_ids: BTreeSet<Identifier> = keyset.shares.keys().copied().collect();
    if share_ids != group_ids {
        return Err(format!(
            "keyset is truncated or mismatched: {} share(s) vs {} group member(s); refusing to reshare a degraded group",
            share_ids.len(),
            group_ids.len()
        )
        .into());
    }
    let identifiers: Vec<Identifier> = group_ids.iter().copied().collect();

    let mut rng = rand::rngs::OsRng;
    let (refreshing_shares, pubkeys) =
        compute_refreshing_shares(keyset.pubkeys.clone(), &identifiers, &mut rng)?;
    let min_signers = pubkeys
        .min_signers()
        .ok_or("refreshed pubkeys missing min_signers")?;
    let group_vk = *pubkeys.verifying_key();

    let mut key_packages: BTreeMap<Identifier, KeyPackage> = BTreeMap::new();
    for zero_share in refreshing_shares {
        let id = *zero_share.identifier();
        let old_share = keyset
            .shares
            .get(&id)
            .ok_or("refreshing share for an unknown identifier")?;
        let old_kp = KeyPackage::try_from(old_share.clone())?;
        let refreshed = refresh_share(zero_share, &old_kp)?;
        // refresh_share updates the signing share but keeps the OLD embedded
        // verifying_share; rebuild the KeyPackage with the refreshed verifying share
        // (from the new pubkeys) so the persisted per-package metadata is consistent.
        let verifying_share = pubkeys
            .verifying_shares()
            .get(&id)
            .ok_or("refreshed pubkeys missing a verifying share")?
            .to_owned();
        let fixed = KeyPackage::new(
            id,
            refreshed.signing_share().to_owned(),
            verifying_share,
            group_vk,
            min_signers,
        );
        key_packages.insert(id, fixed);
    }
    Ok(RefreshedKeyset {
        key_packages,
        pubkeys,
    })
}

/// On-disk form for a refreshed keyset: hex-encoded ZF serializations.
#[derive(Serialize, Deserialize)]
struct PersistedRefreshed {
    pubkeys: String,
    key_packages: Vec<String>,
}

/// Save a refreshed keyset owner-only (0600) and atomically (it holds secret signing
/// material; same discipline as the dealer keyset, reusing persist::write_owner_only_atomic).
pub fn save_refreshed(
    refreshed: &RefreshedKeyset,
    path: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let pubkeys = hex::encode(refreshed.pubkeys.serialize()?);
    let mut key_packages = Vec::with_capacity(refreshed.key_packages.len());
    for kp in refreshed.key_packages.values() {
        key_packages.push(hex::encode(kp.serialize()?));
    }
    let data = serde_json::to_vec_pretty(&PersistedRefreshed {
        pubkeys,
        key_packages,
    })?;
    crate::persist::write_owner_only_atomic(path, &data)
}

/// Load a refreshed keyset previously written by save_refreshed (tightening perms to
/// 0600 first, like the dealer keyset).
pub fn load_refreshed(path: &Path) -> Result<RefreshedKeyset, Box<dyn std::error::Error>> {
    if path.exists() {
        crate::persist::set_owner_only(path)?;
    }
    let bytes = std::fs::read(path)?;
    let persisted: PersistedRefreshed = serde_json::from_slice(&bytes)?;
    let pubkeys = PublicKeyPackage::deserialize(&hex::decode(&persisted.pubkeys)?)?;
    let mut key_packages: BTreeMap<Identifier, KeyPackage> = BTreeMap::new();
    for kp_hex in &persisted.key_packages {
        let kp = KeyPackage::deserialize(&hex::decode(kp_hex)?)?;
        key_packages.insert(*kp.identifier(), kp);
    }
    Ok(RefreshedKeyset {
        key_packages,
        pubkeys,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coordinator::{key_packages, Coordinator, SessionState};
    use crate::{generate_dealer_keyset_with_rng, taproot_address};
    use bitcoin::key::TapTweak;
    use bitcoin::secp256k1::{schnorr, Message, Secp256k1, XOnlyPublicKey};
    use bitcoin::KnownHrp;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    const RESHARE_SEED: [u8; 32] = *b"kirby-custody-c5-reshare-seedmtn";

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

    /// G5 (offline): a proactive reshare PRESERVES the address (group key), the
    /// REFRESHED quorum signs under Q, the refreshed shares actually CHANGED, and
    /// (honestly, D-16) an OLD-share quorum STILL signs under Q (operational erase,
    /// NOT cryptographic revocation).
    #[test]
    fn g5_reshare_preserves_address_and_old_shares_still_sign() {
        let mut rng = StdRng::from_seed(RESHARE_SEED);
        let original = generate_dealer_keyset_with_rng(2, 3, &mut rng).expect("keygen");
        let (orig_addr, internal_p) =
            taproot_address(&original.pubkeys, KnownHrp::Testnets).expect("address");

        let refreshed = reshare_same_membership(&original).expect("reshare");

        // (1) SAME ADDRESS: the refreshed keyset derives the identical p2tr(Q).
        let (new_addr, _p) =
            taproot_address(&refreshed.pubkeys, KnownHrp::Testnets).expect("address");
        assert_eq!(
            orig_addr.to_string(),
            new_addr.to_string(),
            "reshare must preserve the address (group key)"
        );

        // (2) The reshare actually re-randomized the share material (not a no-op).
        let some_id = *original.shares.keys().next().unwrap();
        let orig_kp = key_packages(&original).expect("key packages");
        let orig_share_bytes = orig_kp[&some_id].serialize().expect("serialize");
        let new_share_bytes = refreshed.key_packages[&some_id].serialize().expect("serialize");
        assert_ne!(
            orig_share_bytes, new_share_bytes,
            "reshare must change the share material"
        );

        let message = [0x55u8; 32];

        // (3) The REFRESHED quorum produces a Q-valid signature.
        let new_signers: Vec<KeyPackage> =
            refreshed.key_packages.values().take(2).cloned().collect();
        let mut coord = Coordinator::new(refreshed.pubkeys.clone(), 2);
        let new_sig = coord.run(&new_signers, &message).expect("refreshed sign");
        assert_eq!(coord.state(), SessionState::Done);
        assert!(
            verifies_under_q(&new_sig, &message, internal_p),
            "the refreshed quorum must verify under Q"
        );

        // (4) HONEST (D-16): an OLD-share quorum STILL produces a Q-valid signature.
        //     keys::refresh preserves the group key, so retained old shares are not
        //     cryptographically revoked; the erase is operational only.
        let old_signers: Vec<KeyPackage> = orig_kp.into_values().take(2).collect();
        let mut coord_old = Coordinator::new(original.pubkeys.clone(), 2);
        let old_sig = coord_old.run(&old_signers, &message).expect("old-share sign");
        assert!(
            verifies_under_q(&old_sig, &message, internal_p),
            "OLD shares STILL verify under Q (operational, not cryptographic, erase)"
        );

        println!("G5 PASS (offline): reshare preserves the address; refreshed quorum signs under Q; OLD shares STILL sign under Q (operational erase, NOT crypto revocation)");
    }

    /// The refreshed keyset persists owner-only (0600) and round-trips to the same address.
    #[test]
    fn refreshed_keyset_round_trips_0600() {
        let mut rng = StdRng::from_seed(RESHARE_SEED);
        let original = generate_dealer_keyset_with_rng(2, 3, &mut rng).expect("keygen");
        let refreshed = reshare_same_membership(&original).expect("reshare");
        let (addr, _p) = taproot_address(&refreshed.pubkeys, KnownHrp::Testnets).expect("address");

        let path = std::env::temp_dir().join("kirby-custody-refreshed-test.json");
        let _ = std::fs::remove_file(&path);
        save_refreshed(&refreshed, &path).expect("save");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).expect("metadata").permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "refreshed keyset must be 0600, got {mode:o}");
        }
        let reloaded = load_refreshed(&path).expect("load");
        let _ = std::fs::remove_file(&path);
        assert_eq!(reloaded.key_packages.len(), 3, "all three refreshed packages reload");
        let (addr2, _p) = taproot_address(&reloaded.pubkeys, KnownHrp::Testnets).expect("address");
        assert_eq!(
            addr.to_string(),
            addr2.to_string(),
            "reloaded refreshed keyset derives the same address"
        );
    }

    /// A truncated keyset (fewer shares than the group's verifying-share set) is
    /// REJECTED, never silently refreshed into a smaller group under the same Q.
    #[test]
    fn truncated_keyset_is_rejected() {
        let mut rng = StdRng::from_seed(RESHARE_SEED);
        let full = generate_dealer_keyset_with_rng(2, 3, &mut rng).expect("keygen");
        let mut shares = full.shares.clone();
        let drop_id = *shares.keys().next().unwrap();
        shares.remove(&drop_id);
        let truncated = crate::DealerKeyset {
            shares,
            pubkeys: full.pubkeys.clone(),
        };
        let result = reshare_same_membership(&truncated);
        assert!(
            result.is_err(),
            "a truncated keyset must be rejected, not silently refreshed into a smaller group"
        );
        println!("RESHARE-GUARD PASS: a truncated keyset is rejected (no silent group degradation)");
    }

    /// The refreshed keyset persists, RELOADS from disk, and the reloaded quorum
    /// produces a Q-valid signature -- locking persistence + the refreshed
    /// verifying-share metadata fix.
    #[test]
    fn refreshed_keyset_reloads_and_signs_under_q() {
        let mut rng = StdRng::from_seed(RESHARE_SEED);
        let original = generate_dealer_keyset_with_rng(2, 3, &mut rng).expect("keygen");
        let (_addr, internal_p) =
            taproot_address(&original.pubkeys, KnownHrp::Testnets).expect("address");
        let refreshed = reshare_same_membership(&original).expect("reshare");

        let path = std::env::temp_dir().join("kirby-custody-reload-sign-test.json");
        let _ = std::fs::remove_file(&path);
        save_refreshed(&refreshed, &path).expect("save");
        let reloaded = load_refreshed(&path).expect("load");
        let _ = std::fs::remove_file(&path);

        let signers: Vec<KeyPackage> = reloaded.key_packages.values().take(2).cloned().collect();
        let mut coord = Coordinator::new(reloaded.pubkeys.clone(), 2);
        let message = [0x66u8; 32];
        let sig = coord.run(&signers, &message).expect("reloaded refreshed sign");
        assert!(
            verifies_under_q(&sig, &message, internal_p),
            "the persisted+reloaded refreshed quorum must verify under Q"
        );
        println!("RELOAD-SIGN PASS: persisted+reloaded refreshed quorum signs valid-under-Q (metadata consistent)");
    }
}
