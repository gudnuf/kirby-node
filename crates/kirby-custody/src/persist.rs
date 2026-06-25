//! Keyset persistence (C-3). The dealer keyset (the per-guardian SecretShares plus
//! the group PublicKeyPackage) is saved to disk so the funded p2tr(Q) address
//! reloads and stays spendable AFTER funding: the SAME keyset that derived the
//! address must come back. Honest label (D-2): in v0 all shares are saved together
//! (trusted dealer); real per-guardian distribution is later. This is NOT the
//! OsRng-ephemeral path: a persisted keyset is reused across runs.
//!
//! The file holds the 2-of-3 SECRET SHARES, so it is written owner-only (0600),
//! atomically (temp file + fsync + rename), and any pre-existing file is tightened
//! to 0600 before load. Never world-readable on a shared box. The same atomic-0600
//! discipline is reused for the refreshed keyset (C-5) via write_owner_only_atomic.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::Path;

use frost_secp256k1_tr::keys::{PublicKeyPackage, SecretShare};
use frost_secp256k1_tr::Identifier;
use serde::{Deserialize, Serialize};

use crate::DealerKeyset;

/// On-disk form: hex-encoded ZF serializations (no serde feature needed; the
/// frost key types serialize to bytes natively).
#[derive(Serialize, Deserialize)]
struct PersistedKeyset {
    /// Hex of PublicKeyPackage::serialize().
    pubkeys: String,
    /// Hex of each SecretShare::serialize() (each share self-describes its identifier).
    shares: Vec<String>,
}

/// Force owner-only (0600) permissions on a path. Unix only (no-op elsewhere).
#[cfg(unix)]
pub(crate) fn set_owner_only(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}
#[cfg(not(unix))]
pub(crate) fn set_owner_only(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

/// Write `data` to `path` owner-only (0600) and atomically: a 0600 temp file in the
/// same directory, written, fsync'd, then renamed over `path` (atomic on the same
/// filesystem). Secret material is never momentarily world-readable. Reused for any
/// secret-bearing file (the keyset and the refreshed keyset).
pub(crate) fn write_owner_only_atomic(
    path: &Path,
    data: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or("path has no file name")?;
    let tmp = dir.join(format!(".{file_name}.tmp"));
    {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp)?;
        // Defensive: a pre-existing temp file keeps its old mode (OpenOptions::mode
        // only applies on creation), so force 0600 before writing secret bytes.
        set_owner_only(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// Save a dealer keyset to `path` as JSON (hex-encoded frost serializations),
/// owner-only and atomically.
pub fn save_keyset(keyset: &DealerKeyset, path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let pubkeys = hex::encode(keyset.pubkeys.serialize()?);
    let mut shares = Vec::with_capacity(keyset.shares.len());
    for share in keyset.shares.values() {
        shares.push(hex::encode(share.serialize()?));
    }
    let data = serde_json::to_vec_pretty(&PersistedKeyset { pubkeys, shares })?;
    write_owner_only_atomic(path, &data)
}

/// Load a dealer keyset previously written by save_keyset. Any pre-existing file
/// (e.g. one a prior version wrote 0644) is tightened to 0600 before reading.
pub fn load_keyset(path: &Path) -> Result<DealerKeyset, Box<dyn std::error::Error>> {
    if path.exists() {
        set_owner_only(path)?;
    }
    let bytes = std::fs::read(path)?;
    let persisted: PersistedKeyset = serde_json::from_slice(&bytes)?;
    let pubkeys = PublicKeyPackage::deserialize(&hex::decode(&persisted.pubkeys)?)?;
    let mut shares: BTreeMap<Identifier, SecretShare> = BTreeMap::new();
    for share_hex in &persisted.shares {
        let share = SecretShare::deserialize(&hex::decode(share_hex)?)?;
        shares.insert(*share.identifier(), share);
    }
    Ok(DealerKeyset { shares, pubkeys })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{generate_dealer_keyset_with_rng, taproot_address};
    use bitcoin::KnownHrp;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    const PERSIST_SEED: [u8; 32] = *b"kirby-custody-c3-persist-seedmtn";

    /// A saved keyset round-trips: the reloaded keyset derives the SAME taproot
    /// address (so a funded address stays spendable after a restart) and keeps all
    /// three shares.
    #[test]
    fn keyset_round_trips_to_same_address() {
        let mut rng = StdRng::from_seed(PERSIST_SEED);
        let keyset = generate_dealer_keyset_with_rng(2, 3, &mut rng).expect("keygen");
        let (addr_before, _p) =
            taproot_address(&keyset.pubkeys, KnownHrp::Testnets).expect("address");

        let path = std::env::temp_dir().join("kirby-custody-persist-test.json");
        let _ = std::fs::remove_file(&path);
        save_keyset(&keyset, &path).expect("save");
        let reloaded = load_keyset(&path).expect("load");
        let _ = std::fs::remove_file(&path);

        assert_eq!(reloaded.shares.len(), 3, "all three shares reload");
        let (addr_after, _p2) =
            taproot_address(&reloaded.pubkeys, KnownHrp::Testnets).expect("address");
        assert_eq!(
            addr_before.to_string(),
            addr_after.to_string(),
            "reloaded keyset must derive the same p2tr(Q) address"
        );
    }

    /// The persisted keyset (the 2-of-3 SECRET SHARES) must be owner-only (0600),
    /// never world-readable on a shared box.
    #[test]
    #[cfg(unix)]
    fn persisted_keyset_is_owner_only_0600() {
        use std::os::unix::fs::PermissionsExt;
        let mut rng = StdRng::from_seed(PERSIST_SEED);
        let keyset = generate_dealer_keyset_with_rng(2, 3, &mut rng).expect("keygen");
        let path = std::env::temp_dir().join("kirby-custody-perms-test.json");
        let _ = std::fs::remove_file(&path);
        save_keyset(&keyset, &path).expect("save");
        let mode = std::fs::metadata(&path).expect("metadata").permissions().mode() & 0o777;
        let _ = std::fs::remove_file(&path);
        assert_eq!(mode, 0o600, "secret-share file must be 0600, got {mode:o}");
    }
}
