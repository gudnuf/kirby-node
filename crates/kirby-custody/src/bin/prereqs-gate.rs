//! Custody prereqs-gate (C-1). Proves the toolchain, the deps, and the chain are
//! present, then runs the trusted-dealer 2-of-3 keygen and prints the derived
//! taproot address. Run inside the dev shell:
//!   nix develop --command cargo run --bin prereqs-gate
//!
//! Pass / fail is machine-checkable: a non-zero exit means a prereq failed.

use std::process::Command;

use bitcoin::KnownHrp;
use kirby_custody::{generate_dealer_keyset, taproot_address};

/// Mutinynet esplora tip-height endpoint (charter / D-11: curl it, print the height).
const ESPLORA_TIP: &str = "https://mutinynet.com/api/blocks/tip/height";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("== kirby-custody prereqs-gate (C-1) ==");

    // 1. rustc present (the toolchain comes from the flake, not the host).
    let rustc = Command::new("rustc").arg("--version").output()?;
    if !rustc.status.success() {
        return Err("rustc --version failed".into());
    }
    print!("rustc: {}", String::from_utf8_lossy(&rustc.stdout));

    // 2. rust-bitcoin + ZF frost build/link. This binary compiled against both,
    //    and steps 4 and 5 exercise both at runtime (keygen, then tweak/address).
    println!("deps: rust-bitcoin + ZF frost-secp256k1-tr linked (binary built against both)");

    // 3. Mutinynet esplora reachable: curl the tip-height endpoint, print the height.
    let tip = Command::new("curl")
        .args(["-sS", "--max-time", "20", ESPLORA_TIP])
        .output()?;
    if !tip.status.success() {
        return Err(format!("esplora unreachable: curl exit {:?}", tip.status.code()).into());
    }
    let tip_height = String::from_utf8_lossy(&tip.stdout);
    let tip_height = tip_height.trim();
    // Sanity: the tip must parse as a positive integer (not an error page).
    let height: u64 = tip_height
        .parse()
        .map_err(|_| format!("unexpected tip-height body: {tip_height:?}"))?;
    println!("esplora tip height (Mutinynet): {height}");

    // 4. Trusted-dealer 2-of-3 keygen (D-2, D-6).
    let keyset = generate_dealer_keyset(2, 3)?;
    if keyset.shares.len() != 3 {
        return Err(format!("expected 3 shares, got {}", keyset.shares.len()).into());
    }
    println!("keygen: trusted-dealer 2-of-3 generated {} shares", keyset.shares.len());

    // 5. Derive the taproot address (key-path only, merkle_root = None; D-16).
    //    Signet / Mutinynet uses the `tb` HRP (KnownHrp::Testnets).
    let (address, internal_key) = taproot_address(&keyset.pubkeys, KnownHrp::Testnets)?;
    println!("group internal key P (x-only): {internal_key}");
    println!("taproot address P2TR(Q), key-path only, Mutinynet: {address}");

    println!("== prereqs-gate PASS ==");
    Ok(())
}
