//! C-5 reshare demo, gate G5 (real on-chain proof that resharing moves no funds).
//! Reproduce: nix develop --command cargo run --release --bin reshare-demo
//!
//! Steps (single-shot): load the persisted dealer keyset -> reshare (ZF keys::refresh,
//! group key preserved) -> persist the refreshed keyset (0600) -> assert the address
//! is unchanged -> spend a pre-existing UTXO at that address with the REFRESHED quorum
//! -> confirm -> print the G5 txid. The SAME funds at the SAME address are spent by the
//! post-reshare quorum, with no on-chain move between rotations.
//!
//! Live network. NOT run by plain cargo test. Reuses the existing G2 UTXO; a faucet
//! JWT is needed only if the address has no confirmed UTXO. KIRBY_SPEND_AGAIN=1 redoes.

use std::path::PathBuf;
use std::thread::sleep;
use std::time::Duration;

use bitcoin::{Amount, KnownHrp, Txid};
use frost_secp256k1_tr::keys::KeyPackage;
use kirby_custody::chain::{faucet_fund, Esplora};
use kirby_custody::coordinator::Coordinator;
use kirby_custody::persist::load_keyset;
use kirby_custody::reshare::{reshare_same_membership, save_refreshed};
use kirby_custody::spend::{build_key_path_spend, FundingUtxo};
use kirby_custody::taproot_address;

const KEYSET_PATH: &str = "kirby-custody-keyset.json";
const REFRESHED_PATH: &str = "kirby-custody-refreshed.json";
const G5_MARKER_PATH: &str = "kirby-custody-g5-spend.txt";
const FEE_SATS: u64 = 500;
const FAUCET_SATS: u64 = 100_000;
const POLL_SECS: u64 = 15;
const POLL_TRIES: u32 = 20;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let keyset_path = PathBuf::from(KEYSET_PATH);
    if !keyset_path.exists() {
        return Err(format!("no dealer keyset at {KEYSET_PATH}; run spend-demo (G2) first").into());
    }
    let original = load_keyset(&keyset_path)?;
    let (orig_addr, _p) = taproot_address(&original.pubkeys, KnownHrp::Testnets)?;
    let addr = orig_addr.to_string();
    println!("original p2tr(Q) address: {addr}");

    // Single-shot guard.
    let marker = PathBuf::from(G5_MARKER_PATH);
    if marker.exists() && std::env::var("KIRBY_SPEND_AGAIN").is_err() {
        println!("G5 already completed (single-shot; set KIRBY_SPEND_AGAIN=1 to redo):");
        print!("{}", std::fs::read_to_string(&marker)?);
        return Ok(());
    }

    // 1. Reshare (group key preserved) + persist the refreshed keyset (0600).
    let refreshed = reshare_same_membership(&original)?;
    save_refreshed(&refreshed, &PathBuf::from(REFRESHED_PATH))?;
    println!("reshared: refreshed 2-of-3 keyset written to {REFRESHED_PATH} (0600)");

    // 2. Same-address assertion (the load-bearing G5 property).
    let (new_addr, _p) = taproot_address(&refreshed.pubkeys, KnownHrp::Testnets)?;
    if new_addr.to_string() != addr {
        return Err(format!("reshare changed the address: {addr} -> {new_addr}").into());
    }
    println!("address PRESERVED across reshare: {new_addr}");

    // 3. Ensure a confirmed UTXO (reuse the existing G2 change UTXO; fund only if gone).
    let esplora = Esplora::mutinynet();
    println!("esplora tip height: {}", esplora.tip_height()?);
    let mut funded = esplora.confirmed_utxos(&addr)?.into_iter().max_by_key(|u| u.value);
    if funded.is_none() {
        println!("no confirmed UTXO; self-funding via faucet ({FAUCET_SATS} sats)...");
        match faucet_fund(&addr, FAUCET_SATS) {
            Ok(txid) => println!("faucet funded: {txid}"),
            Err(e) => println!("faucet fund failed: {e}; fund {addr} and re-run."),
        }
        for attempt in 1..=POLL_TRIES {
            sleep(Duration::from_secs(POLL_SECS));
            funded = esplora.confirmed_utxos(&addr)?.into_iter().max_by_key(|u| u.value);
            if funded.is_some() {
                break;
            }
            println!("  waiting for a confirmed UTXO ({attempt}/{POLL_TRIES})...");
        }
    }
    let funded = funded.ok_or("no confirmed UTXO to spend; fund the address and re-run")?;
    println!(
        "spending UTXO {}:{} = {} sats with the REFRESHED quorum",
        funded.txid, funded.vout, funded.value
    );

    // 4. Spend with the REFRESHED quorum (post-reshare shares), self-send to the SAME address.
    let signers: Vec<KeyPackage> = refreshed.key_packages.values().take(2).cloned().collect();
    let utxo = FundingUtxo {
        txid: funded.txid.parse::<Txid>()?,
        vout: funded.vout,
        value: Amount::from_sat(funded.value),
    };
    let mut coord = Coordinator::new(refreshed.pubkeys.clone(), 2);
    let (tx_hex, spend_txid) = build_key_path_spend(
        &mut coord,
        &signers,
        &orig_addr,
        &utxo,
        &orig_addr,
        Amount::from_sat(FEE_SATS),
    )?;
    println!("signed G5 spend tx (refreshed quorum): {spend_txid}");

    // 5. Broadcast, record (single-shot), confirm.
    let txid = esplora.broadcast(&tx_hex)?;
    println!("BROADCAST ACCEPTED. G5 spend txid: {txid}");
    let summary = format!(
        "address: {addr}\nreshare: ZF keys::refresh (group key preserved)\nspent UTXO: {}:{}\nG5 spend txid: {txid}\nexplorer: https://mutinynet.com/tx/{txid}\n",
        utxo.txid, utxo.vout
    );
    if let Err(e) = std::fs::write(&marker, &summary) {
        println!("note: could not write the G5 marker ({e}).");
    }
    println!("explorer: https://mutinynet.com/tx/{txid}");
    println!("waiting for the G5 spend to confirm...");
    for attempt in 1..=POLL_TRIES {
        if esplora.tx_status(&txid)?.confirmed {
            println!("=== G5 CONFIRMED (refreshed quorum spent the same address, no on-chain move) ===");
            print!("{summary}");
            return Ok(());
        }
        println!("  not yet confirmed ({attempt}/{POLL_TRIES})...");
        sleep(Duration::from_secs(POLL_SECS));
    }
    println!("broadcast but not yet confirmed; check https://mutinynet.com/tx/{txid} (re-run to re-poll).");
    Ok(())
}
