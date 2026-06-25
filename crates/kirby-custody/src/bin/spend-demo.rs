//! C-3 spend demo, gate G2 (the real Mutinynet on-chain evidence). Reproduce:
//!   nix develop --command cargo run --release --bin spend-demo
//! (needs a faucet JWT at $FAUCET_JWT or the external FAUCET_JWT_PATH; see chain.rs).
//!
//! Steps (resumable, single-shot): load-or-generate a PERSISTED 2-of-3 keyset ->
//! derive p2tr(Q) -> ensure a confirmed funding UTXO (faucet self-fund) -> build +
//! threshold-sign + broadcast a key-path spend -> confirm -> print the txids, and
//! record the spend so a rerun does NOT re-spend the change output (which would
//! burn test sats). Set KIRBY_SPEND_AGAIN=1 to force a fresh spend.
//!
//! Live network. NOT run by plain `cargo test` (the offline gates stay
//! deterministic; this binary is the documented live reproduce command).

use std::path::{Path, PathBuf};
use std::thread::sleep;
use std::time::Duration;

use bitcoin::{Amount, KnownHrp, Txid};
use kirby_custody::chain::{faucet_fund, Esplora, Utxo};
use kirby_custody::coordinator::{key_packages, Coordinator};
use kirby_custody::persist::{load_keyset, save_keyset};
use kirby_custody::spend::{build_key_path_spend, FundingUtxo};
use kirby_custody::{generate_dealer_keyset, taproot_address};

const KEYSET_PATH: &str = "kirby-custody-keyset.json";
const SPEND_MARKER_PATH: &str = "kirby-custody-last-spend.txt";
const FEE_SATS: u64 = 500;
const FAUCET_SATS: u64 = 100_000;
const POLL_SECS: u64 = 15;
const POLL_TRIES: u32 = 20;

fn poll_confirmed_utxo(esplora: &Esplora, addr: &str) -> Result<Option<Utxo>, Box<dyn std::error::Error>> {
    for attempt in 1..=POLL_TRIES {
        if let Some(best) = esplora.confirmed_utxos(addr)?.into_iter().max_by_key(|u| u.value) {
            return Ok(Some(best));
        }
        println!("  waiting for a confirmed UTXO ({attempt}/{POLL_TRIES})...");
        sleep(Duration::from_secs(POLL_SECS));
    }
    Ok(None)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = PathBuf::from(KEYSET_PATH);

    // 1. Load-or-generate the PERSISTED keyset (NOT ephemeral: the funded address
    //    must reload to stay spendable). The keyset file is written 0600 (persist.rs).
    let keyset = if path.exists() {
        println!("loading persisted keyset from {KEYSET_PATH}");
        load_keyset(&path)?
    } else {
        println!("generating a new trusted-dealer 2-of-3 keyset -> {KEYSET_PATH}");
        let ks = generate_dealer_keyset(2, 3)?;
        save_keyset(&ks, &path)?;
        ks
    };

    // 2. Derive p2tr(Q).
    let (address, _internal_p) = taproot_address(&keyset.pubkeys, KnownHrp::Testnets)?;
    let addr = address.to_string();
    println!("taproot address (p2tr(Q), key-path only, Mutinynet): {addr}");

    // Single-shot guard: if a spend was already completed, reprint it and stop
    // (a confirmed change output looks like fresh funding; re-spending burns sats).
    let marker = PathBuf::from(SPEND_MARKER_PATH);
    if marker.exists() && std::env::var("KIRBY_SPEND_AGAIN").is_err() {
        println!("a spend was already completed (single-shot; set KIRBY_SPEND_AGAIN=1 to spend again):");
        print!("{}", std::fs::read_to_string(&marker)?);
        return Ok(());
    }

    let esplora = Esplora::mutinynet();
    println!("esplora tip height: {}", esplora.tip_height()?);

    // 3. Ensure a confirmed funding UTXO (resumable: reuse one if it already exists).
    let funded = match esplora.confirmed_utxos(&addr)?.into_iter().max_by_key(|u| u.value) {
        Some(u) => {
            println!("found an existing confirmed UTXO; skipping funding");
            u
        }
        None => {
            println!("no confirmed UTXO; self-funding via the faucet ({FAUCET_SATS} sats)...");
            match faucet_fund(&addr, FAUCET_SATS) {
                Ok(txid) => println!("faucet funded: {txid}"),
                Err(e) => {
                    println!("faucet self-fund failed: {e}");
                    println!("fund {addr} on Mutinynet (faucet JWT at FAUCET_JWT_PATH, or web UI) and re-run.");
                }
            }
            match poll_confirmed_utxo(&esplora, &addr)? {
                Some(u) => u,
                None => {
                    println!("no confirmed UTXO yet; fund the address above and re-run (state is persisted).");
                    return Ok(());
                }
            }
        }
    };
    println!("FUNDING UTXO (funding txid): {}:{} = {} sats", funded.txid, funded.vout, funded.value);

    // 4. Build + threshold-sign the 2-of-3 key-path spend (self-send minus fee, so
    //    the funds stay in custody while proving spendability).
    let signers = key_packages(&keyset)?.into_values().take(2).collect::<Vec<_>>();
    let utxo = FundingUtxo {
        txid: funded.txid.parse::<Txid>()?,
        vout: funded.vout,
        value: Amount::from_sat(funded.value),
    };
    let mut coord = Coordinator::new(keyset.pubkeys.clone(), 2);
    let (tx_hex, spend_txid) = build_key_path_spend(
        &mut coord,
        &signers,
        &address,
        &utxo,
        &address,
        Amount::from_sat(FEE_SATS),
    )?;
    println!("signed key-path spend tx: {spend_txid}");

    // 5. Broadcast, record the spend (single-shot guard), then confirm.
    let txid = esplora.broadcast(&tx_hex)?;
    println!("BROADCAST ACCEPTED. spend txid: {txid}");
    let summary = format!(
        "address: {addr}\nfunding txid: {}\nspend txid: {txid}\nexplorer: https://mutinynet.com/tx/{txid}\n",
        utxo.txid
    );
    record_spend(&marker, &summary);
    println!("explorer: https://mutinynet.com/tx/{txid}");
    println!("waiting for the spend to confirm...");
    for attempt in 1..=POLL_TRIES {
        if esplora.tx_status(&txid)?.confirmed {
            println!("=== G2 CONFIRMED ===");
            print!("{summary}");
            return Ok(());
        }
        println!("  not yet confirmed ({attempt}/{POLL_TRIES})...");
        sleep(Duration::from_secs(POLL_SECS));
    }
    println!("broadcast but not yet confirmed; check https://mutinynet.com/tx/{txid} (re-run to re-poll).");
    Ok(())
}

/// Record the completed spend so a rerun does not re-spend the change output.
/// Best-effort (a failed write only means the single-shot guard will not fire).
fn record_spend(marker: &Path, summary: &str) {
    if let Err(e) = std::fs::write(marker, summary) {
        println!("note: could not write the spend marker ({e}); a rerun may re-spend.");
    }
}
