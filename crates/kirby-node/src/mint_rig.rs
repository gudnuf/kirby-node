//! Wallet helpers for the C-6 brokered act (gate G5, D-16): build a `cdk::Wallet`
//! against a mint and fund it on the local fakewallet mint.
//!
//! These wrap the CDK wallet API so the real rail ([`crate::rail::CdkEcashRail`])
//! and the G5 test share one funded-wallet path. The wallet IS the host-only
//! credential the genome never sees; it is constructed and funded host-side and
//! never serialized across vsock.
//!
//! The mint itself (a real cdk-mintd HTTP mint with the cdk-fake-wallet Lightning
//! backend) is BOOTED in the G5 test (it uses cdk-mintd, a dev-dependency); these
//! lib helpers only build and fund a wallet against a mint URL, using the runtime
//! cdk deps.

use std::sync::Arc;

use cdk::amount::{Amount, SplitTarget};
use cdk::nuts::{CurrencyUnit, PaymentMethod};
use cdk::wallet::Wallet;
use cdk::StreamExt;

/// Build a `cdk::Wallet` (Sat unit) against `mint_url`, backed by an in-memory
/// sqlite store, with a fresh random seed. The wallet is the rail's host-only
/// credential. `mint_url` is the local fakewallet mint (e.g. `http://127.0.0.1:8086`).
pub async fn build_wallet(mint_url: &str) -> anyhow::Result<Arc<Wallet>> {
    use rand::TryRngCore;

    // A fresh random 64-byte wallet seed (the cdk Wallet derives its keys from
    // it). Host-only; never serialized to the genome. Drawn from the host CSPRNG,
    // the same source the gateway entropy nonce uses.
    let mut seed = [0u8; 64];
    rand::rngs::OsRng
        .try_fill_bytes(&mut seed)
        .map_err(|e| anyhow::anyhow!("draw wallet seed from the host CSPRNG: {e}"))?;

    let localstore = cdk_sqlite::wallet::memory::empty()
        .await
        .map_err(|e| anyhow::anyhow!("open in-memory wallet store: {e}"))?;

    let wallet = Wallet::new(mint_url, CurrencyUnit::Sat, Arc::new(localstore), seed, None)
        .map_err(|e| anyhow::anyhow!("build cdk wallet against {mint_url}: {e}"))?;
    Ok(Arc::new(wallet))
}

/// Fund `wallet` with `amount` sats on the local fakewallet mint. Mirrors the cdk
/// integration-tests `fund_wallet`: request a BOLT11 mint quote, which the
/// fakewallet backend auto-marks paid, then mint the proofs (the proof stream
/// resolves once the quote is paid). After this the wallet holds spendable proofs
/// the rail can settle with.
pub async fn fund_wallet(wallet: Arc<Wallet>, amount_sats: u64) -> anyhow::Result<()> {
    let amount = Amount::from(amount_sats);
    let quote = wallet
        .mint_quote(PaymentMethod::BOLT11, Some(amount), None, None)
        .await
        .map_err(|e| anyhow::anyhow!("mint_quote for funding: {e}"))?;

    // The fakewallet backend marks the quote paid after a short delay; the proof
    // stream yields the minted proofs once paid.
    wallet
        .proof_stream(quote, SplitTarget::default(), None)
        .next()
        .await
        .ok_or_else(|| anyhow::anyhow!("funding proof stream ended with no proofs"))?
        .map_err(|e| anyhow::anyhow!("funding proofs errored: {e}"))?;
    Ok(())
}
