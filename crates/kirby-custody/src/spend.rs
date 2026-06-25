//! Key-path taproot spend construction (C-3, D-4 money-path). Build a 1-input
//! 1-output key-path spend tx FROM p2tr(Q), compute the BIP-341 key-path sighash
//! (SighashType::Default), drive the in-process coordinator to a 64-byte signature
//! under the tweaked key Q, and assemble the single-element key-path witness
//! (SIGHASH_DEFAULT, so the witness is the bare 64-byte signature, no type byte).

use bitcoin::hashes::Hash;
use bitcoin::secp256k1::schnorr;
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::transaction::Version;
use bitcoin::{
    absolute::LockTime, Address, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut,
    Txid, Witness,
};

use crate::coordinator::Coordinator;
use frost_secp256k1_tr::keys::KeyPackage;

/// A funding UTXO at p2tr(Q) to spend (the prevout).
pub struct FundingUtxo {
    pub txid: Txid,
    pub vout: u32,
    pub value: Amount,
}

/// Build the UNSIGNED key-path spend tx (1 input from `utxo`, 1 output of
/// `utxo.value - fee` to `destination`) and compute its BIP-341 key-path sighash
/// (SIGHASH_DEFAULT) over the prevout (`address`'s scriptPubKey + amount). Returns
/// the 32-byte sighash and the unsigned tx.
pub fn key_path_sighash(
    address: &Address,
    utxo: &FundingUtxo,
    destination: &Address,
    fee: Amount,
) -> Result<([u8; 32], Transaction), Box<dyn std::error::Error>> {
    let value_out = utxo
        .value
        .checked_sub(fee)
        .ok_or("fee exceeds the funding value")?;

    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: utxo.txid,
                vout: utxo.vout,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: value_out,
            script_pubkey: destination.script_pubkey(),
        }],
    };

    // The prevout: the funding output's scriptPubKey (p2tr(Q)) and amount. BIP-341
    // commits to the prevout's spk + value, so this MUST match the funded output.
    let prevout = TxOut {
        value: utxo.value,
        script_pubkey: address.script_pubkey(),
    };
    let sighash = {
        let mut cache = SighashCache::new(&tx);
        cache.taproot_key_spend_signature_hash(
            0,
            &Prevouts::All(&[prevout]),
            TapSighashType::Default,
        )?
    };
    Ok((sighash.to_byte_array(), tx))
}

/// Assemble the key-path witness from a 64-byte BIP-340 signature: a SINGLE
/// element, the bare 64-byte signature (SIGHASH_DEFAULT appends no type byte).
pub fn key_path_witness(sig_bytes: &[u8; 64]) -> Result<Witness, Box<dyn std::error::Error>> {
    let signature = schnorr::Signature::from_slice(sig_bytes)?;
    let tap_sig = bitcoin::taproot::Signature {
        signature,
        sighash_type: TapSighashType::Default,
    };
    Ok(Witness::p2tr_key_spend(&tap_sig))
}

/// Build, threshold-sign (key-path, merkle_root=None via the coordinator), and
/// serialize a spend of `utxo` (at `address` = p2tr(Q)) sending the value minus
/// `fee` to `destination`. Returns the signed tx hex (for broadcast) and its txid.
pub fn build_key_path_spend(
    coordinator: &mut Coordinator,
    signers: &[KeyPackage],
    address: &Address,
    utxo: &FundingUtxo,
    destination: &Address,
    fee: Amount,
) -> Result<(String, Txid), Box<dyn std::error::Error>> {
    let (sighash, mut tx) = key_path_sighash(address, utxo, destination, fee)?;
    // Threshold-sign the sighash; the coordinator applies the taproot tweak so the
    // 64-byte signature verifies under Q (proven offline below and on-chain at G2).
    let sig_bytes = coordinator.run(signers, &sighash)?;
    tx.input[0].witness = key_path_witness(&sig_bytes)?;
    let txid = tx.compute_txid();
    let tx_hex = bitcoin::consensus::encode::serialize_hex(&tx);
    Ok((tx_hex, txid))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coordinator::key_packages;
    use crate::{generate_dealer_keyset_with_rng, taproot_address};
    use bitcoin::key::TapTweak;
    use bitcoin::secp256k1::{Message, Secp256k1};
    use bitcoin::KnownHrp;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    const C3_SEED: [u8; 32] = *b"kirby-custody-c3-spend-seed-mtny";

    /// Offline G2 precursor: build a REAL key-path spend sighash over a synthetic
    /// prevout, threshold-sign it with a 2-of-3 quorum, and assert the signature
    /// verifies under Q (and fails under P), and the witness is a single 64-byte
    /// element. This is exactly what the live network re-checks at G2: it proves
    /// the sighash construction + witness assembly are correct without broadcasting.
    #[test]
    fn key_path_spend_signature_verifies_under_q() {
        let mut rng = StdRng::from_seed(C3_SEED);
        let keyset = generate_dealer_keyset_with_rng(2, 3, &mut rng).expect("keygen");
        let (address, internal_p) =
            taproot_address(&keyset.pubkeys, KnownHrp::Testnets).expect("address");
        let signers: Vec<KeyPackage> =
            key_packages(&keyset).expect("kp").into_values().take(2).collect();

        // Synthetic funded UTXO (offline; no network).
        let utxo = FundingUtxo {
            txid: "0000000000000000000000000000000000000000000000000000000000000001"
                .parse()
                .unwrap(),
            vout: 0,
            value: Amount::from_sat(100_000),
        };

        let (sighash, _unsigned) =
            key_path_sighash(&address, &utxo, &address, Amount::from_sat(500)).expect("sighash");

        let mut coord = Coordinator::new(keyset.pubkeys.clone(), 2);
        let sig_bytes = coord.run(&signers, &sighash).expect("threshold sign");

        // The witness signature must verify under the tweaked key Q (BIP-341
        // key-path) and FAIL under the untweaked internal key P.
        let secp = Secp256k1::verification_only();
        let (q_tweaked, _parity) = internal_p.tap_tweak(&secp, None);
        let q_xonly = q_tweaked.to_x_only_public_key();
        let sig = schnorr::Signature::from_slice(&sig_bytes).expect("parse sig");
        let msg = Message::from_digest(sighash);
        assert!(
            secp.verify_schnorr(&sig, &msg, &q_xonly).is_ok(),
            "spend signature must verify under Q"
        );
        assert!(
            secp.verify_schnorr(&sig, &msg, &internal_p).is_err(),
            "spend signature must NOT verify under untweaked P"
        );

        // The key-path witness is a single 64-byte element (SIGHASH_DEFAULT).
        let witness = key_path_witness(&sig_bytes).expect("witness");
        assert_eq!(witness.len(), 1, "key-path witness is one element");
        assert_eq!(
            witness.iter().next().unwrap().len(),
            64,
            "SIGHASH_DEFAULT witness is the bare 64-byte signature"
        );
        println!(
            "C-3 offline PASS: key-path spend sighash signed, verifies under Q, fails under P; witness = 1x64 bytes"
        );
    }
}
