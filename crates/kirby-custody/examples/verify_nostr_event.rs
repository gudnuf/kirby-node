//! INDEPENDENT verifier for a signed Nostr event (a separate code path from the
//! frost-nostr-cosign binary). It is intentionally written from scratch:
//!   1. parse the event JSON,
//!   2. recompute the NIP-01 event id by HAND-BUILDING the canonical serialization
//!      `[0,"<pubkey>",<created_at>,1,[],"<content>"]` (NOT calling the harness's
//!      nip01_event_id helper), sha256 it, and assert it equals the `id` field,
//!   3. decode the npub independently and assert it equals the `pubkey` field,
//!   4. BIP-340 schnorr-verify the `sig` over the event id under the `pubkey`
//!      x-only key.
//!
//! Run: cargo run --example verify_nostr_event -- '<event-json>' [npub]

use bitcoin::secp256k1::{schnorr, Message, Secp256k1, XOnlyPublicKey};
use sha2::{Digest, Sha256};

fn json_escape(s: &str) -> String {
    // Minimal JSON string escaping matching serde_json for ASCII content.
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: verify_nostr_event '<event-json>' [expected-npub]");
        std::process::exit(2);
    }
    let v: serde_json::Value = serde_json::from_str(&args[1]).expect("parse event JSON");

    let id = v["id"].as_str().expect("id");
    let pubkey = v["pubkey"].as_str().expect("pubkey");
    let created_at = v["created_at"].as_u64().expect("created_at");
    let kind = v["kind"].as_u64().expect("kind");
    let content = v["content"].as_str().expect("content");
    let sig = v["sig"].as_str().expect("sig");
    let tags = v["tags"].as_array().expect("tags");
    assert!(tags.is_empty(), "this verifier handles empty tags only");
    assert_eq!(kind, 1, "expected kind:1");

    // (2) Recompute the NIP-01 id from a hand-built canonical string.
    let canonical = format!(
        "[0,\"{}\",{},{},[],\"{}\"]",
        pubkey,
        created_at,
        kind,
        json_escape(content)
    );
    let mut h = Sha256::new();
    h.update(canonical.as_bytes());
    let recomputed = h.finalize();
    let recomputed_hex = hex::encode(recomputed);
    println!("canonical serialization : {canonical}");
    println!("recomputed id            : {recomputed_hex}");
    println!("event id field           : {id}");
    assert_eq!(recomputed_hex, id, "NIP-01 id mismatch (event id is not the hash of its content)");
    println!("ID CHECK: PASS (event id == sha256 of canonical serialization)");

    // (3) Independent npub check, if supplied.
    if let Some(expected_npub) = args.get(2) {
        let (hrp, data) = bech32::decode(expected_npub).expect("decode npub");
        assert_eq!(hrp.to_string(), "npub", "hrp must be npub");
        let npub_hex = hex::encode(&data);
        println!("npub decodes to          : {npub_hex}");
        assert_eq!(npub_hex, pubkey, "npub does not match the event pubkey");
        println!("NPUB CHECK: PASS (npub decodes to the event pubkey)");
    }

    // (4) BIP-340 schnorr verify under the pubkey x-only key.
    let secp = Secp256k1::verification_only();
    let pk_bytes = hex::decode(pubkey).expect("pubkey hex");
    let xonly = XOnlyPublicKey::from_slice(&pk_bytes).expect("x-only pubkey");
    let id_bytes = hex::decode(id).expect("id hex");
    let msg = Message::from_digest(id_bytes.as_slice().try_into().expect("32-byte id"));
    let sig_bytes = hex::decode(sig).expect("sig hex");
    let signature = schnorr::Signature::from_slice(&sig_bytes).expect("64-byte sig");
    match secp.verify_schnorr(&signature, &msg, &xonly) {
        Ok(()) => println!("SCHNORR VERIFY: PASS (valid Nostr event under its npub)"),
        Err(e) => {
            println!("SCHNORR VERIFY: FAIL ({e})");
            std::process::exit(1);
        }
    }
    println!("INDEPENDENT VERIFY: PASS");
}
