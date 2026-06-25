//! frost-nostr-cosign: a SPLIT (true multi-machine) FROST -> Nostr co-signing harness.
//!
//! A 2-of-3 FROST threshold group, with each KeyPackage on a DIFFERENT machine,
//! collectively signs a real Nostr (kind:1) event. The group's TWEAKED taproot
//! x-only key Q IS the Nostr pubkey (npub). The signature is a BIP-340 schnorr
//! signature over the NIP-01 event id.
//!
//! This binary is ADDITIVE: it reuses kirby-custody's keygen + Q derivation but adds
//! its OWN split transport. It does NOT touch the C-1..C-6 crypto paths. Unlike
//! coordinate_2of3_over_seam (a single-process driver that holds all KeyPackages),
//! here each guardian computes its OWN round1::commit and round2::sign_with_tweak
//! LOCALLY; only opaque non-secret material (SigningCommitments, SigningPackage,
//! SignatureShare) crosses the wire. Secret nonces and KeyPackages NEVER serialize
//! onto the wire.
//!
//! Subcommands:
//!   gen-keyset   --out <dir>
//!   guardian     --connect <host:port> --keypackage <file> --pubkeys <file>
//!   coordinator  --bind <host:port> --keypackage <file> --pubkeys <file>
//!                --expect-guardians <n> --content "<text>" [--relay <ws-url>]
//!                [--created-at <unix>]

use std::collections::BTreeMap;
use std::io::Write;
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use bitcoin::key::TapTweak;
use bitcoin::secp256k1::{schnorr, Message, Secp256k1, XOnlyPublicKey};
use bitcoin::KnownHrp;

use frost_secp256k1_tr as frost;
use frost::keys::{KeyPackage, PublicKeyPackage};
use frost::round1::{SigningCommitments, SigningNonces};
use frost::round2::SignatureShare;
use frost::{Identifier, SigningPackage};

use kirby_custody::cosign_net::{
    nip01_event_id, npub_encode, recv_frame, send_frame, NostrEvent, WireEvent, ROUND_COMMITMENT,
    ROUND_PACKAGE, ROUND_SHARE,
};
use kirby_custody::{generate_dealer_keyset, key_packages, taproot_address};

const PUBKEYS_FILE: &str = "group_pubkeys.json";
const KIND_TEXT_NOTE: u32 = 1;
const SESSION_ID: u64 = 1;

fn main() {
    if let Err(e) = run() {
        eprintln!("ERROR: {e}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        return Err(usage());
    }
    match args[1].as_str() {
        "gen-keyset" => cmd_gen_keyset(&args[2..]),
        "guardian" => cmd_guardian(&args[2..]),
        "coordinator" => cmd_coordinator(&args[2..]),
        other => Err(format!("unknown subcommand '{other}'\n{}", usage())),
    }
}

fn usage() -> String {
    "usage:\n  \
     frost-nostr-cosign gen-keyset --out <dir>\n  \
     frost-nostr-cosign guardian --connect <host:port> --keypackage <file> --pubkeys <file>\n  \
     frost-nostr-cosign coordinator --bind <host:port> --keypackage <file> --pubkeys <file> \
     --expect-guardians <n> --content \"<text>\" [--relay <ws-url>] [--created-at <unix>]"
        .to_string()
}

/// Minimal --flag <value> argument parser.
fn parse_flags(args: &[String]) -> Result<BTreeMap<String, String>, String> {
    let mut map = BTreeMap::new();
    let mut i = 0;
    while i < args.len() {
        let key = &args[i];
        if !key.starts_with("--") {
            return Err(format!("expected a --flag, got '{key}'"));
        }
        let val = args
            .get(i + 1)
            .ok_or_else(|| format!("flag '{key}' needs a value"))?;
        map.insert(key.trim_start_matches("--").to_string(), val.clone());
        i += 2;
    }
    Ok(map)
}

fn require<'a>(flags: &'a BTreeMap<String, String>, key: &str) -> Result<&'a String, String> {
    flags.get(key).ok_or_else(|| format!("missing required --{key}"))
}

// ---------------------------------------------------------------------------
// gen-keyset
// ---------------------------------------------------------------------------

fn cmd_gen_keyset(args: &[String]) -> Result<(), String> {
    let flags = parse_flags(args)?;
    let out = PathBuf::from(require(&flags, "out")?);
    std::fs::create_dir_all(&out).map_err(|e| format!("mkdir {}: {e}", out.display()))?;

    // Production trusted-dealer 2-of-3 over the OS CSPRNG (fresh entropy each run).
    let keyset = generate_dealer_keyset(2, 3).map_err(|e| format!("keygen: {e}"))?;
    let kps = key_packages(&keyset).map_err(|e| format!("key packages: {e}"))?;

    // Group PublicKeyPackage (non-secret) -> file.
    let pub_path = out.join(PUBKEYS_FILE);
    let pub_hex = hex::encode(
        keyset
            .pubkeys
            .serialize()
            .map_err(|e| format!("serialize pubkeys: {e}"))?,
    );
    write_file_0600(&pub_path, pub_hex.as_bytes())?;

    // One KeyPackage per file, named by identifier. The KeyPackage holds the SECRET
    // signing share, so write it owner-only (0600). serde feature serializes it.
    let mut kp_files = Vec::new();
    for (id, kp) in &kps {
        let idx = identifier_to_u16(id);
        let kp_path = out.join(format!("keypackage_{idx}.json"));
        let kp_json = serde_json::to_vec(kp).map_err(|e| format!("serialize keypackage: {e}"))?;
        write_file_0600(&kp_path, &kp_json)?;
        kp_files.push((idx, kp_path));
    }
    kp_files.sort_by_key(|(idx, _)| *idx);

    // The group's tweaked taproot x-only key Q = the agent's Nostr identity.
    let q = kirby_custody::group_xonly_q(&keyset.pubkeys).map_err(|e| format!("Q: {e}"))?;
    let q_hex = hex::encode(q);
    let npub = npub_encode(&q)?;
    // Show the testnet p2tr(Q) address too (sanity: ties Q to the custody address).
    let (addr, _p) =
        taproot_address(&keyset.pubkeys, KnownHrp::Testnets).map_err(|e| format!("addr: {e}"))?;

    println!("gen-keyset: 2-of-3 trusted-dealer keyset written to {}", out.display());
    println!("  group pubkeys file : {}", pub_path.display());
    for (idx, p) in &kp_files {
        println!("  keypackage id {idx}    : {}", p.display());
    }
    println!("  group taproot x-only Q (hex) : {q_hex}");
    println!("  group Nostr identity  (npub) : {npub}");
    println!("  group p2tr(Q) testnet addr   : {addr}");
    Ok(())
}

fn write_file_0600(path: &Path, data: &[u8]) -> Result<(), String> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path).map_err(|e| format!("open {}: {e}", path.display()))?;
    // `mode(0o600)` above only applies when the file is CREATED. If a prior run left an
    // existing file at looser perms (e.g. 0644), re-chmod it AFTER open so a re-run of
    // gen-keyset never leaves a secret KeyPackage world/group-readable (Codex review).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        f.set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("chmod 0600 {}: {e}", path.display()))?;
    }
    f.write_all(data).map_err(|e| format!("write {}: {e}", path.display()))?;
    f.flush().map_err(|e| format!("flush {}: {e}", path.display()))?;
    Ok(())
}

fn identifier_to_u16(id: &Identifier) -> u16 {
    // ZF serializes an Identifier as a 32-byte big-endian scalar; the default
    // dealer identifiers are 1..=n, so the value lives in the last two bytes.
    let bytes = id.serialize();
    let n = bytes.len();
    u16::from_be_bytes([bytes[n - 2], bytes[n - 1]])
}

fn load_pubkeys(path: &str) -> Result<PublicKeyPackage, String> {
    let hex_str = std::fs::read_to_string(path).map_err(|e| format!("read {path}: {e}"))?;
    let bytes = hex::decode(hex_str.trim()).map_err(|e| format!("decode pubkeys hex: {e}"))?;
    PublicKeyPackage::deserialize(&bytes).map_err(|e| format!("deserialize pubkeys: {e}"))
}

fn load_keypackage(path: &str) -> Result<KeyPackage, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("read {path}: {e}"))?;
    serde_json::from_slice(&bytes).map_err(|e| format!("deserialize keypackage: {e}"))
}

// ---------------------------------------------------------------------------
// guardian (remote signer; runs commit + sign LOCALLY, never sends secrets)
// ---------------------------------------------------------------------------

fn cmd_guardian(args: &[String]) -> Result<(), String> {
    let flags = parse_flags(args)?;
    let connect = require(&flags, "connect")?;
    let kp = load_keypackage(require(&flags, "keypackage")?)?;
    let _pubkeys = load_pubkeys(require(&flags, "pubkeys")?)?; // loaded to prove it holds only non-secret group data
    let my_id = identifier_to_u16(kp.identifier());

    eprintln!("guardian id {my_id}: dialing coordinator at {connect} ...");
    let mut stream = TcpStream::connect(connect).map_err(|e| format!("connect {connect}: {e}"))?;
    eprintln!("guardian id {my_id}: connected.");

    // Round 1: receive the START/commit trigger from the coordinator, then commit a
    // FRESH nonce LOCALLY and send only the (opaque) SigningCommitments.
    let trigger = recv_frame(&mut stream)?;
    if trigger.round != ROUND_COMMITMENT {
        return Err(format!("expected a commit trigger (round {ROUND_COMMITMENT}), got round {}", trigger.round));
    }
    let session_id = trigger.session_id;
    let mut rng = rand::rngs::OsRng;
    let (nonce, commitments): (SigningNonces, SigningCommitments) =
        frost::round1::commit(kp.signing_share(), &mut rng);
    let commit_bytes = serde_json::to_vec(&commitments).map_err(|e| format!("encode commitments: {e}"))?;
    send_frame(
        &mut stream,
        &WireEvent::new(session_id, my_id, ROUND_COMMITMENT, &commit_bytes),
    )?;
    eprintln!(
        "guardian id {my_id}: SENT round-1 SigningCommitments ({} bytes opaque). \
         Nonce stays in-process; KeyPackage NOT on the wire.",
        commit_bytes.len()
    );

    // Round 2: receive the SigningPackage (opaque), sign the tweaked share LOCALLY.
    let pkg_frame = recv_frame(&mut stream)?;
    if pkg_frame.round != ROUND_PACKAGE || pkg_frame.session_id != session_id {
        return Err(format!(
            "expected a SigningPackage (round {ROUND_PACKAGE}, session {session_id}), got round {} session {}",
            pkg_frame.round, pkg_frame.session_id
        ));
    }
    let pkg_bytes = pkg_frame.payload()?;
    let package: SigningPackage =
        serde_json::from_slice(&pkg_bytes).map_err(|e| format!("decode package: {e}"))?;
    // DEMO LIMITATION (Codex review) -- THIS GUARDIAN BLIND-SIGNS. It contributes its
    // share for WHATEVER message the coordinator put in the SigningPackage; it does NOT
    // recompute the Nostr event id, derive Q from `pubkeys`, or check
    // `package.message() == expected_id`. That is acceptable for THIS proof harness (one
    // operator, a trusted coordinator, proving the cross-machine co-sign mechanism), but
    // it is NOT safe for production custody: a malicious coordinator could get the quorum
    // to sign an arbitrary message (a different note, or a Bitcoin sighash). PRODUCTION
    // PER-AGENT CUSTODY (fleet S3) MUST add guardian-side validation: send a typed sign
    // request (content + intended kind/created_at), have the guardian derive Q from the
    // PublicKeyPackage, recompute the NIP-01 id, require package.message() == that id, and
    // validate the signer set, BEFORE emitting a share. `pubkeys` is loaded but unused
    // here precisely because that validation is deferred to S3.
    let share: SignatureShare = frost::round2::sign_with_tweak(&package, &nonce, &kp, None)
        .map_err(|e| format!("sign_with_tweak: {e}"))?;
    // `nonce` is consumed by sign_with_tweak's borrow and dropped here; SigningNonces
    // zeroizes its secret on drop (single use).
    let share_bytes = serde_json::to_vec(&share).map_err(|e| format!("encode share: {e}"))?;
    send_frame(
        &mut stream,
        &WireEvent::new(session_id, my_id, ROUND_SHARE, &share_bytes),
    )?;
    eprintln!(
        "guardian id {my_id}: SENT round-2 SignatureShare ({} bytes opaque). \
         Done. Only commitments + share crossed the wire.",
        share_bytes.len()
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// coordinator (also a local signer; computes event id, runs the ceremony)
// ---------------------------------------------------------------------------

fn cmd_coordinator(args: &[String]) -> Result<(), String> {
    let flags = parse_flags(args)?;
    let bind = require(&flags, "bind")?;
    let kp = load_keypackage(require(&flags, "keypackage")?)?;
    let pubkeys = load_pubkeys(require(&flags, "pubkeys")?)?;
    let expect: usize = require(&flags, "expect-guardians")?
        .parse()
        .map_err(|e| format!("--expect-guardians must be a number: {e}"))?;
    let content = require(&flags, "content")?.clone();
    let relay = flags.get("relay").cloned();
    let created_at: u64 = match flags.get("created-at") {
        Some(s) => s.parse().map_err(|e| format!("--created-at must be a unix time: {e}"))?,
        None => SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| format!("clock: {e}"))?
            .as_secs(),
    };

    let my_id = identifier_to_u16(kp.identifier());

    // The group's tweaked taproot x-only key Q = the Nostr pubkey.
    let q = kirby_custody::group_xonly_q(&pubkeys).map_err(|e| format!("Q: {e}"))?;
    let q_hex = hex::encode(q);
    let npub = npub_encode(&q)?;

    // Compute the NIP-01 event id FIRST; THIS is the FROST message.
    let event_id = nip01_event_id(&q_hex, created_at, KIND_TEXT_NOTE, &content);
    let event_id_hex = hex::encode(event_id);

    println!("coordinator id {my_id}: group Nostr identity");
    println!("  Q x-only (hex) : {q_hex}");
    println!("  npub           : {npub}");
    println!("  content        : {content:?}");
    println!("  created_at     : {created_at}");
    println!("  kind           : {KIND_TEXT_NOTE}");
    println!("  NIP-01 event id (FROST message) : {event_id_hex}");
    println!("coordinator id {my_id}: binding {bind}, expecting {expect} remote guardian(s) ...");

    let listener = TcpListener::bind(bind).map_err(|e| format!("bind {bind}: {e}"))?;

    // Accept exactly `expect` guardian connections.
    let mut guardians: Vec<TcpStream> = Vec::with_capacity(expect);
    for _ in 0..expect {
        let (sock, peer) = listener.accept().map_err(|e| format!("accept: {e}"))?;
        eprintln!("coordinator: guardian connected from {peer}");
        guardians.push(sock);
    }

    // --- Round 1 ---
    // Trigger each remote guardian to commit (a commit trigger; payload empty).
    for g in guardians.iter_mut() {
        send_frame(g, &WireEvent::new(SESSION_ID, u16::MAX, ROUND_COMMITMENT, &[]))?;
    }
    // The coordinator is ALSO a signer: commit its OWN fresh nonce LOCALLY.
    let mut rng = rand::rngs::OsRng;
    let (my_nonce, my_commit): (SigningNonces, SigningCommitments) =
        frost::round1::commit(kp.signing_share(), &mut rng);

    let mut commitments_map: BTreeMap<Identifier, SigningCommitments> = BTreeMap::new();
    commitments_map.insert(*kp.identifier(), my_commit);

    // Collect the remote commitments (opaque). Reject a duplicate signer id BEFORE
    // building the package: a duplicate would reuse a single-use round-1 nonce. This
    // mirrors the seam coordinator's dup-signer guard (seam.rs:172-182).
    for g in guardians.iter_mut() {
        let ev = recv_frame(g)?;
        if ev.round != ROUND_COMMITMENT || ev.session_id != SESSION_ID {
            return Err(format!(
                "unexpected round-1 event (session {}, round {})",
                ev.session_id, ev.round
            ));
        }
        let id = u16_to_identifier(ev.from)?;
        if commitments_map.contains_key(&id) {
            return Err(format!(
                "duplicate signer identifier {} in the quorum (would reuse a single-use nonce)",
                ev.from
            ));
        }
        let commit: SigningCommitments =
            serde_json::from_slice(&ev.payload()?).map_err(|e| format!("decode commitment: {e}"))?;
        commitments_map.insert(id, commit);
    }
    eprintln!(
        "coordinator: collected {} commitments ({} local + {} remote)",
        commitments_map.len(),
        1,
        guardians.len()
    );

    // Build ONE SigningPackage over the event id.
    let package = SigningPackage::new(commitments_map, &event_id);
    let pkg_bytes = serde_json::to_vec(&package).map_err(|e| format!("encode package: {e}"))?;

    // --- Round 2 ---
    // Fan out the SigningPackage (opaque) to each remote guardian.
    for g in guardians.iter_mut() {
        send_frame(g, &WireEvent::new(SESSION_ID, u16::MAX, ROUND_PACKAGE, &pkg_bytes))?;
    }
    // Coordinator signs its OWN tweaked share LOCALLY.
    let my_share: SignatureShare = frost::round2::sign_with_tweak(&package, &my_nonce, &kp, None)
        .map_err(|e| format!("local sign_with_tweak: {e}"))?;
    let mut shares_map: BTreeMap<Identifier, SignatureShare> = BTreeMap::new();
    shares_map.insert(*kp.identifier(), my_share);

    // Collect remote shares (opaque).
    for g in guardians.iter_mut() {
        let ev = recv_frame(g)?;
        if ev.round != ROUND_SHARE || ev.session_id != SESSION_ID {
            return Err(format!(
                "unexpected round-2 event (session {}, round {})",
                ev.session_id, ev.round
            ));
        }
        let id = u16_to_identifier(ev.from)?;
        let share: SignatureShare =
            serde_json::from_slice(&ev.payload()?).map_err(|e| format!("decode share: {e}"))?;
        shares_map.insert(id, share);
    }
    eprintln!("coordinator: collected {} signature shares", shares_map.len());

    // Aggregate the tweaked BIP-340 signature under Q.
    let group_sig =
        frost::aggregate_with_tweak(&package, &shares_map, &pubkeys, None).map_err(|e| {
            format!("aggregate_with_tweak: {e}")
        })?;
    let sig_bytes_vec = group_sig.serialize().map_err(|e| format!("serialize sig: {e}"))?;
    let sig_bytes: [u8; 64] = sig_bytes_vec
        .as_slice()
        .try_into()
        .map_err(|_| format!("expected 64-byte signature, got {}", sig_bytes_vec.len()))?;
    let sig_hex = hex::encode(sig_bytes);

    // Verify locally: BIP-340 schnorr verify of sig over event_id under Q x-only.
    let secp = Secp256k1::verification_only();
    let q_xonly = XOnlyPublicKey::from_slice(&q).map_err(|e| format!("Q x-only parse: {e}"))?;
    let sig = schnorr::Signature::from_slice(&sig_bytes).map_err(|e| format!("sig parse: {e}"))?;
    let msg = Message::from_digest(event_id);
    let verify = secp.verify_schnorr(&sig, &msg, &q_xonly);
    // Defense-in-depth: it must FAIL under the untweaked internal key P.
    let (_addr, internal_p) =
        taproot_address(&pubkeys, KnownHrp::Testnets).map_err(|e| format!("addr: {e}"))?;
    let _ = internal_p.tap_tweak(&secp, None); // Q derivation already done above
    let under_p = secp.verify_schnorr(&sig, &msg, &internal_p);

    if verify.is_ok() {
        println!("LOCAL VERIFY: PASS (schnorr sig over the NIP-01 event id verifies under Q)");
    } else {
        println!("LOCAL VERIFY: FAIL ({verify:?})");
    }
    if under_p.is_err() {
        println!("LOCAL VERIFY: sig correctly does NOT verify under the untweaked internal key P (tweak is real)");
    } else {
        println!("LOCAL VERIFY: WARNING sig also verified under P (tweak not applied?)");
    }

    // Assemble the signed Nostr event.
    let event = NostrEvent {
        id: event_id_hex.clone(),
        pubkey: q_hex.clone(),
        created_at,
        kind: KIND_TEXT_NOTE,
        tags: vec![],
        content: content.clone(),
        sig: sig_hex.clone(),
    };
    let event_json = serde_json::to_string(&event).map_err(|e| format!("encode event: {e}"))?;
    println!("SIGNED NOSTR EVENT JSON:");
    println!("{event_json}");

    if verify.is_err() {
        return Err("local schnorr verify FAILED; refusing to claim success".to_string());
    }

    // Optionally publish to a relay over a plaintext WebSocket (ws://, no TLS). A relay
    // that rejects the event (or any non-accepting reply) is a hard error (nonzero exit),
    // not a swallowed log line (Codex review). The local verify above already passed, so
    // this failing means a relay/transport problem, which the operator must see.
    if let Some(relay_url) = relay {
        let resp = publish_to_relay(&relay_url, &event)
            .map_err(|e| format!("relay publish to {relay_url} failed: {e}"))?;
        println!("RELAY ({relay_url}) accepted: {resp}");
    } else {
        println!("(no --relay given; not publishing)");
    }
    Ok(())
}

fn u16_to_identifier(v: u16) -> Result<Identifier, String> {
    Identifier::try_from(v).map_err(|e| format!("bad identifier {v}: {e}"))
}

/// Publish a signed event to a relay over a plaintext WebSocket and return the
/// relay's first text response (expected: an `["OK", <id>, true, ""]` message).
fn publish_to_relay(url: &str, event: &NostrEvent) -> Result<String, String> {
    use tungstenite::Message as WsMessage;
    if url.starts_with("wss://") {
        return Err("this build is plaintext ws:// only (no TLS); use a ws:// relay".to_string());
    }
    let (mut socket, _resp) =
        tungstenite::connect(url).map_err(|e| format!("ws connect {url}: {e}"))?;
    let msg = serde_json::json!(["EVENT", event]);
    let text = serde_json::to_string(&msg).map_err(|e| format!("encode EVENT: {e}"))?;
    socket
        .send(WsMessage::Text(text))
        .map_err(|e| format!("ws send: {e}"))?;
    // Read the relay's reply (OK/NOTICE). One read is enough for the OK frame.
    let reply = socket.read().map_err(|e| format!("ws read: {e}"))?;
    let _ = socket.close(None);
    let text = match reply {
        WsMessage::Text(t) => t.to_string(),
        other => return Err(format!("relay sent a non-text reply: {other:?}")),
    };
    // Require a NIP-01 OK frame ACCEPTING this exact event: ["OK", <event.id>, true, _].
    // A bare first-text-frame is not enough: relays send ["OK", id, false, reason] for
    // rejections and NOTICE frames for errors; treating those as success would mask a
    // failed publish (Codex review).
    let parsed: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| format!("relay reply not JSON ({e}): {text}"))?;
    let arr = parsed
        .as_array()
        .ok_or_else(|| format!("relay reply is not a JSON array: {text}"))?;
    if arr.first().and_then(|v| v.as_str()) != Some("OK") {
        return Err(format!("relay did not send an OK frame: {text}"));
    }
    if arr.get(1).and_then(|v| v.as_str()) != Some(event.id.as_str()) {
        return Err(format!("relay OK frame is for a different event id: {text}"));
    }
    if arr.get(2).and_then(|v| v.as_bool()) != Some(true) {
        return Err(format!("relay REJECTED the event: {text}"));
    }
    Ok(text)
}
