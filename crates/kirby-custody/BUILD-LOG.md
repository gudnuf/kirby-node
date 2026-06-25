# BUILD-LOG (append-only)

Machine evidence for the Kirby custody backbone. Each entry pastes the gate output,
the derived address, and the exact commands to reproduce from a clean `nix develop`.
Diff against the canonical spec (plans/build-spec-kirby-custody-backbone-20260617.md),
never a chat log.

---

## C-1: scaffold + trusted-dealer 2-of-3 keygen + taproot address (2026-06-23)

Worker: worker:frost-c1. Branch: c1-scaffold. Crate base: ZF frost-secp256k1-tr 3.0.0 (D-15).
Scope: C-1 ONLY (scaffold, prereqs-gate, keygen, address). No coordinator/signing (C-2+).

### Toolchain (lean, D-11)

From the flake (no host rustc; Rust comes from `nix develop`):

```
nix (Nix) 2.31.3
rustc 1.90.0 (1159e78c4 2025-09-14)
cargo 1.90.0 (840b83a10 2025-07-30)
clippy 0.1.90 (1159e78c47 2025-09-14)
curl 8.20.0 (from nix; pinned in the dev shell so the esplora check is reproducible)
```

flake.lock pins (committed; the verifier resolves the same inputs):

```
nixpkgs       github:NixOS/nixpkgs/567a49d1913ce81ac6e9582e3553dd90a955875f      (2026-06-16)
rust-overlay  github:oxalica/rust-overlay/f59bc28dd0b89e9c0240d1b80195559fc79c2471 (2026-06-23)
flake-utils   github:numtide/flake-utils/11707dc2f618dd54ca8739b309ec4fc024de578b  (2024-11-13)
```

Key resolved deps (Cargo.lock committed): frost-secp256k1-tr 3.0.0, frost-core 3.0.0,
bitcoin 0.32.10, secp256k1 0.29.1, secp256k1-sys 0.10.1, k256 0.13.4, rand 0.8.6.

### Prereqs-gate output

`nix develop --command cargo run --bin prereqs-gate`

```
== kirby-custody prereqs-gate (C-1) ==
rustc: rustc 1.90.0 (1159e78c4 2025-09-14)
deps: rust-bitcoin + ZF frost-secp256k1-tr linked (binary built against both)
esplora tip height (Mutinynet): 3206620
keygen: trusted-dealer 2-of-3 generated 3 shares
group internal key P (x-only): c5d52f69510a48492ff6162030bc6deaf8670b99461929db26c19e11a31d0785
taproot address P2TR(Q), key-path only, Mutinynet: tb1pk97r35wsthrvmfdznjd7m90as6k2yzmzdpp7mrycedey54lrkgfqenv8md
== prereqs-gate PASS ==
```

### Derived taproot address (two values, both legitimate)

The trusted dealer uses OsRng, so the gate derives a FRESH keyset (and address) every
run by design. To give the verifier an exact reproducible anchor on the load-bearing
P -> Q -> P2TR(Q) derivation, a deterministic fixture seed is asserted in a test.

- Gate (production path, OsRng, NON-deterministic; differs per run):
  the run above derived `tb1pk97r35wsthrvmfdznjd7m90as6k2yzmzdpp7mrycedey54lrkgfqenv8md`
  (an earlier run derived `tb1p2qe5jpt0nj9g7vfjkxv02l3dgh6t2lkfz2uf2q8yqmcjrpuuyghqx8uczs`;
  both valid, by design).
- Fixture (deterministic, REPRODUCIBLE anchor, asserted by `cargo test fixture_address_is_stable`):
  `tb1phuk09kvd7e392qxutmfudfydr4yylhzvgm2n3wv4xpx0dsq2mcws8dw7hf`
  (seed = b"kirby-custody-c1-seed-mutinynet!", non-secret, zero-funds Mutinynet, test-only).

Derivation (D-16, normative): P = group verifying_key (x-only internal key) ->
t = TapTweak(P, merkle_root=None) -> Q = P + t*G -> address = P2TR(Q), KEY-PATH ONLY
(no script tree). Done via rust-bitcoin UntweakedPublicKey::tap_tweak(secp, None) ->
TweakedPublicKey -> Address::p2tr_tweaked, HRP = testnet/signet (tb). C-2 (G1) proves a
signature verifies under exactly this Q and fails under P; this address must use
merkle_root = None.

### Tests / lint / build (all green)

```
cargo test                                   -> 2 passed (dealer_keyset_is_2_of_3, fixture_address_is_stable)
cargo build --release                        -> Finished `release` profile [optimized]
cargo clippy --all-targets -- -D warnings    -> Finished (no warnings)
em-dash scan (git ls-files | xargs grep)     -> clean (no em-dashes)
```

### Reproduce from a clean checkout

```
git clone <repo> kirby-custody && cd kirby-custody && git checkout c1-scaffold
nix develop --command cargo build --release
nix develop --command cargo run  --bin prereqs-gate            # prints toolchain, live esplora tip, keygen, a FRESH address
nix develop --command cargo test                               # fixture_address_is_stable asserts the reproducible address above
nix develop --command cargo clippy --all-targets -- -D warnings
```

DoD status: prereqs-gate passes (output pasted above); 2-of-3 keyset generates (3 shares);
taproot address derives and prints; build + clippy -D warnings clean; no em-dashes;
this log holds the prereqs output + address + repro commands. C-1 complete.

---

## C-2: in-process FROST coordinator + tweaked signing, gate G1 (2026-06-23)

Worker: worker:frost-c1. Branch: c2-coordinator off main (trunk 8f5d08f). Builds on the C-1
lib (taproot_address + generate_dealer_keyset_with_rng). Crate base: ZF frost-secp256k1-tr
3.0.0 (D-15). Scope: coordinator + tweaked signing + G1 ONLY (NOT C-3 sighash/witness/
broadcast, NOT C-4 dedicated G3/G4, NOT relay transport).

### What was built

- src/coordinator.rs: the in-process FROST coordinator, D-16 state machine
  Idle -> Round1Collect -> PackageReady -> Round2Collect -> Aggregate -> Done | Aborted,
  observable via Coordinator::state(). One ceremony = one FRESH nonce per signer; the round-1
  secret nonce is single-use and zeroized on drop after round-2 (frost SigningNonces derives
  ZeroizeOnDrop), never persisted/serialized (D-16).
- Tweaked signing path (native ZF, no bifrost): per signer frost::round1::commit -> ONE
  SigningPackage::new -> frost::round2::sign_with_tweak(merkle_root=None) ->
  frost::aggregate_with_tweak(merkle_root=None) -> 64-byte BIP-340 sig under the tweaked key Q.
- Abort handling: sub-threshold / bad-share / aggregation failure -> Aborted, returns a clean
  SignError (QuorumUnavailable | BadShare | Internal) toward the D-10 shape; NEVER panics.

### Gate G1 output (the headline money-path safety gate)

`nix develop --command cargo test coordinator::tests -- --nocapture`

```
running 2 tests
ABORT PASS: 1-of-3 sub-threshold ceremony Aborted with QuorumUnavailable (no panic)
test coordinator::tests::sub_threshold_aborts_cleanly ... ok
G1 PASS: verify under tweaked Q = OK; verify under untweaked P = REJECTED; merkle_root=None; Q != P
test coordinator::tests::g1_verify_under_q_pass_under_p_fail ... ok
test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 2 filtered out; finished in 0.03s
```

G1 asserts (fixed 32-byte digest [0x42; 32], 2-of-3 quorum {1,2}, deterministic fixture seed
b"kirby-custody-c2-g1-seed-mutiny!"):
- the aggregate VERIFIES under the tweaked output key Q (the exact Q from the C-1
  taproot_address derivation: P -> tap_tweak(merkle_root=None) -> Q) via secp256k1
  verify_schnorr against Q's x-only key;
- the SAME signature FAILS under the untweaked internal key P (proves the tweak is real);
- merkle_root = None throughout (sign_with_tweak / aggregate_with_tweak / tap_tweak all None),
  and Q != P (a non-trivial tweak, so no script-path leaf was committed).

A real BIP-341 sighash over an actual tx + the on-chain spend is C-3; for G1 a fixed 32-byte
message is correct (G1 is verify-under-Q-not-P, not the tx).

### Tests / lint / build (all green)

```
cargo test                                -> 4 passed (C-1: dealer_keyset_is_2_of_3, fixture_address_is_stable; C-2: g1_verify_under_q_pass_under_p_fail, sub_threshold_aborts_cleanly)
cargo build --release                     -> Finished `release` profile [optimized]
cargo clippy --all-targets -- -D warnings -> Finished (no warnings)
em-dash scan (git ls-files | xargs grep)  -> clean
```

### Reproduce from a clean checkout

```
git clone <repo> kirby-custody && cd kirby-custody && git checkout c2-coordinator
nix develop --command cargo build --release
nix develop --command cargo test coordinator::tests -- --nocapture   # G1: under-Q pass, under-P fail; sub-threshold abort
nix develop --command cargo test                                      # all 4
nix develop --command cargo clippy --all-targets -- -D warnings
```

DoD status: G1 green (under-Q pass AND under-P fail AND merkle_root=None asserted, output
pasted); happy-path 2-of-3 produces a valid tweaked aggregate; sub-threshold session errors
cleanly (QuorumUnavailable, no panic); build + test + clippy -D warnings clean; no em-dashes;
this entry appended. C-2 complete (coordinator + tweaked signing + G1). C-3 (sighash/witness/
broadcast + real Mutinynet spend) is next.

### C-2 hardening (pre-merge, from the ground-truth verify + Codex deep pass)

Two coordinator money-path fixes landed on top of the C-2 core (still branch c2-coordinator):

- [med] DUPLICATE SIGNERS: a quorum slice with a repeated identifier (e.g. [1,2,1]) previously
  collapsed in the nonce/commitment BTreeMaps while round2 iterated the slice, reusing a
  single-use nonce. FIX: reject a duplicate kp.identifier() up front (before round1) with
  SignError::DuplicateSigner, AND consume nonces via remove() in round2 (a stray duplicate
  finds no nonce and aborts rather than reusing). Each nonce now zeroizes immediately after its
  single use (owned, dropped per iteration). Test: duplicate_signer_is_rejected.
- [low] TERMINAL STATE: run() could be re-invoked after Done/Aborted. FIX: a terminal-state
  guard returns SignError::InvalidState unless state == Idle, leaving the prior state intact.
  Test: run_is_single_shot.

Tests after hardening (nix develop --command cargo test coordinator::tests -- --nocapture):

```
running 4 tests
DUP PASS: quorum with a duplicate identifier rejected before signing (no nonce reuse)
test coordinator::tests::duplicate_signer_is_rejected ... ok
ABORT PASS: 1-of-3 sub-threshold ceremony Aborted with QuorumUnavailable (no panic)
test coordinator::tests::sub_threshold_aborts_cleanly ... ok
TERMINAL PASS: run() is single-shot; re-invocation after Done rejected, state unchanged
test coordinator::tests::run_is_single_shot ... ok
G1 PASS: verify under tweaked Q = OK; verify under untweaked P = REJECTED; merkle_root=None; Q != P
test coordinator::tests::g1_verify_under_q_pass_under_p_fail ... ok
test result: ok. 4 passed; 0 failed
```

Full suite: cargo test -> 6 passed (2 C-1 + 4 C-2); cargo build --release Finished;
cargo clippy --all-targets -- -D warnings clean; em-dash scan clean. G1 + the sub-threshold
abort remain green.

---

## C-3: key-path spend + esplora + keyset persistence, gate G2 (2026-06-23)

Worker: worker:frost-c1. Branch: c3-spend off main (035f653). Builds on C-1 (taproot_address) +
C-2 (Coordinator::run = sighash-in -> 64-byte-sig-under-Q-out). Scope: the real spend + G2 ONLY
(NOT C-4/C-5/C-6/relay).

### What was built

- src/persist.rs: dealer keyset save/load (hex of native ZF serializations: the SecretShares +
  the PublicKeyPackage). The funded address reloads to stay spendable (D-2: shares saved together
  in v0). NOT the OsRng-ephemeral path.
- src/chain.rs: a real Rust esplora client (ureq) on https://mutinynet.com/api: tip_height,
  utxos / confirmed_utxos, broadcast (POST /tx), tx_status; plus a best-effort faucet_fund.
- src/spend.rs: key_path_sighash (SighashCache::taproot_key_spend_signature_hash,
  TapSighashType::Default, over the prevout spk + amount), key_path_witness
  (Witness::p2tr_key_spend, single 64-byte element, no type byte), build_key_path_spend
  (sighash -> Coordinator::run -> witness -> serialized tx + txid).
- src/bin/spend-demo.rs: the live G2 orchestrator (resumable): load-or-generate keyset -> derive
  p2tr(Q) -> ensure a confirmed UTXO (faucet best-effort, else manual-fund + re-run) -> build +
  threshold-sign + broadcast -> confirm -> print txids.

### Offline gates (deterministic, plain cargo test) GREEN

```
cargo test                                -> 8 passed
  persist::keyset_round_trips_to_same_address
  coordinator:: g1_verify_under_q_pass_under_p_fail / sub_threshold / duplicate / terminal (C-2)
  spend::key_path_spend_signature_verifies_under_q       <- C-3 money-path gate
cargo build --release                     -> Finished [optimized]
cargo clippy --all-targets -- -D warnings -> clean
em-dash scan                              -> clean
```

The C-3 offline gate builds a REAL key-path spend sighash over a synthetic prevout, threshold-signs
it 2-of-3, and asserts the signature VERIFIES under Q and FAILS under P, with a single 64-byte
key-path witness. This is exactly what the network re-checks at G2; it proves the sighash
construction and witness assembly are correct without broadcasting.

### G2 (live on-chain) PENDING a funding decision

The Mutinynet faucet was redesigned since the spec was written: there is no anonymous onchain
form. POST /api/onchain returns 401 "Missing token"; the web UI requires either GitHub login or a
"Pay with Lightning" MAINNET invoice (lnbc500n... = 50 sats of real money) for access. Autonomous
pure-API self-fund is no longer possible. G2 is blocked on a funding decision (authorize a ~50-sat
mainnet LN pay from the turtle NWC wallet, OR a human funds the address); flagged to keeper:kirby.
Once the address holds a confirmed UTXO, spend-demo auto-completes the 2-of-3 key-path spend and
prints the confirmed G2 txid.

Per-gate fixture (D-16), funding pending:
  address (p2tr(Q), key-path only, Mutinynet): tb1pshkf44qc3zplgz7nwpet7cad8z9je5kzmkkwgany72vcsnrulnpqxj29xe

Reproduce (live, after funding): nix develop --command cargo run --release --bin spend-demo

### G2 CONFIRMED (live on-chain, 2026-06-23): autonomous, zero real funds

Funding option 3: the address was funded via the Mutinynet faucet using a reusable faucet JWT
(GitHub-auth, obtained + stored by keeper:pops; zero real money), then the resumable spend-demo
auto-completed the 2-of-3 key-path spend. Real confirmed machine evidence:

```
address (p2tr(Q), key-path only, Mutinynet): tb1pshkf44qc3zplgz7nwpet7cad8z9je5kzmkkwgany72vcsnrulnpqxj29xe
funding txid: 16cb6db75cdeac5a94e5e833d8c43c5ecd8fdf8519a18d1a4ba729b99addc327  (50000 sats, confirmed block 3206851)
spend txid:   bbab7ef854bdd65e5213918d4313cf65295b229c16385c2fec98857eb270213f  (confirmed block 3206853)
explorer:     https://mutinynet.com/tx/bbab7ef854bdd65e5213918d4313cf65295b229c16385c2fec98857eb270213f
```

Ground-truth re-check (esplora GET /tx/{spend}): confirmed = true; 1 input spending
16cb6db...:1; witness = 1 item of 64 bytes (the BIP-340 key-path signature, SIGHASH_DEFAULT, no
type byte); 1 output v1_p2tr of 49500 sats (= 50000 - 500 fee) back to p2tr(Q). The network
validated the tweaked 2-of-3 threshold signature as a taproot key-path witness: G1's prediction
confirmed on-chain. G2 GREEN. C-3 complete (offline gates + a real confirmed Mutinynet spend).

### C-3 hardening (pre-merge, Codex deep-pass code fixes; on-chain G2 unchanged)

Code-only fixes; the G2 evidence (txids above) stands, no re-spend.

- [HIGH] persist.rs: the keyset file holds the 2-of-3 SECRET SHARES but was written with the
  default umask (0644, world-readable) on the shared /srv/forge box. Now written owner-only
  (0600) and atomically (0600 temp file -> write -> fsync -> rename), and load tightens any
  pre-existing file to 0600 first. New test persisted_keyset_is_owner_only_0600 asserts mode 0600.
- [MED] chain.rs faucet_fund: now reads the faucet JWT from $FAUCET_JWT or the external
  FAUCET_JWT_PATH (/srv/forge/scratch/mutinynet-e2e/logs/faucet-jwt.txt), attaches
  Authorization: Bearer, and NEVER logs the token or a response/error body (returns only the
  parsed txid). The JWT stays out of the repo (gitignored). Makes `cargo run --bin spend-demo`
  genuinely reproducible (it self-funds) instead of relying on an out-of-band curl.
- [LOW] spend-demo.rs: single-shot guard. After broadcast it records the spend to a (gitignored)
  marker; a rerun reprints it and exits rather than re-spending the confirmed change output
  (which burned 500 test sats/run). KIRBY_SPEND_AGAIN=1 forces a fresh spend.

Offline gates after the fixes: cargo test -> 9 passed (the 8 prior + persisted_keyset_is_owner_only_0600);
cargo build --release Finished; cargo clippy --all-targets -- -D warnings clean; em-dash clean.
The live G2 was NOT re-run (the existing confirmed txid stands).

---

## C-4: rug-proof gates G3 + G4 (2026-06-24)

Worker: worker:frost-c1. Branch: c4-gates off main (e4b19f9). Dedicated committed gates on the
existing C-2 Coordinator + C-1 keygen; NO new crypto. Scope: G3 + G4 ONLY (NOT C-5 reshare, NOT
C-6).

### G3 (no single guardian can rug it) -- coordinator::tests::g3_single_guardian_cannot_rug

- (a) operational: the coordinator ABORTS a 1-of-3 ceremony (QuorumUnavailable; state Aborted).
- (b) cryptographic floor: hand-driving ZF round1/round2/aggregate from a LONE share yields NO
  signature valid under Q. In practice ZF round2::sign_with_tweak itself REFUSES a sub-threshold
  package (a lone share cannot even be produced); the test also defends against any sig that
  could somehow be produced not verifying under Q. Funds are unspendable by any single node.

### G4 (quorum is the only spend path; no privileged signer) -- coordinator::tests::g4_all_three_pairs_verify_under_q

Drives all THREE distinct signer pairs {1,2}, {1,3}, {2,3}; each produces a 2-of-3 aggregate that
VERIFIES under Q (and fails under P). Offline (verify-under-Q). On-chain spendability is covered
in principle by G2 (the {1,2} pair, real Mutinynet txid) PLUS this offline all-pairs check, so
C-4 does NOT re-spend or hit the faucet.

### Output

```
running 11 tests
G3 PASS: 1-of-3 aborts AND a lone share yields no Q-valid signature (unspendable by one node)
test coordinator::tests::g3_single_guardian_cannot_rug ... ok
G4 pair {1,2}: aggregate verifies under Q (and fails under P)
G4 pair {1,3}: aggregate verifies under Q (and fails under P)
G4 pair {2,3}: aggregate verifies under Q (and fails under P)
G4 PASS: all 3 distinct pairs {1,2} {1,3} {2,3} co-sign valid-under-Q (no privileged signer)
test coordinator::tests::g4_all_three_pairs_verify_under_q ... ok
test result: ok. 11 passed; 0 failed
```

cargo build --release Finished; cargo clippy --all-targets -- -D warnings clean; no em-dashes.
C-4 complete (G3 + G4 dedicated gates).

---

## C-5: resharing without moving funds, gate G5 (2026-06-24)

Worker: worker:frost-c1. Branch: c5-reshare off main (2dc9035). Reshare via ZF keys::refresh.
Builds on C-1 (address), C-2 (Coordinator), C-3 (persist + spend path). Scope: reshare + G5 ONLY.

### What was built

- src/reshare.rs: reshare_same_membership (dealer-style ZF keys::refresh -- compute_refreshing_shares
  over the same identifiers, then fold each zero-share into its member's current KeyPackage via
  refresh_share). The group verifying_key is PRESERVED, so p2tr(Q) and the address are unchanged.
  RefreshedKeyset persists owner-only (0600, atomic) via the shared persist::write_owner_only_atomic.
- src/bin/reshare-demo.rs: the live G5 orchestrator (single-shot): load dealer keyset -> reshare ->
  persist refreshed (0600) -> assert same address -> spend a pre-existing UTXO at that address with
  the REFRESHED quorum -> confirm -> print the G5 txid.

### Form + honest framing (D-16, NOT overclaimed)

ZF keys::refresh (dealer variant) is PROACTIVE refresh of the SAME membership: refresh_share folds a
zero-share into each continuing member's existing KeyPackage, re-randomizing the share material (the
shares "rotate") while preserving the group key. It is NOT cryptographic revocation: a RETAINED
pre-refresh share still reconstructs the same group secret and can still sign. So G5 = rotate-the-shares
+ operationally-erase-old-shares; true revocation needs moving funds to a fresh key = out of MVP. The
offline gate asserts this honestly (an OLD-share quorum STILL verifies under Q).

### Offline gates GREEN

```
cargo test -> 13 passed; new gates:
  reshare::g5_reshare_preserves_address_and_old_shares_still_sign  (same address; refreshed quorum
    signs under Q; refreshed shares changed; OLD shares STILL sign under Q = operational erase)
  reshare::refreshed_keyset_round_trips_0600  (refreshed keyset persists 0600, reloads same address)
cargo build --release + clippy --all-targets -- -D warnings -> clean; em-dash -> clean
```

### G5 CONFIRMED on-chain (live: the refreshed quorum spends the same address)

Reused the G2 change UTXO (no new faucet). The REFRESHED (post-reshare) quorum signed a key-path
spend of the SAME funds at the SAME address:

```
address (preserved across reshare): tb1pshkf44qc3zplgz7nwpet7cad8z9je5kzmkkwgany72vcsnrulnpqxj29xe
reshare: ZF keys::refresh (group verifying_key preserved)
spent UTXO (the G2 change): bbab7ef854bdd65e5213918d4313cf65295b229c16385c2fec98857eb270213f:0  (49500 sats)
G5 spend txid: 76b272a23683b26f6d75e468eb90c2264ce8a64d41979f17e726e0210ea91eae  (confirmed block 3206924)
explorer: https://mutinynet.com/tx/76b272a23683b26f6d75e468eb90c2264ce8a64d41979f17e726e0210ea91eae
```

Ground-truth re-check (esplora GET /tx): confirmed = true; 1 input spending bbab7ef...:0 (the G2
change); witness = 1 item of 64 bytes (BIP-340 key-path sig, SIGHASH_DEFAULT); 1 output v1_p2tr of
49000 sats (= 49500 - 500 fee) back to the SAME address. The post-reshare quorum spent the same funds
at the same address: no on-chain move between rotations. G5 GREEN. C-5 complete.

### C-5 hardening (pre-merge, Codex deep pass; CODE-ONLY, G5 on-chain unchanged)

- [MED] reshare.rs membership-from-shares: reshare_same_membership derived the participant set from
  keyset.shares, but ZF compute_refreshing_shares treats a SUBSET as participant REMOVAL, so a
  truncated keyset would silently refresh a SMALLER group under the same Q (a 2-of-2 wearing the
  2-of-3 address). FIX: membership is now taken from the authoritative group verifying-share set
  (keyset.pubkeys.verifying_shares().keys()), and a keyset whose shares.keys() do NOT exactly match
  is REJECTED with a clear error. Test: truncated_keyset_is_rejected.
- [LOW] reshare.rs stale verifying_share: ZF refresh_share refreshes the signing share but the
  returned KeyPackage keeps its OLD embedded verifying_share. FIX: each KeyPackage is rebuilt
  (KeyPackage::new) with the refreshed verifying share from the new pubkeys, so the persisted
  per-package metadata is consistent. Test: refreshed_keyset_reloads_and_signs_under_q persists the
  refreshed keyset, RELOADS it from disk, and confirms the reloaded quorum signs valid-under-Q.

Offline after the fixes: cargo test -> 15 passed (the 13 prior + truncated_keyset_is_rejected +
refreshed_keyset_reloads_and_signs_under_q); cargo build --release + clippy --all-targets -- -D
warnings clean; no em-dashes. The on-chain G5 (txid 76b272a...) was NOT re-run; it stands.

---

## C-6: D-14 transport seam + G6 / G7 / G8 (2026-06-24): the FINAL chunk

Worker: worker:frost-c1. Branch: c6-seam off main (236885a). Spec: D-14, 3.5, 5 (G6/G7/G8), D-13.
ADDITIVE: a new seam module reusing the SAME ZF crypto; the C-2 Coordinator is untouched, so
G1-G5 stay green by construction (regression-checked, full suite 18 tests).

### D-14 RelayAdapter seam (src/seam.rs)

- trait RelayAdapter { async fn send(&self, to: GuardianId, event: CoSignEvent) -> Result<(),
  TransportError>; async fn recv(&self) -> Result<(GuardianId, CoSignEvent), TransportError>; }
- CoSignEvent { session_id, from: GuardianId, round: u8, payload: Vec<u8> } = the opaque envelope.
  round 1 = commitment, 2 = share (D-16, signer -> coordinator); 3 = PACKAGE (the coordinator's
  SigningPackage fan-out, added to complete the coordinator-centric flow over the opaque seam).
- InMemoryRelay / InMemoryAdapter: same-host carrier, per-endpoint inboxes keyed by GuardianId
  (coordinator = reserved address u16::MAX). Routes by destination ONLY; NEVER deserializes the payload.
- coordinate_2of3_over_seam: drives the 2-of-3 ceremony entirely over the adapter (opaque
  CoSignEvents), reusing frost round1::commit / sign_with_tweak / aggregate_with_tweak. Secret nonces
  stay local, never serialized (D-16). Wire payloads = serde_json of the ZF types (frost serde feature).

### Gates

- G6 (same-host loopback, D-7 first bar): seam::tests::g6_same_host_seam_produces_q_sig: a 2-of-3
  over the in-memory RelayAdapter produces a Q-valid signature.
- G7 (nonce single-use): seam::tests::g7_forced_retry_yields_distinct_nonces: a forced retry commits
  a fresh nonce, so the round-1 commitments are DISTINCT (no reuse).
- Opacity (transport-agnostic): seam::tests::carrier_never_inspects_payload: the carrier delivers
  arbitrary garbage payload bytes verbatim (never parses), so kirby-nostr's relay drops in unchanged.
- G1-G5 REGRESSION: all still green after the additive seam.

### G8 (clean-cut + reproduce)

```
nix develop --command cargo test    -> 18 passed (C-1..C-5 gates + G6 + G7 + opacity); G1-G5 green after the seam.
cargo build --release + clippy --all-targets -- -D warnings -> clean
em-dash scan (git ls-files | xargs grep) -> clean repo-wide
```

Reproduce from a clean checkout: `./reproduce.sh` (runs the offline gates, the clean-cut scan, and
lists the on-chain txids). On-chain evidence to re-confirm at https://mutinynet.com/tx/<txid>:
  address (p2tr(Q)):                tb1pshkf44qc3zplgz7nwpet7cad8z9je5kzmkkwgany72vcsnrulnpqxj29xe
  G2 (2-of-3 key-path spend):       bbab7ef854bdd65e5213918d4313cf65295b229c16385c2fec98857eb270213f
  G5 (refreshed quorum, same addr): 76b272a23683b26f6d75e468eb90c2264ce8a64d41979f17e726e0210ea91eae

### Follow-on (OUT of C-6): the real two-machine run

The REAL multi-node custody claim is retired by a two-machine run (separate boxes) over a Nostr relay
at THIS seam: kirby-nostr's nerve slice-2 implements RelayAdapter against the relay, and a 2nd funded
box (gudnuf-gated) joins. The opaque CoSignEvent + carrier-never-inspects-payload property is exactly
what lets that relay drop in unchanged. Same-host (G6) is the first acceptance bar (D-7); the
two-machine run is the follow-on. C-6 complete: the custody backbone MVP (C-1..C-6) is done.

### C-6 hardening (pre-merge, Codex deep pass; ADDITIVE, G1-G5 untouched)

- [HIGH] seam.rs duplicate-signer nonce reuse: coordinate_2of3_over_seam (a NEW signing entry point)
  had RE-INTRODUCED the bug C-2 fixed: no duplicate-GuardianId guard, and it borrowed nonces with
  get() instead of consuming, so a duplicate GuardianId could reuse a round-1 nonce. FIX (ported from
  C-2): reject a duplicate GuardianId BEFORE round 1 (SignError::DuplicateSigner), and consume nonces
  via remove() in round 2 (single-use; each zeroizes on drop). Test: seam_rejects_duplicate_signer.
  Lesson: a new signing entry point inherits the crypto but NOT the original's input-validation guards.
- [G7 STRENGTHEN] the named G7 now runs the FULL ceremony TWICE over the seam and asserts the round-1
  commitment payloads observed ON THE WIRE differ across the two sessions (a real forced-retry /
  distinct-nonces-observed test, the spec's G7 letter), replacing the unit-level commit() freshness check.

After the fixes: cargo test -> 19 passed (G1-G5 still green; G6 + strengthened G7 + opacity +
seam_rejects_duplicate_signer); cargo build --release + clippy --all-targets -- -D warnings clean;
no em-dashes; reproduce.sh still runs.
