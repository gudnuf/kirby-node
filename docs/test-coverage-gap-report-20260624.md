# kirby-node Test-Coverage Gap Report

> Date: 2026-06-24. Author: keeper:kirby-tests (8-auditor fan-out + synthesis, main @f142cd7).
> Verified against ground truth: HW tests `return` after a "SKIP" eprintln when `KIRBY_GENOME_IMAGE`
> is unset (they pass as green no-ops); there is NO `.github/workflows` / Makefile / justfile, so
> nothing runs `cargo clippy -D warnings` or any G10 check in CI today.

## Headline verdict

Partly trustworthy. The suite is excellent at proving **money-path and crypto LOGIC in isolation**:
treasury unforgeability, never-overspend, the 5-step authorize order, Shamir/hibernation crypto,
idempotency dedupe, and entropy fingerprint divergence all have FAST UNGATED tests. But the **real
enforcement** of the most dangerous invariants -- VM egress isolation (G4), real-mint ecash settle
+ clamp (D-11/D-20), entropy re-derive ORDERING (G7), no-split-brain failover (G8), idempotency
across resume (G9) -- lives ONLY in HW/LIVE-gated tests that silently skip without the genome image.
On a normal box they turn green as no-ops. So as a "never manually test" net it catches logic
regressions but would MISS a broken nftables rule, an unclamped real melt, or a dropped lease fence
until deploy. ~6 fast-ungated seam tests + a CI gate would make it genuinely trustworthy.

## The dangerous gaps (ranked)

1. **CRITICAL -- G4 egress isolation has zero fast verification.** Only `egress_lockdown.rs::
   g4_raw_egress_denied_and_metered_about_zero` exercises it, and it skips silently w/o the image.
   nftables ruleset is a raw `format!` string with no validation; a typo would pass CI and let the
   VM reach the internet. Fix: mock-sudo harness capturing argv, assert ruleset contains the ingress
   hook + `policy drop` + drop counter + no `ip route`/forwarding. Fast-ungated.
2. **CRITICAL -- D-20 real-rail clamp untested.** `MockRail` clamp is proven; the real
   `CdkEcashRail::perform` melt-amount clamp is HW/LIVE-only. An unclamped melt = overspend past
   estimate = real-money loss. Fix: probe/inspect method asserting `melt_amount <= cap_sats`, no mint.
3. **HIGH -- Lease fence (G8 STEP 0) not fast-tested at the gateway** in isolation (a mock
   `FenceVerdict::Fenced` -> deny + cost 0 + no perform). The real-lease path IS fast-covered by
   `no_split_brain.rs::g8_gateway_debit_path_is_lease_fenced` (verify not regressed).
4. **HIGH -- Combined G8+G9 (fenced node cannot double-burn across resume) is HW-only.** Fast fix:
   3-node lease cluster + two gateways on a shared persisted ledger; stale reissue -> DENIED/DUPLICATE,
   perform_count stays 1.
5. **HIGH -- G7 entropy ORDERING (GetEntropyNonce at bumped generation BEFORE first post-resume act)
   is HW-only.** Divergence is fast-tested; ordering (red-team gate, D-5) is not. Fix: mock event
   observer, assert sequence by event kind+generation.
6. **HIGH -- Live RoutstrBrain spend + engram multi-relay round-trip are LIVE-gated/#[ignore].**
   Fix: in-memory mock Routstr (X-Cashu + change/refund) + in-memory mock Nostr relay -> both fast.
   Keep live tests as nightly drift detectors.
7. **MEDIUM -- Concurrent debit race + crash-window idempotency untested** (single-threaded tests
   can't reach the in-txn Duplicate guard or mid-tick crash wseq replay).
8. **MEDIUM -- App-checkpoint membrane validation on the RESTORE path untested** (submit-side is).

## The gating problem

~6 of 10 gates have their load-bearing enforcement HW/LIVE-gated-only (G1 partly, G4, G6, G7, G8,
G9 real-VM paths); **G10 is not gated at all** (no CI). Systemic fix: HW/LIVE tests should emit a
visible SKIPPED count / fail-if-expected, not silently return green, so the dashboard never lies.
Add `tests/g10_reproducible.rs` (clippy -D warnings + image SHA256 vs manifest + em-dash grep) --
pure CI-time, no hardware.

## Test infra to build (deduped; `nix/relay.nix` already exists)

- **In-memory Nostr relay mock** (highest leverage) -- engram multi-relay LWW/tombstone, hibernation
  wake-scoping, presence. Medium.
- **In-memory mock Routstr/Cashu node** (extend existing `MockNode`) -- RoutstrBrain spend + revoke/
  refund. Medium.
- **Mock-sudo + ruleset/`ip` capture harness** -- G4 nftables syntax + no-route assertion. Low-med.
- **Mock aya/eBPF loader + mock `tokio::process::Child`** -- ingress-hook direction, spawn handshake. Medium.
- **Mock LeaseHandle (`FenceVerdict`) + mock gateway Event observer** -- G8 fence + G7 ordering. Low.
- **Mock/in-memory Treasury concurrent-open + crash-inject harness** -- D-9 race, crash-window. Low-med.
- **CdkEcashRail clamp inspector** -- D-20 fast test. Low.
- **`KIRBY_GENOME_IMAGE` in CI + scheduled live lane** -- keep HW/LIVE as real-evidence drift detectors.

## Recommended work order (fast-ungated, highest-risk-per-effort first)

1. **Money-path fence + clamp** (low, critical): mock-LeaseHandle gateway fence; CdkEcashRail D-20
   clamp probe; concurrent-debit race; crash-window wseq idempotency. Reuses existing seams.
2. **Egress seam suite** (medium, critical): mock-sudo + mock-aya harness, then ruleset/policy/device
   validator, no-route assertion, eBPF ingress-hook direction, spawn handshake. Biggest blind spot.
3. **Entropy-ordering + G6/G7 isolation** (low-med, high): mock event observer; restore-path membrane.
4. **G10 CI gate** (low, high, pure CI): `tests/g10_reproducible.rs`.
5. **Mock relay harness** (medium): convert engram + hibernation wake from #[ignore] to fast.
6. **Mock Routstr/Cashu node** (medium): RoutstrBrain spend + recovery into fast CI.
7. **Combined G8+G9 cluster test + VZ backend dispatch + config arch-mismatch** (medium).
8. **Wire `KIRBY_GENOME_IMAGE` into CI + scheduled live lane** (infra): visible SKIPPED counts.

Batches 1-4 alone convert this from "trusts the logic, hopes for the integration" into a genuine
no-manual-test safety net for every money-path and isolation invariant.
