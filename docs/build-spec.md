# Build Spec -- Kirby DKG-less Firecracker compute spike

> Date: 2026-06-17. Status: **FROZEN 2026-06-17. Rulings locked as D-14..D-20 below.
> Build may proceed off this spec; every later change is a dated §2 entry.** This is the
> reliable-build-kit artifact: a precise, testable, frozen-on-confirmation spec is the
> deliverable; implementation comes later off this spec.
>
> **Three minds (kit rule):** spec-author. implementer = a FRESH-context worker (or
> workers, one per chunk). verifier = a DIFFERENT agent. Implementer and verifier both
> diff against THIS file, not the chat log.
> **Repo:** NEW codebase (`kirby-node`). No base to diff against; the verifier diffs
> output against THIS spec + the §7 success tests.

## 1. Goal

Prove the **compute + metering + agency + failover** keystone of Kirby in isolation, with **zero custody and zero real funds**. One Tokio **node daemon** boots a Firecracker microVM running a musl-Rust **stub genome** (built via microvm.nix), **meters** its CPU / memory / network-egress against an **unforgeable stub treasury** (the genome cannot spend or forge balance -- every spend passes the daemon's vsock gateway), lets the genome **act in the world** through at least one **brokered, metered, treasury-gated capability** (never raw network from inside the VM), then **snapshots** the VM and **resumes** it on a **second node** after node 1 is killed. This is the framing-agnostic, IQ-agnostic keystone: it boots/meters/sandboxes/checkpoints/acts/kills-on-broke a fixed genome regardless of whether Kirby is later "digital life" or a "trustless vending machine," and commits the project to nothing. It deliberately excludes FROST/DKG, real keys, and real on-chain spend -- those are the parallel custody spike. The spike exists to retire compute risk cheaply and to bake in the two red-team gates (consensus-under-the-lease, entropy-on-resume) from the first compute milestone, before any value is at stake.

This spec scopes the build around **exactly** that proof and nothing more. Anything past it (FROST, real treasury, real chain, relay-proof/TLSNotary, density tiers) is OUT (§4).

## 2. Decisions (the register -- locked picks; append-only, supersede never delete)

Each: `[D-n | YYYY-MM-DD | signed:who]` decision + one-line rationale. A PIVOT is a new dated entry citing the decision it overrides. **Nothing builds until this section has no unresolved fork on a load-bearing surface.** Entries D-1..D-13 are DERIVED; D-14 forward are operator rulings on §12.

- **D-1 | 2026-06-17 | signed:operator** -- Build the DKG-less Firecracker compute spike as a spec-first artifact; the operator reviews the spec before any code.
- **D-2 | 2026-06-17 | signed:derived** -- **Firecracker microVM, single tier.** NOT WASM. Decisive axes: hardware (KVM) isolation beside (eventual) live keys, and production checkpoint/resume that WASM lacks (wasmtime #3017 open since 2021).
- **D-3 | 2026-06-17 | signed:derived** -- **Custody-less + DKG-less + funds-less.** No FROST, no real keys, no real on-chain spend. A **stub treasury** (an authoritative integer balance the daemon owns) + a **stub signer** (a deterministic mock that returns a fake settlement receipt). The spike proves the compute loop; the custody spike proves custody; they meet later at the spend-authorization seam (spike 4).
- **D-4 | 2026-06-17 | signed:operator(red-team gate)** -- **openraft UNDER the lease/term/active-node election.** Do NOT hand-roll consensus on iroh-gossip (diffusion, not consensus -> split-brain -> double-execute / double-burn). The active-node lease is granted by an embedded Raft.
- **D-5 | 2026-06-17 | signed:operator(red-team gate)** -- **Re-derive-entropy-on-resume is a first-class correctness gate.** VMGenID reseeds the KERNEL CSPRNG, NOT user-space PRNG. On resume the genome MUST fetch a fresh vsock nonce and re-derive ALL ephemeral secrets BEFORE it acts; a resumed clone that skips this reuses PRNG state (-> in the real system, FROST nonce reuse -> key extraction).
- **D-6 | 2026-06-17 | signed:operator** -- **AGENCY is first-class.** The genome must be able to act in the world, but ONLY through brokered, metered, treasury-gated capabilities the daemon mediates over vsock -- NEVER raw network from inside the VM. The spike demonstrates >=1 REAL brokered act end-to-end. The agent's power = a capability SET the daemon grants + meters, not an open door.
- **D-7 | 2026-06-17 | signed:derived** -- Stack: Rust + Tokio; **fctools** drives Firecracker + the **jailer** (chroot + seccomp L2, non-negotiable for an untrusted genome); **microvm.nix** builds the genome image (musl-Rust binary in a read-only squashfs, content-addressed = same hash on every node) on Linux 6.1 LTS stripped guest kernel; **tonic** gRPC over **vsock** for the genome->daemon gateway; **cgroups-rs** (CPU/mem quotas + read `cpu.stat` to bill) + **aya** (pure-Rust eBPF, TC classifier per TAP for network-byte billing) for metering; **nftables** per-VM TAP egress allowlist (host-kernel-enforced; the genome can't touch host rules).
- **D-8 | 2026-06-17 | signed:derived** -- **CPU templates T2CL (Intel) / T2A (AMD)** applied at VM create, so a snapshot restores on a different CPU; **VMGenID device + Linux 6.1 LTS guest** so the kernel CSPRNG reseeds on restore. Snapshot transfers the **mem+state pair** (rootfs is pre-staged on every node via the Nix binary cache, NOT transferred).
- **D-9 | 2026-06-17 | signed:derived** -- **The treasury balance is authoritative ON THE DAEMON (host), never in the VM.** The genome can observe but cannot mutate it; every debit happens host-side under the gateway. The genome holds no key and no balance. This is the unforgeability property the spike must prove.
- **D-10 | 2026-06-17 | signed:derived** -- **2 nodes for the spike** (the minimum to demonstrate failover + a Raft term boundary). openraft runs a 2-node cluster (one leader / one follower). **ASSUMPTION (§12 Q1):** a 2-node Raft cannot form a majority if one is down; the failover test must therefore be structured as a *leadership/lease handoff that does not double-execute* rather than "keep serving with 1 of 2." 3-node cluster (true majority survives one loss) was flagged.
- **D-11 | 2026-06-17 | signed:derived** -- **The brokered act for the spike = settle ecash via a local CDK mint, OR pay a regtest/hold Lightning invoice via NWC.** The act is REAL (a real ecash settlement / real regtest LN payment), but the *value* is play-money on a test mint / regtest. The genome NEVER sees the rail credential; the daemon performs the act. **ASSUMPTION (§12 Q2):** ecash-on-local-mint is the primary; LN-regtest is the fallback if the mint rig is unavailable.
- **D-12 | 2026-06-17 | signed:derived** -- **The genome is a STUB**, not a real LLM harness or earning agent. It does exactly enough to exercise every gate: burn measurable CPU, allocate measurable memory, attempt raw egress (must be denied), request a brokered act over vsock (must be authorized + metered + performed), report a pre-snapshot entropy fingerprint, and after resume re-derive + report a DIFFERENT fingerprint.
- **D-13 | 2026-06-17 | signed:derived** -- **Single host, multi-node-by-process for the default harness.** "Node 1" and "node 2" are two daemon processes (distinct jailer chroots, distinct TAPs, distinct vsock CIDs) on one machine; the snapshot mem+state pair moves over a local path/loopback. This proves the loop without provisioning two boxes. **ASSUMPTION (§12 Q3):** a true two-host run (real network transfer, real cross-CPU) as the acceptance bar was flagged; the spec keeps the transfer behind a seam (§5) so two-host is a config swap, not a rewrite.
- **D-14 | 2026-06-17 | signed:operator** -- Q1 RESOLVED: **3 nodes** (supersedes D-10's 2-node assumption). A 3-node openraft cluster so a true majority survives losing one node, mirroring the real v0 2-of-3 shape. G8 now also demonstrates survive-one-loss, not only a fenced handoff.
- **D-15 | 2026-06-17 | signed:operator** -- Q3 RESOLVED: **same-host (multi-process) is the FIRST acceptance bar; a real TWO-HOST run (real network transfer + real cross-CPU restore) is REQUIRED before the failover keystone is declared retired.** The transfer seam (D-13/§5) keeps two-host a config swap. Same-host green alone does NOT count as failover-proven.
- **D-16 | 2026-06-17 | signed:operator** -- Q2 RESOLVED: canonical brokered act (G5) = **settle ecash on a local CDK fakewallet mint**; LN-regtest-via-NWC and paid-HTTP/L402 remain fallbacks/coverage.
- **D-17 | 2026-06-17 | signed:operator** -- Q4 RESOLVED: inter-node transport = **openraft over plain TCP/loopback** for the spike (keep iroh out of the keystone). NOTE: if the substrate-share decision lands, the real wire is openraft-on-iroh and that integration stays unproven until a later spike.
- **D-18 | 2026-06-17 | signed:operator** -- Q5 RESOLVED: **no stub signer.** Real rail acts carry the rail's own receipt (ecash proof / LN preimage); the non-rail/HTTP `proof` may be empty or a status-hash. Custody is fully out (D-3).
- **D-19 | 2026-06-17 | signed:operator** -- Q6 RESOLVED: build on **OPUS** for the interlocking treasury/consensus/agency core; ONE fresh-context implementer takes the interlocking chunks sequentially; a **DIFFERENT-agent verifier per chunk** (kit); the genome image (C-2) may build in parallel with the daemon (C-3).
- **D-20 | 2026-06-17 | signed:operator** -- REFINEMENT to §3.2/§4.2: `perform` MUST cap the actual spend at the budgeted estimate (`max_fee_sats`/`max_cost_sats`) so `actual <= estimate <= treasury_remaining`, preserving never-overspend even AFTER perform. The §3.2 gate checks an estimate pre-perform but debits actual post-perform; without the cap a rail overshoot could debit past zero after the act already happened. Stub value in the spike; real-money invariant later.

## 3. Shapes (every load-bearing surface, concrete -- ZERO "OPEN" on a load-bearing shape)

> Signatures here are the contract. An "OPEN" on any of these blocks the build (the only OPENs allowed are in §12, none of which is a load-bearing shape).

### 3.1 The gateway service (genome -> daemon, tonic gRPC over vsock)

The genome's ONLY interface to the outside. A narrow service -- every method is a daemon-mediated choke point.

```
service NodeGateway {
  // boot: genome pulls its non-secret session context (task descriptor, budget snapshot, mint/endpoint identifiers -- NOT credentials)
  rpc GetSessionContext(SessionRequest) returns (SessionContext);

  // entropy: the resume gate. Returns a FRESH per-call nonce the genome MUST mix into any ephemeral secret. (§3.4)
  rpc GetEntropyNonce(EntropyRequest) returns (EntropyNonce);

  // metering: genome self-reports app-level events (host metering via cgroups/eBPF is authoritative; this is supplementary/diagnostic).
  rpc ReportEvent(Event) returns (Ack);

  // AGENCY: the brokered-act path. request -> daemon authorizes vs treasury + meters -> daemon performs -> receipt. (§3.2)
  rpc RequestCapability(CapabilityRequest) returns (CapabilityReceipt);
}
```

- The genome is the gRPC **client**; the daemon is the **server**, listening on a vsock port bound to that VM's CID. One genome cannot reach another's daemon (distinct CIDs per VM).
- All messages are versioned (`u32 schema_version`, starts at 1; additive-only thereafter).

### 3.2 The Capability / Treasury-gateway contract (the load-bearing agency surface -- request -> authorize -> meter -> perform)

This is the heart of D-6 and is treated as load-bearing.

```
message CapabilityRequest {
  uint32 schema_version = 1;
  string idempotency_key = 2;     // genome-chosen; the daemon dedupes on it (replay safety across a resume -- §4)
  oneof act {
    PayInvoice  pay_invoice  = 3; // BOLT11 string + max_fee_sats
    SettleEcash settle_ecash = 4; // mint id + amount + recipient/quote
    PaidHttp    paid_http    = 5; // method + url + body + max_cost_sats (covers a generic paid service / L402)
  }
  uint64 budget_sats = 6;          // the max the genome authorizes for THIS act (must be <= remaining treasury)
}

message CapabilityReceipt {
  Outcome outcome = 1;             // AUTHORIZED_AND_PERFORMED | DENIED_INSUFFICIENT_TREASURY | DENIED_OVER_BUDGET | DENIED_NOT_ALLOWLISTED | UPSTREAM_FAILED | DUPLICATE_IGNORED
  uint64 cost_sats = 2;            // actual metered cost debited (0 on any DENIED)
  uint64 treasury_remaining = 3;   // authoritative post-debit balance (daemon-owned, D-9)
  bytes  proof = 4;                // opaque act receipt (ecash proof / LN preimage / HTTP status+body hash)
}
```

**The contract the daemon MUST enforce, in this order, host-side, for every `RequestCapability` (this is the testable spend-authorization logic of §4):**
1. **Dedupe** -- if `idempotency_key` was already performed, return `DUPLICATE_IGNORED` with the prior receipt; perform nothing. (Resume-replay safety.)
2. **Allowlist** -- the act's destination (mint id / invoice's node / URL host) MUST be on the daemon's static allowlist, else `DENIED_NOT_ALLOWLISTED`, debit 0.
3. **Budget gate** -- `cost_estimate <= budget_sats` AND `cost_estimate <= treasury_remaining`, else `DENIED_OVER_BUDGET` / `DENIED_INSUFFICIENT_TREASURY`, debit 0. (The genome can never spend more than the treasury holds -- the unforgeability core, D-9.)
4. **Perform** -- the DAEMON performs the act using the host-held rail credential the genome never sees (settle on the local mint / pay the regtest invoice / make the paid HTTP call). The VM issues no raw network for this -- it goes out the daemon's own host networking, not the VM's TAP.
5. **Meter + debit** -- debit `actual_cost` from the treasury atomically with recording the receipt (persist via sled/sqlx), so a crash mid-act cannot double-debit or lose the record. Return the receipt.

### 3.3 The metering surface (host-authoritative, D-9)

- **CPU + memory:** the VM's vCPU threads run under a cgroup v2; the daemon reads `cpu.stat` (`usage_usec`) and `memory.current` on a tick and converts to a synthetic burn against the treasury. `cgroups-rs`.
- **Network egress bytes:** an aya/eBPF TC classifier on the VM's TAP counts egress bytes; billed per-byte.
- **The budget halt:** when cumulative metered burn (CPU + mem-time + egress + capability spends) reaches the genome's budget, the daemon HALTS the VM (pause then kill) and records `terminated:budget_exhausted`. This is Kirby's "death by exhaustion" proven at spike scale.
- **Authority:** all four meters debit the SAME daemon-owned treasury counter (D-9). The genome's `ReportEvent` numbers are advisory and are NEVER trusted for billing (a malicious genome under-reporting must not under-pay).

### 3.4 The entropy / resume surface (D-5 gate)

- `GetEntropyNonce` returns a fresh 32-byte random nonce per call (host CSPRNG), tagged with the current `vm_generation` (read from the VMGenID device on the host side / passed in at restore).
- **Genome contract:** before performing ANY act that consumes an ephemeral secret (in the spike: deriving its "ephemeral fingerprint"), the genome MUST call `GetEntropyNonce` and mix the returned nonce into its derivation. It MUST re-call after a resume (it detects resume via a changed `vm_generation`, or unconditionally re-derives on every act -- the spec mandates re-derive-before-act, §4).
- **The fingerprint** (spike instrument): the genome computes `fingerprint = H(nonce || vm_generation)` and exposes it via `ReportEvent`. Pre-snapshot fingerprint and post-resume fingerprint MUST differ -- that is the machine-checkable proof the resumed clone did NOT reuse PRNG state (§7-G7).

### 3.5 The lease / consensus surface (D-4 gate)

- An embedded **openraft** cluster across the nodes. The single replicated state-machine value the spike needs: **`active_lease { node_id, term }`** -- which node currently owns the right to run the genome.
- **Active-node election:** only the node that is BOTH the Raft leader AND holds `active_lease` for the current term runs the VM. Granting/transferring the lease is a Raft log entry (linearizable, fenced by term).
- **No split-brain invariant:** at no term boundary are two nodes both "active." A partition or a kill of the active node triggers a Raft-mediated lease handoff with a NEW term; the old active node, if it revives, sees the higher term and refuses to execute (term-fencing).

### 3.6 The genome image (microvm.nix)

- A static **musl-Rust** binary (no glibc, no interpreter) in a read-only **squashfs**, built reproducibly via **microvm.nix** -> content-addressed (identical hash on every node, the verifiable-genome property). Linux 6.1 LTS stripped guest kernel with the **VMGenID** device enabled. The genome does exactly the §3.4/§3.2/§7 stub behaviors.
- Session data (task descriptor, budget) enters via the vsock `GetSessionContext` at boot -- NOT a shared filesystem.

### 3.7 The egress posture (nftables)

- Per-VM TAP. **Default-deny** egress from the VM. The ONLY allowed VM-originated traffic: the vsock channel to the daemon (vsock is not IP, so this is structural -- the gateway is reachable; the IP network is not). DNS from the VM is blocked. The daemon's OWN host networking (separate from the VM TAP) is what reaches the mint / LN node / paid endpoint when performing a brokered act. **The VM never has a route to the internet** -- proven by §7-G4.

## 4. State machines / money-paths (the correctness CI cannot test -- specified here, or it does not exist)

### 4.1 VM lifecycle (per node)

`Provisioned -> Booted -> Running -> (Paused -> Snapshotted) -> Killed` on the source node; `RestorePending -> Restored -> Running` on the target node. Terminal states: `Terminated{budget_exhausted}`, `Terminated{killed_for_failover}`, `Failed{...}`. The daemon owns this machine; the genome cannot drive transitions (it only makes gateway calls).

### 4.2 The treasury debit money-path (stub value, real invariants)

The treasury is a single daemon-owned counter `remaining_sats`, persisted. Every debit (a metered tick OR a `RequestCapability` perform) is an atomic `remaining -= cost` recorded with an idempotency key, under these invariants:
- **Unforgeable:** only daemon-side code debits; no gateway method lets the genome ADD balance or set `remaining`. (G3.)
- **Never-negative / never-overspend:** a debit that would drive `remaining < 0` is refused BEFORE the act (`DENIED_INSUFFICIENT_TREASURY`); the act does not happen. (G2, G3a.)
- **Idempotent across resume:** a `RequestCapability` carries an `idempotency_key`; after a snapshot+resume, a genome re-issuing the same key gets `DUPLICATE_IGNORED` and the act is NOT performed twice. (This is the spike-scale analogue of the red-team's "stale-resume -> replay" / "double ecash burn"; it is tested in G6+G8 together.)
- **Atomic debit+receipt:** the debit and the receipt persist together; a crash between cannot leave value debited with no receipt or an act performed with no debit.

### 4.3 The lease/term money-path (no-split-brain, D-4)

`active_lease{node, term}` transitions ONLY via committed Raft log entries. Transition table:
- node A active@term T; A killed -> Raft elects (B becomes leader if it has the votes), commits `active_lease{B, T+1}` -> B restores the snapshot and runs.
- A revives, still believes term T -> any execute/debit attempt is fenced: A sees committed term T+1 > T and steps down; it does NOT run the VM, does NOT debit. (G8: no double-execute.)
- **Invariant:** `forall committed terms, exactly one node holds active_lease`. Two nodes both-active is unreachable. (G8.)

### 4.4 The resume entropy path (re-derive-before-act, D-5)

On `Restored`, `vm_generation` is incremented (VMGenID). The genome, before its next act, MUST call `GetEntropyNonce` (returns the new generation + a fresh nonce) and re-derive. Transition rule the verifier checks: there is **no code path** in the genome where an ephemeral secret derived BEFORE the snapshot is reused AFTER the resume. (G7.)

## 5. Architecture facts (process boundaries / IPC / what "done" means -- stated up front)

- **Node daemon** = one Tokio process per node. Responsibilities (lean): drive Firecracker via fctools+jailer; own the cgroup + eBPF meters; own the treasury counter + its persistence; serve the vsock gateway (§3.1/§3.2); enforce nftables egress (§3.7); run the openraft node (§3.5); perform brokered acts using host-held rail credentials.
- **Genome** = the musl-Rust binary inside the microVM (§3.6). Adversarial-by-assumption. Reaches the daemon ONLY over vsock; has no IP route, no host FS, no keys, no balance.
- **IPC:** genome->daemon = tonic gRPC over **vsock** (`tonic` + a vsock connector). Inter-node = openraft's transport (openraft over TCP/loopback for the spike avoids pulling iroh into the keystone and keeps the keystone minimal; the spike is agnostic to the eventual iroh-based wire).
- **The snapshot transfer seam (D-13):** "move the mem+state pair from node 1 to node 2" is behind a single trait so the default impl is a local-path/loopback copy (same-host harness) and a two-host impl (scp/iroh-blobs) is a drop-in later. The rootfs is pre-staged on both nodes (Nix), never transferred.
- **"Done / standalone" for the spike** = the §7 success checklist passes end-to-end on the default harness (two daemon processes on one Linux/KVM host), reproducibly, by a different-agent verifier from a clean checkout + `nix develop` (or the documented build), with the producing command output pasted. Two-host is a stretch bar gated on §12 Q3.
- **Host requirements:** a Linux host with KVM, cgroup v2, nftables, vsock (`/dev/vhost-vsock`), and the ability to run the jailer (root or the documented capabilities). The verifier must be able to reproduce these -- the spec's DoD includes a documented host-prereqs check.

## 6. Comment and style rule (clean-cut)

- Comments describe the code as it stands, not its history. No provenance / process narration ("ported from", "lifted from", "was X"). Match surrounding density.
- New code, so most comments are net-new: present-tense, describing what the daemon/genome IS and the invariant a block enforces (esp. the §3.2 ordering and the §4 money-path invariants -- those SHOULD carry a one-line invariant comment, as the money-path code does).
- **No em-dashes** in any code comments, help text, or docs. Commas / colons / parens instead.

## 7. Success Criteria -- the TESTABLE checklist (each proof is a demonstrable, machine-checkable test; NOT "works correctly")

> The spike is DONE only when every G-gate below passes with the producing command's output in hand AND a different-agent verifier has reproduced them from a clean checkout. Each gate names HOW it is checked. This is the kit's "machine evidence or it does not exist."

- **G1 -- Boots.** The daemon boots the microVM from the microvm.nix image; the genome comes up and completes a `GetSessionContext` round-trip over vsock. *Check:* daemon log shows VM `Running` + a `GetSessionContext` response logged; an automated test asserts the genome's "hello, session=<task>" event arrived. Boot-from-cold and boot-from-snapshot both covered (the latter by G6).
- **G2 -- Meters and halts on budget.** With a small budget, the stub genome burns CPU + allocates memory in a loop; the daemon's cgroup/eBPF meters accumulate and, on reaching budget, HALT the VM. *Check:* a test sets budget = B, runs the burn genome, asserts the VM is `Terminated{budget_exhausted}` and that `remaining_sats == 0` (within one tick's granularity) and that termination happened WITHOUT the genome cooperating (the daemon killed it). Assert metered burn ~= B (not 0 -- proving the meter actually read non-zero usage).
- **G3 -- Treasury is unforgeable.** *Check (a):* a test where the stub genome requests a capability with `budget_sats` > `treasury_remaining` asserts `DENIED_INSUFFICIENT_TREASURY`, `cost_sats == 0`, treasury UNCHANGED, and NO act performed (the upstream stub/rail records no call). *Check (b):* a code-level assertion (verifier, by inspection + a fuzzer over gateway messages) that NO gateway method can increase `remaining_sats` or set it directly -- the genome has no balance-write path. *Check (c):* the daemon ignores `ReportEvent` self-metered numbers for billing (a genome under-reporting CPU is still billed by the host meter) -- a test runs a genome that reports `cpu=0` while burning real CPU and asserts it is still billed + halted.
- **G4 -- Raw egress denied.** The stub genome attempts a direct outbound TCP/UDP/DNS from inside the VM (e.g. connect to the mint IP, resolve a name, hit 1.1.1.1). *Check:* the attempt FAILS (no route / blocked by nftables); a test asserts the genome's "raw egress attempt" reports failure AND the host nftables counters show the drop AND the eBPF egress counter shows ~0 IP bytes left the TAP. Contrast: the same destination IS reachable when the daemon performs it brokered (G5) -- proving isolation is preserved while agency is granted.
- **G5 -- Brokered act succeeds and is metered.** The stub genome issues `RequestCapability` for the chosen act (D-11: settle ecash on the local mint, or pay a regtest LN invoice, or a paid HTTP/L402 call). *Check:* an end-to-end test asserts (i) the daemon authorized it against the stub treasury, (ii) the daemon PERFORMED it (the real rail shows the settlement/payment/HTTP-200 -- e.g. the mint shows the token spent, or the regtest node shows the invoice paid, or the L402 endpoint returned 200), (iii) `cost_sats > 0` was debited and `treasury_remaining` dropped by exactly that, (iv) the VM issued NO raw network for it (eBPF TAP egress unchanged; the traffic left via the daemon's host networking), and (v) the genome never received the rail credential (the credential never crosses vsock -- verifier confirms by message inspection). This is the D-6 agency proof.
- **G6 -- Snapshot + resume on node 2.** Node 1 snapshots the running VM (CPU template applied), the mem+state pair moves to node 2 (the transfer seam), node 1 is KILLED, node 2 restores and the genome continues. *Check:* a test kills node 1's process after snapshot, asserts node 2 brings the VM to `Running` from the snapshot, and the genome completes a post-resume `GetSessionContext`/`ReportEvent` round-trip (proving it survived the move). CPU-template path exercised (restore succeeds); on the same-host harness this proves the logic, two-host proves cross-CPU (§12 Q3).
- **G7 -- Entropy re-derived on resume (D-5 gate).** *Check:* the genome reports `fingerprint_pre = H(nonce_pre || gen_pre)` before snapshot and `fingerprint_post = H(nonce_post || gen_post)` after resume; a test asserts `fingerprint_pre != fingerprint_post` AND `gen_post == gen_pre + 1` (VMGenID bumped) AND that the genome CALLED `GetEntropyNonce` after resume before acting (the daemon logs the call ordering). A NEGATIVE control: a deliberately-broken genome that skips the re-derive produces equal fingerprints -- the test for the correct genome must distinguish these (i.e. the gate would FAIL for the broken one). This is the spike-scale proof against the FROST-nonce-reuse class.
- **G8 -- No split-brain (D-4 gate).** *Check:* a partition/kill test: with node 1 active@term T, kill it; assert node 2 acquires `active_lease{node2, T+1}` via committed Raft and runs; then REVIVE node 1's process still believing term T and assert it REFUSES to run/debit (term-fenced) -- no second VM runs, the treasury is debited by at most one node, and the brokered act / metered burn is NOT double-counted. A linearizability assertion: at no observed term boundary do both nodes report `active`.
- **G9 -- Idempotent capability across resume.** *Check:* the genome issues a `RequestCapability` with key K, gets it performed (cost C debited), then a snapshot+resume occurs, then the genome re-issues key K; assert `DUPLICATE_IGNORED`, the act is NOT performed twice on the rail, and the treasury is debited by C exactly once total. (Closes the replay/double-burn money-path of §4.2.)
- **G10 -- Reproducible + clean-cut.** *Check:* the genome image is content-addressed (microvm.nix builds the same hash twice); the daemon builds clean (`cargo build`, `cargo clippy -- -D warnings`); no em-dashes in comments/docs/help (grep); the verifier reproduces G1--G9 from a clean checkout with pasted command output.

## 8. Red-team Gates (the two first-class gates, with their tests -- restated as acceptance bars)

These are NOT optional hardening; they are the reason the spike exists this early. The spike does not pass without both.

1. **Consensus under the lease (openraft, not hand-rolled on iroh-gossip).** iroh-gossip is diffusion not consensus -> split-brain -> two nodes both active -> double LLM calls / double ecash burn. **Gate = G8 (+ G9).** The lease/term/active-node election sits on embedded openraft (§3.5, §4.3); term-fencing makes a revived stale node refuse to execute. **Pass bar:** a partition/kill does not double-execute and no term boundary shows two actives.
2. **Re-derive-entropy-on-resume (VMGenID kernel-only gap).** VMGenID reseeds the kernel CSPRNG but NOT user-space PRNG; a missed/raced resume re-derive -> (in the real system) FROST nonce reuse -> key-share extraction. **Gate = G7.** The genome MUST fetch a fresh vsock nonce and re-derive before acting (§3.4, §4.4). **Pass bar:** the resumed genome's ephemeral fingerprint DIFFERS from the pre-snapshot one, and the negative-control (skip-rederive) genome is shown to fail the same check.

## 9. In-Scope vs Out-of-Scope (explicit)

**In-scope (the spike proves exactly this):**
- One Tokio node daemon driving a Firecracker microVM via fctools + jailer.
- A musl-Rust stub genome built via microvm.nix (Linux 6.1 LTS, VMGenID).
- Host-authoritative metering (cgroups-rs CPU/mem + aya/eBPF egress bytes) against an unforgeable stub treasury, with budget-halt.
- The vsock tonic gateway: `GetSessionContext`, `GetEntropyNonce`, `ReportEvent`, `RequestCapability` (§3.1/§3.2).
- >=1 REAL brokered, metered, treasury-gated act (D-11), with hardware isolation preserved.
- nftables default-deny egress from the VM (raw egress denied; only the daemon-proxied path acts).
- Snapshot + cross-node resume (CPU template + VMGenID + vsock entropy re-derive), 2 nodes.
- openraft under the lease/term/active-node election; no-split-brain + idempotent-across-resume.

**Out-of-scope (explicitly NOT this build -- D-3 and beyond):**
- **Custody / DKG / FROST / real keys / real on-chain spend** -- the parallel custody spike. Stub treasury + stub signer only.
- **Real funds** -- play-money on a test mint / regtest LN. No mainnet.
- The **FROST-as-BDK-signer keystone** and the **spend-authorization SEAM** where custody meets the gateway -- that is spike 4, after 1+2 are green.
- **Relay-proof / TLSNotary / output-integrity verification** -- deferred (v0 majority-vote + custody-stops-theft makes output-integrity a low bar).
- **Genome intelligence / a real earning task** -- the genome is a stub; earning is IQ-dependent and orthogonal.
- **Density / WASM tiers** (Hyperlight) -- only if >~1k agents/node later.
- **iroh/Blossom/Nostr substrate integration** (genome storage, checkpoint pointers, birth-cert) -- the spike pre-stages the rootfs locally and moves the snapshot over a seam; substrate-share is not needed to prove the compute loop.
- **Resharing / HSM / proactive secret sharing** -- custody-side, deferred.
- **3+ nodes, autoscaling, a VM pool of >1** -- the spike runs one genome across two nodes.

## 10. Architecture (the node daemon + microVM + gateway + the 2-node failover) -- the picture

```
            NODE 1 (Tokio daemon, jailer chroot)                 NODE 2 (Tokio daemon, jailer chroot)
   +-------------------------------------------------+   +-------------------------------------------------+
   |  openraft node  <----- Raft (TCP/loopback) ----->|  openraft node                                   |
   |   active_lease{N1,T}  (leader+lease => RUN)      |   |   follower (no lease => IDLE), fenced by term  |
   |                                                  |   |                                                |
   |  treasury (authoritative counter, persisted) D9  |   |  treasury (its own; authoritative on resume)   |
   |  meters: cgroups-rs(CPU/mem) + aya/eBPF(egress)  |   |  meters: same                                  |
   |  nftables: default-DENY on VM TAP  (§3.7)        |   |  nftables: same                                |
   |  rail creds (mint/LN/HTTP) HOST-ONLY  (G5)       |   |  rail creds HOST-ONLY                           |
   |                                                  |   |                                                |
   |   [ Firecracker microVM ]                        |   |   [ Firecracker microVM (restored) ]           |
   |     musl-Rust STUB genome (microvm.nix)          |   |     same image (pre-staged via Nix), restored  |
   |     no IP route / no keys / no balance           |   |     vm_generation bumped (VMGenID) => re-derive|
   |        |  vsock (tonic gRPC) ONLY                 |   |        |  vsock                                 |
   |   NodeGateway: GetSessionContext / GetEntropy    |   |   NodeGateway: same                             |
   |               ReportEvent / RequestCapability    |   |                                                |
   +-------------------------------------------------+   +-------------------------------------------------+
            |  snapshot mem+state pair (transfer seam, D-13)  |
            +----------------- node1 KILLED ------------------>+  restore + continue (G6)

   Brokered act (G5): genome --RequestCapability--> daemon --authorize(treasury)+meter--> daemon PERFORMS via HOST net --> receipt
   Raw egress (G4):   genome --direct TCP/DNS--> nftables DROP (VM has no route)   [isolation preserved while agency granted]
```

## 11. Risks / Gotchas (the concrete ones, pulled from the design docs)

- **CPU-template heterogeneity (G6).** A snapshot restores on a different CPU only with CPU-template normalization (T2CL/T2A) or homogeneous hardware; without it, restore fails on a different CPU generation. Same-host harness sidesteps this (identical CPU); the two-host stretch bar (§12 Q3) is where it bites. *Mitigation:* apply the template at create; on same-host, additionally assert the template is in effect (not silently a no-op).
- **VMGenID user-space gap (G7, the gate itself).** VMGenID reseeds the KERNEL CSPRNG, NOT user-space PRNG. This is precisely why the genome must re-derive via a fresh vsock nonce, not trust its in-process RNG. The gotcha IS the gate; the negative control (G7) guards against an implementation that *looks* fine because the kernel reseeded but the genome reused a user-space secret.
- **In-flight vsock loss on resume.** The vsock connection drops across snapshot/restore (like the TAP). *Mitigation:* the genome must RE-ESTABLISH the gateway connection on resume before acting (and re-derive entropy, G7); any in-flight `RequestCapability` at snapshot time is NOT assumed completed -- the `idempotency_key` (G9) makes a re-issue safe. The spec must not assume a long-lived stream survives the move.
- **Network re-attach on resume.** The TAP connection drops on restore; node 2 must wire a fresh TAP + nftables rules before the VM runs (so egress stays default-deny on node 2 too -- re-tested by running G4 after a resume, recommended).
- **Alpha/semi-stable lib churn.** `fctools` is semi-stable, `aya`/microvm.nix mature-but-moving, openraft pre-1.0-ish; `tonic`-over-vsock needs a vsock connector glue. *Mitigation:* pin every version; expect churn; budget for a vsock-transport shim for tonic.
- **Jailer + seccomp.** The jailer (chroot + seccomp L2) is non-negotiable for an untrusted genome, and the 2026 Firecracker-jailer CVE class (host-FS reach) is a named risk. *Mitigation:* run UNDER the jailer from day one (not "add it later"); the spike's threat model treats the genome as adversarial, so a daemon that only works without the jailer is not a pass. Verify the seccomp filter is actually applied (not disabled for convenience).
- **Host privilege for reproduction.** The verifier needs a KVM + cgroup-v2 + nftables + vsock host with jailer privileges; "it works on my box" is not a pass. *Mitigation:* document the host-prereqs check as part of DoD (§5).
- **Metering granularity vs the halt (G2).** cgroup `cpu.stat` + eBPF counters are sampled on a tick; the budget-halt is therefore accurate to one tick, not one instruction (WASM-fuel would be per-instruction, but we chose Firecracker for isolation/checkpoint). *Mitigation:* state the tick granularity in the spec; G2 asserts halt within one tick of budget, not exact-to-the-sat.
- **Don't let a green spike read as a viable economics/custody proof.** It proves compute+metering+agency+failover ONLY; it says NOTHING about earning, custody safety, or decentralization.

## 12. Open Questions resolved (reference)

- **Q1** -- 3 nodes (D-14).
- **Q2** -- canonical brokered act = settle ecash on a local CDK fakewallet mint (D-16).
- **Q3** -- same-host first; two-host required before failover declared retired (D-15).
- **Q4** -- openraft over plain TCP/loopback (D-17).
- **Q5** -- no stub signer; real rail receipts (D-18).
- **Q6** -- OPUS for the core; different-agent verifier per chunk (D-19).

## 13. Chunks (the live progress log -- split into small independently-verifiable units; only the verifier flips [x])

> Each chunk: implement -> machine-evidence DoD (the producing command's output) -> DIFFERENT-agent verifier diffs vs THIS spec. Ordering reflects the interlocks (gateway + treasury before the act; single-node green before failover).

- [x] **C-1 -- Host prereqs + skeleton** (satisfies §5): a Tokio daemon skeleton + the documented host-prereqs check (KVM, cgroup v2, nftables, vsock, jailer). DoD: the check passes on the target host with output pasted; `cargo build` + `cargo clippy -- -D warnings` green.
- [x] **C-2 -- Genome image (microvm.nix) + boot** (satisfies §3.6, G1): the musl-Rust stub genome + microvm.nix build (Linux 6.1 LTS + VMGenID), booted by the daemon via fctools+jailer; vsock `GetSessionContext` round-trip. DoD: G1 green; image hash reproducible (built twice, G10).
- [x] **C-3 -- Gateway + unforgeable treasury** (satisfies §3.1, §3.2, §4.2, G3): the tonic-over-vsock `NodeGateway`; the daemon-owned persisted treasury counter; the §3.2 authorize-order (dedupe->allowlist->budget->perform->meter+debit). DoD: G3 a/b/c green (incl. the no-balance-write fuzz + the ignore-self-report test).
- [x] **C-4 -- Metering + budget halt** (satisfies §3.3, §4.1, G2): cgroups-rs CPU/mem + aya/eBPF egress bytes debiting the treasury; budget-halt kills the VM. DoD: G2 green (halt within one tick, daemon-initiated, metered burn ~= budget).
- [x] **C-5 -- Egress lockdown** (satisfies §3.7, G4): per-VM TAP + nftables default-deny; vsock-only reachability. DoD: G4 green (raw egress fails; nftables drop counter + ~0 eBPF IP bytes).
- [x] **C-6 -- The brokered act** (satisfies §3.2, D-6/D-11, G5): the daemon performs the chosen act (D-16: settle ecash on a local CDK fakewallet mint) via host networking using a host-held credential, metered + treasury-debited, VM issuing no raw network. DoD: G5 (i)-(v) green end-to-end against the real test rail.
- [x] **C-7 -- Snapshot + cross-node resume** (satisfies D-8, §4.1, §5 transfer seam, G6): CPU-template snapshot, mem+state transfer (local seam), node-1 kill, node-2 restore + continue. DoD: G6 green.
- [x] **C-8 -- Entropy re-derive on resume** (satisfies §3.4, §4.4, red-team gate 2, G7): the `GetEntropyNonce` path + the genome re-derive-before-act + the fingerprint instrument + the negative control. DoD: G7 green (pre != post, gen+1, call-ordering, broken-genome fails).
- [x] **C-9 -- openraft lease + no-split-brain** (satisfies §3.5, §4.3, red-team gate 1, G8): the embedded Raft `active_lease{node,term}`; leader+lease-to-run; term-fencing a revived stale node. DoD: G8 green (handoff + fence + no two-actives + at-most-one-node-debits).
- [x] **C-10 -- Idempotent capability across resume** (satisfies §4.2, G9): `idempotency_key` dedupe surviving a snapshot+resume. DoD: G9 green (DUPLICATE_IGNORED, no double-perform, debited once).
- [x] **C-11 -- Full-loop + verifier sign-off** (satisfies §7, §8): the end-to-end run (boot -> meter -> brokered act -> snapshot -> resume on node 2 after node-1 kill -> no-split-brain -> entropy re-derived), reproduced clean by the different-agent verifier with all command output pasted; G10 reproducibility + clean-cut. DoD: G1-G10 + both §8 gates green under an independent reproduction; spike report states what it does NOT prove (§11 last bullet).

---
**Rules of use (kit discipline)**
- DERIVE from ground truth (cited inline); the operator CONFIRMS §2 and rules §12, does not author.
- FREEZE on confirmation; every later change is a dated entry in §2 (supersede, never delete).
- One canonical file. The implementer and the verifier both diff against THIS -- it is the shared contract, not the chat log.
- Every success criterion is a machine-checkable G-gate (§7); "works" without the producing command's output is void.
