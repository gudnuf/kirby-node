# Kirby VZ app-checkpoint resume: design (2026-06-17)

> The PORTABLE cross-backend resume path, the sibling of C-7's same-platform VM-snapshot.
> C-7 left the slot open + documented (sandbox.rs `restore()` doc lines 494-507,
> `BackendCapabilities.app_checkpoint`, snapshot_run.rs header). This is the design to
> slot into it. Design only; the implementation is gated (see Dependencies). No em-dashes
> per house style.

## Why it exists (the contract C-7 froze)

A VM-memory snapshot cannot cross hypervisor or arch (structural: Firecracker
mem+vmstate is x86/KVM-private, a VZ save is Mac-bound + arm64). So a genome can
NEVER move Linux<->macOS, or onto a VZ node at all, by VM-snapshot. VZ reports
`snapshot: None`. The app-checkpoint is the ONLY resume mechanism that reaches a
VZ node, and the only cross-backend one. It trades transparent sub-second failover
for portability: resume happens at a genome-defined checkpoint boundary, and
in-flight work since the last checkpoint is redone.

Mechanism (per the C-7 `restore()` note): boot a FRESH guest via
`SandboxBackend::boot` (NOT `restore()`), hand the genome `restore_from:
CheckpointRef`, the genome rehydrates its LOGICAL state and re-derives ephemeral
secrets. The scheduler chooses this branch when `SnapshotClass::restorable_on`
fails over the source class and the target's `snapshot`/`app_checkpoint` caps.

## The key framing: this is AGNOSTIC machinery, not VZ code

Nothing in the app-checkpoint is macOS-specific. It is: a checkpoint-aware genome
workload, two gateway RPCs, a `CheckpointRef`/`CheckpointStore`, a `restore_from`
boot field, a scheduler branch, and a negative-control test. All of it lives in
the AGNOSTIC core (genome, gateway, kirby-proto, sandbox.rs types, a new
`app_checkpoint_run.rs`) exactly as C-7's VM-snapshot orchestration lives in the
agnostic `snapshot_run.rs` with only the mechanics behind the backend.

VZ merely DEPENDS on it (because `snapshot: None`, app-checkpoint is its only
resume); Firecracker gains it for free (any backend that runs the genome can
rehydrate, so once built BOTH report `app_checkpoint: true`). The VZ-specific work
is the boot/vsock/egress/meter/halt backend + booting with `restore_from` on the
Mac; the resume MECHANISM itself is shared.

## Concrete additions

Types (sandbox.rs, agnostic):
- `CheckpointRef`: a content-addressed pointer to a checkpoint blob. Local-path /
  content-hash for the spike harness; the real transport (iroh-blobs/Blossom + a
  Nostr replaceable-event pointer, the based-stack) is a drop-in, MIRRORING how
  C-7's `LocalDirTransfer` stands in for the real `SnapshotTransfer`.
- `CheckpointBlob`/`CheckpointArtifact`: the genome's serialized LOGICAL state,
  content-addressed, opaque to the daemon. Carries NO ephemeral secret (the
  invariant). Analogous to `SnapshotArtifact` but logical, not mem+vmstate.
- `CheckpointStore` trait + `LocalDirCheckpointStore` default (put/get a blob by
  ref), the agnostic transfer seam, mirroring `SnapshotTransfer`.
- `GuestSpec.restore_from: Option<CheckpointRef>` (the sibling of the existing
  `snapshot_capable: bool`): when `Some`, `boot()` tells the genome to rehydrate
  instead of cold-start (kernel cmdline `kirby.restore_from=` or via SessionContext).

Two gateway RPCs (kirby-proto node_gateway.proto + gateway.rs) extending the 4
existing (GetSessionContext, GetEntropyNonce, ReportEvent, RequestCapability):
- `SubmitCheckpoint(CheckpointBlob) -> Ack`. NOTE the direction wrinkle: the
  gateway is genome->daemon (genome is the CLIENT), so the logical
  "Checkpoint(reason) -> CheckpointBlob" (daemon asks, genome produces) inverts:
  the genome PUSHES its latest logical-state blob at mission-defined safe points;
  the daemon content-addresses + retains the latest. On-demand daemon-initiated
  checkpoint, if wanted, is a "checkpoint-requested" flag returned in the next
  heartbeat ack, NOT a daemon->genome call.
- boot-time ref: the genome's `GetSessionContext` response gains a `restore_from`
  field carrying the ref (+ inline blob bytes if small). Add a separate
  `FetchCheckpoint(CheckpointRef) -> CheckpointBlob` only if blobs grow large
  enough to want streaming.

Genome (checkpoint-aware workload): serialize its logical mission state to a blob
at safe points (-> SubmitCheckpoint); on boot with `restore_from`, fetch + rehydrate
from the blob instead of cold-starting.

Scheduler (app_checkpoint_run.rs, agnostic): the new branch. Same-class source/
target -> C-7 VM-snapshot (snapshot -> transfer -> restore). Else, if target
`app_checkpoint` -> boot fresh + restore_from. Else, no resume path (refuse).

Capabilities: VZ `{ snapshot: None, app_checkpoint: true }`; Firecracker flips to
`{ snapshot: Some(IntelT2CL), app_checkpoint: true }` once the machinery lands.

## The no-ephemeral-secret invariant (G7 sibling) + its test

C-7 enforces G7 for VM-snapshot via the genome+gateway: on the VMGenID generation
bump after restore, the genome re-fetches `GetEntropyNonce` rather than reusing the
cloned PRNG state. The artifact carries no secret.

App-checkpoint is actually a SIMPLER case: a fresh `boot()` = a brand-new VM with a
fresh VMGenID, so the genome's entropy is fresh BY CONSTRUCTION (it never inherited
the old PRNG state, it is a new process). The ONLY hole is the genome serializing
an ephemeral secret (a FROST signing nonce, any PRNG-derived ephemeral key) INTO
the checkpoint blob and rehydrating it. So the invariant is narrow and enforceable:
the checkpoint schema EXCLUDES ephemeral-secret fields; on rehydrate the genome
re-derives them via `GetEntropyNonce`.

Negative-control test (the G7 dup, gate it like G7): construct a checkpoint, resume
from it, and assert the rehydrated genome's ephemeral nonce is FRESH (re-fetched,
differs from any value present pre-checkpoint), i.e. a blob cannot smuggle a stale
nonce across the move. This DEPENDS on C-8 having built the GetEntropyNonce
re-derive surface (Dependency below).

## Resume liveness: the stale-transport black hole (FIX-3, C-11)

The C-11 benchcheck caught a failover-liveness bug the per-chunk gates missed (a
~20% flake on COLD resumes, masked by the warm capstone). It is a direct input to
this design.

The bug: after a VM-snapshot resume, the genome's restored vsock channel still
points at the KILLED source node's daemon. That host peer is gone and no RST ever
reaches the restored guest, so the first post-resume RPC on the stale channel
blocks FOREVER. The genome had no per-request deadline and no keepalive, so it never
got an error, so it never reached its existing re-dial branch: the reconnect
silently never fired. The fix (crates/kirby-genome/src/main.rs `connect()`): a 5s
per-request `.timeout()` plus HTTP/2 keepalive (`http2_keep_alive_interval` 2s,
`keep_alive_timeout` 4s, `keep_alive_while_idle` true) on the genome's gateway
Endpoint. The hang becomes a `tonic::Status`, the existing re-dial runs, the genome
reconnects to the new active node's gateway.

Three consequences for THIS design, in order of who must act:

1. INHERITED, no VZ action. The fix is in the genome binary, the agnostic workload
   that runs IDENTICALLY in a VZ Linux guest (guest-side AF_VSOCK + tonic client are
   the same; only the HOST side of vsock differs by backend). VZ inherits the
   genome-side guard for free. Do not re-implement it.

2. App-checkpoint DODGES the genome-side bug by construction, but does not retire the
   lesson. App-checkpoint boots a FRESH guest (the same reason its G7 case is
   simpler): a fresh process has a fresh tonic client and never inherits a stale
   channel, so the precise FIX-3 hang cannot occur on the app-checkpoint genome
   client. (VZ same-platform VM-snapshot, IF a Mac-to-Mac save is ever wired under
   `snapshot: Some(...)`, WOULD reproduce FIX-3 exactly and relies on the inherited
   genome-side fix.)

3. NEW VZ surface: the HOST-side vsock shim is a second instance of the same black
   hole. This is the load-bearing addition. Firecracker's host side is a UnixListener
   (its vsock muxer maps AF_VSOCK to a Unix socket); the VZ host side is the framework
   API, VZVirtioSocketDevice / VZVirtioSocketConnection, handing `serve_vz_vsock` a
   connection file descriptor that it wraps and feeds to tonic `serve_with_incoming`.
   When the old guest dies (halt, reboot, or a restore that replaces it) the framework
   can leave a VZVirtioSocketConnection whose guest peer is gone. If the accept loop or
   a per-connection server task blocks forever on a read from that dead fd with no
   liveness guard, the host side wedges exactly as the genome did, and the genome's
   re-dial reaches a server that never serves it (a black hole on the SERVE side, not
   the dial side).

So `serve_vz_vsock` MUST carry, host-side:
- The accept loop tolerates and reaps dead connections: peer-gone closes the fd and
  keeps accepting, so a fresh re-dial is always served.
- Per-connection reads/writes on the framework fd get a liveness guard (a read
  deadline or the framework's own peer-close signal), so a half-dead
  VZVirtioSocketConnection (fd open, guest gone) cannot wedge a server task.
- VERIFY-ON-MAC (a boot-confirm item, alongside the arm64 console choice): does a dead
  VZVirtioSocketConnection fd return EOF promptly, or does it hang? The framework's
  peer-close semantics are NOT assumed; confirm on real VZ before the shim is trusted.
  If the framework holds the connection object alive past guest-death, the host-side
  deadline is mandatory, not optional. BASELINE for the A/B: on Firecracker the host
  side did NOT wedge in the spike (the uds peer appears to EOF promptly on guest
  death, INFERRED from reliable failover, not separately probed). The Mac check
  compares against that baseline, and ideally probes Firecracker directly rather than
  leaving it inferred; a VZVirtioSocketConnection may well differ from a uds.
- COORDINATION (FIX-2): the symmetric question exists agnostic-side too (the daemon's
  per-VM serve task vs a dead guest, adjacent to FIX-2's reap-leak). "Audit the
  serve-loop for a post-death liveness guard + reap dead conns" is folded into the
  FIX-2 hardening, so the agnostic reap + keep-accepting may land from that side;
  `serve_vz_vsock`'s job is then the framework-fd-specific delta on top (whatever a
  dead VZVirtioSocketConnection does that a dead uds does not).

The deadline is a tradeoff, not a constant. The genome's 5s suits the spike's LOCAL
mint (~1.46s settle). It must exceed the slowest LEGITIMATE brokered act, or the
inverse failure bites: a real non-local Lightning melt that is slow-but-alive gets
killed mid-flight and looks like a black hole when it is not. When the VZ path runs
real acts, the per-request deadline (genome-side, inherited) AND any host-side read
deadline added must both follow the rule "> worst-case LIVE-act latency + margin"
(act-type-aware once a non-local mint/melt is in play), not at 5s by reflex.
Too-short a deadline turns a slow live peer into a false dead peer.

## Dependencies + sequencing (why this is design-now, build-later)

1. Mac access for the VZ-side execution (boot with `restore_from` on VZ).
2. C-8 (entropy/G7): builds the GetEntropyNonce re-derive the negative-control test
   asserts against. Sequence the app-checkpoint AFTER C-8 lands. (C-8 rides on C-7.)
3. Genome checkpoint-awareness: the genome needs a mission that has logical state
   worth serializing. The spike genome is a stub heartbeat; a real checkpoint test
   needs a workload with rehydratable state (a "checkpoint" workload sibling of the
   "snapshot" heartbeat workload C-7 added).
4. Build-ownership: the machinery is agnostic-core + genome + proto, which the main
   build loop owns and where C-8 works next. Cleanest: the build loop treats this as a
   numbered chunk from this design (fresh-agent impl + verifier), with the VZ
   backend's job being the design + the VZ-backend integration (boot-with-restore_from
   on the Mac) + review.

## Open questions
- Q1: the Checkpoint-direction shaping (genome-client SubmitCheckpoint + SessionContext
  restore_from, vs a literal daemon-initiated Checkpoint). Agree the genome-client shape?
- Q2: build-ownership of the agnostic machinery (parent's loop as a chunk from this
  design, vs the VZ track building in the main tree coordinating with C-8).
- Q3: sequence after C-8 (the negative-control test needs the re-derive surface).

## Related
docs/cross-platform-sandbox.md (hybrid resume, the app-checkpoint origin),
docs/vz-macos-backend-sketch.md,
crates/kirby-node/src/{sandbox.rs (C-7 restore() note 494-507), snapshot_run.rs (C-7
orchestration), gateway.rs, kirby-proto/proto/node_gateway.proto}.
Spike: docs/build-spec.md.
