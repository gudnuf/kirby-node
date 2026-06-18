# Kirby cross-platform sandbox: research synthesis + recommendation (2026-06-17)

> Driven by the requirement that node hosts must be FIRST-CLASS on macOS WITHOUT the
> operator installing Linux, AND still support Linux servers. The sandbox becomes an
> INTERFACE with multiple backends, not one frozen Firecracker binary. Three background
> researchers (Apple Virtualization.framework; libkrun + Tart; the checkpoint/resume parity
> seam + interface). This is the synthesis + recommendation. No em-dashes per house style.

## TL;DR (the recommendation)

1. Make the sandbox a `SandboxBackend` trait (promote the current `firecracker.rs` to the first impl).
   The daemon (treasury, gateway, meter, lease) stays backend-agnostic and talks only to the trait.
2. Two backends: **Firecracker** (Linux/KVM, the reference, already built) and **Apple
   Virtualization.framework** (macOS, native, no Linux install). NOT libkrun (no snapshot at all) and
   NOT Tart (it is a CLI wrapping VZ.framework, not an embeddable backend).
3. Cross-backend "resume on another node" by VM-memory snapshot is a structural NO. Use a **hybrid**:
   same-platform VM-snapshot resume (fast, v1, the path the build-spec already specs) PLUS an
   **application-level checkpoint** as the only portable cross-backend path.
4. Both resume paths obey the SAME invariant that powers the entropy gate (G7): no ephemeral secret
   survives a move. On the app-checkpoint path the logical blob must EXCLUDE ephemeral secrets and
   re-derive on rehydrate (else G7's FROST-nonce-reuse failure is smuggled through the portable path).
5. macOS is first-class but carries real, named caveats (below). The Firecracker/Linux path stays the
   strongest backend; macOS is a genuine second backend with weaker post-escape isolation, no usable
   Linux checkpoint, and a Rust-FFI cost.

## The hard verdict: cross-backend VM-memory snapshot = NO (structural, not a maturity gap)

Three independent walls, any one fatal:
- **Formats are hypervisor-private.** Firecracker writes its own snapshot (microVM state + guest-RAM +
  versioned device state). Apple `saveMachineStateTo` writes a `.vzvmsave` that is hardware-encrypted
  and bound to that specific Mac + user account (WWDC23), restorable only by a new VZVirtualMachine
  from the same config. libkrun has NO snapshot/restore API at all. No shared format, no transcoder.
- **Same hypervisor + same arch + different CPU already needs a CPU template** (Firecracker T2CL/T2A),
  and those are x86-only. No template fabricates a different ISA.
- **Cross-ISA is a research problem** (state rewriting, ASLR disabled both ends, homogeneous OS), not
  shipping infra. An x86_64 Linux snapshot cannot restore on an Apple-silicon arm64 node.

Corollary: a Firecracker snapshot restores only on another Firecracker/KVM/x86 node with a compatible
(templated) CPU; a VZ save restores only on the same Mac. The two backends share no resumable runtime
state. Cross-backend resume cannot mean VM-memory resume.

## Resume approach: hybrid

- **v1 = same-platform-resume only.** A VM-snapshot is tagged with a `SnapshotClass`
  (= backend x arch x CPU-class). The lease/scheduler may only resume a snapshot on a node with a
  matching class. This is the build-spec's G6/G7 path generalized; the D-13 transfer seam becomes "move
  within a snapshot-compat class." Cost: the failover pool is per-platform-class (need >=2 Linux/x86
  nodes to fail a Linux agent over; >=2 Apple-silicon nodes for a mac agent).
- **Portable path = application-level checkpoint.** The genome serializes its LOGICAL state (not VM
  memory) to a portable, content-addressed blob (on the based-stack substrate: iroh-blobs/Blossom +
  a Nostr replaceable-event pointer); resume = boot a FRESH VM on ANY backend/arch + rehydrate. This
  is the only thing that crosses Linux<->macOS. It costs mid-execution in-memory continuity (resume is
  only at a genome-defined checkpoint boundary; in-flight work since the last checkpoint is redone).
  It requires genome cooperation (a checkpoint-aware mission) + 2 new gateway RPCs:
  `Checkpoint(reason) -> CheckpointBlob` and a boot-time `restore_from: CheckpointRef`.
- **Why hybrid not app-only:** VM-snapshot gives transparent sub-second same-backend failover;
  app-checkpoint gives portability + survives losing a whole platform pool. Same lease, two mechanisms,
  chosen by whether source and target share a SnapshotClass.
- **The shared invariant (load-bearing):** the entropy-re-derive gate (G7) exists because a VM-snapshot
  resume clones user-space PRNG state -> FROST nonce reuse -> key extraction. On the app-checkpoint
  path the danger INVERTS: if the genome naively serializes "everything," it carries a stale nonce
  across the move. So the checkpoint contract MUST exclude ephemeral secrets and re-derive on rehydrate
  via GetEntropyNonce. Same invariant ("no ephemeral secret survives a move"), enforced at two layers.
  Duplicate G7's negative-control test for the checkpoint path.

## Backend assessment

### Firecracker (Linux/KVM) = the reference backend (already built: C-1/C-2/C-3/C-4)
Strongest isolation (KVM hardware + jailer: chroot + seccomp L2 + namespaces + uid-drop), production
snapshot/restore (CPU templates, x86), cgroups+eBPF metering. This is the bar the others are measured
against. Stays the primary/strongest backend.

### Apple Virtualization.framework (macOS) = the macOS backend, VIABLE WITH CAVEATS
- GREEN: boots a Linux microVM (VZLinuxBootLoader + squashfs virtio-blk + static-musl /init) on Apple
  Silicon AND Intel, no Linux install; headless on a Mac mini fleet (Tart proves it at production
  scale for CI). vsock supported (VZVirtioSocketDevice) but the HOST side is NOT raw AF_VSOCK (it is
  the VZ framework API; ENODEV on a raw host vsock socket), so the macOS backend needs a VZ-specific
  host gateway shim. Guest side (genome) is identical to Linux.
- RED/caveats:
  - **Checkpoint:** Apple-Silicon-ONLY (arm64 preprocessor guard; absent on Intel), AND Linux-guest
    save/restore is broken in practice (validateSaveRestoreSupport rejects Linux configs with a
    graphics device; headless-no-GPU might pass but is unconfirmed; no production tool does it). The
    save file is hardware-encrypted + Mac-bound (no cross-host move anyway). So: do NOT rely on VZ
    checkpoint for Linux genomes; the macOS backend leans on the app-level checkpoint for resume.
  - **Isolation after escape:** the hardware VM boundary is real (guest cannot read host memory), but
    there is NO jailer-equivalent. A VM escape (hypervisor 0-day) lands in an unconfined macOS user
    process (no seccomp, no chroot, no namespace cage), vs Firecracker where an escape is still jailed.
    Mitigate: run the VZ host process as a dedicated low-priv user, no VirtioFS, minimal home.
  - **Rust:** no production-ready VZ.framework Rust crate; plan an objc2 FFI layer or a small Swift/Go
    shim. Budget real platform-engineering time.
  - **Metering:** no cgroups. Memory is hard-capped at boot (cannot enforce a running ceiling like
    cgroups). CPU via host-thread rusage/Mach; egress via pf on the vmnet interface or a vsock-proxied
    data plane. Coarser + softer than Linux; the daemon must widen the budget-halt margin. (A raw
    vmnet attachment for pf-on-the-interface needs the com.apple.vm.networking entitlement or root; a
    framework-managed VZNATNetworkDeviceAttachment avoids it but gives less data-plane control.)
  - **Keychain (unlock at boot is the portable fix):** VZ needs an unlocked login.keychain (else
    "Interaction is not allowed with the Security Server"). Documented on macOS 15; UNVERIFIED on
    macOS 26 (the current dev/test box), so treat as version-independent: unlock login.keychain at
    node boot (works on any version). macOS 14 Sonoma never had the regression (a fleet-node option,
    not a dev-box requirement). Entitlement com.apple.security.virtualization (ad-hoc self-sign OK;
    not App Store).

### libkrun = NOT the primary backend
The "one API, KVM-on-Linux + Hypervisor.framework-on-macOS" claim is real and appealing, no Linux
install on mac. BUT: NO snapshot/checkpoint/restore anywhere in libkrun (confirmed across releases,
issues, PRs, roadmap), which is a dealbreaker for Kirby's pause/move/resume. Isolation is weaker by
design ("guest and VMM in the same security context"); adversarial guests need crun-namespace+non-root
layering. Rust = thin krun-sys FFI. Verdict: viable only as a "fast local execution" backend if
checkpoint is relaxed; not the primary. (microsandbox ships a snapshot/fork/restore on top of libkrun,
but likely disk-COW at the orchestration layer, not VMM memory+CPU state; cross-host not shipped.)

### Tart = NOT a backend
Tart is a CLI/fleet tool (OCI-image VM distribution for Mac CI) that WRAPS Virtualization.framework. It
is not an embeddable library; its snapshot feature request is closed "not planned." The real backend
behind Tart is VZ.framework. Tart-the-orchestrator is orthogonal to the backend-interface question.

## The SandboxBackend trait + parity map

Promote `firecracker.rs` to a trait; the daemon talks only to it. (Pseudocode, illustrative.)

methods: `boot/configure`, `meter`, `halt`, `gateway_endpoint` (vsock wire), `apply_egress_policy`,
`snapshot`, `restore`; plus `capabilities() -> BackendCapabilities { backend, guest_arch, isolation,
snapshot: None | Supported{class}, app_checkpoint: bool, metering: Fidelity }`.

Parity map:
- **boot / vsock-wire / gateway / halt = FULL PARITY.** The vsock + gateway parity is THE keystone that
  makes one interface honest: the genome only ever sees the gateway, never the host, so the genome is
  genuinely portable across backends. (Firecracker = host Unix socket per CID; VZ =
  VZVirtioSocketConnection; libkrun = krun vsock; all expose one gateway endpoint per VM.)
- **meter / egress = SAME INTENT, MECHANISM GAP.** Linux: cgroups v2 + eBPF + nftables (authoritative,
  tick-accurate, hard memory bound). macOS: rusage/Mach + pf, no cgroups, softer memory bound. The
  trait returns the same MeterSample shape (so the treasury debit logic D-9 is shared) plus a
  MeterFidelity so the daemon trusts the macOS sample less and widens the halt margin.
- **snapshot / restore = NO PARITY (the gap).** Artifacts are non-interchangeable across backends;
  libkrun has none. Expressed as a SnapshotClass capability the scheduler matches on; never a generic
  snapshot() the scheduler blindly trusts. `app_checkpoint = true` for any backend that runs the
  genome (the portability escape hatch, independent of VM-snapshot support).

## Threading into lease / birth-cert / metering

- **Lease/scheduler (the openraft lease, now platform-aware):** when the lease moves and a resume is
  needed, pick a target by resume mechanism. Same SnapshotClass -> fast VM-snapshot resume (G6/G7).
  No same-class healthy node -> fall back to app-checkpoint on any node. So "pick a resume node"
  becomes constraint-satisfaction over BackendCapabilities, and the failover pool is per-class. The
  term-fencing / no-split-brain invariant (G8) is unchanged + backend-agnostic.
- **Birth-cert policy:** extend with `required_isolation` (HardwareVm), `allowed_backends`
  ([Firecracker, VirtualizationFramework, ...] | any), and a `portability` stance:
  `SameClassOnly` (simplest, v1 default) vs `CrossBackend` (genome is checkpoint-aware, may move
  across platforms). A node admits an agent against this at boot. "Can this agent move from Linux to a
  Mac?" becomes a declared, admission-checked property, not an operational surprise.
- **Metering:** D-9's host-authoritative-treasury invariant is unchanged + portable. What changes is
  the meter SOURCE (cgroups on Linux; rusage/pf on macOS) and FIDELITY (macOS coarser, no running
  memory ceiling -> rely on the boot-time memory cap + a wider halt margin). G2 still required on
  macOS, but its memory-axis acceptance bar is honestly looser; name it as a risk.

## Honest cost of supporting macOS (the caveats, collected)
1. No usable Linux-guest VM-checkpoint on VZ -> macOS resume leans on the app-level checkpoint path.
2. No jailer-equivalent -> a VM escape on macOS is unconfined (vs jailed on Firecracker). Weaker
   defense-in-depth; mitigate with a low-priv host user + no VirtioFS.
3. Rust-FFI cost (objc2 / Swift shim) to drive VZ.framework.
4. Coarser metering (no cgroups; memory hard-capped at boot only).
5. Keychain unlock-at-boot need (documented on macOS 15, unverified on macOS 26) + entitlement/code-signing friction for a headless fleet.
6. The app-level checkpoint path is net-new genome surface (a checkpoint-aware mission + 2 gateway
   RPCs + the no-ephemeral-secret invariant + a duplicated G7 negative-control test).

## Open decisions
- Confirm the two backends: Firecracker (Linux) + Apple Virtualization.framework (macOS); drop libkrun
  + Tart as primary backends (libkrun possibly later as a checkpoint-relaxed fast tier).
- Confirm the hybrid resume model (same-platform VM-snapshot + app-level checkpoint) and that v1 ships
  same-platform-resume first, with the app-checkpoint path as the cross-platform follow-on.
- Greenlight (post-spike) refactoring the spike's `firecracker.rs` into the `SandboxBackend` trait
  (Firecracker as the first impl), and whether to start the macOS/VZ backend now or after the
  Firecracker spike (C-5..C-11) completes. (Recommend: finish the Firecracker spike as the reference,
  THEN add the VZ backend behind the trait + the app-checkpoint path.)
- This becomes a dated entry in the build-spec's Decisions register (the single-Firecracker-backend
  becomes Firecracker-as-first-backend-behind-an-interface) once confirmed.

## Sources
Firecracker CPU templates + snapshot docs; Apple saveMachineStateTo / restoreMachineStateFrom +
WWDC23 (hardware-encrypted, Mac-bound); Apple dev-forum threads (arm64-only guard; Linux-guest
save fails; host vsock ENODEV); libkrun repo/releases/issues + security discussion #538 (no snapshot;
same-security-context); Code-Hex/vz (host vsock via framework API); Tart FAQ + issue #213 (CLI, snapshot
not-planned, macOS-15 keychain); cross-ISA migration papers (Wharf, CRIU-het); krun-sys / virt-fwk /
virtualization-rs (Rust binding maturity). Full source list in the three background research logs.

Related: docs/build-spec.md (D-13 seam, D-5/G7 entropy, D-4 lease, D-9 treasury);
docs/vz-macos-backend-sketch.md; docs/vz-app-checkpoint-resume.md.
