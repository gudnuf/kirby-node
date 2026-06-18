# The genome image (spec 3.6, gate G1, gate G10): the musl-Rust stub genome in a
# read-only squashfs plus the stripped Linux 6.1 LTS guest kernel, built
# reproducibly so the image hash is identical on every node (the
# verifiable-genome property, content-addressed).
#
# The pieces:
#   - genomeBin: the kirby-genome crate built as a static musl binary (no glibc,
#     no interpreter), stripped. Built inside Nix off the workspace Cargo.lock so
#     it is a pure function of the sources and the pinned toolchain.
#   - rootfs.squashfs: a read-only squashfs whose only payload is the genome at
#     /init (the microVM boots it as PID 1). Built with deterministic mksquashfs
#     flags (sorted, all-root, no timestamps, reproducible) so the bytes, and
#     thus the hash, are stable.
#   - vmlinux: the guest kernel (nix/guest-kernel.nix), VMGenID built-in.
#   - the default output bundles vmlinux plus rootfs.squashfs plus a manifest the
#     daemon reads to find them.
#
# The daemon boots this image via fctools plus the jailer (spec D-7); microvm.nix
# is the technique reference for the minimal kernel-plus-squashfs microVM shape,
# and is pinned as a flake input. This build does NOT use a full NixOS guest
# (the genome is the only userspace, no glibc, no systemd), matching spec 3.6.
{ pkgs, rustToolchain }:
let
  inherit (pkgs) lib;

  muslTarget = "x86_64-unknown-linux-musl";

  # The genome does NOT depend on the CDK ecash stack (that is the host daemon's
  # C-6 brokered rail). The cdk crates now come from the crates.io registry
  # (cashubtc/cdk 0.17.x), but they still bloat the genome build and, more
  # importantly, the genome's closure is cdk-free, so prune the cdk/cashu packages
  # (and their dangling references from the host-daemon package block) from a
  # build-time copy of the lock. Matched by PACKAGE NAME (cdk, cdk-*, cashu,
  # cashu-*) rather than by git source, since the registry source string is shared
  # by every other crate. This keeps ONE source-of-truth lock (the workspace one)
  # and makes the genome image a pure function of the genome's actual closure. The
  # pruned lock is still consistent for resolving crates/kirby-genome + kirby-proto
  # (neither references cdk); the removed packages were referenced only by the host
  # daemon, which this image build does not compile.
  prunedCargoLock = pkgs.runCommand "kirby-genome-pruned-cargo.lock" { } ''
    ${pkgs.gawk}/bin/awk '
      BEGIN { RS = "\n\n"; ORS = "\n\n" }
      {
        # Drop every [[package]] block for a cdk/cashu crate (the ecash stack the
        # genome never uses): name = "cdk", "cdk-...", "cashu", or "cashu-...".
        if ($0 ~ /\nname = "(cdk|cashu)(-[a-z0-9-]+)?"\n/ || $0 ~ /^name = "(cdk|cashu)(-[a-z0-9-]+)?"\n/) next
        block = $0
        # In the kirby-node host-daemon block, drop the now-dangling cdk/cashu
        # dependency lines so the lock has no references to the pruned packages.
        if (block ~ /name = "kirby-node"/) {
          n = split(block, lines, "\n")
          block = ""
          for (i = 1; i <= n; i++) {
            if (lines[i] ~ /^ "(cdk|cashu)/) continue
            block = block (block == "" ? "" : "\n") lines[i]
          }
        }
        print block
      }
    ' ${../Cargo.lock} > "$out"
  '';

  # Cross-build the genome for static musl. pkgsCross.musl64 sets buildPlatform =
  # gnu (so build scripts and proc-macros run on the host with glibc, avoiding
  # the static-build-script SIGSEGV) and hostPlatform = musl (so the genome
  # binary itself is fully static, no glibc, no interpreter, spec 3.6).
  # buildRustPackage's cargoBuildHook then targets musl. The rust-overlay
  # toolchain (pinned, same as the dev shell) supplies cargo and rustc with the
  # musl target component, keeping the binary reproducible.
  muslPkgs = pkgs.pkgsCross.musl64;
  muslRustPlatform = muslPkgs.makeRustPlatform {
    cargo = rustToolchain;
    rustc = rustToolchain;
  };

  # The whole workspace is the source (the genome depends on kirby-proto). Filter
  # to the inputs that affect the build so unrelated edits do not change the
  # hash. The proto build needs protoc at build time.
  workspaceSrc = lib.cleanSourceWith {
    src = ../.;
    filter = path: type:
      let rel = lib.removePrefix (toString ../. + "/") (toString path);
      in
      rel == "Cargo.toml"
      || rel == "Cargo.lock"
      || rel == "crates"
      || lib.hasPrefix "crates/" rel;
  };

  genomeBin = muslRustPlatform.buildRustPackage {
    pname = "kirby-genome";
    version = "0.1.0";
    src = workspaceSrc;
    # The cdk-free pruned lock (see prunedCargoLock above): the genome's closure
    # has no cdk deps, so the image builds against a lock with the CDK git packages
    # removed, sidestepping the importCargoLock bare-rev fetch limitation.
    cargoLock.lockFile = prunedCargoLock;
    # Swap in the pruned lock AND drop the host daemon (kirby-node) from the
    # workspace so cargo never tries to RESOLVE its cdk git deps (offline) when
    # building only the genome. The genome + kirby-proto are a self-contained,
    # cdk-free subgraph; dropping the daemon member and its cdk workspace.deps
    # makes the offline genome build consistent against the pruned lock.
    postPatch = ''
      cp ${prunedCargoLock} Cargo.lock
      # Remove the kirby-node member line from the workspace members list.
      ${pkgs.gnused}/bin/sed -i '/"crates\/kirby-node",/d' Cargo.toml
      # Remove the cdk/cashu/bip39 workspace.dependencies lines (the host daemon's,
      # not the genome's) so cargo does not try to fetch them offline.
      ${pkgs.gnused}/bin/sed -i '/^cdk\( \|-\)/d;/^cashu /d' Cargo.toml
    '';

    # Build only the genome crate (the daemon is host-side, built by cargo, not
    # in the image).
    buildAndTestSubdir = "crates/kirby-genome";
    # The genome has no tests of its own and the integration tests need the host
    # target plus a vsock; the image build only needs the binary.
    doCheck = false;

    nativeBuildInputs = [ pkgs.protobuf ];
    PROTOC = "${pkgs.protobuf}/bin/protoc";

    # Force a FULLY static binary: +crt-static statically links the C runtime AND
    # libgcc, so the genome has NO dynamic dependencies (nixpkgs' cross-musl
    # otherwise dynamically links libgcc_s, which a microVM init off a read-only
    # root with no shared libraries could not load). Strip symbols for a smaller
    # image. Scoped to the musl target so the host build platform is unaffected.
    CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_RUSTFLAGS = "-C target-feature=+crt-static -C strip=symbols";

    # cargoBuildHook builds into the musl target dir (the static stdenv's host
    # platform); install the binary from there.
    installPhase = ''
      runHook preInstall
      install -Dm755 \
        "target/${muslTarget}/release/kirby-genome" \
        "$out/bin/kirby-genome"
      runHook postInstall
    '';

    meta.description = "kirby stub genome, static musl, the microVM init";
  };

  kernel = import ./guest-kernel.nix { inherit pkgs; };

  # The read-only squashfs rootfs. The genome is /init (PID 1 off the read-only
  # root). mksquashfs is driven with deterministic flags so the image is
  # content-addressed (gate G10):
  #   -all-root        every file owned by root:root (no build-user uid leak)
  #   -no-xattrs       no extended attributes (none are needed, and they vary)
  #   -comp xz         matches the kernel's built-in SQUASHFS_XZ decompressor
  # Timestamps are pinned by the nix-provided SOURCE_DATE_EPOCH (mksquashfs honors
  # it), so the explicit time flags are omitted (mksquashfs refuses both at once).
  rootfs = pkgs.runCommand "kirby-genome-rootfs.squashfs"
    {
      nativeBuildInputs = [ pkgs.squashfsTools ];
    }
    ''
      root=$(mktemp -d)
      mkdir -p "$root"
      # The genome is the init process: install it at /init.
      install -Dm755 ${genomeBin}/bin/kirby-genome "$root/init"
      # Mount points the genome mounts as PID 1 (no init system in the image):
      # /proc and /sys are mounted by the genome, /dev is auto-mounted by the
      # kernel (CONFIG_DEVTMPFS_MOUNT). Empty dirs in the read-only squashfs.
      mkdir -p "$root/proc" "$root/sys" "$root/dev"

      mksquashfs "$root" "$out" \
        -all-root \
        -no-xattrs \
        -comp xz \
        -noappend \
        -no-progress
    '';

  # The kernel image Firecracker boots is the uncompressed vmlinux ELF, under
  # the kernel's dev output on x86_64 (the firecracker runner uses the same
  # path). The dev output's vmlinux carries debug info; the image build strips it
  # (a stripped guest kernel, spec 3.6) so the image is small. strip removes only
  # the symbol and debug sections; the PT_LOAD segments Firecracker boots from are
  # untouched.
  vmlinux = "${kernel.dev}/vmlinux";

in
pkgs.runCommand "kirby-genome-image"
  {
    nativeBuildInputs = [ pkgs.binutils ];
    passthru = { inherit genomeBin rootfs kernel; vmlinuxPath = vmlinux; };
  }
  ''
    mkdir -p "$out"
    # Strip the guest kernel (drop debug and symbol sections; loadable segments
    # are preserved so Firecracker still boots it).
    strip -s -o "$out/vmlinux" ${vmlinux}
    cp ${rootfs} "$out/rootfs.squashfs"

    # A manifest the daemon reads to locate the boot artifacts without hardcoding
    # nix store paths. Plain key=value lines, no timestamps, so it stays
    # reproducible.
    {
      echo "vmlinux=$out/vmlinux"
      echo "rootfs=$out/rootfs.squashfs"
      echo "kernel_version=${kernel.version}"
    } > "$out/manifest.env"
  ''
