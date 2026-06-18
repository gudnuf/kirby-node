# The genome guest kernel (spec 3.6, D-8): a stripped Linux 6.1 LTS kernel for
# the Firecracker microVM, with the VMGenID device enabled.
#
# The base is nixpkgs linux_6_1 (an LTS series, 6.1.x). Its generic config ships
# the pieces the microVM needs as MODULES; a microVM that boots a squashfs root
# over virtio with no initrd cannot load modules before it has mounted root, so
# every piece on the boot path is promoted to built-in here:
#   - virtio plus the MMIO transport (Firecracker presents virtio-MMIO devices)
#   - virtio-blk (the read-only squashfs rootfs is a virtio block device)
#   - squashfs with the xz decompressor (the rootfs filesystem)
#   - the vsock stack (the genome to daemon gateway transport, spec 3.1)
#   - VMGENID (the device the kernel CSPRNG reseeds from on a snapshot restore,
#     the D-5 / D-8 resume gate; C-2 only needs it present, later chunks exercise
#     it)
# The 8250 serial console is built-in so the boot log reaches the daemon over
# the Firecracker serial port.
#
# Reproducible: the derivation is a pure function of the pinned nixpkgs and this
# config, so the kernel hash is identical on every node (the verifiable-genome
# property, spec 3.6 and gate G10).
{ pkgs }:
let
  inherit (pkgs) lib;
  inherit (lib.kernel) yes;
  # nixpkgs' common-config sets IP_PNP (and its DHCP variant) to "n"; the spike
  # wants kernel boot-time IP autoconfiguration so the genome's eth0 is set from
  # the `ip=` cmdline (C-5), so force them on over that default.
  forceYes = lib.mkForce yes;
in
(pkgs.linux_6_1.override {
  # structuredExtraConfig is merged over the generic nixpkgs config, so we keep
  # everything that config already provides (a known-bootable base) and only
  # force the boot-path pieces built-in plus trim a little weight.
  structuredExtraConfig = {
    # The VMGenID device, built-in so it is live at boot (spec D-5 / D-8).
    VMGENID = yes;

    # virtio core plus both transports. Firecracker uses MMIO; PCI is kept built
    # in too so the same kernel works if a later chunk flips on the PCI path.
    VIRTIO = yes;
    VIRTIO_MMIO = yes;
    VIRTIO_PCI = yes;
    VIRTIO_PCI_LEGACY = yes;

    # The read-only squashfs rootfs rides a virtio block device.
    VIRTIO_BLK = yes;

    # The squashfs filesystem and its xz decompressor (the rootfs format).
    SQUASHFS = yes;
    SQUASHFS_XZ = yes;

    # The vsock stack: the genome to daemon gateway transport (spec 3.1).
    VSOCKETS = yes;
    VIRTIO_VSOCKETS = yes;

    # The network stack and virtio-net, built-in (C-5, spec 3.7): the per-VM TAP
    # appears to the guest as a virtio-net device, so the genome has an interface
    # it can ATTEMPT egress on (which the host nftables default-deny then drops,
    # gate G4). INET is the IPv4 stack; VIRTIO_NET is the device; IP_PNP is the
    # kernel boot-time IP autoconfiguration so the genome's eth0 is configured
    # from the `ip=` kernel cmdline (no in-genome interface setup needed off the
    # read-only root). Built-in because the microVM loads no modules on boot.
    INET = yes;
    NETDEVICES = yes;
    NET_CORE = yes;
    VIRTIO_NET = yes;
    IP_PNP = forceYes;
    IP_PNP_DHCP = forceYes;

    # Serial console, built-in, so the boot log streams over the Firecracker
    # serial port to the daemon (the G1 boot evidence).
    SERIAL_8250 = yes;
    SERIAL_8250_CONSOLE = yes;
  };
  # The generic nixpkgs config carries many module (=m) options, so loadable
  # module support stays enabled (turning it off wholesale breaks the config
  # tool against the inherited answers). The genome boots entirely on the
  # built-in pieces above, so no module is loaded on the boot path.
}).overrideAttrs (old: {
  # A stripped guest kernel (spec 3.6): no debug info, smaller image.
  pname = "kirby-genome-kernel";
})
