//! The per-VM TAP and its nftables default-deny egress lockdown (spec 3.7, gate
//! G4).
//!
//! C-5 gives the VM a network interface it can ATTEMPT egress on, then locks
//! that interface down so the attempt fails. The shape:
//!
//! - A per-VM TAP device (`kirby-tap-<short-id>`), owned by the daemon's uid so
//!   the daemon (not root) can hand it to the jailed firecracker. The TAP is the
//!   VM's only network interface (wired into fctools `network_interfaces`). The
//!   host end gets a link-local-ish address but is NOT a router for it: there is
//!   no default route for the VM, no IP forwarding enabled for the TAP, and no
//!   NAT, so even before nftables the VM has no path to the internet.
//!
//! - nftables DEFAULT-DENY on the VM's egress (the host-kernel enforcer, D-7).
//!   A dedicated `netdev` table with a hook bound to THIS TAP, `policy drop`, and
//!   a `counter`. The hook is the TAP's INGRESS hook: for a TAP, the packets the
//!   GUEST transmits (the VM's egress) arrive at the host as the device's
//!   INGRESS (the host RX path), so the ingress hook is where the VM's outbound
//!   is seen and dropped (verified empirically; the egress hook would only see
//!   host-to-guest traffic). Every packet the VM emits is dropped by the host
//!   kernel and counted. The genome cannot touch this (it is a host rule in the
//!   daemon's own table; the genome has no host access). DNS is blocked
//!   structurally (it is just more egress with no route and a drop). The ONLY
//!   VM-originated channel that works is the vsock to the daemon, and vsock is
//!   not IP, so it never traverses this TAP (structural isolation, spec 3.7).
//!
//! - The daemon's OWN host networking is entirely separate from this TAP; the
//!   brokered act (C-6) goes out the daemon's host interface, never the VM TAP.
//!
//! All of this needs root (TAP create, nftables), so it runs through the SAME
//! sudo path the jailer uses (the locked D-7 decision: `sudo` the privileged
//! step, never weaken the boundary). We use our OWN dedicated nftables tables and
//! never touch the host's existing tables (the host runs iptables-nft for Docker
//! and Tailscale; a dedicated `netdev` table per TAP is isolated from those).

use std::path::PathBuf;
use std::process::Command;

/// A per-VM TAP plus its nftables egress lockdown. Held by the VM lifecycle; on
/// drop (or explicit teardown) the nftables table and the TAP are removed so a
/// run leaves no host state behind.
pub struct VmTap {
    /// The TAP device name (`kirby-tap-<short-id>`), wired into the VM.
    name: String,
    /// The dedicated nftables netdev table name for this TAP's egress lockdown.
    nft_table: String,
    /// The sudo binary the daemon runs the privileged steps through (the locked
    /// D-7 launch path; NOPASSWD via the NixOS wrapper).
    sudo_bin: PathBuf,
    /// Whether teardown already ran (so Drop does not double-tear-down).
    torn_down: bool,
}

/// The MAC the guest interface gets (Firecracker assigns it; deterministic so the
/// guest can configure the link without DHCP). Locally administered, unicast.
pub const GUEST_MAC: &str = "06:00:ac:10:00:02";

impl VmTap {
    /// The TAP device name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Create the per-VM TAP (owned by `uid`/`gid` so the daemon can hand it to
    /// the jailed firecracker) and install the nftables default-deny egress
    /// lockdown on it (spec 3.7). Both steps run through sudo (the D-7 path).
    ///
    /// The TAP gets a host-side address but the host is NOT a router for it (no
    /// default route for the VM, no forwarding, no NAT), so the VM has no path to
    /// the internet even before the nftables drop; the drop is the enforced,
    /// counted host-kernel backstop (G4: the drop counter shows the dropped
    /// egress attempt).
    pub fn create(
        short_id: &str,
        uid: u32,
        gid: u32,
        sudo_bin: PathBuf,
    ) -> anyhow::Result<Self> {
        // A short, unique, interface-name-safe device name. Linux caps IFNAMSIZ
        // at 15 chars, so keep `kirby-tap-<id>` within that.
        let name = format!("kirby-tap-{}", short_tail(short_id, 5));
        let nft_table = format!("kirby_egress_{}", short_tail(short_id, 8));

        let mut tap = VmTap { name, nft_table, sudo_bin, torn_down: false };

        // A prior crashed run may have left the TAP or table; remove them first
        // so create is idempotent. Best-effort (absent is fine).
        tap.teardown_quiet();

        // 1) Create the TAP, owned by the daemon's uid/gid (so the daemon can
        // bind it into the jailed firecracker without the VM needing root).
        tap.sudo(&[
            "ip", "tuntap", "add", "dev", &tap.name, "mode", "tap", "user",
            &uid.to_string(), "group", &gid.to_string(),
        ])
        .map_err(|e| anyhow::anyhow!("create TAP {}: {e}", tap.name))?;

        // 2) Give the host end an address but DO NOT make the host a router for
        // the VM: no `ip route` for a VM subnet via this TAP beyond the on-link
        // /30, no forwarding, no NAT. The VM can put a packet on the wire; it has
        // nowhere to go. The on-link host address lets the VM's egress attempt
        // actually emit a packet (so the drop counter and eBPF meter see it)
        // rather than failing earlier with "network unreachable" before egress.
        tap.sudo(&["ip", "addr", "add", "172.16.0.1/30", "dev", &tap.name])
            .map_err(|e| anyhow::anyhow!("address TAP {}: {e}", tap.name))?;
        tap.sudo(&["ip", "link", "set", "dev", &tap.name, "up"])
            .map_err(|e| anyhow::anyhow!("bring up TAP {}: {e}", tap.name))?;

        // 3) The nftables default-deny lockdown on the VM's egress (spec 3.7).
        // A dedicated netdev table with a hook bound to the device, policy drop,
        // and a named counter so the drop is observable (G4). The hook is the
        // TAP's INGRESS hook: the packets the GUEST sends (the VM's egress) arrive
        // at the host as the device's ingress (the host RX path), so this is where
        // the VM's outbound is dropped and counted (the egress hook would only see
        // host-to-guest). This is our own table; it does not touch the host's
        // iptables-nft tables.
        let ruleset = format!(
            "table netdev {table} {{\n\
            \x20 counter dropped_egress {{ }}\n\
            \x20 chain vm_egress {{\n\
            \x20\x20 type filter hook ingress device \"{dev}\" priority filter; policy drop;\n\
            \x20\x20 counter name dropped_egress\n\
            \x20 }}\n\
            }}\n",
            table = tap.nft_table,
            dev = tap.name,
        );
        tap.sudo_stdin(&["nft", "-f", "-"], &ruleset)
            .map_err(|e| anyhow::anyhow!("install nftables egress lockdown for {}: {e}", tap.name))?;

        tracing::info!(
            tap = %tap.name,
            nft_table = %tap.nft_table,
            "per-VM TAP created and nftables default-deny egress installed (spec 3.7); VM has no route to the internet"
        );
        Ok(tap)
    }

    /// Read the host nftables drop counter (packets, bytes) for this TAP's egress
    /// lockdown. The G4 evidence: after the genome's denied egress attempt this
    /// shows a non-zero drop (the host kernel dropped the VM's packets). Returns
    /// (packets, bytes); a missing table or counter reads as (0, 0) with a warn.
    pub fn drop_counter(&self) -> NftDropCounter {
        // `nft -j list counter ...` emits JSON; parse without a JSON dep by
        // pulling the integer fields. The plain-text form is simpler to parse
        // robustly here.
        let out = self.sudo_capture(&[
            "nft", "list", "counter", "netdev", &self.nft_table, "dropped_egress",
        ]);
        match out {
            Ok(text) => parse_nft_counter(&text).unwrap_or_else(|| {
                tracing::warn!(table = %self.nft_table, "could not parse nftables drop counter");
                NftDropCounter::default()
            }),
            Err(e) => {
                tracing::warn!(table = %self.nft_table, error = %e, "could not read nftables drop counter");
                NftDropCounter::default()
            }
        }
    }

    /// Tear down the TAP and its nftables table (daemon-initiated cleanup). Idempotent.
    pub fn teardown(mut self) {
        self.teardown_quiet();
        self.torn_down = true;
    }

    fn teardown_quiet(&mut self) {
        // Remove the nftables table first (it references the device), then the TAP.
        // Stderr is discarded: this also runs as a best-effort pre-create cleanup
        // where the table and device do NOT exist yet, and the "No such file" /
        // "Cannot find device" errors are expected and not worth logging.
        self.sudo_discard(&["nft", "delete", "table", "netdev", &self.nft_table]);
        self.sudo_discard(&["ip", "link", "del", "dev", &self.name]);
    }

    /// Run a privileged command, discarding its output and ignoring failure (for
    /// idempotent teardown where the target may not exist).
    fn sudo_discard(&self, args: &[&str]) {
        use std::process::Stdio;
        let _ = Command::new(&self.sudo_bin)
            .arg("-n")
            .args(args)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }

    /// Run a privileged command through the sudo wrapper (NOPASSWD, the D-7 path).
    fn sudo(&self, args: &[&str]) -> anyhow::Result<()> {
        let status = Command::new(&self.sudo_bin)
            .arg("-n")
            .args(args)
            .status()
            .map_err(|e| anyhow::anyhow!("spawn sudo {args:?}: {e}"))?;
        if status.success() {
            Ok(())
        } else {
            anyhow::bail!("sudo {args:?} exited with {status}")
        }
    }

    /// Run a privileged command feeding `stdin` (for `nft -f -`).
    fn sudo_stdin(&self, args: &[&str], stdin: &str) -> anyhow::Result<()> {
        use std::io::Write;
        use std::process::Stdio;
        let mut child = Command::new(&self.sudo_bin)
            .arg("-n")
            .args(args)
            .stdin(Stdio::piped())
            .spawn()
            .map_err(|e| anyhow::anyhow!("spawn sudo {args:?}: {e}"))?;
        child
            .stdin
            .as_mut()
            .expect("piped stdin")
            .write_all(stdin.as_bytes())
            .map_err(|e| anyhow::anyhow!("write stdin to sudo {args:?}: {e}"))?;
        let status = child
            .wait()
            .map_err(|e| anyhow::anyhow!("wait sudo {args:?}: {e}"))?;
        if status.success() {
            Ok(())
        } else {
            anyhow::bail!("sudo {args:?} (stdin) exited with {status}")
        }
    }

    /// Run a privileged command and capture stdout.
    fn sudo_capture(&self, args: &[&str]) -> anyhow::Result<String> {
        let out = Command::new(&self.sudo_bin)
            .arg("-n")
            .args(args)
            .output()
            .map_err(|e| anyhow::anyhow!("spawn sudo {args:?}: {e}"))?;
        if out.status.success() {
            Ok(String::from_utf8_lossy(&out.stdout).into_owned())
        } else {
            anyhow::bail!(
                "sudo {args:?} exited with {}: {}",
                out.status,
                String::from_utf8_lossy(&out.stderr)
            )
        }
    }
}

impl Drop for VmTap {
    fn drop(&mut self) {
        if !self.torn_down {
            self.teardown_quiet();
        }
    }
}

/// The host nftables egress drop counter for a TAP (G4 evidence).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct NftDropCounter {
    pub packets: u64,
    pub bytes: u64,
}

/// Parse `nft list counter ...` plain-text output for the `packets N bytes M`
/// line. The output looks like:
/// `table netdev <t> { counter dropped_egress { packets 7 bytes 420 } }`.
fn parse_nft_counter(text: &str) -> Option<NftDropCounter> {
    let tokens: Vec<&str> = text.split_whitespace().collect();
    let mut packets = None;
    let mut bytes = None;
    let mut i = 0;
    while i + 1 < tokens.len() {
        match tokens[i] {
            "packets" => packets = tokens[i + 1].parse().ok(),
            "bytes" => bytes = tokens[i + 1].parse().ok(),
            _ => {}
        }
        i += 1;
    }
    Some(NftDropCounter { packets: packets?, bytes: bytes? })
}

/// Keep the last `n` interface-name-safe characters of an id (so a long jail id
/// still yields a device name within IFNAMSIZ). Alphanumerics only.
fn short_tail(id: &str, n: usize) -> String {
    let safe: String = id
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect();
    let start = safe.len().saturating_sub(n);
    safe[start..].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_nft_counter_text() {
        let text = "table netdev kirby_egress_ab { \n counter dropped_egress { packets 7 bytes 420 } \n }";
        assert_eq!(
            parse_nft_counter(text),
            Some(NftDropCounter { packets: 7, bytes: 420 })
        );
    }

    #[test]
    fn parses_zero_counter() {
        let text = "counter dropped_egress { packets 0 bytes 0 }";
        assert_eq!(
            parse_nft_counter(text),
            Some(NftDropCounter { packets: 0, bytes: 0 })
        );
    }

    #[test]
    fn short_tail_is_ifname_safe_and_bounded() {
        assert_eq!(short_tail("node-1-2807480", 5), "07480");
        assert_eq!(short_tail("abc", 5), "abc");
        // Device name kirby-tap-<=5 stays within IFNAMSIZ (15).
        let dev = format!("kirby-tap-{}", short_tail("g4test-9999999", 5));
        assert!(dev.len() <= 15, "device name {dev} must fit IFNAMSIZ");
    }
}
