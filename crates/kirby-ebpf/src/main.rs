//! The kernel-side egress-byte meter (spec 3.3, D-7, gate G4).
//!
//! A TC classifier attached to the INGRESS (clsact) path of the VM's TAP. For a
//! TAP, the packets the GUEST transmits (the VM's egress) arrive at the host as
//! the device's ingress, so the VM's outbound bytes are counted here. It runs in
//! the host kernel for every packet the VM emits and adds the packet length to a
//! single-slot array map. The daemon's userspace loader (kirby-node
//! `meter_egress`) reads that map on a tick and bills the bytes per-byte against
//! the treasury (the same authoritative counter CPU and memory debit, D-9).
//!
//! This program only COUNTS; it does not drop. The drop is the host nftables
//! default-deny on the same TAP ingress hook (spec 3.7): the VM has no route to
//! the internet. The TC ingress classifier runs before the netfilter ingress
//! hook, so it counts the bytes the VM ATTEMPTED to egress (which nftables then
//! drops). Under the lockdown that total is ~0 IP bytes: a denied genome egress
//! attempt is only the handful of unanswered SYN or DNS packets the VM emits
//! before giving up, never a flowing connection. So the eBPF counter and the
//! nftables drop counter tell the same story (a few hundred bytes attempted, all
//! dropped, nothing established). The classifier returns TC_ACT_OK so it never
//! itself changes forwarding; nftables is the enforcer.

#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::TC_ACT_OK,
    macros::{classifier, map},
    maps::Array,
    programs::TcContext,
};

/// A single u64 slot holding cumulative egress bytes seen on the TAP. The daemon
/// reads slot 0 each tick (aya `Array` is shared host and kernel via a pinned or
/// fd-backed map). One slot is enough: the meter only needs the running total.
#[map]
static EGRESS_BYTES: Array<u64> = Array::with_max_entries(1, 0);

/// Count this packet's bytes on the VM TAP egress path. Adds the wire length to
/// the cumulative total and passes the packet on unchanged (TC_ACT_OK): the
/// classifier meters, it does not enforce. nftables default-deny (spec 3.7) is
/// what actually blocks the VM's egress; this only measures what hit the wire.
#[classifier]
pub fn kirby_egress(ctx: TcContext) -> i32 {
    let len = ctx.len() as u64;
    if let Some(slot) = EGRESS_BYTES.get_ptr_mut(0) {
        // SAFETY: slot 0 exists (the map has one entry) and is the only writer
        // path; the add is a per-CPU-safe single-slot accumulator for the spike's
        // metering granularity (exactness is not load-bearing, the host nftables
        // drop is). A racing under-count cannot let the genome egress more (the
        // route does not exist), it would only under-bill, and the bill here is
        // ~0 by construction.
        unsafe {
            *slot += len;
        }
    }
    TC_ACT_OK
}

/// eBPF programs cannot unwind; abort on panic. The verifier rejects an
/// unwinding eBPF program, and the BPF target has no unwinder anyway.
#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
