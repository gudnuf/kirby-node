#!/usr/bin/env bash
# Kirby custody backbone (C-1..C-6): reproduce the offline gates from a clean
# checkout, run the clean-cut scan, and list the on-chain txids (G2, G5) for a
# verifier to re-confirm on Mutinynet. Run from the crate root.
set -euo pipefail

echo "== offline gates (deterministic: G1, G3, G4, G5-offline, G6, G7, persist, spend) =="
nix develop --command cargo build --release
nix develop --command cargo test
nix develop --command cargo clippy --all-targets -- -D warnings

echo
echo "== clean-cut: no em-dashes anywhere (expect 'clean') =="
if git ls-files | xargs grep -lP '\x{2014}' 2>/dev/null; then
  echo "EM-DASH FOUND (fail)"
  exit 1
else
  echo "clean: no em-dashes"
fi

echo
echo "== on-chain evidence (re-confirm at https://mutinynet.com/tx/<txid>) =="
echo "address (p2tr(Q)): tb1pshkf44qc3zplgz7nwpet7cad8z9je5kzmkkwgany72vcsnrulnpqxj29xe"
echo "G2 (2-of-3 key-path spend):       bbab7ef854bdd65e5213918d4313cf65295b229c16385c2fec98857eb270213f"
echo "G5 (refreshed quorum, same addr): 76b272a23683b26f6d75e468eb90c2264ce8a64d41979f17e726e0210ea91eae"

echo
echo "== live demos (need a Mutinynet faucet JWT; see chain.rs FAUCET_JWT_PATH or env FAUCET_JWT) =="
echo "  nix develop --command cargo run --release --bin spend-demo     # G2: fund + 2-of-3 spend"
echo "  nix develop --command cargo run --release --bin reshare-demo   # G5: reshare + refreshed-quorum spend"
