# The Kirby "nerve" relay deploy artifact (slice 1): a packaged nostr-rs-relay
# (single Rust binary, SQLite-backed) plus an MVP config and a runner script.
#
# This relay is the shared coordination point the fleet's nodes publish their
# presence beacons to and subscribe to each other through. It runs on its OWN box,
# separate from the participant nodes (a node only needs the ws:// URL). For the
# local slice-1 test, running this relay on localhost is sufficient.
#
# MVP posture (spec section 7): accept ARBITRARY event kinds (so the custom
# KIND_KIRBY_PRESENCE = 10100 replaceable beacon is stored), and NIP-42 auth is
# OFF (public, no relay-side authentication; presence is public by design in slice
# 1). nostr-rs-relay implements NIP-16 replaceable events, so the relay keeps only
# the latest beacon per pubkey for kind 10100 (the death-via-staleness mechanism).
#
# Outputs (wired into flake.nix):
#   packages.relay        -> the runner script (a relay bound to 127.0.0.1:7777 by
#                            default; override host/port/db via env or args).
#   packages.relay-bin    -> the bare nostr-rs-relay binary from nixpkgs.
#   apps.relay            -> `nix run .#relay` to start it.
{ pkgs }:

let
  # The relay binary straight from nixpkgs (a maintained nostr-rs-relay build).
  relayBin = pkgs.nostr-rs-relay;

  # The MVP relay config (nostr-rs-relay reads a TOML config). Arbitrary kinds are
  # accepted (no `limits.event_kind_allowlist`), NIP-42 auth is off (no
  # `[authorization]` pubkey allowlist and `nip42_auth = false`), and the store is
  # a local SQLite db. The address/port/db are overridden at runtime by the runner
  # so the same config serves any bind; these are the defaults.
  configToml = pkgs.writeText "kirby-relay-config.toml" ''
    [info]
    name = "kirby-nerve-relay"
    description = "Kirby fleet presence relay (nerve slice 1): public, accepts arbitrary kinds, NIP-42 off."

    [database]
    # Overridden at runtime by --db (the runner sets a writable data dir).
    data_directory = "."

    [network]
    # Overridden at runtime by KIRBY_RELAY_ADDRESS / KIRBY_RELAY_PORT.
    address = "127.0.0.1"
    port = 7777

    [options]
    reject_future_seconds = 1800

    [authorization]
    # NIP-42 auth OFF for the MVP: the relay does not require AUTH and has no
    # pubkey allowlist, so any node may publish/subscribe (presence is public).
    nip42_auth = false

    [limits]
    # No event_kind_allowlist -> arbitrary kinds are accepted (incl. the custom
    # replaceable KIND_KIRBY_PRESENCE = 10100 beacon). Generous, MVP-only bounds.
    messages_per_sec = 0
    max_event_bytes = 131072
    max_ws_message_bytes = 131072
    max_ws_frame_bytes = 131072
  '';

  # The runner: stand up the relay on a chosen host/port with a writable SQLite
  # data dir. Defaults to 127.0.0.1:7777 with the db under $KIRBY_RELAY_DATA (or a
  # fresh temp dir), so it is a one-command local relay for the slice-1 test:
  #   nix run .#relay
  # Override with env: KIRBY_RELAY_ADDRESS, KIRBY_RELAY_PORT, KIRBY_RELAY_DATA.
  runner = pkgs.writeShellScriptBin "kirby-relay" ''
    set -euo pipefail
    ADDR="''${KIRBY_RELAY_ADDRESS:-127.0.0.1}"
    PORT="''${KIRBY_RELAY_PORT:-7777}"
    DATA="''${KIRBY_RELAY_DATA:-$(mktemp -d -t kirby-relay-XXXXXX)}"
    mkdir -p "$DATA"

    # Materialize a config with the runtime address/port/db patched in (the relay
    # has no CLI for these, so render a per-run config from the template).
    CFG="$DATA/config.toml"
    ${pkgs.gnused}/bin/sed \
      -e "s|^address = .*|address = \"$ADDR\"|" \
      -e "s|^port = .*|port = $PORT|" \
      -e "s|^data_directory = .*|data_directory = \"$DATA\"|" \
      ${configToml} > "$CFG"

    echo "kirby-nerve relay: ws://$ADDR:$PORT  (db: $DATA, NIP-42 off, arbitrary kinds)" >&2
    exec ${relayBin}/bin/nostr-rs-relay --config "$CFG"
  '';
in
{
  inherit relayBin runner configToml;
}
