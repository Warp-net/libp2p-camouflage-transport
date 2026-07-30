#!/usr/bin/env bash
#
# Builds a sniffable wire inside the container's own network namespace, runs two
# relay nodes across it, and asks nDPI what the traffic looks like. Requires
# CAP_NET_ADMIN (docker --privileged); nothing outside the container is touched.
#
#   root ns of the container
#     bridge wire
#     ├── br-a  <-> [ns dpi-a] eth-a 10.77.0.11   relay node A (listens)
#     └── br-b  <-> [ns dpi-b] eth-b 10.77.0.12   relay node B (dials)
#
# The capture point is br-a, so every packet to and from node A is recorded,
# and both peers are in their own namespace so the traffic crosses a real link
# with a 1500-byte MTU instead of being delivered over loopback in 64 KB
# chunks. Segmentation offload is switched off for the same reason: the
# transport fragments its TLS ClientHello across TCP segments, and a capture
# taken behind GSO would not show the segments a DPI box sees.
#
# Two arms run back to back:
#   camouflage  the shipped transport   - must look like browsing
#   plain       stock libp2p TCP        - must NOT look like browsing
# A green run needs both, otherwise the checks are not measuring anything.

set -euo pipefail

BIN=${BIN:-/usr/local/bin/dpilab}
NDPI=${NDPI:-/usr/local/bin/ndpiReader}
OUT_DIR=${OUT_DIR:-/var/log/dpilab}
RUN_DIR=${RUN_DIR:-/run/dpilab}
# 443 is where browsing traffic lives, so that is the default; PORT=4001 runs
# the labs on the production relay port, which costs one nDPI risk (see README).
PORT=${PORT:-443}
ROUNDS=${ROUNDS:-5}
TIMEOUT=${TIMEOUT:-180s}
ARMS=${ARMS:-camouflage plain}
SNI=${SNI:-}

IP_A=10.77.0.11
IP_B=10.77.0.12
SEED_A=dpilab-relay-a
SEED_B=dpilab-relay-b

pids=()
declare -A arm_status=()

say() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
die() { printf '\033[31mFAIL: %s\033[0m\n' "$*" >&2; exit 1; }

cleanup() {
  local pid
  for pid in "${pids[@]:-}"; do
    [ -n "$pid" ] && kill "$pid" 2>/dev/null || true
  done
  for ns in dpi-a dpi-b; do
    ip netns del "$ns" 2>/dev/null || true
  done
  ip link del wire 2>/dev/null || true
}
trap cleanup EXIT

# ---------------------------------------------------------------- topology

attach() {
  local ns=$1 host_if=$2 br_if=$3 ip_addr=$4

  ip netns add "$ns"
  ip link add "$host_if" type veth peer name "$br_if"
  ip link set "$br_if" master wire up
  ip link set "$host_if" netns "$ns"
  ip -n "$ns" addr add "$ip_addr/24" dev "$host_if"
  ip -n "$ns" link set "$host_if" mtu 1500 up
  ip -n "$ns" link set lo up
  ip link set "$br_if" mtu 1500

  # Without this the capture shows 64 KB super-segments instead of what
  # actually crosses a wire, which is exactly the detail DPI works on.
  ip netns exec "$ns" ethtool -K "$host_if" tso off gso off gro off 2>/dev/null || true
  ethtool -K "$br_if" tso off gso off gro off 2>/dev/null || true
}

say "building the wire"
ip link add wire type bridge
ip link set wire up
attach dpi-a eth-a br-a "$IP_A"
attach dpi-b eth-b br-b "$IP_B"

mkdir -p "$OUT_DIR" "$RUN_DIR"
rm -f "$RUN_DIR"/* "$OUT_DIR"/*

for ns in dpi-a dpi-b; do
  printf '  %-6s %s\n' "$ns" "$(ip -n "$ns" -brief addr show | tr '\n' ' ')"
done

say "sanity: the two namespaces can reach each other"
ip netns exec dpi-a ping -c1 -W2 "$IP_B" >/dev/null || die "no connectivity across the wire"
echo "  ok"

ID_A=$("$BIN" -role print-id -seed "$SEED_A")
ID_B=$("$BIN" -role print-id -seed "$SEED_B")
printf '  relay A %s\n  relay B %s\n' "$ID_A" "$ID_B"

# -------------------------------------------------------------------- arms

run_arm() {
  local transport=$1 expect=$2
  local pcap="$OUT_DIR/$transport.pcap"
  local flows="$OUT_DIR/$transport.flows.json"

  say "arm: $transport (expect: $expect)"

  rm -f "$RUN_DIR/a.addr" "$RUN_DIR/done"

  tcpdump -i br-a -s0 -U -w "$pcap" tcp >"$OUT_DIR/$transport.tcpdump.log" 2>&1 &
  local tcpdump_pid=$!
  pids+=("$tcpdump_pid")
  for _ in $(seq 40); do
    grep -q 'listening on' "$OUT_DIR/$transport.tcpdump.log" 2>/dev/null && break
    sleep 0.25
  done
  grep -q 'listening on' "$OUT_DIR/$transport.tcpdump.log" || die "tcpdump did not start"

  ip netns exec dpi-a "$BIN" -role serve -seed "$SEED_A" -ip "$IP_A" -port "$PORT" \
    -transport "$transport" -sni "$SNI" -ready-file "$RUN_DIR/a.addr" -done-file "$RUN_DIR/done" \
    -timeout "$TIMEOUT" >"$OUT_DIR/$transport.relay-a.log" 2>&1 &
  local a_pid=$!
  pids+=("$a_pid")

  for _ in $(seq 120); do
    [ -s "$RUN_DIR/a.addr" ] && break
    sleep 0.25
  done
  [ -s "$RUN_DIR/a.addr" ] || { tail -20 "$OUT_DIR/$transport.relay-a.log"; die "relay A never came up"; }

  local rc_b=0
  ip netns exec dpi-b "$BIN" -role dial -seed "$SEED_B" -ip "$IP_B" -port "$PORT" \
    -transport "$transport" -sni "$SNI" -target "$(cat "$RUN_DIR/a.addr")" -rounds "$ROUNDS" \
    -timeout "$TIMEOUT" >"$OUT_DIR/$transport.relay-b.log" 2>&1 || rc_b=$?

  touch "$RUN_DIR/done"
  wait "$a_pid" 2>/dev/null || true

  # Let the last FINs reach the capture before it is closed.
  sleep 1
  kill -TERM "$tcpdump_pid" 2>/dev/null || true
  wait "$tcpdump_pid" 2>/dev/null || true

  grep -h 'DPILAB event=' "$OUT_DIR/$transport.relay-b.log" || true
  if [ "$rc_b" -ne 0 ]; then
    tail -20 "$OUT_DIR/$transport.relay-b.log"
    die "$transport arm: the nodes failed to exchange traffic (exit $rc_b)"
  fi

  say "arm: $transport - nDPI"
  # -d turns off guessing by port and by IP, so a TLS verdict can only come
  # from the payload. -T raises the per-flow packet budget above the default
  # 80 so the obfuscation and entropy heuristics see the bulk transfer too.
  "$NDPI" -i "$pcap" -d -T 300 --tls_heuristics -v 2 \
    -K json -k "$flows" -C "$OUT_DIR/$transport.flows.csv" \
    >"$OUT_DIR/$transport.ndpi.log" 2>&1 || die "ndpiReader failed on $pcap"
  grep -E '^\s+[0-9]+\s+(TCP|UDP)' "$OUT_DIR/$transport.ndpi.log" | cut -c1-220 || true

  local rc=0
  "$BIN" -role verify -flows "$flows" -ndpi-log "$OUT_DIR/$transport.ndpi.log" \
    -wire-a "$IP_A" -wire-b "$IP_B" -port "$PORT" \
    -min-flows 1 -min-handshakes "$ROUNDS" -expect "$expect" || rc=$?
  arm_status["$transport"]=$rc
}

for arm in $ARMS; do
  case "$arm" in
    camouflage) run_arm camouflage browsing ;;
    plain)      run_arm plain not-browsing ;;
    *)          die "unknown arm $arm" ;;
  esac
done

# ------------------------------------------------------------------ report

say "verdict"
fail=0
for arm in $ARMS; do
  if [ "${arm_status[$arm]:-1}" -eq 0 ]; then
    printf '  \033[32mPASS\033[0m %s arm\n' "$arm"
  else
    printf '  \033[31mFAIL\033[0m %s arm\n' "$arm"
    fail=1
  fi
done

[ "$fail" -eq 0 ] || die "the DPI lab did not pass (captures and nDPI output are in $OUT_DIR)"

printf '\n\033[32mTRAFFIC MASKING VERIFIED: nDPI sees browsing between the two relay nodes'
case " $ARMS " in
  *" plain "*) printf ',\nand says the same libp2p stack without the camouflage transport is not browsing' ;;
  *)           printf '\n(control arm skipped: ARMS=%s)' "$ARMS" ;;
esac
printf '\033[0m\n'
