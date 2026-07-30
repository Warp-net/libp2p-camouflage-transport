#!/usr/bin/env bash
#
# Runs the DPI lab. No sudo needed: membership in the docker group is enough,
# and --privileged gives the container CAP_NET_ADMIN inside its own network
# namespace. --network none keeps the lab off every real network, so nothing it
# does can touch a real Warpnet node.
#
#   ./dpilab/run.sh                     # build + run both arms
#   ARMS=camouflage ./dpilab/run.sh     # camouflage arm only
#   PORT=4001 ROUNDS=8 ./dpilab/run.sh  # production relay port, more flows
#   SNI=10.77.0.11 ARMS=camouflage ./dpilab/run.sh   # break the SNI, watch it go red
#   ./dpilab/run.sh --shell             # shell in the lab (run lab.sh by hand)

set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
image=${IMAGE:-warpnet-dpilab:latest}

cd "$repo_root"

# CI builds the image itself to get layer caching, then sets SKIP_BUILD=1.
if [ "${SKIP_BUILD:-0}" = "1" ]; then
  echo "== using prebuilt $image"
else
  echo "== building $image"
  docker build -f dpilab/Dockerfile -t "$image" .
fi

run_args=(
  --rm
  --privileged
  --network none
  -e "ARMS=${ARMS:-camouflage plain}"
  -e "PORT=${PORT:-443}"
  -e "ROUNDS=${ROUNDS:-5}"
  -e "TIMEOUT=${TIMEOUT:-180s}"
  -e "SNI=${SNI:-}"
)

if [ -n "${OUT:-}" ]; then
  mkdir -p "$OUT"
  run_args+=(-v "$(cd "$OUT" && pwd):/var/log/dpilab")
  echo "== captures and nDPI output will land in $OUT"
fi

if [ "${1:-}" = "--shell" ]; then
  echo "== opening a shell in the lab (run /usr/local/bin/lab.sh by hand)"
  exec docker run -it "${run_args[@]}" --entrypoint /bin/bash "$image"
fi

echo "== running the lab"
exec docker run "${run_args[@]}" "$image"
