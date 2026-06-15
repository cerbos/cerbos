#!/usr/bin/env bash
# Collect K cold-start memory samples of the current build, for a median-of-K
# comparison. Each sample is a fresh `cerbos-go-run` launch (kills the prior
# instance, rebuilds from source, waits for health) scraped right after the
# index build + post-init FreeOSMemory.
#
#   PREFIX=srcattr K=4 hack/loadtest/collect-unique-samples.sh
#
# Writes hack/loadtest/${PREFIX}-${n}.txt for n in START_IDX..START_IDX+K-1.
# heap_inuse has ~13-20 MiB run-to-run variance, so compare medians, not singles.
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE}")" && pwd)  
cd "$SCRIPT_DIR"

K=${K:-4}
START_IDX=${START_IDX:-1}
PREFIX=${PREFIX:-"sample"}
OUT_DIR=${OUT_DIR:-"."}

for i in $(seq 0 $((K - 1))); do
  n=$((START_IDX + i))
  echo "=== cold start, sample ${n} ==="
  # The launcher hard-kills the prior instance and waits for it get healthy.
  ./cerbos-go-run.sh
  ./scrape.sh "${OUT_DIR}/${PREFIX}-${n}.txt"
done
echo "=== done collecting ${K} samples ==="
