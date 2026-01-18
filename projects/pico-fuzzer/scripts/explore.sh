#!/usr/bin/env bash

set -e

SCRIPT_DIR=$(cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd)
ROOT_DIR=$(realpath "$SCRIPT_DIR/../../../")

source "$SCRIPT_DIR/defaults.sh"
source "$ROOT_DIR/scripts/helper.sh"

banner

FUZZER_TIMEOUT=$((60*60*24))  # 24 hours

PODMAN_PODS=1
RANDOM=$DEFAULT_MASTER_SEED

echo "== START EXPLORING =="
echo "  => instances       : $PODMAN_PODS"
echo "  => cpus / instance : $PODMAN_CPUS"
echo "  => timeout in sec  : $FUZZER_TIMEOUT"

install
explore

echo "== END EXPLORING =="
