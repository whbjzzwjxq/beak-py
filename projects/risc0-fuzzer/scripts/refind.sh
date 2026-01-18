#!/usr/bin/env bash

set -e

SCRIPT_DIR=$(cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd)
ROOT_DIR=$(realpath "$SCRIPT_DIR/../../../")

source "$SCRIPT_DIR/defaults.sh"

banner

# FUZZER_TIMEOUT=$((60*60*24))  # 24 hours
FUZZER_TIMEOUT=0  # disable and checked by hand

echo "== START REFINDING =="
echo "  => bugs            : ${#FIX_COMMITS[@]}"
echo "  => instances / bug : $PODMAN_PODS"
echo "  => cpus / instance : $PODMAN_CPUS"
echo "  => timeout in sec  : $FUZZER_TIMEOUT"

explore_pids=()

for commit_index in "${!BUG_COMMITS[@]}"; do
    fix_commit=${FIX_COMMITS[$commit_index]}
    bug_commit=${BUG_COMMITS[$commit_index]}
    echo "starting $bug_commit  <=>  $fix_commit ..."
    (
        RANDOM=$DEFAULT_MASTER_SEED
        COMMIT_OR_BRANCH=$bug_commit
        source "$ROOT_DIR/scripts/helper.sh"
        install
        explore
        echo "starting $bug_commit  <=>  $fix_commit ... done"
    ) & explore_pids[$commit_index]=$!
done

echo "waiting for processes to finish ..."
for prod_pid in "${explore_pids[@]}"; do
    wait "$prod_pid"
done
echo "== END REFINDING =="
