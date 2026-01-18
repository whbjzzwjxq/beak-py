#!/usr/bin/env bash

set -e # stop on error

SCRIPT_DIR=$(cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd)
ROOT_DIR=$(realpath "$SCRIPT_DIR/../../../")

source "$SCRIPT_DIR/defaults.sh"

banner

if [ -z "${FINDINGS_NAMESPACE_POSTFIX+x}" ]; then
    echo "ERROR: FINDINGS_NAMESPACE_POSTFIX is not set!"
    echo "FINDINGS_NAMESPACE_POSTFIX is required to find the 'findings.csv' file to check!" >&2
    exit 1
fi

PODMAN_CPUS=10

echo "== START CECKING =="
echo "  => bugs            : ${#FIX_COMMITS[@]}"
echo "  => cpus / bug      : $PODMAN_CPUS"

explore_pids=()

for commit_index in "${!BUG_COMMITS[@]}"; do
    fix_commit=${FIX_COMMITS[$commit_index]}
    bug_commit=${BUG_COMMITS[$commit_index]}
    echo "starting $bug_commit  <=>  $fix_commit ..."
    (
        COMMIT_OR_BRANCH=$fix_commit
        FINDINGS_COMMIT_OR_BRANCH=$bug_commit
        source "$ROOT_DIR/scripts/helper.sh"
        install
        check
        echo "starting $bug_commit  <=>  $fix_commit ... done"
    ) & explore_pids[$commit_index]=$!
done

echo "waiting for processes to finish ..."
for prod_pid in "${explore_pids[@]}"; do
    wait "$prod_pid"
done
echo "== END CECKING =="
