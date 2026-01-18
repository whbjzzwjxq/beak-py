#!/usr/bin/env bash

set -e

SCRIPT_DIR=$(cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd)
ROOT_DIR=$(realpath "$SCRIPT_DIR/../../../")

source "$SCRIPT_DIR/defaults.sh"
source "$ROOT_DIR/scripts/helper.sh"

banner
install
