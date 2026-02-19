#!/usr/bin/env python3

import argparse
import logging
from pathlib import Path

from openvm_fuzzer.settings import (
    OPNEVM_BENCHMARK_REGZERO_ALIAS,
    OPENVM_AVAILABLE_COMMITS_OR_BRANCHES,
    resolve_openvm_commit,
)
from openvm_fuzzer.utils_install import (
    clone_and_checkout_openvm,
)

from openvm_fuzzer.patches import (
    rewrite_private_stark,
    create_fuzzer_utils_crate,
    add_fuzzer_utils_workspace,
    rv32im_overwrite_cores,
    vm_replace_asserts,
    vm_add_serde_json,
    patch_integration_api_microops,
    patch_padding_samples,
    patch_segment_and_regzero_microops,
    rv32im_circuit_add_deps,
    rv32im_replace_asserts,
)

logger = logging.getLogger("fuzzer")


def _build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="openvm-fuzzer", description="OpenVM installer.")
    sp = ap.add_subparsers(dest="command", required=True)

    install = sp.add_parser("install", help="Materialize a snapshot into out/.")
    install.add_argument(
        "--commit-or-branch",
        type=str,
        default=OPNEVM_BENCHMARK_REGZERO_ALIAS,
        choices=OPENVM_AVAILABLE_COMMITS_OR_BRANCHES,
        help="OpenVM commit/alias to install.",
    )
    install.add_argument(
        "--out-root", type=Path, default=Path("out"), help="Output root (default: ./out)."
    )

    trace = sp.add_parser("trace", help="Trace a snapshot.")
    trace.add_argument(
        "--zkvm-src",
        type=Path,
        default=Path("openvm-src"),
        help="Path to a local OpenVM git repo (source). Default: ./openvm-src",
    )
    trace.add_argument(
        "--commit-or-branch",
        type=str,
        default=OPNEVM_BENCHMARK_REGZERO_ALIAS,
        choices=OPENVM_AVAILABLE_COMMITS_OR_BRANCHES,
        help="OpenVM commit/alias to trace.",
    )
    trace.add_argument(
        "--out-root", type=Path, default=Path("out"), help="Output root (default: ./out)."
    )
    return ap


def _install(args: argparse.Namespace) -> int:
    # First, resolve the commit or branch to a concrete commit.
    resolved = resolve_openvm_commit(args.commit_or_branch)

    # Then, materialize the snapshot into out/openvm-<commit>/openvm-src.
    dest = (args.out_root / f"openvm-{resolved}" / "openvm-src").expanduser().resolve()

    dest = clone_and_checkout_openvm(dest=dest, commit_or_branch=resolved)

    # Now, we have the OpenVM snapshot in `dest`.
    # Then, we modify the OpenVM snapshot to make it suitable for fuzzing.

    applied_functions = [
        rewrite_private_stark.apply,
        create_fuzzer_utils_crate.apply,
        add_fuzzer_utils_workspace.apply,
        vm_replace_asserts.apply,
        vm_add_serde_json.apply,
        patch_integration_api_microops.apply,
        patch_padding_samples.apply,
        patch_segment_and_regzero_microops.apply,
        rv32im_circuit_add_deps.apply,
        rv32im_overwrite_cores.apply,
        rv32im_replace_asserts.apply,
    ]
    for apply_function in applied_functions:
        logger.info(f"Applying {apply_function.__name__}...")
        apply_function(openvm_install_path=dest, commit_or_branch=resolved)

    # Finally, print the destination path.
    print(dest)
    return 0


def _trace(args: argparse.Namespace) -> int:
    # TODO: implement trace command
    return 0


def app() -> None:
    args = _build_parser().parse_args()
    if args.command == "install":
        raise SystemExit(_install(args))
    if args.command == "trace":
        raise SystemExit(_trace(args))
    raise SystemExit(2)


if __name__ == "__main__":
    app()
