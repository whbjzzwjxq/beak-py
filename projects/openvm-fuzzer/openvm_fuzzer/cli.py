#!/usr/bin/env python3

import argparse
import subprocess
from pathlib import Path

from beak_core.rv32im import FuzzingInstance, Instruction
from openvm_fuzzer.settings import (
    OPNEVM_BENCHMARK_REGZERO_ALIAS,
    OPENVM_AVAILABLE_COMMITS_OR_BRANCHES,
    resolve_openvm_commit,
)
from openvm_fuzzer.utils_install import (
    clone_and_checkout_openvm,
)
from openvm_fuzzer.utils_trace import CircuitProjectGenerator

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
    trace.add_argument(
        "--project-root",
        type=Path,
        default=None,
        help="Where to generate the trace project (default: <out-root>/trace-<commit>).",
    )
    trace.add_argument(
        "--hex",
        type=str,
        nargs="*",
        default=[],
        help=(
            "RV32IM instruction words as 32-bit hex (e.g. 00c58533). "
            "If omitted, uses a tiny default program."
        ),
    )
    trace.add_argument(
        "--reg",
        type=str,
        action="append",
        default=[],
        help="Initial register value as IDX=VALUE (decimal or 0x..). Repeatable.",
    )
    trace.add_argument(
        "--no-run",
        action="store_true",
        help="Only generate the trace project; do not run cargo.",
    )
    trace.add_argument(
        "--profile",
        type=str,
        choices=["release", "debug"],
        default="release",
        help="Cargo profile for running the host (default: release).",
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
        print("Applying %s..." % apply_function.__module__.split(".")[-1])
        apply_function(openvm_install_path=dest, commit_or_branch=resolved)

    # Finally, print the destination path.
    print(dest)
    return 0


def _trace(args: argparse.Namespace) -> int:
    resolved = resolve_openvm_commit(args.commit_or_branch)

    # If user didn't explicitly point to a repo, default to the installed snapshot path.
    zkvm_src = args.zkvm_src.expanduser().resolve()
    if args.zkvm_src == Path("openvm-src"):
        zkvm_src = (args.out_root / f"openvm-{resolved}" / "openvm-src").expanduser().resolve()

    if not zkvm_src.exists():
        raise SystemExit(f"zkvm source path does not exist: {zkvm_src}")

    if args.project_root is None:
        project_root = (args.out_root / f"trace-{resolved}").expanduser().resolve()
    else:
        project_root = args.project_root.expanduser().resolve()

    # Parse program
    if args.hex:
        instructions = [Instruction.from_hex(x) for x in args.hex]
    else:
        # Default: NOP; NOP; (ADDI x0,x0,0) is 0x00000013
        instructions = [Instruction.from_hex("00000013"), Instruction.from_hex("00000013")]

    initial_regs: dict[int, int] = {}
    for item in args.reg:
        if "=" not in item:
            raise SystemExit(f"invalid --reg (expected IDX=VALUE): {item}")
        k_str, v_str = item.split("=", 1)
        k = int(k_str, 0)
        v = int(v_str, 0)
        initial_regs[k] = v

    instance = FuzzingInstance(instructions=instructions, initial_regs=initial_regs)
    gen = CircuitProjectGenerator(
        root=project_root,
        zkvm_path=zkvm_src,
        instance=instance,
        fault_injection=False,
        trace_collection=True,
        commit_or_branch=resolved,
    )
    gen.create()

    if args.no_run:
        print(project_root)
        return 0

    print(f"Running trace via cargo in {project_root}")
    cargo_cmd = [
        "cargo",
        "run",
        "-p",
        "openvm-host",
        "--manifest-path",
        str(project_root / "Cargo.toml"),
    ]
    if args.profile == "release":
        cargo_cmd.append("--release")
    cargo_cmd += [
        "--",
        "--trace",
    ]
    subprocess.run(
        cargo_cmd,
        check=True,
        cwd=project_root,
    )
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
