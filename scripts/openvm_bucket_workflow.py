from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import textwrap
from dataclasses import dataclass
from pathlib import Path
from typing import Any


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _add_repo_to_syspath():
    root = _repo_root()
    sys.path.insert(0, str(root / "beak-fuzz" / "libs" / "beak-core"))
    sys.path.insert(0, str(root / "beak-fuzz" / "libs" / "zkvm-fuzzer-utils"))
    sys.path.insert(0, str(root / "beak-fuzz" / "projects" / "openvm-fuzzer"))


def _extract_record_json(stdout: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    start = 0
    while True:
        i = stdout.find("<record>", start)
        if i < 0:
            break
        j = stdout.find("</record>", i)
        if j < 0:
            break
        payload = stdout[i + len("<record>") : j]
        start = j + len("</record>")
        try:
            records.append(json.loads(payload))
        except Exception:
            continue
    return records


@dataclass(frozen=True)
class RunResult:
    stdout: str
    stderr: str
    returncode: int


def write_run_artifacts(
    *,
    project_root: Path,
    run: RunResult,
    records: list[dict[str, Any]],
    hits: list[dict[str, Any]],
) -> None:
    """
    Convenience artifacts for inspection:
    - `<project_root>/openvm_run.stdout.txt`
    - `<project_root>/openvm_run.stderr.txt`
    - `<project_root>/micro_op_records.json`  (only context=="micro_op")
    - `<project_root>/bucket_hits.json`
    """
    project_root.mkdir(parents=True, exist_ok=True)
    (project_root / "openvm_run.stdout.txt").write_text(run.stdout)
    (project_root / "openvm_run.stderr.txt").write_text(run.stderr)
    micro_op_records = [r for r in records if r.get("context") == "micro_op"]
    (project_root / "micro_op_records.json").write_text(json.dumps(micro_op_records, indent=2, sort_keys=True))
    (project_root / "bucket_hits.json").write_text(json.dumps(hits, indent=2, sort_keys=True, default=str))


def _ensure_writable_cargo_home() -> Path:
    """
    Cargo writes into $CARGO_HOME (registry index updates, etc.). In this sandbox run, the default
    `/home/work/.cargo` may be read-only, so mirror it into a workspace-writable location once and
    point builds at it.
    """
    dest = _repo_root() / "beak-fuzz" / "out" / ".cargo-home"
    if (dest / "registry").exists():
        return dest

    src = Path("/home/work/.cargo")
    dest.mkdir(parents=True, exist_ok=True)
    for sub in ("registry", "git", "bin", "config.toml", "config"):
        sp = src / sub
        dp = dest / sub
        if not sp.exists() or dp.exists():
            continue
        if sp.is_dir():
            shutil.copytree(sp, dp, symlinks=True)
        else:
            shutil.copy2(sp, dp)
    return dest


def run_openvm_project(project_root: Path) -> RunResult:
    env = dict(os.environ)
    env.setdefault("CARGO_NET_OFFLINE", "true")
    env.setdefault("CARGO_HOME", str(_ensure_writable_cargo_home()))
    rustflags = env.get("RUSTFLAGS", "")
    custom_cfg = '--cfg getrandom_backend="custom"'
    if custom_cfg not in rustflags:
        env["RUSTFLAGS"] = (rustflags + " " + custom_cfg).strip()
    proc = subprocess.run(
        ["cargo", "run", "-q", "--release", "--", "--trace"],
        cwd=project_root / "host",
        text=True,
        capture_output=True,
        env=env,
    )
    return RunResult(stdout=proc.stdout, stderr=proc.stderr, returncode=proc.returncode)


def build_trace_from_records(records: list[dict[str, Any]]):
    _add_repo_to_syspath()
    from beak_core.micro_ops import (  # type: ignore
        ChipRow,
        InteractionBase,
        InteractionKind,
        InteractionMultiplicity,
        InteractionScope,
        InteractionType,
        ZKVMTrace,
    )

    micro_ops: list[Any] = []
    op_spans: dict[int, list[int]] = {}

    def _add(step: int, item: Any):
        idx = len(micro_ops)
        micro_ops.append(item)
        op_spans.setdefault(step, []).append(idx)

    for rec in records:
        if rec.get("context") != "micro_op":
            continue
        step = rec.get("step")
        if not isinstance(step, int):
            continue
        typ = rec.get("micro_op_type")
        if typ == "chip_row":
            row_id = rec.get("row_id")
            domain = rec.get("domain")
            chip = rec.get("chip")
            gates = rec.get("gates")
            locals_ = rec.get("locals")
            if not isinstance(row_id, str) or not isinstance(domain, str) or not isinstance(chip, str):
                continue
            if not isinstance(gates, dict):
                gates = {}
            if not isinstance(locals_, dict):
                locals_ = {}
            _add(
                step,
                ChipRow(
                    row_id=row_id,
                    domain=domain,
                    chip=chip,
                    gates=dict(gates),
                    locals=dict(locals_),
                    event_id=None,
                ),
            )
        elif typ == "interaction":
            table_id = rec.get("table_id")
            io = rec.get("io")
            kind = rec.get("kind")
            scope = rec.get("scope")
            anchor_row_id = rec.get("anchor_row_id")
            multiplicity = rec.get("multiplicity")
            if not isinstance(table_id, str) or not isinstance(io, str) or not isinstance(kind, str):
                continue
            if scope is None:
                scope = "global"
            if not isinstance(scope, str):
                scope = "global"
            if anchor_row_id is not None and not isinstance(anchor_row_id, str):
                anchor_row_id = None
            mult_obj = None
            if isinstance(multiplicity, dict):
                mv = multiplicity.get("value")
                mr = multiplicity.get("ref")
                if isinstance(mv, int) and isinstance(mr, str):
                    mult_obj = InteractionMultiplicity(value=mv, ref=mr)
            try:
                io_t = InteractionType(io)
            except Exception:
                continue
            try:
                scope_t = InteractionScope(scope)
            except Exception:
                scope_t = InteractionScope.GLOBAL
            try:
                kind_t = InteractionKind(kind)
            except Exception:
                kind_t = InteractionKind.CUSTOM

            _add(
                step,
                InteractionBase(
                    table_id=table_id,
                    io=io_t,
                    scope=scope_t,
                    anchor_row_id=anchor_row_id,
                    event_id=None,
                    kind=kind_t,
                    multiplicity=mult_obj,
                ),
            )

    if not micro_ops:
        raise RuntimeError("no micro_op records found")

    spans = [op_spans[k] for k in sorted(op_spans.keys())]
    trace = ZKVMTrace(micro_ops, op_spans=spans)
    errors = trace.validate()
    if errors:
        raise RuntimeError(f"trace validation errors: {errors}")
    return trace


def run_buckets(trace, *, openvm_commit: str):
    _add_repo_to_syspath()
    from beak_core.buckets import (  # type: ignore
        GateBoolDomainBucket,
        InactiveRowEffectsBucket,
        NextPcUnderconstrainedBucket,
    )
    from openvm_fuzzer.settings import OPENVM_REGZERO_COMMIT  # type: ignore

    # OpenVM control-flow candidates:
    # - audit-* snapshots emit adapter/core ChipRows, so we can match specific adapter chips.
    # - regzero snapshot currently emits connector edges per op; use that as a coarse proxy so
    #   the next-pc bucket can still run end-to-end.
    # TODO(beak-fuzz): Once regzero injection is moved down into the rv32im trace fill stage and
    # emits real adapter/core ChipRows (e.g. `Rv32JalrAdapterAir` / `Rv32BranchAdapterAir`), switch
    # the regzero `NextPcUnderconstrainedBucket` matcher to those concrete chips instead of
    # `VmConnectorAir` (or to `Exec(JALR)` / `Exec(BEQ)` if we keep executor-granularity chips).
    if openvm_commit == OPENVM_REGZERO_COMMIT:
        nextpc_buckets = [
            NextPcUnderconstrainedBucket(
                instruction_label="openvm.VmConnectorAir",
                chip="VmConnectorAir",
                min_following_instructions=2,
            )
        ]
    else:
        nextpc_buckets = [
            NextPcUnderconstrainedBucket(
                instruction_label="openvm.Rv32JalrAdapterAir",
                chip="Rv32JalrAdapterAir",
                min_following_instructions=2,
            ),
            NextPcUnderconstrainedBucket(
                instruction_label="openvm.Rv32BranchAdapterAir",
                chip="Rv32BranchAdapterAir",
                min_following_instructions=2,
            ),
        ]

    buckets = nextpc_buckets + [GateBoolDomainBucket(), InactiveRowEffectsBucket(activation_gate="is_real")]

    hits: list[dict[str, Any]] = []
    for op_idx in range(len(trace.op_spans or [])):
        op_micro_ops = trace.op_micro_ops(op_idx)
        for b in buckets:
            h = b.match_hits(trace, op_idx, op_micro_ops)
            if h is None:
                continue
            hits.append(
                {
                    "bucket": h.bucket_type,
                    "op_idx": op_idx,
                    "details": h.details,
                }
            )
    return hits


def _load_instructions(path: Path) -> list[str]:
    lines: list[str] = []
    for line in path.read_text().splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        lines.append(s)
    return lines


def _relpath(from_dir: Path, to_path: Path) -> str:
    return os.path.relpath(to_path, start=from_dir).replace(os.sep, "/")


def _write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)


def install_and_inject_openvm(*, openvm_src: Path, out_dir: Path, commit_or_branch: str) -> Path:
    """
    Local "install" flow (no network): materialize an OpenVM checkout for `commit_or_branch`
    under out_dir, then run injection once.

    If `openvm_src` is a git repo, use `git worktree` (fast, no duplication). Otherwise fall back
    to `copytree`.
    """
    _add_repo_to_syspath()
    from openvm_fuzzer.zkvm_repository.injection import openvm_fault_injection  # type: ignore
    from openvm_fuzzer.settings import resolve_openvm_commit  # type: ignore
    from openvm_fuzzer.zkvm_repository.install import _rewrite_private_stark_backend  # type: ignore

    resolved = resolve_openvm_commit(commit_or_branch)
    dest = out_dir / f"openvm-{resolved}" / "openvm-src"
    marker = dest / ".beak_fuzz_injected_ok"
    if not dest.exists():
        dest.parent.mkdir(parents=True, exist_ok=True)
        if (openvm_src / ".git").exists():
            subprocess.run(
                ["git", "worktree", "add", "--detach", "--force", str(dest), resolved],
                cwd=openvm_src,
                check=True,
                text=True,
            )
        else:
            shutil.copytree(openvm_src, dest, symlinks=True)
    # Always rewrite private deps (offline builds cannot fetch private repos).
    _rewrite_private_stark_backend(dest, resolved)
    if not marker.exists():
        openvm_fault_injection(dest, commit_or_branch=resolved)
        marker.write_text("ok\n")
    (dest / ".openvm_commit").write_text(resolved + "\n")
    return dest


def _parse_used_registers(inst) -> tuple[set[int], set[int]]:
    """
    Returns (all_regs_used, mem_base_regs_used).
    x0 is not included in all_regs_used (it is treated as a constant register).
    """
    regs: set[int] = set()
    base_regs: set[int] = set()

    def _add(r: int | None):
        if r is None or r == 0:
            return
        regs.add(r)

    _add(getattr(inst, "rd", None))
    _add(getattr(inst, "rs1", None))
    _add(getattr(inst, "rs2", None))

    mnemonic = getattr(getattr(inst, "mnemonic", None), "literal", None)
    if mnemonic in {"lb", "lh", "lw", "lbu", "lhu", "sb", "sh", "sw"}:
        r1 = getattr(inst, "rs1", None)
        if isinstance(r1, int) and r1 != 0:
            base_regs.add(r1)
    return regs, base_regs


def generate_project_from_instructions(*, out_root: Path, openvm_path: Path, lines: list[str]) -> Path:
    _add_repo_to_syspath()
    from beak_core.rv32im import DEFAULT_DATA_BASE, Instruction  # type: ignore
    from openvm_fuzzer.settings import (  # type: ignore
        OPENVM_AUDIT_336_COMMIT,
        OPENVM_AUDIT_F038_COMMIT,
        OPENVM_REGZERO_COMMIT,
    )

    insts = [Instruction.from_asm(s) for s in lines]
    regs: set[int] = set()
    base_regs: set[int] = set()
    for inst in insts:
        used, base = _parse_used_registers(inst)
        regs |= used
        base_regs |= base

    # OpenVM guest inline asm constraints: keep to "normal" registers.
    # (x1..x4, x8, x9 are special; x0 is constant and not tracked as a variable.)
    disallowed = {1, 2, 3, 4, 8, 9}
    bad = sorted(r for r in regs if r in disallowed)
    if bad:
        bad_s = ", ".join(f"x{r}" for r in bad)
        raise RuntimeError(
            f"unsupported register(s) in instructions: {bad_s}. "
            "Please use x5..x7 or x10..x31 (avoid x1..x4, x8, x9)."
        )
    if any(getattr(inst, "rd", None) == 0 for inst in insts):
        raise RuntimeError("instructions write to x0 (rd=x0) which is invalid")

    out_root.mkdir(parents=True, exist_ok=True)
    host_dir = out_root / "host"
    guest_dir = out_root / "guest"
    (host_dir / "src").mkdir(parents=True, exist_ok=True)
    (guest_dir / "src").mkdir(parents=True, exist_ok=True)

    _write_text(
        out_root / "Cargo.toml",
        textwrap.dedent(
            """\
            [workspace]
            members = ["host", "guest"]
            default-members = ["host"]
            resolver = "2"
            """
        ),
    )

    fuzzer_utils_path = _relpath(host_dir, openvm_path / "crates" / "fuzzer_utils")
    sdk_path = _relpath(host_dir, openvm_path / "crates" / "sdk")
    build_path = _relpath(host_dir, openvm_path / "crates" / "toolchain" / "build")
    openvm_guest_path_host = _relpath(host_dir, openvm_path / "crates" / "toolchain" / "openvm")
    platform_path = _relpath(host_dir, openvm_path / "crates" / "toolchain" / "platform")
    transpiler_path = _relpath(host_dir, openvm_path / "crates" / "toolchain" / "transpiler")
    _write_text(
        host_dir / "Cargo.toml",
        textwrap.dedent(
            f"""\
            [package]
            name = "openvm-microops-host"
            version = "0.1.0"
            edition = "2021"

            [dependencies]
            fuzzer_utils = {{ path = "{fuzzer_utils_path}" }}
            openvm = {{ path = "{openvm_guest_path_host}", features = ["std"] }}
            openvm-sdk = {{ path = "{sdk_path}" }}
            openvm-build = {{ path = "{build_path}" }}
            openvm-platform = {{ path = "{platform_path}" }}
            openvm-transpiler = {{ path = "{transpiler_path}" }}
            """
        ),
    )

    regs_sorted = sorted(regs)
    init_regs: dict[int, int] = {0: 0}
    for r in regs_sorted:
        init_regs[r] = DEFAULT_DATA_BASE if r in base_regs else (0x10 + r)

    # Host program: prove+verify to ensure we go through the circuit tracegen path that emits micro-ops.
    if (openvm_path / ".openvm_commit").exists():
        commit = (openvm_path / ".openvm_commit").read_text().strip()
    else:
        commit = ""
    use_generic_sdk = commit == OPENVM_REGZERO_COMMIT
    use_legacy_sdk_unit = commit in {OPENVM_AUDIT_336_COMMIT, OPENVM_AUDIT_F038_COMMIT}

    if use_generic_sdk:
        host_main = textwrap.dedent(
            """\
            use std::sync::Arc;

            use openvm_build::GuestOptions;
            use openvm_sdk::{
                config::{AppConfig, AppFriParams, SdkVmConfig, TranspilerConfig},
                prover::verify_app_proof,
                Sdk, StdIn,
            };

            use fuzzer_utils;

            fn main() {
                let trace = std::env::args().any(|arg| arg == "--trace");
                fuzzer_utils::set_trace_logging(trace);

                let vm_config = SdkVmConfig::builder()
                    .system(Default::default())
                    .rv32i(Default::default())
                    .rv32m(Default::default())
                    .io(Default::default())
                    .build();
                let app_fri_params = AppFriParams::default().fri_params;
                let app_config = AppConfig::new(app_fri_params.clone(), vm_config.clone());
                let sdk = Sdk::new(app_config).expect("sdk init");

                let guest_opts = GuestOptions::default();
                let elf = sdk
                    .build(guest_opts, "../guest", &Default::default(), None)
                    .expect("guest build");
                let exe = sdk.convert_to_exe(elf).expect("guest transpile");

                let mut stdin = StdIn::default();
            """
        )
    elif use_legacy_sdk_unit:
        host_main = textwrap.dedent(
            """\
            use std::sync::Arc;

            use openvm_build::GuestOptions;
            use openvm_sdk::{
                config::{AppConfig, AppFriParams, SdkVmConfig},
                Sdk, StdIn,
            };

            use fuzzer_utils;

            fn main() {
                let trace = std::env::args().any(|arg| arg == "--trace");
                fuzzer_utils::set_trace_logging(trace);

                let vm_config = SdkVmConfig::builder()
                    .system(Default::default())
                    .rv32i(Default::default())
                    .rv32m(Default::default())
                    .io(Default::default())
                    .build();
                let app_fri_params = AppFriParams::default().fri_params;
                let sdk = Sdk;
                let guest_opts = GuestOptions::default();

                let elf = sdk
                    .build(guest_opts, "../guest", &Default::default())
                    .expect("guest build");
                let exe = sdk.transpile(elf, vm_config.transpiler()).expect("guest transpile");

                let mut stdin = StdIn::default();
            """
        )
    else:
        # Default to the newer SDK API (Sdk::new + execute) used by ca36de+.
        host_main = textwrap.dedent(
            """\
            use openvm_build::GuestOptions;
            use openvm_sdk::config::SdkVmConfig;
            use openvm_sdk::{Sdk, StdIn};

            use fuzzer_utils;

            fn main() {
                let trace = std::env::args().any(|arg| arg == "--trace");
                fuzzer_utils::set_trace_logging(trace);

                let vm_config = SdkVmConfig::builder()
                    .system(Default::default())
                    .rv32i(Default::default())
                    .rv32m(Default::default())
                    .io(Default::default())
                    .build();

                let sdk = Sdk::new();
                let guest_opts = GuestOptions::default();

                let elf = sdk
                    .build(guest_opts, &vm_config, "../guest", &Default::default(), None)
                    .expect("guest build");
                let exe = sdk
                    .transpile(elf, vm_config.transpiler())
                    .expect("guest transpile");

                let stdin = StdIn::default();
                let _public_values = sdk.execute(exe, vm_config, stdin).expect("execute");
            }
            """
        )

    if use_generic_sdk or use_legacy_sdk_unit:
        for reg_idx in sorted(init_regs.keys()):
            if reg_idx == 0:
                continue
            host_main += f"    stdin.write(&{init_regs[reg_idx]}u32);\n"

        if use_generic_sdk:
            host_main += textwrap.dedent(
                """\

                let mut app_prover = sdk.app_prover(exe.clone()).expect("app prover");
                let app_commit = app_prover.app_commit();
                let (_app_pk, app_vk) = sdk.app_keygen();

                let proof = app_prover.prove(stdin.clone()).expect("prove");
                let verified = verify_app_proof(&app_vk, &proof).expect("verify");
                if verified.app_exe_commit != app_commit.app_exe_commit {
                    panic!("app exe commit mismatch");
                }
            """
            )
        else:
            host_main += textwrap.dedent(
                """\

                let app_config = AppConfig::new(app_fri_params.clone(), vm_config);
                let app_committed_exe = sdk
                    .commit_app_exe(app_fri_params, exe)
                    .expect("commit app exe");
                let app_pk = Arc::new(sdk.app_keygen(app_config).expect("app keygen"));

                let proof = sdk
                    .generate_app_proof(app_pk.clone(), app_committed_exe.clone(), stdin.clone())
                    .expect("prove");
                let app_vk = app_pk.get_app_vk();
                sdk.verify_app_proof(&app_vk, &proof).expect("verify");
            """
            )
        host_main += "}\n"

    _write_text(host_dir / "src" / "main.rs", host_main)

    openvm_guest_path = _relpath(guest_dir, openvm_path / "crates" / "toolchain" / "openvm")
    _write_text(
        guest_dir / "Cargo.toml",
        textwrap.dedent(
            f"""\
            [package]
            name = "openvm-microops-guest"
            version = "0.1.0"
            edition = "2021"

            [dependencies]
            openvm = {{ path = "{openvm_guest_path}", features = ["std"] }}
            """
        ),
    )

    asm_lines = "\n".join(f'            "{s}",' for s in lines)
    # Guest reads initial regs from stdin (excluding x0), runs asm, then reveals a sentinel.
    reveal_fn = "reveal_u32" if commit == OPENVM_REGZERO_COMMIT else "reveal"
    guest_main_lines: list[str] = [
        "#![allow(unused_unsafe)]",
        "#![allow(arithmetic_overflow)]",
        "#![no_main]",
        "",
        "use core::arch::asm;",
        f"use openvm::io::{{read, {reveal_fn}}};",
        "",
        "openvm::entry!(main);",
        "",
        "#[no_mangle]",
        "pub fn main() {",
    ]
    for r in sorted(init_regs.keys()):
        if r == 0:
            continue
        guest_main_lines.append(f"    let mut x{r}: u32 = read();")
    guest_main_lines += [
        "",
        "    unsafe {",
        "        asm!(",
        "            // instruction sequence",
        asm_lines,
    ]
    for r in sorted(init_regs.keys()):
        if r == 0:
            continue
        guest_main_lines.append(f'            inout("x{r}") x{r},')
    guest_main_lines += [
        "            options(nostack)",
        "        );",
        "    }",
        "",
        f"    {reveal_fn}(0xDEADBEEF, 0);",
        "}",
        "",
    ]
    guest_main = "\n".join(guest_main_lines)
    _write_text(guest_dir / "src" / "main.rs", guest_main)
    return out_root


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--openvm-path",
        type=Path,
        default=_repo_root() / "beak-fuzz" / "out" / "openvm-repo",
        help="Path to an OpenVM git repo or checkout (used as the source for install+inject).",
    )
    ap.add_argument(
        "--openvm-commit",
        type=str,
        default="audit-f038",
        help="OpenVM commit or alias (regzero/audit-336/audit-f038).",
    )
    ap.add_argument(
        "--install-openvm",
        action="store_true",
        help="Local install+inject flow: copy --openvm-path into beak-fuzz/out and inject instrumentation there.",
    )
    ap.add_argument(
        "--project-root",
        type=Path,
        default=None,
        help="OpenVM project root containing `host/` and `guest/` (defaults under beak-fuzz/out/openvm-<commit>/).",
    )
    ap.add_argument(
        "--instructions-file",
        type=Path,
        default=None,
        help="Optional: file with one RV32IM asm instruction per line; generates a project and runs it.",
    )
    ap.add_argument(
        "--no-write-artifacts",
        action="store_true",
        help="Do not write run artifacts (stdout/stderr/records/hits) into the project root.",
    )
    args = ap.parse_args()
    _add_repo_to_syspath()
    from openvm_fuzzer.settings import resolve_openvm_commit  # type: ignore

    commit = resolve_openvm_commit(args.openvm_commit)

    openvm_path = args.openvm_path
    if args.install_openvm:
        out_dir = _repo_root() / "beak-fuzz" / "out"
        openvm_path = install_and_inject_openvm(
            openvm_src=openvm_path, out_dir=out_dir, commit_or_branch=commit
        )

    if args.project_root is None:
        project_root = _repo_root() / "beak-fuzz" / "out" / f"openvm-{commit}" / "microops-fixed-elf"
    else:
        project_root = args.project_root
    if args.instructions_file is not None:
        out_root = _repo_root() / "beak-fuzz" / "out" / f"openvm-{commit}" / "from-insts"
        project_root = generate_project_from_instructions(
            out_root=out_root, openvm_path=openvm_path, lines=_load_instructions(args.instructions_file)
        )

    run = run_openvm_project(project_root)
    if run.returncode != 0:
        if not args.no_write_artifacts:
            write_run_artifacts(project_root=project_root, run=run, records=[], hits=[])
        print(f"project_root={project_root}")
        print(f"exit={run.returncode}")
        print("stderr tail:")
        tail = "\n".join(run.stderr.strip().splitlines()[-40:])
        print(tail)
        return 1

    records = _extract_record_json(run.stdout)
    if not records:
        if not args.no_write_artifacts:
            write_run_artifacts(project_root=project_root, run=run, records=[], hits=[])
        raise RuntimeError(
            "no <record> json objects found in stdout. "
            f"project_root={project_root} (see openvm_run.stdout.txt / openvm_run.stderr.txt)"
        )
    trace = build_trace_from_records(records)
    hits = run_buckets(trace, openvm_commit=commit)
    if not args.no_write_artifacts:
        write_run_artifacts(project_root=project_root, run=run, records=records, hits=hits)

    print(f"project_root={project_root}")
    print(f"exit={run.returncode}")
    print(f"micro_ops={len(trace.micro_ops)} ops={len(trace.op_spans or [])} hits={len(hits)}")
    for h in hits[:20]:
        print(json.dumps(h, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
