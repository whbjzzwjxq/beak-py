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
from typing import Any, Optional


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _add_repo_to_syspath():
    root = _repo_root()
    sys.path.insert(0, str(root / "beak-fuzz" / "libs" / "beak-core"))
    sys.path.insert(0, str(root / "beak-fuzz" / "libs" / "zkvm-fuzzer-utils"))
    sys.path.insert(0, str(root / "beak-fuzz" / "projects" / "sp1-fuzzer"))


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
    hits: Optional[list[dict[str, Any]]],
) -> None:
    project_root.mkdir(parents=True, exist_ok=True)
    (project_root / "sp1_run.stdout.txt").write_text(run.stdout)
    (project_root / "sp1_run.stderr.txt").write_text(run.stderr)
    micro_op_records = [r for r in records if r.get("context") == "micro_op"]
    (project_root / "micro_op_records.json").write_text(json.dumps(micro_op_records, indent=2, sort_keys=True))
    bucket_hits_path = project_root / "bucket_hits.json"
    if hits is not None:
        bucket_hits_path.write_text(json.dumps(hits, indent=2, sort_keys=True, default=str))
    elif bucket_hits_path.exists():
        bucket_hits_path.unlink()


def _ensure_writable_cargo_home() -> Path:
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


def run_sp1_project(project_root: Path) -> RunResult:
    env = dict(os.environ)
    env.setdefault("CARGO_NET_OFFLINE", "true")
    env.setdefault("CARGO_HOME", str(_ensure_writable_cargo_home()))
    # SP1 guest programs require the Succinct toolchain which provides the custom target spec.
    env.setdefault("RUSTUP_TOOLCHAIN", "succinct")

    # Build the guest ELF first; `cargo run` in the host crate won't build non-default members.
    build_guest = subprocess.run(
        [
            "cargo",
            "build",
            "-q",
            "-p",
            "sp1-guest",
            "--release",
            "--target",
            "riscv32im-succinct-zkvm-elf",
        ],
        cwd=project_root,
        text=True,
        capture_output=True,
        env=env,
    )
    if build_guest.returncode != 0:
        return RunResult(stdout=build_guest.stdout, stderr=build_guest.stderr, returncode=build_guest.returncode)

    proc = subprocess.run(
        ["cargo", "run", "-q", "--release", "--", "--trace"],
        cwd=project_root / "host",
        text=True,
        capture_output=True,
        env=env,
    )
    return RunResult(
        stdout=(build_guest.stdout + proc.stdout),
        stderr=(build_guest.stderr + proc.stderr),
        returncode=proc.returncode,
    )


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
            if not isinstance(gates, dict) or not isinstance(locals_, dict):
                continue
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


def run_buckets(trace, *, sp1_commit: str):
    _add_repo_to_syspath()
    from beak_core.buckets import (  # type: ignore
        GateBoolDomainBucket,
        InactiveRowEffectsBucket,
        NextPcUnderconstrainedBucket,
    )

    nextpc_buckets = [
        NextPcUnderconstrainedBucket(
            instruction_label="sp1.Exec(JALR)",
            chip="Exec(JALR)",
            min_following_instructions=2,
        ),
        NextPcUnderconstrainedBucket(
            instruction_label="sp1.Exec(BEQ)",
            chip="Exec(BEQ)",
            min_following_instructions=2,
        ),
        NextPcUnderconstrainedBucket(
            instruction_label="sp1.Exec(BNE)",
            chip="Exec(BNE)",
            min_following_instructions=2,
        ),
        NextPcUnderconstrainedBucket(
            instruction_label="sp1.Exec(BLTU)",
            chip="Exec(BLTU)",
            min_following_instructions=2,
        ),
        NextPcUnderconstrainedBucket(
            instruction_label="sp1.Exec(BGEU)",
            chip="Exec(BGEU)",
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


def install_and_inject_sp1(*, out_root: Path, commit_or_branch: str, install_sp1: bool) -> Path:
    _add_repo_to_syspath()
    from sp1_fuzzer.settings import resolve_sp1_commit  # type: ignore
    from sp1_fuzzer.zkvm_repository.injection import sp1_fault_injection  # type: ignore

    resolved = resolve_sp1_commit(commit_or_branch)
    label = f"sp1-{resolved}"
    dest = out_root / label / "sp1-src"
    marker = dest / ".beak_fuzz_injected_ok"

    if not install_sp1:
        if not dest.exists():
            raise RuntimeError(f"missing installed SP1 snapshot at {dest}; re-run with --install-sp1")
        return dest

    if install_sp1:
        sp1_src = _repo_root() / "beak-fuzz" / "sp1-src"
        if not sp1_src.exists():
            raise RuntimeError(f"missing base checkout at {sp1_src}")
        if dest.exists() and not (dest / ".git").exists():
            shutil.rmtree(dest)
        dest.parent.mkdir(parents=True, exist_ok=True)
        if not dest.exists():
            subprocess.run(
                ["git", "worktree", "add", "--detach", "--force", str(dest), resolved],
                cwd=sp1_src,
                check=True,
                text=True,
            )
        if not marker.exists():
            # Support "force reinjection" by deleting the marker: reset any previous patches
            # (including prepends/replacements) before applying our injection again.
            subprocess.run(["git", "reset", "--hard"], cwd=dest, check=True, text=True)
            subprocess.run(["git", "clean", "-fdx"], cwd=dest, check=True, text=True)
            sp1_fault_injection(dest, commit_or_branch=resolved)
            marker.write_text("ok\n")
        (dest / ".sp1_commit").write_text(resolved + "\n")
    return dest


def _parse_used_registers(inst) -> tuple[set[int], set[int]]:
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


def generate_project_from_instructions(*, out_root: Path, sp1_path: Path, lines: list[str]) -> Path:
    _add_repo_to_syspath()
    from beak_core.rv32im import DEFAULT_DATA_BASE, Instruction  # type: ignore

    insts = [Instruction.from_asm(s) for s in lines]
    regs: set[int] = set()
    base_regs: set[int] = set()
    for inst in insts:
        used, base = _parse_used_registers(inst)
        regs |= used
        base_regs |= base

    disallowed = {1, 2, 3, 4, 8, 9}
    bad = sorted(r for r in regs if r in disallowed)
    if bad:
        bad_s = ", ".join(f"x{r}" for r in bad)
        raise RuntimeError(
            f"unsupported register(s) in instructions: {bad_s}. "
            "Please use x5..x7 or x10..x31 (avoid x1..x4, x8, x9)."
        )

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

    fuzzer_utils_path = _relpath(host_dir, sp1_path / "crates" / "fuzzer_utils")
    sdk_path = _relpath(host_dir, sp1_path / "crates" / "sdk")
    zkvm_entry_path = _relpath(guest_dir, sp1_path / "crates" / "zkvm" / "entrypoint")

    _write_text(
        host_dir / "Cargo.toml",
        textwrap.dedent(
            f"""\
            [package]
            version = "0.1.0"
            name = "sp1-microops-host"
            edition = "2021"
            default-run = "sp1-microops-host"

            [[bin]]
            name = "sp1-microops-host"
            path = "src/main.rs"

            [dependencies]
            sp1-sdk = {{ path = "{sdk_path}" }}
            fuzzer_utils = {{ path = "{fuzzer_utils_path}" }}
            serde_json = "1"
            """
        ),
    )

    regs_sorted = sorted(regs)
    init_regs: dict[int, int] = {0: 0}
    for r in regs_sorted:
        init_regs[r] = DEFAULT_DATA_BASE if r in base_regs else (0x10 + r)
    output_word_count = 2 * len(init_regs)

    host_main = textwrap.dedent(
        f"""\
        use sp1_sdk::{{ProverClient, SP1Stdin}};
        use serde_json::json;
        use std::fs;
        use std::time::Instant;

        use fuzzer_utils;

        const SP1_GUEST_PATH: &str = "../target/riscv32im-succinct-zkvm-elf/release/sp1-guest";

        fn create_sp1_stdin() -> SP1Stdin {{
            let mut stdin = SP1Stdin::new();
        """
    )
    for r in sorted(init_regs.keys()):
        if r == 0:
            continue
        host_main += f"    stdin.write(&{init_regs[r]}u32);\n"
    host_main += textwrap.dedent(
        f"""\
            stdin
        }}

        fn main() {{
            sp1_sdk::utils::setup_logger();
            let trace = std::env::args().any(|arg| arg == "--trace");
            fuzzer_utils::set_trace_logging(trace);
            // Disable fixed-shape enforcement so core proving works for arbitrary small programs.
            // We only need trace generation here (for padding-row sampling), not shape validation.
            std::env::set_var("FIX_CORE_SHAPES", "false");

            println!("<record>{{}}</record>", json!({{"context":"Executor","status":"start"}}));
            let timer = Instant::now();
            let client = ProverClient::new();
            let stdin = create_sp1_stdin();
            let elf = fs::read(SP1_GUEST_PATH).expect("read guest elf");
            // NOTE: `execute()` does not build chip traces, so padding rows (is_real=0) won't
            // exist yet. Use a core proof to force trace generation so we can sample inactive rows.
            let (pk, _vk) = client.setup(&elf);
            let proof = client.prove(&pk, stdin).core().run().unwrap();
            let mut public_values = proof.public_values;

            let mut outputs: Vec<u32> = Vec::new();
            for _ in 0..{output_word_count} {{
                outputs.push(public_values.read::<u32>());
            }}

            println!(
                "<record>{{}}</record>",
                json!({{"context":"Executor","status":"success","time": format!("{{:.2?}}", timer.elapsed()),"output": outputs}})
            );
        }}
        """
    )
    _write_text(host_dir / "src" / "main.rs", host_main)

    _write_text(
        guest_dir / "Cargo.toml",
        textwrap.dedent(
            f"""\
            [package]
            name = "sp1-guest"
            version = "0.1.0"
            edition = "2021"

            [dependencies]
            sp1-zkvm = {{ path = "{zkvm_entry_path}" }}
            """
        ),
    )

    guest_main = textwrap.dedent(
        """\
        #![allow(unused_unsafe)]
        #![allow(unconditional_panic)]
        #![allow(arithmetic_overflow)]
        #![no_main]

        use core::arch::asm;

        sp1_zkvm::entrypoint!(main);

        pub fn main() {
        """
    )
    for r in sorted(init_regs.keys()):
        if r == 0:
            continue
        guest_main += f"    let mut x{r}: u32 = sp1_zkvm::io::read();\n"
    guest_main += "\n    let mut final_x0: u32 = 0;\n\n    unsafe {\n        asm!(\n"
    for inst in insts:
        guest_main += f'            "{inst.asm}",\n'
    guest_main += '            "mv {final_x0}, x0",\n\n'
    for r in sorted(init_regs.keys()):
        if r == 0:
            continue
        guest_main += f'            inout("x{r}") x{r},\n'
    guest_main += "            final_x0 = out(reg) final_x0,\n            options(nostack)\n        );\n    }\n\n"
    for r in sorted(init_regs.keys()):
        guest_main += f"    sp1_zkvm::io::commit(&{r}u32);\n"
        if r == 0:
            guest_main += "    sp1_zkvm::io::commit(&final_x0);\n"
        else:
            guest_main += f"    sp1_zkvm::io::commit(&x{r});\n"
    guest_main += "}\n"
    _write_text(guest_dir / "src" / "main.rs", guest_main)

    return out_root


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sp1-commit", required=True, help="commit hash or alias (s26/s27/s29)")
    ap.add_argument("--install-sp1", action="store_true", help="install+inject SP1 snapshot into out/")
    ap.add_argument("--instructions-file", required=True)
    ap.add_argument(
        "--trace-only",
        action="store_true",
        help=(
            "Trace mode: run and export micro_op_records.json only (skip bucket matching and do not write "
            "bucket_hits.json)."
        ),
    )
    args = ap.parse_args()

    out_base = _repo_root() / "beak-fuzz" / "out"
    sp1_path = install_and_inject_sp1(out_root=out_base, commit_or_branch=args.sp1_commit, install_sp1=args.install_sp1)
    lines = _load_instructions(Path(args.instructions_file))
    project_root = generate_project_from_instructions(
        out_root=sp1_path.parent / "from-insts",
        sp1_path=sp1_path,
        lines=lines,
    )

    run = run_sp1_project(project_root)
    print(f"project_root={project_root}")
    print(f"exit={run.returncode}")

    # Always persist stdout/stderr for debugging, even if downstream trace parsing fails.
    (project_root / "sp1_run.stdout.txt").write_text(run.stdout)
    (project_root / "sp1_run.stderr.txt").write_text(run.stderr)

    if run.returncode != 0:
        tail = "\n".join(run.stderr.splitlines()[-30:])
        print("stderr tail:")
        print(tail)
        write_run_artifacts(project_root=project_root, run=run, records=[], hits=[] if not args.trace_only else None)
        return run.returncode

    records = _extract_record_json(run.stdout)
    micro_op_records = [r for r in records if r.get("context") == "micro_op"]
    if args.trace_only:
        write_run_artifacts(project_root=project_root, run=run, records=records, hits=None)
        print(f"trace_mode=on micro_op_records={len(micro_op_records)}")
        manifest = {
            "mode": "trace_only",
            "project_root": str(project_root),
            "micro_op_records_path": str(project_root / "micro_op_records.json"),
            "stdout_path": str(project_root / "sp1_run.stdout.txt"),
            "stderr_path": str(project_root / "sp1_run.stderr.txt"),
            "micro_op_record_count": len(micro_op_records),
        }
        print(json.dumps(manifest))
        return 0

    try:
        trace = build_trace_from_records(records)
    except Exception as e:
        # Still write extracted records so we can inspect what broke.
        write_run_artifacts(project_root=project_root, run=run, records=records, hits=[])
        raise

    hits = run_buckets(trace, sp1_commit=args.sp1_commit)
    write_run_artifacts(project_root=project_root, run=run, records=records, hits=hits)

    print(f"micro_ops={len(trace.micro_ops)} ops={len(trace.op_spans or [])} hits={len(hits)}")
    for h in hits[:20]:
        print(json.dumps(h, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
