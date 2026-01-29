from __future__ import annotations

import os
from dataclasses import dataclass, replace
from pathlib import Path

from beak_core.buckets import (
    BoolDomainBucket,
    BoolDomainSignal,
    BoolDomainStatus,
    BucketKey,
    BucketType,
)
from beak_core.micro_ops import MemoryRead, MemoryWrite, ZKVMTrace
from beak_core.rv32im import DEFAULT_DATA_BASE, FuzzingInstance, Instruction
from beak_core.rv32im_micro_ops import micro_ops_from_unicorn_execution


@dataclass(frozen=True)
class DemoConfig:
    out_dir: Path
    zkvm_dir: Path
    is_real_injected_value: int = 2


@dataclass(frozen=True)
class _MemEvent:
    kind: str  # "memw" or "memr"
    addr: int
    value: int
    step_idx: int
    uop_idx: int


def _make_demo_instance() -> FuzzingInstance:
    # Avoid x2(sp) and x3(gp) in inline asm operands.
    insts = [
        Instruction.from_asm("sw x6, 0(x5)"),
        Instruction.from_asm("lw x7, 0(x5)"),
    ]
    return FuzzingInstance(
        insts,
        initial_regs={
            5: DEFAULT_DATA_BASE,
            6: 0x12345678,
            7: 0,
        },
    )


def _flatten_trace(trace: ZKVMTrace) -> list[object]:
    out: list[object] = []
    for s_idx in trace.micro_ops_by_step.keys():
        out.extend(trace.micro_ops_by_step[s_idx])
    return out


def _first_mem_event_from_trace(trace: ZKVMTrace) -> _MemEvent:
    first_read: _MemEvent | None = None
    for uop in _flatten_trace(trace):
        if isinstance(uop, MemoryWrite):
            return _MemEvent(
                kind="memw",
                addr=uop.addr,
                value=int(uop.value),
                step_idx=uop.step_idx,
                uop_idx=uop.uop_idx,
            )
        if first_read is None and isinstance(uop, MemoryRead):
            first_read = _MemEvent(
                kind="memr",
                addr=uop.addr,
                value=int(uop.value),
                step_idx=uop.step_idx,
                uop_idx=uop.uop_idx,
            )
    if first_read is None:
        raise RuntimeError("no memory events found in trace (expected at least one MemoryRead/MemoryWrite)")
    return first_read


def _simulate_is_real_injection(trace: ZKVMTrace, *, target: _MemEvent, injected_is_real_value: int) -> ZKVMTrace:
    # For bucket debugging only: mimic "is_real = 2" on the chosen memory row.
    uops_bad: list[object] = []
    for uop in _flatten_trace(trace):
        if (
            isinstance(uop, (MemoryRead, MemoryWrite))
            and uop.step_idx == target.step_idx
            and uop.uop_idx == target.uop_idx
        ):
            uops_bad.append(replace(uop, meta=replace(uop.meta, is_real=injected_is_real_value)))
        else:
            uops_bad.append(uop)
    return ZKVMTrace(uops_bad)  # type: ignore[arg-type]


def _print_record_lines(stdout: str) -> None:
    for line in stdout.splitlines():
        if "<record>" in line:
            print(line)


def run_demo(cfg: DemoConfig) -> None:
    """
    Closed-loop demo for:
      - bucket: bool_domain (meta.is_real is non-boolean)
      - backend: Pico (fault injection via env)

    Flow:
      - execute instance -> micro-op trace
      - run BoolDomainBucket on trace
      - request a repair payload for (meta.is_real, non_bool)
      - map payload + chosen mem event -> Pico injection env
      - run Pico prover baseline + injected
    """

    # Import Pico adapter lazily so importing beak_core doesn't require Pico deps.
    from pico_fuzzer.adapter import build_and_run_pico

    instance = _make_demo_instance()

    trace_ok = micro_ops_from_unicorn_execution(instance)
    ev = _first_mem_event_from_trace(trace_ok)

    ok_hits = BoolDomainBucket().features(trace_ok)
    print("== demo (micro-op side) ==")
    print("program:")
    for inst in instance.instructions:
        print("  ", inst.asm)
    print(f"derived mem event: kind={ev.kind} addr=0x{ev.addr:08x} value=0x{ev.value:08x}")
    print("bucket hits (before):")
    for h in ok_hits:
        if h.key.label[0] == BoolDomainSignal.IS_REAL.value:
            print("  ", BoolDomainBucket().explain(h))

    target_key = BucketKey(
        BucketType.BOOL_DOMAIN,
        (BoolDomainSignal.IS_REAL.value, BoolDomainStatus.NON_BOOLEAN.value),
    )
    payload = BoolDomainBucket().repair(target_key)
    if payload is None:
        raise RuntimeError("unexpected: bool_domain repair payload is None")
    print("selected bucket target:", target_key)
    print("repair payload:", payload)

    trace_bad = _simulate_is_real_injection(
        trace_ok, target=ev, injected_is_real_value=cfg.is_real_injected_value
    )
    bad_hits = BoolDomainBucket().features(trace_bad)
    print("bucket hits (simulated after):")
    for h in bad_hits:
        if h.key.label[0] == BoolDomainSignal.IS_REAL.value:
            print("  ", BoolDomainBucket().explain(h))

    injection_env = {
        "BEAK_PICO_INJECT_BOOL_DOMAIN_IS_REAL": "1",
        "BEAK_PICO_INJECT_BOOL_DOMAIN_IS_REAL_VALUE": str(cfg.is_real_injected_value),
        "BEAK_PICO_INJECT_BOOL_DOMAIN_IS_REAL_ADDR": str(ev.addr),
    }

    build = os.environ.get("BEAK_SKIP_BUILD", "0").strip().lower() not in {"1", "true", "yes"}
    result = build_and_run_pico(
        instance=instance,
        zkvm_dir=cfg.zkvm_dir,
        out_dir=cfg.out_dir,
        injection_env=injection_env,
        build=build,
    )

    print("== pico (zkvm side) ==")
    print("baseline exit:", result.baseline.returncode)
    _print_record_lines(result.baseline.stdout)

    assert result.injected is not None
    print("injected exit:", result.injected.returncode)
    _print_record_lines(result.injected.stdout)
    if result.injected.is_failure():
        print("injected stderr tail:")
        print("\n".join(result.injected.stderr.splitlines()[-10:]))


if __name__ == "__main__":
    # Make defaults independent of the current working directory.
    # This file lives at: beak-fuzz/libs/beak-core/beak_core/demos/...
    beak_fuzz_dir = Path(__file__).resolve().parents[4]
    run_demo(
        DemoConfig(
            out_dir=(beak_fuzz_dir / "out" / "pico-bool-domain").resolve(),
            zkvm_dir=(beak_fuzz_dir / "pico-src").resolve(),
        )
    )
