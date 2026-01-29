# pico-fuzzer (Beak Loop1)

This package integrates Pico zkVM into Beak's Loop 1 instruction-sequence fuzzing flow:
generate RV32IM asm, compute expected register results via the Oracle, prove/execute in Pico,
and diff the public outputs.

Entry point:
- `pico-fuzzer`

## bool_domain / is_real fault injection (Pico-IsReal-01)

This repo includes an internal fault-injection hook for exercising the `bool_domain` bucket
against Pico's `MemoryLocalChip.is_real`. End users should run the demo below rather than
setting low-level injection knobs manually.

## Closed-loop demo (bool_domain / is_real)

Run from the `beak-fuzz/` directory:

```bash
export UV_CACHE_DIR="$PWD/.uv-cache"

uv venv
uv sync --package pico-fuzzer
source .venv/bin/activate

python libs/beak-core/beak_core/demos/pico_bool_domain_is_real.py
```
