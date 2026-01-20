# pico-fuzzer (Beak Loop1)

This package integrates Pico zkVM into Beak's Loop 1 instruction-sequence fuzzing flow:
generate RV32IM asm, compute expected register results via the Oracle, prove/execute in Pico,
and diff the public outputs.

Entry point:
- `pico-fuzzer`

