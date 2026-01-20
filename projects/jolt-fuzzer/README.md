# jolt-fuzzer (Beak Loop1)

This package integrates Jolt zkVM into Beak's Loop 1 instruction-sequence fuzzing flow:
generate RV32IM asm, compute expected register results via the Oracle, prove/execute in Jolt,
and diff the outputs.

Entry point:
- `jolt-fuzzer`

