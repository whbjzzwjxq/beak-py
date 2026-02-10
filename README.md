# Beak-py: Differential Fuzzing for zkVMs

Beak-py is a next-generation zkVM fuzzer designed to detect **Soundness** bugs by comparing zkVM execution results against a trusted RISC-V Oracle (Unicorn).

## Core Architecture

1. **beak-core**: Platform-independent logic.
   - `generator.py`: Generates legal RV32IM assembly sequences directly (no CIRCIL IR).
   - `oracle.py`: Obtains ground truth via `rustc` assembly compilation + `Unicorn` emulation.
2. **Jinja2 Templating**: All Rust source code (Guest/Host) and `Cargo.toml` are decoupled into `.j2` templates.
3. **UV Workspace**: Modern dependency management using `uv` for ultra-fast synchronization and consistent environments.

## Quick Start

### 1. Prerequisites
- [uv](https://github.com/astral-sh/uv)
- Rust toolchain with RISC-V target:
  ```bash
  rustup target add riscv32im-unknown-none-elf
  rustup component add llvm-tools-preview
  ```

### 2. Installation
Initialize the workspace and install OpenVM fuzzer:
```bash
make install-openvm
```

### 3. Run Loop 1 (Natural Mode)
Generate a random instruction sequence and compare Prover results with Oracle:
```bash
make run-openvm-loop1
```

## Loop 1 Mechanism
- **Generate**: Produces 10-20 random RV32IM instructions.
- **Precompute**: Oracle calculates the final register states.
- **Render**: `zkvm_project.py` injects instructions and initial register values into Jinja templates.
- **Diff Check**: Python script reconstructs `u32` values from Prover's byte-stream output and performs a field-by-field comparison.

## Register Safety
Beak-py uses a subset of safe RISC-V registers (`x5-x7`, `x10-x17`, `x28-x31`) to avoid conflicts with system-reserved registers like `sp` (stack pointer) and `gp` (global pointer).

## Bucket Workflow: Trace-Only Mode

`beak-fuzz/scripts/openvm_bucket_workflow.py` and `beak-fuzz/scripts/sp1_bucket_workflow.py` now support `--trace-only`.

- Purpose: run from an instruction file and export only micro-op trace artifacts for downstream tooling.
- Behavior: skip bucket matching and do not write `bucket_hits.json`.
- Output: always writes `micro_op_records.json` + run stdout/stderr files.

### Commit Options

- OpenVM (`--openvm-commit`):
  - aliases: `regzero`, `audit-336`, `audit-f038`
  - or pass a full commit hash directly
  - current pinned hashes:
    - `regzero` -> `d7eab708f43487b2e7c00524ffd611f835e8e6b5`
    - `audit-336` -> `336f1a475e5aa3513c4c5a266399f4128c119bba`
    - `audit-f038` -> `f038f61d21db3aecd3029e1a23ba1ba0bb314800`

- SP1 (`--sp1-commit`):
  - aliases: `s26`, `s27`, `s29`
  - or pass a full commit hash directly
  - current pinned hashes:
    - `s26` -> `7f643da16813af4c0fbaad4837cd7409386cf38c`
    - `s27` -> `f3326e6d0bf78d6b4650ea1e26c501d72fb3c90b`
    - `s29` -> `811a3f2c03914088c7c9e1774266934a3f9f5359`

### OpenVM

```bash
cd beak-fuzz
python3 scripts/openvm_bucket_workflow.py \
  --openvm-commit audit-f038 \
  --install-openvm \
  --instructions-file /tmp/openvm_insts.txt \
  --trace-only
```

Output directory:
- `out/openvm-<commit>/from-insts/micro_op_records.json`
- `out/openvm-<commit>/from-insts/openvm_run.stdout.txt`
- `out/openvm-<commit>/from-insts/openvm_run.stderr.txt`

### SP1

```bash
cd /home/work/workflow/beak-workflow
python3 beak-fuzz/scripts/sp1_bucket_workflow.py \
  --sp1-commit 7f643da16813af4c0fbaad4837cd7409386cf38c \
  --install-sp1 \
  --instructions-file /tmp/sp1_insts.txt \
  --trace-only
```

Output directory:
- `beak-fuzz/out/sp1-<commit>/from-insts/micro_op_records.json`
- `beak-fuzz/out/sp1-<commit>/from-insts/sp1_run.stdout.txt`
- `beak-fuzz/out/sp1-<commit>/from-insts/sp1_run.stderr.txt`
