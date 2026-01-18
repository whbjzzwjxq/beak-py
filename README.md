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
