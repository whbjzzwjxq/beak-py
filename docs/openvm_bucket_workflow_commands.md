# OpenVM Bucket Workflow：TODO + 运行指令速查

## TODO（regzero：打印真实 Adapter/Core ChipRow）

目前 `regzero` 的注入点在 `preflight interpreter` 层（只能看到 decoded `Instruction` + executor dispatch），拿不到 `Rv32*AdapterAir` 这类 AIR 的“真实行对象/列字段”，因此无法在这一层打印出 `Rv32JalrAdapterAir / Rv32BranchAdapterAir` 的 ChipRow locals。

已在代码里留了 TODO（用于后续下沉到 trace build/filler 阶段注入）：

- `projects/openvm-fuzzer/openvm_fuzzer/zkvm_repository/injection.py:564`
  - 说明：如果要输出 `Rv32JalrAdapterAir / Rv32BranchAdapterAir` 这种“真实 AIR 行字段”的 ChipRow，需要在 **trace build/filler**（例如 rv32im adapter fillers / tracegen）阶段插桩，而不是 `interpreter_preflight.rs`。
- `scripts/openvm_bucket_workflow.py:237`
  - 说明：regzero 的 `NextPcUnderconstrainedBucket` 目前用 `VmConnectorAir` 做 proxy matcher；等 regzero 能输出 adapter/core ChipRows（或改用 `Exec(JALR)` / `Exec(BEQ)` 这种 executor-granularity chip）再切换。

## 一键跑通 3 个版本（install+inject+run+collect+buckets）

### 1) 准备指令文件

```bash
cat > /tmp/openvm_insts.txt <<'EOF'
addi x11, x0, 42
sw x11, 0(x10)
lw x12, 0(x10)
addi x13, x12, 1
EOF
```

### 2) 运行（3 个版本）

```bash
uv run python scripts/openvm_bucket_workflow.py --openvm-commit bmk-f038 --install-openvm --instructions-file /tmp/openvm_insts.txt
uv run python scripts/openvm_bucket_workflow.py --openvm-commit bmk-336f  --install-openvm --instructions-file /tmp/openvm_insts.txt
uv run python scripts/openvm_bucket_workflow.py --openvm-commit bmk-regzero    --install-openvm --instructions-file /tmp/openvm_insts.txt
```

### 3) 输出位置（每个版本各自目录）

每个 commit 的输出都在：

- `out/openvm-<commit>/from-insts/micro_op_records.json`
- `out/openvm-<commit>/from-insts/bucket_hits.json`
- `out/openvm-<commit>/from-insts/openvm_run.stdout.txt`
- `out/openvm-<commit>/from-insts/openvm_run.stderr.txt`

其中 `<commit>` 是完整 commit hash，例如：

- `openvm-f038f61d21db3aecd3029e1a23ba1ba0bb314800`
- `openvm-336f1a475e5aa3513c4c5a266399f4128c119bba`
- `openvm-d7eab708f43487b2e7c00524ffd611f835e8e6b5`（regzero）

### 4) 需要强制“重新注入”时

删除 marker 文件后重新跑 `--install-openvm`：

```bash
rm -f out/openvm-<commit>/openvm-src/.beak_fuzz_injected_ok
```

## （可选）渲染 micro-ops Markdown 报告

如果你希望把运行时打印的 micro-op records 渲染成更适合阅读的 `micro_ops.md`：

```bash
python3 scripts/render_openvm_microops_md.py --project-root out/openvm-<commit>/from-insts
```

## （可选）初步定位 regzero：trace filler / adapter filler 入口

```bash
rg -n "AdapterFiller|Filler|tracegen|build_trace" -S out/openvm-d7eab708f43487b2e7c00524ffd611f835e8e6b5/openvm-src/extensions/rv32im | head -n 80
```

