# SP1 Bucket Workflow（3 个版本）

这份文档对应 `scripts/sp1_bucket_workflow.py`，实现与 OpenVM 类似的流程：

1. `--install-sp1`：将指定 commit 的 SP1 源码以 `git worktree` 安装到 `beak-fuzz/out/sp1-<commit>/sp1-src`，并注入 micro-op 输出逻辑（ChipRow + Interaction）。
2. `--instructions-file`：输入一段 RV32IM 指令序列，自动生成一个最小 host/guest 项目并运行（core 证明，用于触发 trace/padding）。
3. 收集 stdout 里 `<record>...</record>` 的 JSON，构建 `ZKVMTrace`，并跑 buckets，输出命中结果。

## 1) 准备指令文件

```bash
cat > /tmp/sp1_insts.txt <<'EOF'
addi x5, x0, 1
addi x6, x0, 2
beq  x5, x6, 8
bne  x5, x5, 8
bltu x11, x10, 8
bgeu x10, x11, 8
addi x7, x7, 1
addi x12, x12, 3
EOF
```

注意：guest 里使用 inline `asm!` 拼接指令，尽量避免会真正改变控制流的 `jalr/jal`（否则可能跳到无效地址导致崩溃）。上面这些分支均设计为“不跳转”。

补充：为了让 SP1 真正生成各 chip 的 trace（从而出现 padding 行 `is_real=0`），workflow 的 host 会走 `client.setup(...)` + `client.prove(...).core().run()`，
并自动设置 `FIX_CORE_SHAPES=false` 来关闭固定 shape 校验（否则对临时小程序可能出现 `ShapeError`）。

## 2) 运行（Makefile 对应的 3 个 commit）

```bash
uv run python scripts/sp1_bucket_workflow.py --sp1-commit 7f643da16813af4c0fbaad4837cd7409386cf38c --install-sp1 --instructions-file /tmp/sp1_insts.txt
uv run python scripts/sp1_bucket_workflow.py --sp1-commit f3326e6d0bf78d6b4650ea1e26c501d72fb3c90b --install-sp1 --instructions-file /tmp/sp1_insts.txt
uv run python scripts/sp1_bucket_workflow.py --sp1-commit 811a3f2c03914088c7c9e1774266934a3f9f5359 --install-sp1 --instructions-file /tmp/sp1_insts.txt
```

## 3) 输出位置（每个版本各自目录）

每个 commit 的输出都在：

- `beak-fuzz/out/sp1-<commit>/from-insts/micro_op_records.json`
- `beak-fuzz/out/sp1-<commit>/from-insts/bucket_hits.json`
- `beak-fuzz/out/sp1-<commit>/from-insts/sp1_run.stdout.txt`
- `beak-fuzz/out/sp1-<commit>/from-insts/sp1_run.stderr.txt`

其中 `<commit>` 是完整 commit hash，例如：

- `sp1-7f643da16813af4c0fbaad4837cd7409386cf38c`
- `sp1-f3326e6d0bf78d6b4650ea1e26c501d72fb3c90b`
- `sp1-811a3f2c03914088c7c9e1774266934a3f9f5359`

## 4) 需要强制“重新注入”时

删除 marker 文件后重新跑 `--install-sp1`：

```bash
rm -f beak-fuzz/out/sp1-<commit>/sp1-src/.beak_fuzz_injected_ok
```

`sp1_bucket_workflow.py` 会在重新注入前对该 worktree 进行 `git reset --hard` + `git clean -fdx`，避免重复插桩造成 Cargo.toml / 源码重复 patch。
