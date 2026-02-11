from __future__ import annotations

import argparse
import json
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class MicroOpRow:
    step: int
    pc: int
    instruction: str
    assembly: str
    chips: list[dict[str, Any]]

    @property
    def total_delta(self) -> int:
        total = 0
        for c in self.chips:
            d = c.get("delta")
            if isinstance(d, int):
                total += d
        return total

    def chips_compact(self, *, max_items: int = 8) -> str:
        items: list[tuple[str, int]] = []
        for c in self.chips:
            name = c.get("chip")
            delta = c.get("delta")
            if isinstance(name, str) and isinstance(delta, int) and delta > 0:
                items.append((name, delta))
        items.sort(key=lambda x: (-x[1], x[0]))
        shown = items[:max_items]
        suffix = "" if len(items) <= max_items else f", …(+{len(items) - max_items})"
        return ", ".join([f"{n}:{d}" for (n, d) in shown]) + suffix


@dataclass(frozen=True)
class ChipRowItem:
    step: int
    pc: int
    instruction: str
    assembly: str
    row_id: str
    domain: str
    chip: str
    gates: dict[str, Any]
    values: dict[str, Any]

@dataclass(frozen=True)
class InteractionItem:
    step: int
    pc: int
    instruction: str
    assembly: str
    table_id: str
    io: str
    kind: str
    scope: str | None
    anchor_row_id: str | None
    multiplicity: dict[str, Any] | None
    payload: Any


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
            # Ignore non-JSON or malformed records.
            continue
    return records


def run_openvm_and_collect(project_root: Path) -> tuple[list[MicroOpRow], list[ChipRowItem], list[InteractionItem], str]:
    env = dict(os.environ)
    env.setdefault("CARGO_NET_OFFLINE", "true")
    # getrandom v0.3 uses cfg-based backend selection on some targets; OpenVM provides
    # the `__getrandom_v03_custom` symbol (a backend that always errors) for builds
    # that shouldn't rely on randomness.
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
    delta_rows: list[MicroOpRow] = []
    chip_rows: list[ChipRowItem] = []
    interactions: list[InteractionItem] = []
    for rec in _extract_record_json(proc.stdout):
        ctx = rec.get("context")
        if ctx == "micro_ops":
            step = rec.get("step")
            pc = rec.get("pc")
            instruction = rec.get("instruction")
            assembly = rec.get("assembly")
            chips = rec.get("chips")
            if not isinstance(step, int) or not isinstance(pc, int):
                continue
            if not isinstance(instruction, str) or not isinstance(assembly, str):
                continue
            if not isinstance(chips, list):
                chips = []
            delta_rows.append(
                MicroOpRow(
                    step=step,
                    pc=pc,
                    instruction=instruction,
                    assembly=assembly,
                    chips=chips,
                )
            )
        elif ctx == "micro_op" and rec.get("micro_op_type") == "chip_row":
            step = rec.get("step")
            pc = rec.get("pc")
            instruction = rec.get("instruction")
            assembly = rec.get("assembly")
            row_id = rec.get("row_id")
            domain = rec.get("domain")
            chip = rec.get("chip")
            gates = rec.get("gates")
            values = rec.get("values")
            if not isinstance(step, int) or not isinstance(pc, int):
                continue
            if (
                not isinstance(instruction, str)
                or not isinstance(assembly, str)
                or not isinstance(row_id, str)
                or not isinstance(domain, str)
                or not isinstance(chip, str)
            ):
                continue
            if not isinstance(gates, dict):
                gates = {}
            if not isinstance(values, dict):
                values = {}
            chip_rows.append(
                ChipRowItem(
                    step=step,
                    pc=pc,
                    instruction=instruction,
                    assembly=assembly,
                    row_id=row_id,
                    domain=domain,
                    chip=chip,
                    gates=gates,
                    values=values,
                )
            )
        elif ctx == "micro_op" and rec.get("micro_op_type") == "interaction":
            step = rec.get("step")
            pc = rec.get("pc")
            instruction = rec.get("instruction")
            assembly = rec.get("assembly")
            table_id = rec.get("table_id")
            io = rec.get("io")
            kind = rec.get("kind")
            scope = rec.get("scope")
            anchor_row_id = rec.get("anchor_row_id")
            multiplicity = rec.get("multiplicity")
            payload = rec.get("payload")
            if not isinstance(step, int) or not isinstance(pc, int):
                continue
            if not isinstance(instruction, str) or not isinstance(assembly, str):
                continue
            if not isinstance(table_id, str) or not isinstance(io, str) or not isinstance(kind, str):
                continue
            if scope is not None and not isinstance(scope, str):
                scope = None
            if anchor_row_id is not None and not isinstance(anchor_row_id, str):
                anchor_row_id = None
            if multiplicity is not None and not isinstance(multiplicity, dict):
                multiplicity = None
            interactions.append(
                InteractionItem(
                    step=step,
                    pc=pc,
                    instruction=instruction,
                    assembly=assembly,
                    table_id=table_id,
                    io=io,
                    kind=kind,
                    scope=scope,
                    anchor_row_id=anchor_row_id,
                    multiplicity=multiplicity,
                    payload=payload,
                )
            )

    delta_rows.sort(key=lambda r: r.step)
    chip_rows.sort(key=lambda r: (r.step, r.row_id))
    interactions.sort(key=lambda r: (r.step, r.table_id, r.io))
    run_info = f"- `cwd`: `{project_root / 'host'}`\n- `exit`: `{proc.returncode}`"
    if proc.returncode != 0:
        tail = "\n".join(proc.stderr.strip().splitlines()[-40:])
        run_info += "\n- `stderr (tail)`:"
        run_info += "\n```"
        run_info += f"\n{tail}\n"
        run_info += "```"

    if proc.returncode != 0 and not delta_rows and not chip_rows and not interactions:
        raise RuntimeError("openvm host failed (no records)\n" f"{run_info}\n")

    return delta_rows, chip_rows, interactions, run_info


def _uop_seq_compact(rows: list[ChipRowItem], *, max_items: int = 6) -> str:
    names = [u.chip for u in rows]
    shown = names[:max_items]
    suffix = "" if len(names) <= max_items else f" …(+{len(names) - max_items})"
    return " → ".join(shown) + suffix


def render_markdown(
    delta_rows: list[MicroOpRow],
    chip_rows: list[ChipRowItem],
    interactions: list[InteractionItem],
    *,
    run_info: str | None = None,
) -> str:
    lines: list[str] = []
    lines.append("# OpenVM micro-ops (per-instruction micro-op sequences)")
    lines.append("")
    lines.append("This report is generated from OpenVM execution with beak-fuzz instrumentation enabled.")
    lines.append("")
    if run_info:
        lines.append("## Run")
        lines.append("")
        lines.append(run_info.strip())
        lines.append("")

    if not chip_rows and not interactions and not delta_rows:
        lines.append(
            "_No micro-op records were found. (Did you run with `--trace` and a patched OpenVM repo?)_"
        )
        lines.append("")
        return "\n".join(lines)

    # Group chip rows by step
    rows_by_step: dict[int, list[ChipRowItem]] = {}
    for u in chip_rows:
        rows_by_step.setdefault(u.step, []).append(u)

    interactions_by_step: dict[int, list[InteractionItem]] = {}
    for it in interactions:
        interactions_by_step.setdefault(it.step, []).append(it)

    if chip_rows:
        lines.append("## Per instruction (micro-op sequence)")
        lines.append("")
        lines.append("| step | pc | instr | uops | sequence (top) |")
        lines.append("| ---: | ---: | :--- | ---: | :--- |")
        for step in sorted(rows_by_step.keys()):
            rows = rows_by_step[step]
            head = rows[0]
            lines.append(
                f"| {step} | `0x{head.pc:08x}` | `{head.instruction}` | {len(rows)} | {_uop_seq_compact(rows)} |"
            )
        lines.append("")

    if delta_rows:
        # Per-step deltas (optional legacy/proxy view)
        lines.append("## Per instruction (chip trace-height deltas, proxy)")
        lines.append("")
        lines.append("| step | pc | instr | totalΔ | chipΔ (top) |")
        lines.append("| ---: | ---: | :--- | ---: | :--- |")
        for r in delta_rows:
            lines.append(
                f"| {r.step} | `0x{r.pc:08x}` | `{r.instruction}` | {r.total_delta} | {r.chips_compact()} |"
            )
        lines.append("")

    if chip_rows:
        lines.append("## Details")
        lines.append("")
        steps = sorted(set(rows_by_step.keys()) | set(interactions_by_step.keys()))
        for step in steps:
            rows = rows_by_step.get(step, [])
            head = rows[0] if rows else None
            lines.append(f"### step {step} · pc `0x{head.pc:08x}` · `{head.instruction}`")
            lines.append("")
            lines.append(f"- asm: `{head.assembly}`")
            lines.append("")
            for i, u in enumerate(rows):
                stage = None
                if isinstance(u.values, dict):
                    stage = u.values.get("stage")
                stage_s = "" if not isinstance(stage, str) else f" ({stage})"
                lines.append(f"<details><summary>uop {i}: <code>{u.chip}</code>{stage_s}</summary>")
                lines.append("")
                try:
                    pretty = json.dumps(
                        {"row_id": u.row_id, "domain": u.domain, "gates": u.gates, "values": u.values},
                        indent=2,
                        sort_keys=True,
                    )
                except Exception:
                    pretty = json.dumps({"_unserializable": True})
                lines.append("```json")
                lines.append(pretty)
                lines.append("```")
                lines.append("")
                lines.append("</details>")
                lines.append("")

            its = interactions_by_step.get(step, [])
            if its:
                lines.append("**Interactions**")
                lines.append("")
                for it in its:
                    anchor = "" if not it.anchor_row_id else f" anchor=`{it.anchor_row_id}`"
                    lines.append(f"- `{it.table_id}` `{it.io}` kind=`{it.kind}`{anchor}")
                lines.append("")

    if delta_rows:
        # Aggregate deltas by instruction label (optional)
        agg: dict[str, dict[str, int]] = {}
        for r in delta_rows:
            per_chip = agg.setdefault(r.instruction, {})
            for c in r.chips:
                name = c.get("chip")
                delta = c.get("delta")
                if isinstance(name, str) and isinstance(delta, int) and delta > 0:
                    per_chip[name] = per_chip.get(name, 0) + delta

        def _agg_total(chip_map: dict[str, int]) -> int:
            return sum(chip_map.values())

        lines.append("## By instruction (chip deltas, aggregated)")
        lines.append("")
        lines.append("| instr | totalΔ | chipΔ (top) |")
        lines.append("| :--- | ---: | :--- |")
        for instr, chip_map in sorted(agg.items(), key=lambda kv: (-_agg_total(kv[1]), kv[0])):
            items = sorted(chip_map.items(), key=lambda x: (-x[1], x[0]))
            top = ", ".join([f"{n}:{d}" for (n, d) in items[:10]])
            suffix = "" if len(items) <= 10 else f", …(+{len(items) - 10})"
            lines.append(f"| `{instr}` | {_agg_total(chip_map)} | {top}{suffix} |")
        lines.append("")

    return "\n".join(lines)


def main() -> int:
    repo_root = Path(__file__).resolve().parents[2]
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--project-root",
        type=Path,
        default=repo_root / "beak-fuzz" / "out" / "microops-openvm-fixed-elf",
        help="OpenVM project root containing `host/` and `guest/`.",
    )
    ap.add_argument(
        "--out-md",
        type=Path,
        default=None,
        help="Output markdown path (default: <project-root>/micro_ops.md).",
    )
    args = ap.parse_args()

    project_root: Path = args.project_root
    out_md: Path = args.out_md or (project_root / "micro_ops.md")

    delta_rows, chip_rows, interactions, run_info = run_openvm_and_collect(project_root)
    out_md.write_text(render_markdown(delta_rows, chip_rows, interactions, run_info=run_info))
    print(f"wrote {out_md}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
