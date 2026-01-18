import io
import os
from pathlib import Path

import matplotlib
from matplotlib import rcParams

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402, needed because of matplotlib
import pandas as pd  # noqa: E402, needed because of matplotlib

# set export settings
rcParams["pdf.fonttype"] = 42  # TrueType
rcParams["font.family"] = "Times New Roman"  # or 'DejaVu Sans', etc.


def load_data_as_series(csv_file: Path) -> pd.Series:
    df = pd.read_csv(csv_file, quotechar="|")
    df = df.drop(columns=["fuzzer_id", "run_id", "iteration_id"])
    totals = df.sum().sort_index()
    return totals


def generate_bar_plot(instruction_totals: pd.Series, output_pdf: Path):
    instruction_totals = instruction_totals.sort_values(ascending=False)
    instruction_names = instruction_totals.index.tolist()
    is_zero = instruction_totals == 0
    display_labels = {
        instr: f"{instr} (*)" if is_zero.iloc[i] else instr
        for i, instr in enumerate(instruction_names)
    }
    instruction_totals.rename(display_labels, inplace=True)

    plt.figure(figsize=(12, 6))
    instruction_totals.plot(kind="bar", color="#2E86AB", logy=True)

    plt.xlabel("Instructions", fontsize=16)
    plt.ylabel("Count", fontsize=16)
    plt.yscale("log")
    plt.xticks(rotation=90)

    plt.tight_layout()
    plt.savefig(output_pdf, format="pdf")


def generate_RQ4(csv_lookup: dict[str, dict[str, Path]], output_dir: Path):
    """
    Expects the lookup in the form zkvms -> setting -> csv file, where
        - zkvms: jolt, nexus, openvm, pico, risc0, sp1
        - setting: default, no-inline
    While zkvms are optional, settings must contain both.
    The parameter output_dir should already be the target dir (e.g. 'RQ4')
    The csv files are expected to be the `summary.csv` containing instruction
    counts.
    """
    os.makedirs(output_dir, exist_ok=True)

    increase_table: dict[str, float] = {}

    for zkvm_name in csv_lookup:
        csv_default = csv_lookup[zkvm_name]["default"]
        csv_no_inline = csv_lookup[zkvm_name]["no-inline"]

        default_series = load_data_as_series(csv_default)
        no_inline_series = load_data_as_series(csv_no_inline)

        assert (default_series.index == no_inline_series.index).all(), "mis-matching indices"

        # remove all values where both entries are 0
        mask = ~((default_series == 0) & (no_inline_series == 0))
        default_series = default_series[mask]
        no_inline_series = no_inline_series[mask]

        # make type checker happy and double check the type
        assert isinstance(default_series, pd.Series), "unexpected type"
        assert isinstance(no_inline_series, pd.Series), "unexpected type"

        default_covered: int = (default_series != 0).sum()
        no_inline_covered: int = (no_inline_series != 0).sum()
        covered_increase = ((default_covered / no_inline_covered) - 1) * 100

        increase_table[zkvm_name] = covered_increase

        df = pd.DataFrame(
            {
                "default": default_series,
                "no-inline": no_inline_series,
            }
        )

        buffer = io.StringIO()
        buffer.write("========================\n")
        buffer.write(f"  {zkvm_name} \n")
        buffer.write("========================\n\n")
        buffer.write(f"increase: {covered_increase}\n\n")
        buffer.write("------------------------\n\n")
        buffer.write(df.to_string())
        buffer.write("\n\n")
        buffer.write("========================\n")

        info_txt = output_dir / f"RQ4{zkvm_name}-normal-instr-raw.txt"
        info_txt.write_text(buffer.getvalue())

        default_pdf = output_dir / f"RQ4{zkvm_name}-default-normal-instr.pdf"
        generate_bar_plot(default_series, default_pdf)

        no_inline_pdf = output_dir / f"RQ4{zkvm_name}-no-inline-normal-instr.pdf"
        generate_bar_plot(no_inline_series, no_inline_pdf)

    # print the increase table for all VMs combined
    headers = list(increase_table.keys())
    values = [f"{v:.1f}%" for v in increase_table.values()]
    widths = [max(len(h), len(v)) for h, v in zip(headers, values)]
    buffer = io.StringIO()
    buffer.write("Instruction Coverage Increase after inline-assembly:\n\n")
    header_line = "   ".join(f"{h:<{w}}" for h, w in zip(headers, widths))
    buffer.write(f"{header_line}\n")
    value_line = "   ".join(f"{v:<{w}}" for v, w in zip(values, widths))
    buffer.write(f"{value_line}\n")

    increase_txt = output_dir / "RQ4-instruction-increase-table.txt"
    increase_txt.write_text(buffer.getvalue())
