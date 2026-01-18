import argparse
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


def generate_summary_bar_plot(csv_file: Path, output_pdf: Path, logy=False):
    os.makedirs(output_pdf.parent, exist_ok=True)

    df = pd.read_csv(csv_file, quotechar="|")
    df = df.drop(columns=["fuzzer_id", "run_id", "iteration_id"])
    instruction_totals = df.sum().sort_values(ascending=False)
    instructions = instruction_totals.index.tolist()

    is_zero = instruction_totals == 0
    display_labels = {
        instr: f"{instr} (*)" if is_zero.iloc[i] else instr for i, instr in enumerate(instructions)
    }

    instruction_totals.rename(display_labels, inplace=True)

    plt.figure(figsize=(12, 6))
    # instruction_totals.plot(kind="bar", color="gray", logy=logy)
    instruction_totals.plot(kind="bar", color="#2E86AB", logy=logy)
    # instruction_totals.plot(kind="bar", color="skyblue", logy=logy)

    # plt.title("Instruction Occurrences (Execution)")
    plt.xlabel("Instructions", fontsize=16)
    plt.ylabel("Count", fontsize=16)
    plt.yscale("log")
    plt.xticks(rotation=90)

    plt.tight_layout()
    plt.savefig(output_pdf, format="pdf")


def generate_injection_bar_plot(csv_file: Path, output_pdf: Path, logy=False):
    os.makedirs(output_pdf.parent, exist_ok=True)

    df = pd.read_csv(csv_file, quotechar="|")
    instruction_counts = (
        df["fault_original_instruction"].value_counts().sort_values(ascending=False)
    )
    plt.figure(figsize=(12, 6))
    # instruction_counts.plot(kind="bar", color="gray", logy=logy)
    instruction_counts.plot(kind="bar", color="#2E86AB", logy=logy)
    # instruction_counts.plot(kind="bar", color="skyblue", logy=logy)

    # plt.title("Instruction Occurrences (Injection)")
    plt.xlabel("Instructions", fontsize=16)
    plt.ylabel("Count", fontsize=16)
    plt.xticks(rotation=90)

    plt.tight_layout()
    plt.savefig(output_pdf, format="pdf")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Create a bar plot from an fault injection CSV file."
    )
    parser.add_argument("csv_file", help="Path to the CSV file containing instruction data.")
    parser.add_argument(
        "--type",
        help="Specifies the type of the input csv data",
        choices=["summary", "injections"],
        required=True,
    )
    parser.add_argument(
        "-o",
        "--output",
        default="output.png",
        help="Filename for the output image (output: bar_plot.png)",
    )
    parser.add_argument("--logy", action="store_true", help="Uses a logarithmic scale for y")
    args = parser.parse_args()

    if args.type == "summary":
        generate_summary_bar_plot(Path(args.csv_file), Path(args.output), args.logy)

    if args.type == "injections":
        generate_injection_bar_plot(Path(args.csv_file), Path(args.output), args.logy)
