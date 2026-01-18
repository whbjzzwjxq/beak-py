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


def generate_summary_scatter_plot(input_csv: Path, output_pdf: Path):
    os.makedirs(output_pdf.parent, exist_ok=True)

    df = pd.read_csv(input_csv, quotechar="|")
    df_clean = df[["execution_time", "circuits_accumulated_size"]].copy()
    df_clean["execution_time"] = pd.to_numeric(df_clean["execution_time"], errors="coerce")
    df_clean["circuits_accumulated_size"] = pd.to_numeric(
        df_clean["circuits_accumulated_size"], errors="coerce"
    )
    plt.figure(figsize=(10, 6))
    plt.scatter(
        df_clean["circuits_accumulated_size"],
        df_clean["execution_time"],
        marker=".",
        s=10,
        alpha=0.7,
        color="black",
    )
    plt.xlabel("Circuit nodes", fontsize=16)
    plt.ylabel("Execution time in seconds", fontsize=16)
    # plt.title("Scatter Plot of Program Size vs. Execution Time")
    plt.grid(True)
    plt.tight_layout()
    plt.savefig(output_pdf)
    plt.savefig(output_pdf, format="pdf")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Create a scatter plot from an fault injection CSV file."
    )
    parser.add_argument("csv_file", help="Path to the CSV file containing instruction data.")
    parser.add_argument(
        "-o",
        "--output",
        default="output.png",
        help="Filename for the output image (output: bar_plot.png)",
    )
    args = parser.parse_args()

    generate_summary_scatter_plot(args.csv_file, Path(args.output))
