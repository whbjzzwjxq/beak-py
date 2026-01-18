import os
from io import StringIO
from pathlib import Path
from typing import List

import matplotlib
from matplotlib import rcParams

matplotlib.use("Agg")

import matplotlib.pyplot as plt  # noqa: E402, needed because of matplotlib
import pandas as pd  # noqa: E402, needed because of matplotlib
from matplotlib.lines import Line2D  # noqa: E402, needed because of matplotlib

# set export settings
rcParams["pdf.fonttype"] = 42  # TrueType
rcParams["font.family"] = "Times New Roman"  # or 'DejaVu Sans', etc.


def generate_pie_charts(csv_path: Path, output_pdf: Path) -> None:
    os.makedirs(output_pdf.parent, exist_ok=True)
    output_txt = output_pdf.parent / (output_pdf.name + ".txt")

    df = pd.read_csv(csv_path, quotechar="|")

    categories: List[str] = [
        "timeout",
        "correct_output & exitcode=0",
        "correct_output & exitcode≠0",
        "incorrect_output & exitcode=0",
        "incorrect_output & exitcode≠0",
    ]

    def categorize(row: pd.Series) -> str:
        is_timeout = str(row["execution_is_timeout"]).lower() == "true"
        is_correct_output = str(row["execution_is_correct_output"]).lower() == "true"
        exitcode = int(row["execution_exitcode"])
        if is_timeout:
            return "timeout"
        if is_correct_output:
            return "correct_output & exitcode=0" if exitcode == 0 else "correct_output & exitcode≠0"
        return "incorrect_output & exitcode=0" if exitcode == 0 else "incorrect_output & exitcode≠0"

    df["category"] = df.apply(categorize, axis=1)

    fault_kinds = df["fault_injection_kind"].dropna().unique()
    n = len(fault_kinds)
    cols = min(3, n)
    rows = (n + cols - 1) // cols

    # Use tab10 discrete colors for categories
    cmap = plt.get_cmap("tab10")
    colors = [cmap(i) for i in range(len(categories))]

    fig, axs = plt.subplots(rows, cols, figsize=(5 * cols, 5 * rows), squeeze=False)
    axs_flat = axs.flatten()

    for ax in axs_flat:
        ax.axis("off")

    buffer_for_txt = StringIO()

    for ax, kind in zip(axs_flat, fault_kinds):
        group = df[df["fault_injection_kind"] == kind]
        category_series = pd.Series(group["category"])
        counts = category_series.value_counts().reindex(categories, fill_value=0)
        counts = counts[counts > 0]
        counts = pd.Series(counts)

        labels = counts.index.tolist()
        values = counts.values
        pie_colors = [colors[categories.index(str(cat))] for cat in labels]

        buffer_for_txt.write(f"== {kind} ==\n")
        total = sum(values)
        buffer_for_txt.write(f" - total injections: {total}\n")
        for category in categories:
            category_total = counts.get(category, 0)
            assert category_total is not None, "impossible to be 'None'"
            buffer_for_txt.write(
                f" - {category}: {category_total} | {(category_total / total * 100):.2f}%\n"
            )
        buffer_for_txt.write("===============\n")

        ax.pie(
            values,
            colors=pie_colors,
            autopct=lambda p: f"{p:.1f}%" if p > 0 else "",
            startangle=90,
            counterclock=False,
            wedgeprops={"edgecolor": "w"},
        )
        ax.set_title(f"Fault Injection: {kind}", fontsize=12)

    # Legend with category-color mapping
    handles = [
        Line2D([0], [0], marker="o", color="w", label=cat, markerfacecolor=colors[i], markersize=10)
        for i, cat in enumerate(categories)
    ]
    fig.legend(handles=handles, loc="center right", title="Categories")

    fig.tight_layout(rect=(0, 0, 0.85, 1))
    Path(output_pdf).parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output_pdf, dpi=300)
    plt.close(fig)

    output_txt.write_text(buffer_for_txt.getvalue())


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Generate pie charts from CSV.")
    parser.add_argument("csv_path", type=str, help="Input CSV file path.")
    parser.add_argument("output_pdf", type=str, help="Output PNG file path.")
    args = parser.parse_args()
    generate_pie_charts(Path(args.csv_path), Path(args.output_pdf))


if __name__ == "__main__":
    main()
