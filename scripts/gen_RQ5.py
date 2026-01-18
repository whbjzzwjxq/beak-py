import os
from pathlib import Path

import matplotlib
import numpy as np
from matplotlib import rcParams

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402, needed because of matplotlib
import pandas as pd  # noqa: E402, needed because of matplotlib

# set export settings
rcParams["pdf.fonttype"] = 42  # TrueType
rcParams["font.family"] = "Times New Roman"  # or 'DejaVu Sans', etc.


def load_data_as_series(csv_file: Path) -> pd.Series:
    df = pd.read_csv(csv_file, quotechar="|")
    counts = df["fault_original_instruction"].value_counts().sort_values(ascending=False)
    return counts


def generate_RQ5(csv_lookup: dict[str, dict[str, Path]], output_dir: Path):
    """
    Expects the lookup in the form zkvms -> setting -> csv file, where
        - zkvms: jolt, nexus, openvm, pico, risc0, sp1
        - setting: default, no-schedular
    While zkvms are optional, settings must contain both.
    The parameter output_dir should already be the target dir (e.g. 'RQ4').
    The csv files are expected to be the `injection.csv` containing instruction
    counts for injections.
    """
    os.makedirs(output_dir, exist_ok=True)

    data: dict[str, dict[str, pd.Series]] = {}

    VMs = []
    for zkvm_name in csv_lookup:
        csv_default = csv_lookup[zkvm_name]["default"]
        csv_no_schedular = csv_lookup[zkvm_name]["no-schedular"]

        default_series = load_data_as_series(csv_default)
        no_schedular_series = load_data_as_series(csv_no_schedular)

        # NOTE: the order here has to match the configs lables !
        data[zkvm_name] = {
            "default": default_series,
            "no-schedular": no_schedular_series,
        }
        VMs.append(zkvm_name)

    VMs = sorted(VMs)
    configs = ["no-schedular", "default"]

    # Prepare positions for boxplots
    positions = []
    all_data = []
    tick_labels = []
    config_labels = []

    x = 1  # starting x position
    for vm in VMs:
        for config in configs:
            config_series = data[vm][config]
            all_data.append(config_series.values)  # convert Series to ndarray
            positions.append(x)
            tick_labels.append(config)
            config_labels.append(f"{vm} with {config}")
            x += 1.2
        x += 1.5  # extra space between VMs

    # Create the boxplot
    plt.figure(figsize=(10, 5))
    plt.boxplot(all_data, positions=positions, widths=0.7)

    for pos, config_values in zip(positions, all_data):
        # Add small horizontal jitter so points don't overlap the box
        np.random.seed(0xC00FFEE)
        jitter = np.random.uniform(-0.1, 0.1, size=len(config_values))
        offset = -0.6 + jitter  # offset to the boxplot
        plt.scatter(
            np.full(len(config_values), pos) + offset, config_values, color="black", alpha=0.5, s=2
        )

    # Set x-ticks in the middle of each VM group
    vm_positions = []
    for i in range(0, len(positions), 2):
        vm_positions.append((positions[i] + positions[i + 1]) / 2)

    plt.xlabel("zkVMs", fontsize=17)
    plt.ylabel("Instruction frequency", fontsize=17)
    plt.xticks(fontsize=14)
    plt.yticks(fontsize=14)

    # plt.xticks(positions, config_labels, rotation=45)
    VMs_lable = [
        {
            "jolt": "Jolt",
            "nexus": "Nexus",
            "openvm": "OpenVM",
            "pico": "Pico",
            "risc0": "RISCZero",
            "sp1": "SP1",
        }[e]
        for e in VMs
    ]
    plt.xticks(vm_positions, VMs_lable)  # rotation=90)

    plt.tight_layout()

    output_pdf = output_dir / "RQ5-all-boxplot.pdf"
    plt.savefig(output_pdf, format="pdf")
