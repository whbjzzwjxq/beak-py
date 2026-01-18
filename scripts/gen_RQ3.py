import os
import re
from io import StringIO
from pathlib import Path

import pandas as pd

TIMEOUT_IN_SECONDS: float = 60 * 60 * 24  # 24 hour cutoff


def to_hms(time_in_seconds: float) -> str:
    time_in_seconds = int(time_in_seconds)
    h = int(time_in_seconds // 3600)
    m = int((time_in_seconds % 3600) // 60)
    s = int(time_in_seconds % 60)
    return f"{h:02}h{m:02}m{s:02}s"


def fix_csv_to_be_readable(csv_file: Path) -> str:
    # NOTE: there was a small bug with the input flag emitting so we have to
    # make clean up some data if it contains the broken csv format before using it:
    #
    # EXAMPLE LINE:
    #
    #  ...,['--in0', '760724864', '--in1', '--trace'], ...
    #      ^^     ^^ ^         ^^ ^     ^^ ^       ^^
    #         These are the problematic characters
    #
    return re.sub(
        r"\[(.*?)\]",
        lambda m: " ".join(m.group(1).replace("'", "").split(",")),
        csv_file.read_text(),
    )


def load_and_prune_data(csv_file: Path) -> pd.DataFrame:
    csv_data = fix_csv_to_be_readable(csv_file)
    df = pd.read_csv(StringIO(csv_data), quotechar="|")
    df["runtime"] = df["runtime"].astype(float)

    df = df[df["fixed"]]
    df = df[df["runtime"] <= TIMEOUT_IN_SECONDS]
    assert isinstance(df, pd.DataFrame), "check if we still have a 'DataFrame'"

    df = df.drop(columns=["iteration_id", "timestamp", "circuit_seed", "input_flags"])  # , "fixed"]
    df = df.sort_values("runtime").drop_duplicates(subset="fuzzer_id", keep="first")
    df = df.rename(columns={"is_injection": "oracle"})
    df["oracle"] = df["oracle"].replace({True: "INJ", False: "MT"})

    # df["runtime_hms"] = df["runtime"].map(to_hms)

    return df


def generate_RQ3(csv_lookup: dict[int, dict[str, Path]], output_dir: Path):
    """
    Expects the lookup to contain bug ids from 1 to n, followed by a setting
    which is either "default" or "no-modification". This function reads the
    checked_findings.csv files and generates a reproducibility table.
    """
    os.makedirs(output_dir, exist_ok=True)

    buffer = StringIO()

    configs = ["default", "no-modification"]
    bug_ids = sorted(csv_lookup.keys())

    for config in configs:
        buffer.write(f"=== {config} ===\n\n")
        for bug_id in bug_ids:
            buffer.write(f"# Bug {bug_id}:\n")

            if config not in csv_lookup[bug_id]:
                buffer.write("nothing found...\n\n")
                continue

            data = load_and_prune_data(csv_lookup[bug_id][config])
            if data.empty:
                buffer.write("nothing found...\n\n")
                continue

            # buffer.write(data.to_string(index=False))

            oracles = " ".join(data["oracle"].to_list())
            unique_ids = data["fuzzer_id"].size

            run_min = to_hms(int(data["runtime"].min()))
            run_max = to_hms(int(data["runtime"].max()))
            run_med = to_hms(int(data["runtime"].median()))

            gen_min = int(data["run_id"].min())
            gen_max = int(data["run_id"].max())
            gen_med = int(data["run_id"].median())

            buffer.write(f" - unique-ids : {unique_ids}\n")
            buffer.write(f" - oracles    : {oracles}\n")
            buffer.write(f" - run stats  : {run_min} {run_max} {run_med}\n")
            buffer.write(f" - gen stats  : {gen_min} {gen_max} {gen_med}\n\n")

    bug_refinds = output_dir / "RQ3-bug-refind-tables.txt"
    bug_refinds.write_text(buffer.getvalue())
