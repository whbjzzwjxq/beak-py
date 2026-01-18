import os
import re
from io import StringIO
from pathlib import Path

import pandas as pd  # noqa: E402, needed because of matplotlib


def to_hms(time_in_seconds: float) -> str:
    time_in_seconds = int(time_in_seconds)
    h = int(time_in_seconds // 3600)
    m = int((time_in_seconds % 3600) // 60)
    s = int(time_in_seconds % 60)
    return f"{h:02}h{m:02}m{s:02}s"


def generate_bug_refind_table(csv_file: Path, out_file: Path):
    os.makedirs(out_file.parent, exist_ok=True)
    csv_data = csv_file.read_text()

    # NOTE: there was a small bug with the input flag emitting so we have to
    # make clean up some data if it contains the broken csv format before using it:
    #
    # EXAMPLE LINE:
    #
    #  ...,['--in0', '760724864', '--in1', '--trace'], ...
    #      ^^     ^^ ^         ^^ ^     ^^ ^       ^^
    #         These are the problematic characters
    #
    csv_data = re.sub(
        r"\[(.*?)\]", lambda m: " ".join(m.group(1).replace("'", "").split(",")), csv_data
    )
    df = pd.read_csv(StringIO(csv_data))

    df["runtime"] = df["runtime"].astype(float)
    df["runtime_hms"] = df["runtime"].map(to_hms)
    df = df.sort_values("runtime")
    df = df[df["fixed"]].copy()
    df = pd.DataFrame(df[["fuzzer_id", "run_id", "runtime", "runtime_hms", "is_injection"]])
    df = df.drop_duplicates(subset="fuzzer_id", keep="first")

    if df.empty:
        return  # nothing todo, no file created

    buffer = StringIO()

    buffer.write("== Raw Table ==\n")
    buffer.write(df.to_string())

    buffer.write("\n\n")

    buffer.write("== Runs ==\n")
    buffer.write("min, max, median\n")
    run_min = df["run_id"].min()
    run_max = df["run_id"].max()
    run_med = df["run_id"].median()
    buffer.write(f"{run_min}, {run_max}, {run_med}\n")

    buffer.write("\n\n")
    buffer.write("== Runtime ==\n")
    buffer.write("min, max, median\n")
    run_min = to_hms(int(df["runtime"].min()))
    run_max = to_hms(int(df["runtime"].max()))
    run_med = to_hms(int(df["runtime"].median()))
    buffer.write(f"{run_min}, {run_max}, {run_med}\n")

    out_file.write_text(buffer.getvalue())


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Creates a text file with a table in it about containing"
        " information on the bug refind experiments."
    )
    parser.add_argument("csv_file", help="Path to the CSV file containing checked data.")
    parser.add_argument("out_file", help="Path to the output text file to store the table.")
    args = parser.parse_args()

    csv_path = Path(args.csv_file)
    if not csv_path.is_file():
        print(f"ERROR: unable to find {csv_path}!")
        exit(1)
    elif csv_path.suffix != ".csv":
        print(f"ERROR: Expected file extension: '.csv', but got {csv_path.suffix}!")
        exit(1)
    out_path = Path(args.out_file)

    try:
        generate_bug_refind_table(csv_path, out_path)
    except Exception as e:
        print(f"ERROR: {e}")
        exit(1)
