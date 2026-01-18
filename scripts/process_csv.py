from pathlib import Path

from gen_bar_plot import generate_injection_bar_plot, generate_summary_bar_plot
from gen_bug_refind_table import generate_bug_refind_table
from gen_error_statistic import generate_error_statistic
from gen_pie_plot import generate_pie_charts
from gen_RQ3 import generate_RQ3
from gen_RQ4 import generate_RQ4
from gen_RQ5 import generate_RQ5
from gen_size_time_scatter import generate_summary_scatter_plot

ZKVM_NAME_LIST = ["jolt", "nexus", "openvm", "pico", "risc0", "sp1"]
ACTION_LIST = ["explore", "refind", "check"]
CONFIG_LIST = ["default", "no-inline", "no-modification", "no-schedular"]

# maps a zkvm name to its first 7 character commit used for the
# explore experiments
ZKVM_TO_EXPLORE_COMMITS_TABLE = {
    "jolt": "1687134",
    "nexus": "8f4ba56",
    "openvm": "ca36de3",
    "pico": "dd5b7d1",
    "risc0": "ebd64e4",
    "sp1": "429e95e",
}

# maps the first 7 character of the "fix" commit to the bug id
FIX_COMMIT_TO_BUG_ID_TABLE: dict[str, int] = {
    # -- risc0 --
    "67f2d81": 1,  # Missing constraint in three-register instructions
    "31f6570": 2,  # Off-by-one error in cycle-counting logic
    # -- nexus --
    "62e3abc": 3,  # Unconstrained store operand in load-store instructions
    "54cebc7": 4,  # completeness MT Out-of-bounds panic due to memory size misestimation
    "c684c4e": 5,  # completeness MT Carry overflow in multiplication extension
    # -- JOLT --
    "85bf51d": 6,  # Unconstrained immediate operand in lui
    "20ac6eb": 7,  # Incorrect RAM size calculation
    "55b9830": 8,  # Out-of-bounds panic for high-address bytecode
    "0582b2a": 9,  # Dory-commitment failure for traces shorter than 256 cycles
    "0369981": 10,  # Sumcheck-verification failure for mulhsu
}

# maps the zkvms to their "fix" commits
ZKVM_TO_FIX_COMMITS = {
    "risc0": ["67f2d81", "31f6570"],
    "nexus": ["62e3abc", "54cebc7", "c684c4e"],
    "jolt": ["85bf51d", "20ac6eb", "55b9830", "0582b2a", "0369981"],
}


def process_explore(timestamp: str, zkvm_name: str, explore_dir: Path, out_dir: Path):
    assert explore_dir.name == "explore", f"probably invalid explore dir {explore_dir}"
    assert explore_dir.is_dir(), f"{explore_dir} is not a directory"

    for commit_dir in explore_dir.iterdir():
        if not commit_dir.is_dir():
            raise ValueError(f"unexpected non directory {commit_dir}!")
        commit = commit_dir.name

        # == config == #

        for config_dir in commit_dir.iterdir():
            if not config_dir.is_dir():
                raise ValueError(f"unexpected non directory {config_dir}!")

            config = config_dir.name
            if config not in CONFIG_LIST:
                raise ValueError(f"unexpected config '{config}'!")

            print(f"== EXPLORE PROCESSING: {timestamp} {zkvm_name} {config} {commit} ==")

            # == csv file == #

            # final output directory
            final_out_dir = out_dir / timestamp / zkvm_name / "explore" / commit / config
            visited_csv = set()

            for csv_file in config_dir.iterdir():
                if not csv_file.is_file():
                    raise ValueError(f"unexpected non file {csv_file}!")

                csv_file_name = csv_file.name
                visited_csv.add(csv_file_name)
                match csv_file_name:
                    case "build.csv":
                        pass
                    case "findings.csv":
                        pass
                    case "checked_findings.csv":
                        pass
                    case "injection.csv":
                        generate_summary_scatter_plot(
                            csv_file, final_out_dir / "size_time_injection.pdf"
                        )
                        generate_error_statistic(csv_file, final_out_dir / "fault_errors.txt")
                        generate_pie_charts(csv_file, final_out_dir / "categories.pdf")
                        generate_injection_bar_plot(csv_file, final_out_dir / "injection.pdf")
                    case "normal.csv":
                        generate_summary_scatter_plot(
                            csv_file, final_out_dir / "size_time_normal.pdf"
                        )
                        generate_error_statistic(csv_file, final_out_dir / "normal_errors.txt")
                    case "pipeline.csv":
                        pass
                    case "run.csv":
                        pass
                    case "summary.csv":
                        generate_summary_bar_plot(csv_file, final_out_dir / "summary.pdf")
                    case _:
                        raise ValueError(f"unexpected csv file '{csv_file_name}'!")

            missing_csv = {"injection.csv", "normal.csv", "summary.csv"} - visited_csv
            if len(missing_csv) > 0:
                print(f" - WARNING MISSING CSVs: {missing_csv}")
                print(" - Some processing steps were skipped ...")

            print(f"== LEAVING EXPLORE: {timestamp} {zkvm_name} {config} {commit} ==")


def process_check(timestamp: str, zkvm_name: str, check_dir: Path, out_dir: Path):
    assert check_dir.name == "check", f"probably invalid check dir {check_dir}"
    assert check_dir.is_dir(), f"{check_dir} is not a directory"

    for commit_dir in check_dir.iterdir():
        if not commit_dir.is_dir():
            raise ValueError(f"unexpected non directory {commit_dir}!")
        commit = commit_dir.name

        # == config == #

        for config_dir in commit_dir.iterdir():
            if not config_dir.is_dir():
                raise ValueError(f"unexpected non directory {config_dir}!")

            config = config_dir.name
            if config not in CONFIG_LIST:
                print(f"WARNING unknown configuration: {config}")
                continue
                # raise ValueError(f"unexpected config '{config}'!")

            print(f"== CHECK PROCESSING: {timestamp} {zkvm_name} {config} {commit} ==")

            # == csv file == #

            # final output directory
            final_out_dir = out_dir / timestamp / zkvm_name / "check" / commit / config
            visited_csv = set()

            for csv_file in config_dir.iterdir():
                if not csv_file.is_file():
                    raise ValueError(f"unexpected non file {csv_file}!")

                csv_file_name = csv_file.name
                visited_csv.add(csv_file_name)
                match csv_file_name:
                    case "build.csv":
                        pass
                    case "findings.csv":
                        pass
                    case "checked_findings.csv":
                        generate_bug_refind_table(csv_file, final_out_dir / "found-bugs.txt")
                    case "injection.csv":
                        pass
                    case "normal.csv":
                        pass
                    case "pipeline.csv":
                        pass
                    case "run.csv":
                        pass
                    case "summary.csv":
                        pass
                    case _:
                        raise ValueError(f"unexpected csv file '{csv_file_name}'!")

            missing_csv = {"checked_findings.csv"} - visited_csv
            if len(missing_csv) > 0:
                print(f" - WARNING MISSING CSVs: {missing_csv}")
                print(" - Some processing steps were skipped ...")

            print(f"== LEAVING CHECK: {timestamp} {zkvm_name} {config} {commit} ==")


def process_actions(
    timestamp: str,
    zkvm_name: str,
    zkvm_dir: Path,
    out_dir: Path,
    enable_explore: bool,
    enable_refind: bool,
):
    # == explore ==
    if enable_explore:
        explore_dir = zkvm_dir / "explore"
        if explore_dir.is_dir():
            process_explore(timestamp, zkvm_name, explore_dir, out_dir)
        else:
            print(f"WARNING: unable to find an 'explore' folder for {timestamp} / {zkvm_name}")
            print("Skipping 'explore' data processing...")

    # == refind / check ==
    if enable_refind:
        check_dir = zkvm_dir / "check"
        if check_dir.is_dir():
            process_check(timestamp, zkvm_name, check_dir, out_dir)
        else:
            print(f"WARNING: unable to find an 'check' folder for {timestamp} / {zkvm_name}")
            print("Skipping 'check' data processing...")


def process_csv(csv_dir: Path, out_dir: Path, enable_explore: bool, enable_refind: bool):
    assert csv_dir.is_dir(), f"not a directory {csv_dir}"

    # although it must not necessarily be a timestamp folder, in a normal usecase it is.
    timestamp = csv_dir.name

    rq3_csv_lookup: dict[int, dict[str, Path]] = {}
    rq4_csv_lookup: dict[str, dict[str, Path]] = {}
    rq5_csv_lookup: dict[str, dict[str, Path]] = {}

    for zkvm_name in ZKVM_NAME_LIST:
        zkvm_dir = csv_dir / zkvm_name
        if not zkvm_dir.is_dir():
            print(f"WARNING: unable to find data for {zkvm_name}!")
            print(f"         No directory at {zkvm_dir} ...")
            continue

        if enable_explore:
            explore_commit = ZKVM_TO_EXPLORE_COMMITS_TABLE[zkvm_name]

            # == start RQ4 data collection ==
            default_summary_csv = zkvm_dir / "explore" / explore_commit / "default" / "summary.csv"
            no_inline_summary_csv = (
                zkvm_dir / "explore" / explore_commit / "no-inline" / "summary.csv"
            )
            if default_summary_csv.is_file() and no_inline_summary_csv.is_file():
                rq4_csv_lookup[zkvm_name] = {}
                rq4_csv_lookup[zkvm_name]["default"] = default_summary_csv
                rq4_csv_lookup[zkvm_name]["no-inline"] = no_inline_summary_csv
            else:
                print(f"WARNING: unable to produce RQ4 for {zkvm_name}")
                print(f"            - {default_summary_csv}")
                print(f"            - {no_inline_summary_csv}")
            # == end RQ4 data collection ==

            # == start RQ5 data collection ==
            default_injection_csv = (
                zkvm_dir / "explore" / explore_commit / "default" / "injection.csv"
            )
            no_schedular_injection_csv = (
                zkvm_dir / "explore" / explore_commit / "no-schedular" / "injection.csv"
            )
            if default_injection_csv.is_file() and no_schedular_injection_csv.is_file():
                rq5_csv_lookup[zkvm_name] = {}
                rq5_csv_lookup[zkvm_name]["default"] = default_injection_csv
                rq5_csv_lookup[zkvm_name]["no-schedular"] = no_schedular_injection_csv
            else:
                print(f"WARNING: unable to produce RQ5 for {zkvm_name}")
                print(f"            - {default_injection_csv}")
                print(f"            - {no_schedular_injection_csv}")
            # == end RQ5 data collection ==

        if enable_refind:
            if zkvm_name in ZKVM_TO_FIX_COMMITS:
                for refind_commit in ZKVM_TO_FIX_COMMITS[zkvm_name]:
                    # == start RQ3 data collection ==
                    bug_id = FIX_COMMIT_TO_BUG_ID_TABLE[refind_commit]
                    rq3_csv_lookup[bug_id] = {}

                    default_checked_findings_csv = (
                        zkvm_dir / "check" / refind_commit / "default" / "checked_findings.csv"
                    )
                    no_modification_checked_findings_csv = (
                        zkvm_dir
                        / "check"
                        / refind_commit
                        / "no-modification"
                        / "checked_findings.csv"
                    )

                    if default_checked_findings_csv.is_file():
                        rq3_csv_lookup[bug_id]["default"] = default_checked_findings_csv

                    if no_modification_checked_findings_csv.is_file():
                        rq3_csv_lookup[bug_id][
                            "no-modification"
                        ] = no_modification_checked_findings_csv
                    # == end RQ3 data collection ==

        # legacy computation per zkvm
        process_actions(timestamp, zkvm_name, zkvm_dir, out_dir, False, enable_refind)
        process_actions(timestamp, zkvm_name, zkvm_dir, out_dir, enable_explore, enable_refind)

    if enable_explore:
        generate_RQ4(rq4_csv_lookup, out_dir / timestamp / "RQ4")

    if enable_explore:
        generate_RQ5(rq5_csv_lookup, out_dir / timestamp / "RQ5")

    if enable_refind:
        generate_RQ3(rq3_csv_lookup, out_dir / timestamp / "RQ3")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Helps to process data extracted using the extract_csv.py. "
        "If using the extraction script as recommended, make sure to provide the "
        "timestamp folder (e.g. '2025-08-20_20-19-50') inside of the extraction "
        "folder and not the outer folder or any other sub-folders!"
    )
    parser.add_argument(
        "--disable-explore", action="store_true", help="Disables explore processing"
    )
    parser.add_argument(
        "--disable-refind", action="store_true", help="Disables bug refinding processing"
    )

    parser.add_argument("csv_dir", help="Input folder containing the extracted CSV files.")
    parser.add_argument(
        "out_dir",
        help="Output folder for the processed data. The name of "
        "the provided csv_dir is always used as subfolder!",
    )

    args = parser.parse_args()
    csv_dir = Path(args.csv_dir)
    out_dir = Path(args.out_dir)
    enable_explore = not args.disable_explore
    enable_refind = not args.disable_refind

    if not csv_dir.is_dir():
        parser.error(f"unable to find csv directory {csv_dir}")

    process_csv(csv_dir, out_dir, enable_explore, enable_refind)
