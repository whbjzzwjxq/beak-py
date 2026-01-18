import os
import shutil
from datetime import datetime
from pathlib import Path


def extract_csv(source: Path, target: Path):
    now = datetime.now()
    date_string = now.strftime("%Y-%m-%d_%H-%M-%S")
    for zkvm_dir in source.iterdir():
        if zkvm_dir.is_dir():
            zkvm_name = zkvm_dir.name
            for action_dir in zkvm_dir.iterdir():
                if action_dir.is_dir():
                    action_name = action_dir.name
                    commit, action, *options_list = action_name.split("-")
                    options = "-".join(options_list)
                    workspace = action_dir / "workspace"
                    csv_files: list[Path] = []
                    if workspace.is_dir():
                        for csv_file in workspace.iterdir():
                            if csv_file.is_file() and csv_file.suffix == ".csv":
                                csv_files.append(csv_file)
                    if len(csv_files) != 0:  # at least 1 csv available
                        specific_target = (
                            target / date_string / zkvm_name / action / commit / f"{options}"
                        )
                        os.makedirs(specific_target, exist_ok=True)
                        for csv_file in csv_files:
                            dest_csv = specific_target / csv_file.name
                            shutil.copy2(csv_file, dest_csv)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Helps to extract the CSV files from Arguzz output folder"
    )
    parser.add_argument("out_dir", help="Output folder to scrap for CSV files.")
    parser.add_argument("target_dir", help="Target folder to copy the CSV files.")
    args = parser.parse_args()
    out_dir = Path(args.out_dir)
    target_dir = Path(args.target_dir)
    if not out_dir.is_dir():
        parser.error(f"unable to find output dir {out_dir}")
    extract_csv(out_dir, target_dir)
