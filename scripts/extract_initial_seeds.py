

import json
from pathlib import Path

from beak_core.fuzzing_seeds import parse_riscv_tests


def _main():
    import argparse
    parser = argparse.ArgumentParser(
        description="Extract initial seeds from a RISC-V test dump file"
    )
    parser.add_argument("-i", "--input", required=True, help="Path to the directory containing the RISC-V test dump files")
    parser.add_argument("-o", "--output", required=True, help="Path to the directory to save the all seeds")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose mode")
    args = parser.parse_args()
    dump_file_directory = Path(args.input)
    output_file = Path(args.output)
    all_seeds = []
    for dump_file in dump_file_directory.glob("*.dump"):
        seeds = parse_riscv_tests(dump_file, verbose=args.verbose)
        all_seeds.extend(seeds)
    with open(output_file, "w") as f:
        for seed in all_seeds:
            f.write(json.dumps(seed.to_dict()) + "\n")


if __name__ == "__main__":
    _main()