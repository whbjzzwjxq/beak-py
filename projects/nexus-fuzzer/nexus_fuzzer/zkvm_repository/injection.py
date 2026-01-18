import logging
from pathlib import Path

from nexus_fuzzer.zkvm_repository.fuzzer_utils_crate import create_fuzzer_utils_crate
from nexus_fuzzer.zkvm_repository.injection_source import (
    nexus_vm_src_emulator_executor_rs,
)
from zkvm_fuzzer_utils.file import (
    overwrite_file,
    prepend_file,
    replace_in_file,
)

logger = logging.getLogger("fuzzer")


def nexus_fault_injection(nexus_install_path: Path, commit_or_branch: str):

    # create the fuzzer util crate
    create_fuzzer_utils_crate(nexus_install_path)

    # add fuzzer util crate to workspace in ./Cargo.toml
    replace_in_file(
        nexus_install_path / "Cargo.toml",
        [
            (
                r"members = \[",
                """members = [
    "fuzzer_utils",""",
            )
        ],
    )

    # add rand dependency to vm/Cargo.toml
    replace_in_file(
        nexus_install_path / "vm" / "Cargo.toml",
        [
            (
                r"\[dependencies\]",
                """[dependencies]
rand = "0.9.1"
fuzzer_utils = {path = "../fuzzer_utils"}
""",
            )
        ],
    )

    # injection of vm/src/emulator/executor.rs
    overwrite_file(
        nexus_install_path / "vm" / "src" / "emulator" / "executor.rs",
        nexus_vm_src_emulator_executor_rs(commit_or_branch),
    )

    # add fuzzer util crate to prover/Cargo.toml
    replace_in_file(
        nexus_install_path / "prover" / "Cargo.toml",
        [
            (
                r"\[dependencies\]",
                """[dependencies]
fuzzer_utils = {path = "../fuzzer_utils"}""",
            )
        ],
    )

    # replace assertions with custom assertions for prover
    excluded_prover_dirs_and_files = ["extensions", "column.rs"]
    working_dirs = [nexus_install_path / "prover" / "src" / ""]
    while len(working_dirs) > 0:
        elem = working_dirs.pop()
        for elem in elem.iterdir():
            if elem.name in excluded_prover_dirs_and_files:
                continue  # skip
            if elem.is_dir():
                working_dirs.append(elem)
            if elem.is_file() and elem.suffix == ".rs":
                is_updated = replace_in_file(
                    elem,
                    [
                        (r"\bassert_eq!", "fuzzer_utils::fuzzer_assert_eq!"),
                        (r"\bassert!", "fuzzer_utils::fuzzer_assert!"),
                    ],
                )
                if is_updated:
                    prepend_file(elem, "#[allow(unused_imports)]\nuse fuzzer_utils;\n")
