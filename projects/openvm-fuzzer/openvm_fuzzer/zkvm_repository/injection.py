import logging
from pathlib import Path

from openvm_fuzzer.zkvm_repository.fuzzer_utils_crate import create_fuzzer_utils_crate
from openvm_fuzzer.zkvm_repository.injection_sources import (
    openvm_crates_vm_src_arch_segment_rs,
    openvm_extensions_rv32im_circuit_src_auipc_core_rs,
    openvm_extensions_rv32im_circuit_src_base_alu_core_rs,
    openvm_extensions_rv32im_circuit_src_divrem_core_rs,
    openvm_extensions_rv32im_circuit_src_load_sign_extend_core_rs,
    openvm_extensions_rv32im_circuit_src_loadstore_core_rs,
)
from zkvm_fuzzer_utils.file import overwrite_file, prepend_file, replace_in_file

logger = logging.getLogger("fuzzer")


def openvm_fault_injection(openvm_install_path: Path, commit_or_branch: str):

    # create a fuzzer_utils crate at zkvm root
    create_fuzzer_utils_crate(openvm_install_path)

    fuzzer_utils_crate_path = openvm_install_path / "crates" / "fuzzer_utils"

    # add fuzzer utils to root Cargo.toml
    replace_in_file(
        openvm_install_path / "Cargo.toml",
        [
            (r"members = \[", f'members = [\n    "{fuzzer_utils_crate_path}",'),
            (
                r"\[workspace\.dependencies\]",
                f"""[workspace.dependencies]
    fuzzer_utils = {{ path = "{fuzzer_utils_crate_path}" }}""",
            ),
        ],
    )

    # recursively remove asserts in the whole vm folder
    working_dirs = [openvm_install_path / "crates" / "vm"]
    while len(working_dirs) > 0:
        working_dir = working_dirs.pop()
        for elem in working_dir.iterdir():
            if elem.is_dir():
                working_dirs.append(elem)
            if elem.is_file() and elem.name == "Cargo.toml":
                replace_in_file(
                    elem,
                    [
                        (
                            r"\[dependencies\]",
                            "[dependencies]\nfuzzer_utils.workspace = true",
                        )
                    ],
                )
            if elem.is_file() and elem.suffix == ".rs":
                # NOTE: the order matters here because the replacement is done iteratively
                is_updated = replace_in_file(
                    elem,
                    [
                        (r"\bassert!", "fuzzer_utils::fuzzer_assert!"),
                        (r"\bassert_eq!", "fuzzer_utils::fuzzer_assert_eq!"),
                        (r"\bassert_ne!", "fuzzer_utils::fuzzer_assert_ne!"),
                        (r"\bdebug_assert!", "fuzzer_utils::fuzzer_assert!"),
                        (r"\bdebug_assert_eq!", "fuzzer_utils::fuzzer_assert_eq!"),
                    ],
                )
                if is_updated:
                    prepend_file(elem, "#[allow(unused_imports)]\nuse fuzzer_utils;\n")

    # fault inject segment rs
    overwrite_file(
        openvm_install_path / "crates" / "vm" / "src" / "arch" / "segment.rs",
        openvm_crates_vm_src_arch_segment_rs(commit_or_branch),
    )

    # add fuzzer utils to extensions/rv32im/circuit/Cargo.toml
    replace_in_file(
        openvm_install_path / "extensions" / "rv32im" / "circuit" / "Cargo.toml",
        [
            (
                r"\[dependencies\]",
                "[dependencies]\nfuzzer_utils.workspace = true",
            )
        ],
    )

    # overwrite base_alu/core.rs
    # NOTE: this is done before all assertions are replaced! This is intentional!
    overwrite_file(
        openvm_install_path / "extensions" / "rv32im" / "circuit" / "src" / "base_alu" / "core.rs",
        openvm_extensions_rv32im_circuit_src_base_alu_core_rs(commit_or_branch),
    )

    # overwrite auipc/core.rs
    # NOTE: this is done before all assertions are replaced! This is intentional!
    overwrite_file(
        openvm_install_path / "extensions" / "rv32im" / "circuit" / "src" / "auipc" / "core.rs",
        openvm_extensions_rv32im_circuit_src_auipc_core_rs(commit_or_branch),
    )

    # overwrite loadstore/core.rs
    # NOTE: this is done before all assertions are replaced! This is intentional!
    overwrite_file(
        openvm_install_path / "extensions" / "rv32im" / "circuit" / "src" / "loadstore" / "core.rs",
        openvm_extensions_rv32im_circuit_src_loadstore_core_rs(commit_or_branch),
    )

    # overwrite divrem/core.rs
    # NOTE: this is done before all assertions are replaced! This is intentional!
    overwrite_file(
        openvm_install_path / "extensions" / "rv32im" / "circuit" / "src" / "divrem" / "core.rs",
        openvm_extensions_rv32im_circuit_src_divrem_core_rs(commit_or_branch),
    )

    # overwrite load_sign_extend/core.rs
    # NOTE: this is done before all assertions are replaced! This is intentional!
    overwrite_file(
        openvm_install_path
        / "extensions"
        / "rv32im"
        / "circuit"
        / "src"
        / "load_sign_extend"
        / "core.rs",
        openvm_extensions_rv32im_circuit_src_load_sign_extend_core_rs(commit_or_branch),
    )

    # recursively remove asserts in the whole rv32im circuit folder
    working_dirs = [openvm_install_path / "extensions" / "rv32im" / "circuit" / "src"]
    while len(working_dirs) > 0:
        working_dir = working_dirs.pop()
        for elem in working_dir.iterdir():
            if elem.is_dir():
                working_dirs.append(elem)
            if elem.is_file() and elem.suffix == ".rs":
                # NOTE: the order matters here because the replacement is done iteratively
                is_updated = replace_in_file(
                    elem,
                    [
                        (r"\bassert!", "fuzzer_utils::fuzzer_assert!"),
                        (r"\bassert_eq!", "fuzzer_utils::fuzzer_assert_eq!"),
                        (r"\bdebug_assert!", "fuzzer_utils::fuzzer_assert!"),
                        (r"\bdebug_assert_eq!", "fuzzer_utils::fuzzer_assert_eq!"),
                    ],
                )
                if is_updated:
                    prepend_file(elem, "#[allow(unused_imports)]\nuse fuzzer_utils;\n")
