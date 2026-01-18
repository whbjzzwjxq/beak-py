import logging
from pathlib import Path

from pico_fuzzer.zkvm_repository.fuzzer_utils_crate import create_fuzzer_utils_crate
from pico_fuzzer.zkvm_repository.injection_sources import (
    pico_vm_src_compiler_riscv_register_rs,
    pico_vm_src_emulator_riscv_emulator_instruction_rs,
)
from zkvm_fuzzer_utils.file import overwrite_file, prepend_file, replace_in_file

logger = logging.getLogger("fuzzer")


def pico_fault_injection(pico_install_path: Path, commit_or_branch: str):
    # create a fuzzer_utils crate at zkvm root
    create_fuzzer_utils_crate(pico_install_path)

    fuzzer_utils_crate_path = pico_install_path / "fuzzer_utils"

    # add fuzzer utils to root Cargo.toml
    replace_in_file(
        pico_install_path / "Cargo.toml",
        [
            (r"members = \[", 'members = [ "fuzzer_utils", '),
            (
                r"\[workspace\.dependencies\]",
                f"""[workspace.dependencies]
fuzzer_utils = {{ path = "{fuzzer_utils_crate_path}" }}""",
            ),
        ],
    )

    # add the fuzzer_utils to vm/Cargo.toml
    vm_cargo_toml = pico_install_path / "vm" / "Cargo.toml"
    replace_in_file(
        vm_cargo_toml,
        [
            (
                r"\[dependencies\]",
                """[dependencies]\nfuzzer_utils.workspace = true""",
            ),
        ],
    )

    # overwrite instruction emulator
    overwrite_file(
        pico_install_path / "vm" / "src" / "emulator" / "riscv" / "emulator" / "instruction.rs",
        pico_vm_src_emulator_riscv_emulator_instruction_rs(commit_or_branch),
    )

    # overwrite register reads
    riscv_register_rs = pico_install_path / "vm" / "src" / "compiler" / "riscv" / "register.rs"
    overwrite_file(
        riscv_register_rs,
        pico_vm_src_compiler_riscv_register_rs(commit_or_branch),
    )

    # replace asserts inside of lt chip (trace.rs)
    replace_targets = [
        pico_install_path / "vm" / "src" / "chips" / "chips" / "alu" / "lt" / "traces.rs"
    ]
    for elem in replace_targets:
        is_update = replace_in_file(
            elem,
            [
                (r"\bassert!", "fuzzer_utils::fuzzer_assert!"),
                (r"\bassert_eq!", "fuzzer_utils::fuzzer_assert_eq!"),
                (r"\bdebug_assert!", "fuzzer_utils::fuzzer_assert!"),
                (r"\bdebug_assert_eq!", "fuzzer_utils::fuzzer_assert_eq!"),
            ],
        )
        if is_update:
            prepend_file(elem, "#[allow(unused_imports)]\nuse fuzzer_utils;\n")
