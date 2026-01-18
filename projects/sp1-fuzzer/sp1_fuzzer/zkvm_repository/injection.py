import logging
from pathlib import Path

from sp1_fuzzer.zkvm_repository.fuzzer_utils_crate import create_fuzzer_utils_crate
from sp1_fuzzer.zkvm_repository.injection_source import (
    sp1_crates_core_executor_src_executor_rs,
)
from zkvm_fuzzer_utils.file import overwrite_file, prepend_file, replace_in_file

logger = logging.getLogger("fuzzer")


class SP1ManagerException(Exception):
    pass


def sp1_fault_injection(sp1_install_path: Path, commit_or_branch: str):

    # add fuzzer utils crate
    create_fuzzer_utils_crate(sp1_install_path)

    replace_in_file(
        sp1_install_path / "Cargo.toml",
        [
            (
                r"""\[workspace\]
members = \[""",
                """[workspace]
members = [
  "crates/fuzzer_utils",""",
            ),
            (
                r"\[workspace.dependencies\]",
                '[workspace.dependencies]\nfuzzer_utils = { path = "crates/fuzzer_utils" }',
            ),
        ],
    )

    # inject executor behavior
    overwrite_file(
        sp1_install_path / "crates" / "core" / "executor" / "src" / "executor.rs",
        sp1_crates_core_executor_src_executor_rs(commit_or_branch),
    )

    # prepend the fuzzer util to registers.rs
    prepend_file(
        sp1_install_path / "crates" / "core" / "executor" / "src" / "register.rs",
        "#[allow(unused_imports)]\nuse fuzzer_utils;\n",
    )

    # manipulate register to avoid invalid register panics
    replace_in_file(
        sp1_install_path / "crates" / "core" / "executor" / "src" / "register.rs",
        [
            (
                r"""pub fn from_u8\(value: u8\) -> Self \{
        match value \{""",
                """pub fn from_u8(value: u8) -> Self {
        let value = if value >= 32 && fuzzer_utils::is_injection() {
            println!("WARNING: Hotfix for register access out-of-bounds!");
            value % 32_u8
        } else {
            value
        };
        match value {""",
            )
        ],
    )

    # prepend the fuzzer util to memory.rs
    prepend_file(
        sp1_install_path / "crates" / "core" / "executor" / "src" / "memory.rs",
        "#[allow(unused_imports)]\nuse fuzzer_utils;\n",
    )

    # modify memory to fix addr out of bounds
    replace_in_file(
        sp1_install_path / "crates" / "core" / "executor" / "src" / "memory.rs",
        [
            (
                r"""pub fn get\(&self, addr: u32\) -> Option<&V> \{
        let \(upper, lower\) = Self::indices\(addr\);
        let index = self.index\[upper\];
        if index == NO_PAGE \{
            None
        \} else \{
            self\.page_table\[index as usize\]\.0\[lower\]\.as_ref\(\)
        \}
    \}

    /// Get a mutable reference to the memory value at the given address, if it exists\.
    pub fn get_mut\(&mut self, addr: u32\) -> Option<&mut V> \{
        let \(upper, lower\) = Self::indices\(addr\);
        let index = self\.index\[upper\];
        if index == NO_PAGE \{
            None
        \} else \{
            self\.page_table\[index as usize\]\.0\[lower\]\.as_mut\(\)
        \}
    \}""",
                """pub fn get(&self, addr: u32) -> Option<&V> {
        let (upper, lower) = Self::indices(addr);
        if upper >= self.index.len() && fuzzer_utils::is_injection() {
            println!("WARNING: Hotfix memory access out-of-bounds");
            return None;
        }
        let index = self.index[upper];
        if index == NO_PAGE {
            None
        } else {
            self.page_table[index as usize].0[lower].as_ref()
        }
    }

    /// Get a mutable reference to the memory value at the given address, if it exists.
    pub fn get_mut(&mut self, addr: u32) -> Option<&mut V> {
        let (upper, lower) = Self::indices(addr);
        if upper >= self.index.len() && fuzzer_utils::is_injection() {
            println!("WARNING: Hotfix memory access out-of-bounds");
            return None;
        }
        let index = self.index[upper];
        if index == NO_PAGE {
            None
        } else {
            self.page_table[index as usize].0[lower].as_mut()
        }
    }""",
            )
        ],
    )

    # skipped elements are ones where the replacement makes errors
    excluded_elems = [
        (
            sp1_install_path
            / "crates"
            / "core"
            / "machine"
            / "src"
            / "operations"
            / "field"
            / "field_inner_product.rs"
        ).absolute()
    ]

    # add fuzzer utils to toml and replace asserts
    working_dirs = [sp1_install_path / "crates" / "core"]
    while len(working_dirs) > 0:
        working_dir = working_dirs.pop()
        for elem in working_dir.iterdir():
            elem = elem.absolute()
            if elem in excluded_elems:
                continue  # skip
            if elem.is_dir():
                working_dirs.append(elem)
            if elem.is_file() and elem.name == "Cargo.toml":
                replace_in_file(
                    elem,
                    [
                        (
                            r"\[dependencies\]",
                            """[dependencies]\nfuzzer_utils.workspace = true""",
                        )
                    ],
                )
            if elem.is_file() and elem.suffix == ".rs":
                is_updated = replace_in_file(
                    elem,
                    [
                        (r"\bassert_eq!", "fuzzer_utils::fuzzer_assert_eq!"),
                        (r"\bassert!", "fuzzer_utils::fuzzer_assert!"),
                    ],
                )
                if is_updated and elem.name != "executor.rs":
                    prepend_file(
                        elem,
                        "#[allow(unused_imports)]\nuse fuzzer_utils;\n",
                    )
