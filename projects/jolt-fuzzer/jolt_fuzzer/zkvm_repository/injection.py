import logging
from pathlib import Path

from jolt_fuzzer.zkvm_repository.fuzzer_utils_crate import create_fuzzer_utils_crate
from jolt_fuzzer.zkvm_repository.injection_sources import (
    jolt_tracer_src_emulator_cpu_rs,
)
from zkvm_fuzzer_utils.file import (
    overwrite_file,
    prepend_file,
    replace_in_file,
)

logger = logging.getLogger("fuzzer")


def jolt_fault_injection(jolt_install_path: Path, commit_or_branch: str):

    # create a fuzzer_utils crate at zkvm root
    create_fuzzer_utils_crate(jolt_install_path)

    # update the ./Cargo.toml file with the fuzzer utils
    replace_in_file(
        jolt_install_path / "Cargo.toml",
        [
            (
                r"""\[workspace\]
members = \[""",
                """[workspace]
members = [
    "fuzzer_utils",""",
            ),
        ],
    )

    if commit_or_branch in [
        "0369981446471c2ed2c4a4d2f24d61205a2d0853",
        "d59219a0633d91dc5dbe19ade5f66f179c27c834",
        "0582b2aa4a33944506d75ce891db7cf090814ff6",
        "57ea518d6d9872fb221bf6ac97df1456a5494cf2",
        "20ac6eb526af383e7b597273990b5e4b783cc2a6",
        "70c77337426615b67191b301e9175e2bb093830d",
        "55b9830a3944dde55d33a55c42522b81dd49f87a",
        "42de0ca1f581dd212dda7ff44feee806556531d2",
        "85bf51da10efa9c679c35ffc1a8d45cc6cb1c788",
        "e9caa23565dbb13019afe61a2c95f51d1999e286",
    ]:
        # NOTE: no workspace dependencies present, so we create one
        replace_in_file(
            jolt_install_path / "Cargo.toml",
            [
                (
                    r"\[dependencies\]",
                    """[workspace.dependencies]
fuzzer_utils = { path = "./fuzzer_utils" }

[dependencies]
""",
                ),
            ],
        )

    else:
        # NOTE: workspace dependencies is present, so we add to it
        replace_in_file(
            jolt_install_path / "Cargo.toml",
            [
                (
                    r"\[workspace.dependencies\]",
                    """[workspace.dependencies]
fuzzer_utils = { path = "./fuzzer_utils" }""",
                ),
            ],
        )

    # update ./tracer/Cargo.toml with random and fuzzer util
    replace_in_file(
        jolt_install_path / "tracer" / "Cargo.toml",
        [
            (
                r"\[dependencies\]",
                "[dependencies]\nfuzzer_utils.workspace = true",
            ),
        ],
    )

    # add random dependency if not already present (we use 0.7.3 because latest version uses this)
    if "rand =" not in (jolt_install_path / "tracer" / "Cargo.toml").read_text():
        replace_in_file(
            jolt_install_path / "tracer" / "Cargo.toml",
            [
                (r"\[dependencies\]", '[dependencies]\nrand = "0.7.3"'),
            ],
        )

    # Overwrite the cpu.rs with the injected source
    overwrite_file(
        jolt_install_path / "tracer" / "src" / "emulator" / "cpu.rs",
        jolt_tracer_src_emulator_cpu_rs(commit_or_branch),
    )

    # NOTE: these files are excluded because we cannot simply resolve
    #       the None Option type "<T>" for the macro
    excluded_replacement_files = [
        (jolt_install_path / "jolt-core" / "src" / "utils" / "profiling.rs").absolute(),
        (jolt_install_path / "jolt-core" / "src" / "zkvm" / "bytecode" / "mod.rs").absolute(),
        (jolt_install_path / "jolt-core" / "src" / "jolt" / "vm" / "bytecode.rs").absolute(),
    ]

    working_dirs = [jolt_install_path / "jolt-core"]
    while len(working_dirs) > 0:
        working_dir = working_dirs.pop()
        for elem in working_dir.iterdir():
            elem = elem.absolute()
            if elem.is_dir():
                working_dirs.append(elem)
            if elem.is_file() and elem.name == "Cargo.toml":
                replace_in_file(
                    elem,
                    [
                        (
                            r"\[dependencies\]",
                            """[dependencies]\nfuzzer_utils.workspace = true""",
                        ),
                    ],
                )
            if elem.is_file() and elem.suffix == ".rs" and elem not in excluded_replacement_files:
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
