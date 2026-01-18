import shutil
import subprocess
from pathlib import Path
from random import Random

from sp1_fuzzer.zkvm_project import CircuitProjectGenerator
from sp1_fuzzer.zkvm_repository.injection_source import (
    sp1_crates_core_executor_src_executor_rs,
)
from zkvm_fuzzer_utils.common import generate_metamorphic_bundle
from zkvm_fuzzer_utils.default import (
    FUZZER_CONFIG,
    FUZZER_ITERATIVE_REWRITE,
    MAX_FUZZER_BATCH_SIZE,
    MAX_FUZZER_REWRITES,
    MAX_VALUE_U32,
    MIN_FUZZER_BATCH_SIZE,
    MIN_FUZZER_REWRITES,
    MIN_VALUE_U32,
    REWRITE_RULES,
)
from zkvm_fuzzer_utils.file import create_dir


def test_circuit_project_setup():
    circuits = generate_metamorphic_bundle(
        Random(0xC0FFEE),
        MIN_VALUE_U32,
        MAX_VALUE_U32,
        (MIN_FUZZER_REWRITES + MAX_FUZZER_REWRITES) // 2,
        (MIN_FUZZER_BATCH_SIZE + MAX_FUZZER_BATCH_SIZE) // 2,
        REWRITE_RULES,
        FUZZER_CONFIG,
        FUZZER_ITERATIVE_REWRITE,
    )
    _ = CircuitProjectGenerator(
        Path("out") / "test-sp1" / "projects" / "circuit",
        Path("dummy-path-to-sp1"),
        circuits,
        True,  # fault injection
        True,  # trace collection
    ).create()


def test_injection_source():
    output_dir = Path("out") / "test-sp1" / "injections"
    create_dir(output_dir)
    source_file = output_dir / "executor.rs"
    source_content = sp1_crates_core_executor_src_executor_rs("dev")
    with open(source_file, "w") as fp:
        fp.write(source_content)

    # NOTE: only works if clippy is available and parse the injection file
    clippy_driver_bin = shutil.which("clippy-driver")
    if clippy_driver_bin:
        completed_process = subprocess.run(
            [clippy_driver_bin, source_file], text=True, capture_output=True
        )

        known_error_lines = {
            (
                "error: couldn't read `out/test-sp1/injections/"
                "./artifacts/rv32im_costs.json`: No such file or "
                "directory (os error 2)"
            ),
            "error[E0432]: unresolved import `crate::estimator`",
            "error[E0432]: unresolved import `clap`",
            "error[E0432]: unresolved import `enum_map`",
            "error[E0432]: unresolved import `hashbrown`",
            "error[E0432]: unresolved import `fuzzer_utils`",
            (
                "error[E0433]: failed to resolve: use of unresolved module or "
                "unlinked crate `sp1_primitives`"
            ),
            (
                "error[E0433]: failed to resolve: use of unresolved module or "
                "unlinked crate `sp1_stark`"
            ),
            "error[E0432]: unresolved import `serde`",
            "error[E0432]: unresolved import `sp1_stark`",
            "error[E0432]: unresolved import `strum`",
            "error[E0432]: unresolved import `thiserror`",
            (
                "error[E0432]: unresolved imports `crate::context`, "
                "`crate::dependencies`, `crate::estimate_riscv_lde_size`, "
                "`crate::events`, `crate::hook`, `crate::memory`, "
                "`crate::pad_rv32im_event_counts`, `crate::record`, "
                "`crate::report`, `crate::state`, `crate::subproof`, "
                "`crate::syscalls`, `crate::CoreAirId`, `crate::Instruction`, "
                "`crate::MaximalShapes`, `crate::Opcode`, `crate::Program`, "
                "`crate::Register`, `crate::RiscvAirId`"
            ),
            "error[E0433]: failed to resolve: use of unresolved module or unlinked crate `eyre`",
            "error[E0433]: failed to resolve: use of unresolved module or unlinked crate `tracing`",
            "error: cannot find attribute `error` in this scope",
            "error[E0601]: `main` function not found in crate `executor`",
            (
                "error[E0433]: failed to resolve: use of unresolved module or "
                "unlinked crate `serde_json`"
            ),
            "error[E0432]: unresolved import `rand`",
            "error[E0433]: failed to resolve: use of unresolved module or unlinked crate `rand`",
            "error[E0433]: failed to resolve: use of unresolved module or unlinked crate `eyre`",
            "error: aborting due to 41 previous errors; 1 warning emitted",
        }

        lines = completed_process.stderr.split("\n")
        unknown_error_lines = set()
        for line in lines:
            # check for unknown errors
            if line.startswith("error"):
                if line not in known_error_lines:
                    unknown_error_lines.add(line)

        if len(unknown_error_lines) > 0:
            print(completed_process.stderr)
            print("\n".join(unknown_error_lines))
            raise RuntimeError(f"{len(unknown_error_lines)} unknown rust error lines")
