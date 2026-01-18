import shutil
import subprocess
from pathlib import Path
from random import Random

from nexus_fuzzer.zkvm_project import CircuitProjectGenerator
from nexus_fuzzer.zkvm_repository.injection_source import (
    nexus_vm_src_emulator_executor_rs,
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
        Path("out") / "test-nexus" / "projects" / "circuit",
        Path("dummy-path-to-nexus"),
        circuits,
        True,  # fault injection
        True,  # trace collection
        "main",
    ).create()


def test_injection_source():
    output_dir = Path("out") / "test-nexus" / "injections"
    create_dir(output_dir)
    source_file = output_dir / "executor.rs"
    source_content = nexus_vm_src_emulator_executor_rs("main")
    with open(source_file, "w") as fp:
        fp.write(source_content)

    # NOTE: only works if clippy is available and parse the injection file
    clippy_driver_bin = shutil.which("clippy-driver")
    if clippy_driver_bin:
        completed_process = subprocess.run(
            [clippy_driver_bin, source_file], text=True, capture_output=True
        )
        lines = completed_process.stderr.split("\n")
        for line in lines:
            is_error = False

            # check for unknown errors
            if line.startswith("error"):
                is_error = True
                if (
                    line.startswith("error[E0412]: cannot find type")
                    or line.startswith("error[E0422]: cannot find struct")
                    or line.startswith("error[E0432]: unresolved import")
                    or line.startswith("error[E0433]: failed to resolve")
                    or line.startswith("error[E0601]: `main` function not found")
                    or line.startswith("error: aborting due to 61 previous errors")
                ):
                    is_error = False

            if is_error:
                print(completed_process.stderr)
                raise RuntimeError(f"rust error: {line}")
