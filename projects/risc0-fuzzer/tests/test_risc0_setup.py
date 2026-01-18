import shutil
import subprocess
from pathlib import Path
from random import Random

from risc0_fuzzer.zkvm_project import CircuitProjectGenerator
from risc0_fuzzer.zkvm_repository.injection_sources import (
    risc0_circuit_rv32im_src_execute_rv32im_rs,
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


def test_project_setup():
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
        Path("out") / "test-risc0" / "projects" / "circuit",
        Path("dummy-path-to-risc0"),
        circuits,
        True,  # fault injection
        True,  # trace collection
    ).create()


def test_injection_source():
    output_dir = Path("out") / "test-risc0" / "injections"
    create_dir(output_dir)
    source_file = output_dir / "rv32im.rs"
    source_content = risc0_circuit_rv32im_src_execute_rv32im_rs("main")
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
            # check for unknown errors
            if line.startswith("error"):
                if (
                    not line.startswith("error[E0433]:")  # ignore missing imports
                    and not line.startswith("error[E0432]:")  # ignore missing imports
                    and not line.startswith("error[E0601]:")  # ignore missing main function
                    and not line.startswith("error[E0277]: `InsnKind`")  # ignore missing 'Debug'
                    and not line.startswith(
                        "error: cannot find attribute"
                    )  # ignore missing 'Debug'
                    and not line.startswith(
                        "error: aborting due to 14 previous errors"
                    )  # explicitly check for the 14 expected errors
                ):
                    print(completed_process.stderr)
                    raise RuntimeError(f"rust error: {line}")
