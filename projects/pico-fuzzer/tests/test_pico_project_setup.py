from pathlib import Path
from random import Random

from pico_fuzzer.zkvm_project import CircuitProjectGenerator
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


def test_pico_circuit_project_generation():
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
        Path("out") / "test-pico" / "projects" / "circuit",
        Path("dummy-path-to-pico"),
        circuits,
        True,  # fault injection
        True,  # trace collection
    ).create()
