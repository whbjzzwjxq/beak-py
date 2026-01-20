from pathlib import Path
from random import Random

from beak_core.generator import RISCVGenerator
from openvm_fuzzer.zkvm_project import CircuitProjectGenerator, _set_openvm_stark_sdk_from_openvm


def test_openvm_circuit_project_generation():
    _set_openvm_stark_sdk_from_openvm(
        'openvm-stark-sdk = { git = "https://github.com/openvm-org/stark-backend.git",'
        ' tag = "v1.1.1", default-features = false }'
    )
    instance = RISCVGenerator(seed=Random(0xC0FFEE).randint(0, 1_000_000)).generate_instance(num_insts=3)
    _ = CircuitProjectGenerator(
        Path("out") / "test-openvm" / "projects" / "circuit",
        Path("dummy-path-to-openvm"),
        instance,
        True,  # fault injection
        True,  # trace collection
        "main",
    ).create()
