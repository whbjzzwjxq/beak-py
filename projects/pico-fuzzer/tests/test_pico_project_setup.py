from pathlib import Path
from random import Random

from beak_core.generator import RISCVGenerator
from pico_fuzzer.zkvm_project import InstructionProjectGenerator


def test_pico_instruction_project_generation():
    instance = RISCVGenerator(seed=Random(0xC0FFEE).randint(0, 1_000_000)).generate_instance(num_insts=3)
    InstructionProjectGenerator(
        Path("out") / "test-pico" / "projects" / "loop1",
        Path("dummy-path-to-pico"),
        instance,
    ).create()

