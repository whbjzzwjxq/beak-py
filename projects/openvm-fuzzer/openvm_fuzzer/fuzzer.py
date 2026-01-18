import logging
from pathlib import Path
from random import Random

from beak_core.generator import RISCVGenerator
from beak_core.oracle import RISCVOracle
from beak_core.types import FuzzingInstSeqInstance

from openvm_fuzzer.kinds import InjectionKind, InstrKind
from openvm_fuzzer.settings import (
    TIMEOUT_PER_BUILD,
    TIMEOUT_PER_RUN,
)
from openvm_fuzzer.zkvm_project import CircuitProjectGenerator
from zkvm_fuzzer_utils.cmd import ExecStatus
from zkvm_fuzzer_utils.fuzzer import (
    FuzzerCore,
    FuzzerConfig,
)
from zkvm_fuzzer_utils.injection import InjectionArguments
from zkvm_fuzzer_utils.record import Record
from zkvm_fuzzer_utils.trace import Trace

logger = logging.getLogger("fuzzer")

class BeakFuzzer(FuzzerCore[InstrKind, InjectionKind]):
    commit_or_branch: str
    instance: FuzzingInstSeqInstance | None

    def __init__(
        self,
        project_dir: Path,
        zkvm_dir: Path,
        rng: Random,
        commit_or_branch: str,
    ):
        config = FuzzerConfig(
            input_iterations=1,
            available_injections_lookup={}, 
            preferred_instructions=[],
            build_timeout=TIMEOUT_PER_BUILD,
            execution_timeout=TIMEOUT_PER_RUN,
            instr_kind_enum=InstrKind,
            injection_kind_enum=InjectionKind,
            expected_output=None,
        )
        super().__init__(project_dir, zkvm_dir, config, rng)
        self.commit_or_branch = commit_or_branch
        self.instance = None
        self.generator = RISCVGenerator(seed=rng.randint(0, 1000000))
        self.oracle = RISCVOracle()

    def run(self):
        self.instance = self.generator.generate_instance(num_insts=20)
        self.oracle.compute_expected_results(self.instance)
        self.create_project()
        self.build_project()
        self.execute_without_injection()

    def create_project(self):
        """Implement abstract method from FuzzerCore"""
        CircuitProjectGenerator(
            self.project_dir,
            self.zkvm_dir,
            self.instance,
            self.is_fault_injection,
            self.is_trace_collection,
            self.commit_or_branch,
        ).create()

    def create_execution_arguments(
        self, injection_arguments: InjectionArguments | None = None
    ) -> list[str]:
        """Implement abstract method from FuzzerCore"""
        return []

    def get_outputs_from_record(self, record: Record) -> dict[str, str]:
        """Implement abstract method from FuzzerCore"""
        return {"status": "checked"}

    def is_skip_fault_injection_inspection(
        self, trace: Trace, arguments: InjectionArguments
    ) -> bool:
        """Implement abstract method from FuzzerCore"""
        return False

    def is_ignored_execution_error(self, exec_status: ExecStatus) -> bool:
        """Implement abstract method from FuzzerCore"""
        return False
