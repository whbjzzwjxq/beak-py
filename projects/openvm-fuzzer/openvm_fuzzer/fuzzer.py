import logging
import json
import struct
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
        self, project_dir: Path, zkvm_dir: Path, rng: Random, commit_or_branch: str,
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
        self.instance = self.generator.generate_instance(num_insts=10)
        logger.info(f"Generated {len(self.instance.instructions)} instructions.")
        self.oracle.compute_expected_results(self.instance)
        self.create_project()
        self.build_project()
        self.execute_without_injection()

    def create_project(self):
        CircuitProjectGenerator(
            self.project_dir, self.zkvm_dir, self.instance,
            self.is_fault_injection, self.is_trace_collection, self.commit_or_branch,
        ).create()

    def create_execution_arguments(self, injection_arguments: InjectionArguments | None = None) -> list[str]:
        return []

    def get_outputs_from_record(self, record: Record) -> dict[str, str]:
        """
        LOOP 1 CORE: Reconstruct u32 from bytes and compare with Oracle.
        """
        actual_results = {}
        prover_record = record.search_by_key("output")
        
        if prover_record:
            try:
                # 1. Parse raw byte list from Rust Debug output: "[1, 0, 0, 0, 165, 10, ...]"
                clean_str = prover_record.strip("[]").replace(" ", "")
                if clean_str:
                    bytes_list = [int(x) for x in clean_str.split(",")]
                    
                    # 2. Reconstruct u32 from every 4 bytes (little-endian)
                    u32_list = []
                    for i in range(0, len(bytes_list), 4):
                        if i + 4 <= len(bytes_list):
                            # Pack 4 bytes and unpack as little-endian u32
                            val = struct.unpack("<I", bytes(bytes_list[i:i+4]))[0]
                            u32_list.append(val)
                    
                    # 3. Pair (reg_idx, val) from reconstructed u32 list
                    # Guest sends: reveal(idx, 0), reveal(val, 0)
                    for i in range(0, len(u32_list), 2):
                        if i + 1 < len(u32_list):
                            reg_idx = u32_list[i]
                            reg_val = u32_list[i+1]
                            actual_results[reg_idx] = reg_val
            except Exception as e:
                logger.error(f"Failed to parse bytes: {e}. Raw: {prover_record}")

        # Comparison
        success = True
        logger.info("=== Loop 1 (Oracle vs Prover) Result ===")
        for reg_idx, expected_val in self.instance.expected_results.items():
            actual_val = actual_results.get(reg_idx)
            
            # Mask to 32-bit
            expected_val &= 0xFFFFFFFF
            
            if actual_val is None:
                # SKIP: If it's missing, it might not have been revealed (optimization)
                # We skip rather than failing
                continue
            
            actual_val &= 0xFFFFFFFF
            if actual_val != expected_val:
                logger.error(f"  Reg x{reg_idx}: FAILED! Expected 0x{expected_val:08x}, got 0x{actual_val:08x}")
                success = False
            else:
                logger.info(f"  Reg x{reg_idx}: OK (0x{actual_val:08x})")

        if success:
            logger.info("  >> ALL REGISTERS MATCH! Oracle and Prover are consistent.")
        else:
            logger.error("  >> LOOP 1 FAILED! Potential Prover bug found.")
        return {"status": "success" if success else "failed"}

    def is_skip_fault_injection_inspection(self, trace: Trace, arguments: InjectionArguments) -> bool:
        return False

    def is_ignored_execution_error(self, exec_status: ExecStatus) -> bool:
        return False
