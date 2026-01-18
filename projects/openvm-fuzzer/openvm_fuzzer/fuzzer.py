import logging
import json
import struct
import shutil
import time
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
        """A single fuzzing iteration: Generate -> Oracle -> Prover -> Compare"""
        start_time = time.time()
        
        try:
            # 1. Clean up generated code but PRESERVE 'target' directory for build cache
            if self.project_dir.exists():
                for item in self.project_dir.iterdir():
                    if item.name == "target":
                        continue # Keep the build cache!
                    if item.is_dir():
                        shutil.rmtree(item)
                    else:
                        item.unlink()
            else:
                self.project_dir.mkdir(parents=True, exist_ok=True)
            
            # 2. Generate a new sequence
            num_insts = self.random.randint(1, 8)
            self.instance = self.generator.generate_instance(num_insts=num_insts)
            logger.info(f"Iteration {self.run_id}: Generated {num_insts} instructions.")
            
            # 3. Compute Ground Truth (Oracle)
            self.oracle.compute_expected_results(self.instance)
            
            # 4. Create and Build OpenVM project
            self.create_project()
            build_status = self.build_project()
            
            if any(s.is_failure() for s in build_status):
                for s in build_status:
                    if s.is_failure():
                        logger.error(f"Iteration {self.run_id}: Build failed! Command: {s.command}")
                        logger.error(f"Stdout: {s.stdout}")
                        logger.error(f"Stderr: {s.stderr}")
                return

            # 5. Execute without injection (Loop 1 check)
            # This triggers get_outputs_from_record automatically
            self.execute_without_injection()
            
            elapsed = time.time() - start_time
            logger.info(f"Iteration {self.run_id}: Completed in {elapsed:.2f}s")

        except Exception as e:
            logger.error(f"Iteration {self.run_id}: Crashed with error: {e}", exc_info=True)

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
                # Raw byte list parsing
                clean_str = prover_record.strip("[]").replace(" ", "")
                if clean_str:
                    bytes_list = [int(x) for x in clean_str.split(",")]
                    u32_list = []
                    for i in range(0, len(bytes_list), 4):
                        if i + 4 <= len(bytes_list):
                            val = struct.unpack("<I", bytes(bytes_list[i:i+4]))[0]
                            u32_list.append(val)
                    
                    for i in range(0, len(u32_list), 2):
                        if i + 1 < len(u32_list):
                            reg_idx = u32_list[i]
                            reg_val = u32_list[i+1]
                            actual_results[reg_idx] = reg_val
            except Exception as e:
                logger.error(f"Failed to parse Prover output: {e}. Raw: {prover_record}")

        success = True
        logger.info(f"=== Loop 1 Result (Iteration {self.run_id}) ===")
        for reg_idx, expected_val in self.instance.expected_results.items():
            actual_val = actual_results.get(reg_idx)
            expected_val &= 0xFFFFFFFF
            if actual_val is None:
                continue # Skip if not revealed
            
            actual_val &= 0xFFFFFFFF
            if actual_val != expected_val:
                logger.error(f"  Reg x{reg_idx}: FAILED! Expected 0x{expected_val:08x}, got 0x{actual_val:08x}")
                success = False
            # Reduced log verbosity for loop
        
        if success:
            logger.info("  >> SUCCESS: Oracle and Prover match.")
        else:
            logger.error("  >> FAILED: Potential Soundness bug found!")
            
        return {"status": "success" if success else "failed"}

    def is_skip_fault_injection_inspection(self, trace: Trace, arguments: InjectionArguments) -> bool:
        return False

    def is_ignored_execution_error(self, exec_status: ExecStatus) -> bool:
        return False
