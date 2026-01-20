import logging
import shutil
import time
from pathlib import Path
from random import Random

from beak_core.generator import RISCVGenerator
from beak_core.oracle import RISCVOracle
from beak_core.rv32im import FuzzingInstance
from nexus_fuzzer.kinds import InjectionKind, InstrKind
from nexus_fuzzer.settings import TIMEOUT_PER_BUILD, TIMEOUT_PER_RUN
from nexus_fuzzer.zkvm_project import InstructionProjectGenerator
from zkvm_fuzzer_utils.cmd import ExecStatus, invoke_command
from zkvm_fuzzer_utils.fuzzer import FuzzerConfig, FuzzerCore
from zkvm_fuzzer_utils.injection import InjectionArguments
from zkvm_fuzzer_utils.record import Record
from zkvm_fuzzer_utils.trace import Trace

logger = logging.getLogger("fuzzer")


class NexusBeakFuzzer(FuzzerCore[InstrKind, InjectionKind]):
    commit_or_branch: str
    instance: FuzzingInstance | None

    def __init__(self, project_dir: Path, zkvm_dir: Path, rng: Random, commit_or_branch: str):
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
        start_time = time.time()

        try:
            if self.project_dir.exists():
                for item in self.project_dir.iterdir():
                    if item.name == "target":
                        continue
                    if item.is_dir():
                        shutil.rmtree(item)
                    else:
                        item.unlink()
            else:
                self.project_dir.mkdir(parents=True, exist_ok=True)

            num_insts = self.random.randint(1, 8)
            denied_mnemonics = {
                "ecall",
                "ebreak",
                "beq",
                "bne",
                "blt",
                "bge",
                "bltu",
                "bgeu",
                "jal",
                "jalr",
                "lb",
                "lh",
                "lw",
                "lbu",
                "lhu",
                "sb",
                "sh",
                "sw",
            }
            for _ in range(50):
                candidate = self.generator.generate_instance(num_insts=num_insts)
                if all(inst.mnemonic.literal not in denied_mnemonics for inst in candidate.instructions):
                    self.instance = candidate
                    break
            else:
                self.instance = self.generator.generate_instance(num_insts=num_insts)

            logger.info(f"[nexus:{self.commit_or_branch[:7]}] Iteration {self.run_id}: {num_insts} insts")

            self.oracle.compute_expected_results(self.instance)

            self.create_project()
            build_status = self.build_project()
            if any(s.is_failure() for s in build_status):
                for s in build_status:
                    if s.is_failure():
                        logger.error(f"Build failed: {s.command}")
                        logger.error(f"Stdout: {s.stdout}")
                        logger.error(f"Stderr: {s.stderr}")
                return

            self.execute_without_injection()

            elapsed = time.time() - start_time
            logger.info(f"[nexus:{self.commit_or_branch[:7]}] Iteration {self.run_id}: done in {elapsed:.2f}s")
        except Exception as e:
            logger.error(f"Iteration {self.run_id}: crashed: {e}", exc_info=True)

    def create_project(self):
        assert self.instance is not None, "no fuzzing instance"
        InstructionProjectGenerator(self.project_dir, self.zkvm_dir, self.instance, self.commit_or_branch).create()

    def build_project(self) -> list[ExecStatus]:
        return [
            invoke_command(
                ["cargo", "build", "--release"],
                cwd=self.project_dir / "host",
                env={
                    "RUSTFLAGS": "--cap-lints allow",
                    "CARGO_REGISTRIES_CRATES_IO_PROTOCOL": "sparse",
                },
                timeout=self.fuzzer_config.build_timeout,
            )
        ]

    def execute_project(self, arguments: list[str]) -> ExecStatus:
        return invoke_command(
            ["cargo", "run", "--release"],
            cwd=self.project_dir / "host",
            env={
                "RUSTFLAGS": "--cap-lints allow",
                "CARGO_REGISTRIES_CRATES_IO_PROTOCOL": "sparse",
            },
            timeout=self.fuzzer_config.execution_timeout,
            explicit_clean_zombies=True,
        )

    def create_execution_arguments(self, injection_arguments: InjectionArguments | None = None) -> list[str]:
        return []

    def get_outputs_from_record(self, record: Record) -> dict[str, str]:
        output = record.search_by_key("output")
        if output is None:
            logger.error("No 'output' found in record")
            return {"status": "failed"}

        if isinstance(output, str):
            import json

            outputs = json.loads(output)
        else:
            outputs = output

        actual_results: dict[int, int] = {}
        try:
            for i in range(0, len(outputs), 2):
                reg_idx = int(outputs[i])
                reg_val = int(outputs[i + 1])
                actual_results[reg_idx] = reg_val
        except Exception as e:
            logger.error(f"Failed to parse Nexus output: {e}. Raw: {output}")
            return {"status": "failed"}

        assert self.instance is not None, "no fuzzing instance"
        success = True
        for reg_idx, expected_val in self.instance.expected_results.items():
            actual_val = actual_results.get(reg_idx)
            if actual_val is None:
                continue
            if (actual_val & 0xFFFFFFFF) != (expected_val & 0xFFFFFFFF):
                logger.error(
                    f"Reg x{reg_idx}: expected 0x{expected_val & 0xFFFFFFFF:08x}, got 0x{actual_val & 0xFFFFFFFF:08x}"
                )
                success = False

        if success:
            logger.info("Loop1: oracle and prover match.")
        else:
            logger.error("Loop1: mismatch detected.")

        return {"status": "success" if success else "failed"}

    def is_skip_fault_injection_inspection(self, trace: Trace, arguments: InjectionArguments) -> bool:
        return False

    def is_ignored_execution_error(self, exec_status: ExecStatus) -> bool:
        return False
