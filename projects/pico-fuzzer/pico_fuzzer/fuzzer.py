import logging
from pathlib import Path
from random import Random

from pico_fuzzer.kinds import InjectionKind, InstrKind
from pico_fuzzer.settings import (
    APPLY_SAFE_REM_DIV_TRANSFORMATION,
    ENABLED_INJECTION_KINDS,
    PREFERRED_INSTRUCTIONS,
    RUST_GUEST_CORRECT_VALUE_AS_BYTES,
    TIMEOUT_PER_BUILD,
    TIMEOUT_PER_RUN,
)
from pico_fuzzer.zkvm_project import CircuitProjectGenerator
from zkvm_fuzzer_utils.cmd import ExecStatus
from zkvm_fuzzer_utils.default import (
    FUZZER_CONFIG,
    FUZZER_ITERATIVE_REWRITE,
    INPUT_LOOP_ITERATIONS,
    MAX_FUZZER_BATCH_SIZE,
    MAX_FUZZER_REWRITES,
    MAX_VALUE_U32,
    MIN_FUZZER_BATCH_SIZE,
    MIN_FUZZER_REWRITES,
    MIN_VALUE_U32,
    REWRITE_RULES,
)
from zkvm_fuzzer_utils.fuzzer import (
    CircuitFuzzerBase,
    CircuitGenerationConfig,
    FuzzerConfig,
)
from zkvm_fuzzer_utils.injection import InjectionArguments
from zkvm_fuzzer_utils.rust.cargo import CargoCmd
from zkvm_fuzzer_utils.trace import Trace

logger = logging.getLogger("fuzzer")

# ---------------------------------------------------------------------------- #
#                                    Fuzzer                                    #
# ---------------------------------------------------------------------------- #


def create_circuit_config(no_inline_assembly: bool) -> CircuitGenerationConfig:
    if no_inline_assembly:
        FUZZER_CONFIG.custom_functions = []  # remove custom functions

    return CircuitGenerationConfig(
        MIN_VALUE_U32,
        MAX_VALUE_U32,
        MIN_FUZZER_REWRITES,
        MAX_FUZZER_REWRITES,
        MIN_FUZZER_BATCH_SIZE,
        MAX_FUZZER_BATCH_SIZE,
        REWRITE_RULES,
        FUZZER_CONFIG,
        FUZZER_ITERATIVE_REWRITE,
        APPLY_SAFE_REM_DIV_TRANSFORMATION,
    )


# ---------------------------------------------------------------------------- #


def create_instr_kind_to_injection_kind_lookup(
    only_modify_word: bool,
) -> dict[InstrKind, list[InjectionKind]]:
    if only_modify_word:
        return {
            e: InjectionKind.retrieve_injection_types(e, [InjectionKind.INSTR_WORD_MOD])
            for e in list(InstrKind)
        }
    else:
        return {
            e: InjectionKind.retrieve_injection_types(e, ENABLED_INJECTION_KINDS)
            for e in list(InstrKind)
        }


# ---------------------------------------------------------------------------- #


def create_fuzzer_config(only_modify_word: bool) -> FuzzerConfig:
    return FuzzerConfig(
        INPUT_LOOP_ITERATIONS,
        create_instr_kind_to_injection_kind_lookup(only_modify_word),
        PREFERRED_INSTRUCTIONS,
        TIMEOUT_PER_BUILD,
        TIMEOUT_PER_RUN,
        InstrKind,
        InjectionKind,
        {"output": f"{RUST_GUEST_CORRECT_VALUE_AS_BYTES}"},
    )


# ---------------------------------------------------------------------------- #
#                                    Fuzzer                                    #
# ---------------------------------------------------------------------------- #


class CircuitFuzzer(CircuitFuzzerBase[InstrKind, InjectionKind]):
    def __init__(
        self,
        project_dir: Path,
        jolt_dir: Path,
        rng: Random,
        only_modify_word: bool,
        no_inline_assembly: bool,
    ):
        super().__init__(
            project_dir,
            jolt_dir,
            create_fuzzer_config(only_modify_word),
            rng,
            create_circuit_config(no_inline_assembly),
        )

    def create_project(self):
        CircuitProjectGenerator(
            self.project_dir,
            self.zkvm_dir,
            self.circuits,
            self.is_fault_injection,
            self.is_trace_collection,
        ).create()

    def build_project(self) -> list[ExecStatus]:
        built_app = (
            CargoCmd.build()
            .with_sub_cli("pico")
            .with_cd(self.project_dir / "app")
            .with_timeout(self.fuzzer_config.build_timeout)
            .execute()
        )
        built_prover = (
            CargoCmd.build()
            .with_cd(self.project_dir / "prover")
            .with_timeout(self.fuzzer_config.build_timeout)
            .in_release()
            .execute()
        )
        return [built_app, built_prover]

    def execute_project(self, arguments: list[str]):
        return (
            CargoCmd.run()
            .with_cd(self.project_dir / "prover")
            .with_args(arguments)
            .with_timeout(self.fuzzer_config.execution_timeout)
            .in_release()
            .with_explicit_clean_zombies()
            .execute()
        )

    def is_skip_fault_injection_inspection(
        self, trace: Trace, arguments: InjectionArguments[InjectionKind]
    ) -> bool:
        return False

    def is_ignored_execution_error(self, exec_status: ExecStatus) -> bool:
        return False


# ---------------------------------------------------------------------------- #
