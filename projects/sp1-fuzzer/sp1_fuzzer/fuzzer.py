import logging
import re
from pathlib import Path
from random import Random

from sp1_fuzzer.kinds import InjectionKind, InstrKind
from sp1_fuzzer.settings import (
    APPLY_SAFE_REM_DIV_TRANSFORMATION,
    ENABLED_INJECTION_KINDS,
    PREFERRED_INSTRUCTIONS,
    RUST_GUEST_CORRECT_VALUE,
    TIMEOUT_PER_BUILD,
    TIMEOUT_PER_RUN,
)
from sp1_fuzzer.zkvm_project import CircuitProjectGenerator
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
from zkvm_fuzzer_utils.trace import Trace

logger = logging.getLogger("fuzzer")

# ---------------------------------------------------------------------------- #
#                               Config Generators                              #
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
        {"output": f"{RUST_GUEST_CORRECT_VALUE}"},
    )


# ---------------------------------------------------------------------------- #
#                                    Helper                                    #
# ---------------------------------------------------------------------------- #


def guest_division_or_modulo_by_zero(status: ExecStatus) -> bool:
    # this pattern checks for the inserted assertion (if present)
    pattern = re.compile(
        r"stderr: division-by-zero \(id: [0-9]+\)"  # match on arbitrary assertion id
    )
    opt_match = pattern.search(status.stderr)
    if opt_match and "panicked at guest/src/main.rs" in status.stderr:
        return True

    # this pattern checks for the error in the guest
    pattern = re.compile(
        r"(attempt to calculate the remainder with a divisor of zero|"
        r"attempt to divide by zero)"  # match the guest error
    )
    opt_match = pattern.search(status.stderr)
    if opt_match and "panicked at guest/src/main.rs" in status.stderr:
        return True

    return False


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

    def is_skip_fault_injection_inspection(
        self, trace: Trace, arguments: InjectionArguments[InjectionKind]
    ) -> bool:
        return False

    def is_ignored_execution_error(self, exec_status: ExecStatus) -> bool:
        return guest_division_or_modulo_by_zero(exec_status)


# ---------------------------------------------------------------------------- #
