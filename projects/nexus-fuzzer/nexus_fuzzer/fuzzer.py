import logging
import re
from pathlib import Path
from random import Random

from nexus_fuzzer.kinds import InjectionKind, InstrKind
from nexus_fuzzer.settings import (
    APPLY_SAFE_REM_DIV_TRANSFORMATION,
    ENABLED_INJECTION_KINDS,
    PREFERRED_INSTRUCTIONS,
    RUST_GUEST_CORRECT_VALUE,
    TIMEOUT_PER_BUILD,
    TIMEOUT_PER_RUN,
    get_riscv_target,
)
from nexus_fuzzer.zkvm_project import CircuitProjectGenerator
from zkvm_fuzzer_utils.checker import CheckerConfig, CircuitCheckerBase
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
from zkvm_fuzzer_utils.risc32_im import RISCV_I_EXTENSION
from zkvm_fuzzer_utils.trace import Trace

logger = logging.getLogger("fuzzer")


# ---------------------------------------------------------------------------- #
#                               Config Generators                              #
# ---------------------------------------------------------------------------- #


def create_circuit_config(
    commit_or_branch: str, no_inline_assembly: bool
) -> CircuitGenerationConfig:
    if no_inline_assembly:
        FUZZER_CONFIG.custom_functions = []  # remove custom functions

    elif get_riscv_target(commit_or_branch) == "riscv32i-unknown-none-elf":
        # Remove the M Extension from the custom functions
        FUZZER_CONFIG.custom_functions = RISCV_I_EXTENSION

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


def create_checker_config() -> CheckerConfig:
    return CheckerConfig(
        TIMEOUT_PER_BUILD,
        TIMEOUT_PER_RUN,
        InstrKind,
        InjectionKind,
        {"output": f"{RUST_GUEST_CORRECT_VALUE}"},
    )


# ---------------------------------------------------------------------------- #
#                                Helper Function                               #
# ---------------------------------------------------------------------------- #


def guest_division_or_modulo_by_zero(status: ExecStatus) -> bool:
    pattern = re.compile(
        r"Emulated program panic in file 'guest/src/main.rs' "  # force default guest file
        r"at line [0-9]+: (attempt to divide by zero|"  # match on arbitrary line and id
        r"attempt to calculate the remainder with a divisor of zero)"  # match a division by zero
    )
    opt_match = pattern.search(status.stdout)
    if opt_match:
        return True
    return False


# ---------------------------------------------------------------------------- #
#                                    Fuzzer                                    #
# ---------------------------------------------------------------------------- #


class CircuitFuzzer(CircuitFuzzerBase[InstrKind, InjectionKind]):
    commit_or_branch: str

    def __init__(
        self,
        project_dir: Path,
        jolt_dir: Path,
        rng: Random,
        commit_or_branch: str,
        only_modify_word: bool,
        no_inline_assembly: bool,
    ):
        super().__init__(
            project_dir,
            jolt_dir,
            create_fuzzer_config(only_modify_word),
            rng,
            create_circuit_config(commit_or_branch, no_inline_assembly),
        )
        self.commit_or_branch = commit_or_branch

    def create_project(self):
        CircuitProjectGenerator(
            self.project_dir,
            self.zkvm_dir,
            self.circuits,
            self.is_fault_injection,
            self.is_trace_collection,
            self.commit_or_branch,
        ).create()

    def is_skip_fault_injection_inspection(
        self, trace: Trace, arguments: InjectionArguments[InjectionKind]
    ) -> bool:
        if (
            trace.steps[-1].step == arguments.step
            and arguments.kind == InjectionKind.POST_EXEC_PC_MOD
        ):
            logger.warning("TODO: Trying PC modification after last step ...")
            return True
        return False

    def is_ignored_execution_error(self, exec_status: ExecStatus) -> bool:
        return guest_division_or_modulo_by_zero(exec_status)


# ---------------------------------------------------------------------------- #
#                                    Checker                                   #
# ---------------------------------------------------------------------------- #


class CircuitChecker(CircuitCheckerBase[InstrKind, InjectionKind]):
    commit_or_branch: str

    def __init__(
        self,
        project_dir: Path,
        jolt_dir: Path,
        commit_or_branch: str,
        findings_csv: Path,
        no_inline_assembly: bool,
    ):
        super().__init__(
            project_dir,
            jolt_dir,
            findings_csv,
            create_checker_config(),
            create_circuit_config(commit_or_branch, no_inline_assembly),
        )
        self.commit_or_branch = commit_or_branch

    def create_project(self):
        CircuitProjectGenerator(
            self.project_dir,
            self.zkvm_dir,
            self.circuits,
            self.active_finding.is_injection,
            "--trace" in self.active_finding.input_flags,
            self.commit_or_branch,
        ).create()


# ---------------------------------------------------------------------------- #
