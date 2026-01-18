import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Generic, Type

from circil.ir.node import Circuit
from zkvm_fuzzer_utils.cmd import ExecStatus
from zkvm_fuzzer_utils.csvlogger import (
    ParsedFinding,
    create_empty_checked_findings_csv,
    log_checked_findings_csv,
)
from zkvm_fuzzer_utils.fuzzer import (
    CircuitGenerationConfig,
    FuzzerInternalError,
    generate_metamorphic_bundle_from_config,
)
from zkvm_fuzzer_utils.kinds import InjectionKind, InstrKind
from zkvm_fuzzer_utils.record import Record, record_from_exec_status
from zkvm_fuzzer_utils.rust.cargo import CargoCmd
from zkvm_fuzzer_utils.trace import trace_from_exec

logger = logging.getLogger("fuzzer")


# ---------------------------------------------------------------------------- #
#                                 Configuration                                #
# ---------------------------------------------------------------------------- #


@dataclass(frozen=True)
class CheckerConfig(Generic[InstrKind, InjectionKind]):
    build_timeout: int
    execution_timeout: int
    instr_kind_enum: Type[InstrKind]
    injection_kind_enum: Type[InjectionKind]
    expected_output: dict[str, str] | None


# ---------------------------------------------------------------------------- #
#                                 Checker Core                                 #
# ---------------------------------------------------------------------------- #


class CheckerCore(ABC, Generic[InstrKind, InjectionKind]):

    #
    # Checker Configuration Data
    #

    __project_dir: Path
    __zkvm_dir: Path
    __findings_csv: Path
    __checker_config: CheckerConfig

    #
    # Checker State
    #

    __outputs_for_execution: dict[str, str] | None
    __active_finding: ParsedFinding | None

    def __init__(
        self, project_dir: Path, zkvm_dir: Path, findings_csv: Path, checker_config: CheckerConfig
    ):
        self.__project_dir = project_dir
        self.__zkvm_dir = zkvm_dir
        self.__findings_csv = findings_csv
        self.__checker_config = checker_config
        self.__outputs_for_execution = None
        self.__active_finding = None

    def loop(self):
        """Starts the checker loop"""

        if not self.__findings_csv.is_file():
            create_empty_checked_findings_csv(self.project_dir)
            logger.error("Found nothing to check! Stopping checker...")
            return  # exit

        findings = ParsedFinding.parse_from(self.__findings_csv)

        if len(findings) == 0:
            create_empty_checked_findings_csv(self.project_dir)
            logger.error("Found nothing to check! Stopping checker...")
            return  # exit

        try:
            for finding in findings:
                self.__active_finding = finding
                self.check()

        except FuzzerInternalError as e:
            logger.warning("Checker stopped because of an internal error!")
            logger.critical(e, exc_info=True)

        except KeyboardInterrupt:
            # NOTE: this is the expected interrupt to turn off the fuzzer
            logger.warning("Fuzzer stopped by keyboard interrupt...")

        except Exception as e:
            # NOTE: this is really bad!
            logger.error("Fuzzer stopped because of an unexpected internal exception!")
            logger.critical(e, exc_info=True)

    def check(self):
        """Entry point for a single check of the current active finding"""

        self.create_project()

        build_status_list = self.build_project()
        for build_status in build_status_list:
            if build_status.is_failure():
                if build_status.is_timeout:
                    logger.error(f"COMMAND: {build_status.command}")
                    logger.error(f"zkvm build timed out with {self.checker_config.build_timeout}")
                raise FuzzerInternalError("unable to build zkvm host build!")

        self.__outputs_for_execution = None

        is_fixed = False
        if self.active_finding.is_injection:
            is_fixed = self.execute_with_injection()
        else:
            is_fixed = self.execute_without_injection()
        log_checked_findings_csv(self.project_dir, self.active_finding, is_fixed)

    def execute_without_injection(self) -> bool:
        """Executes the zkvm project without fault injection"""

        # execute the program without injection mode
        execution_status = self.execute_project(self.active_finding.input_flags)

        # get trace and record data from execution
        record = record_from_exec_status(execution_status)
        self.__outputs_for_execution = self.get_outputs_from_record(record)
        logger.debug(f"record output: {self.__outputs_for_execution}")

        # if the execution failed we have to check the reason
        if execution_status.is_failure():
            # if it was a timeout we continue and log an error
            if execution_status.is_timeout:
                logger.error(
                    f"Host program reached timeout of {self.checker_config.execution_timeout}s!"
                    " Consider increasing the timeout or change the prover setup..."
                )
                raise FuzzerInternalError("unexpected time out for checking!")
            # not a timeout problem
            logger.error("completeness violation in execution!")
            return False

        else:
            # check expected output
            if self.checker_config.expected_output:
                if self.checker_config.expected_output != self.outputs_for_execution:
                    logger.error("Actual output value does not match expected value!")
                    logger.info(f"expected       : {self.checker_config.expected_output}")
                    logger.info(f"actual         : {self.outputs_for_execution}")
                    logger.error("soundness violation in execution!")
                    return False

        return True

    def execute_with_injection(self) -> bool:
        """Executes the zkvm project with fault injection"""

        # execute the program in injection mode
        host_execution = self.execute_project(self.active_finding.input_flags)

        # get trace and record data from execution
        record = record_from_exec_status(host_execution)
        trace = trace_from_exec(
            host_execution,
            self.checker_config.instr_kind_enum,
            self.checker_config.injection_kind_enum,
        )
        self.__outputs_for_execution = self.get_outputs_from_record(record)
        logger.debug(f"record output: {self.outputs_for_execution}")

        # Check that the trace of the fault injection execution has exactly on fault
        fault_count = len(trace.faults)
        if fault_count != 1:
            logger.critical(
                f"Unexpected number of fault injections! Expected 1, but was {fault_count}!"
            )
            raise FuzzerInternalError("unexpected number of fault injections!")

        # if the injection was successful we have to check the output
        if record.is_success():
            # check expected output
            if self.checker_config.expected_output:
                if self.checker_config.expected_output != self.outputs_for_execution:
                    logger.error("Actual output value does not match expected value!")
                    logger.info(f"expected       : {self.checker_config.expected_output}")
                    logger.info(f"actual         : {self.outputs_for_execution}")
                    logger.error("soundness violation in execution!")
                    return False
        return True

    @abstractmethod
    def create_project(self):
        """Updates or creates the zkvm host and guest code based"""
        raise NotImplementedError()

    def build_project(self) -> list[ExecStatus]:
        """Builds the zkvm host and guest code and returns the status"""
        return [
            CargoCmd.build()
            .with_cd(self.project_dir)
            .in_release()
            .with_timeout(self.checker_config.build_timeout)
            .execute()
        ]

    def execute_project(self, arguments: list[str]) -> ExecStatus:
        """Executes the zkvm host and guest code with the provided arguments
        and returns the status"""
        return (
            CargoCmd.run()
            .with_cd(self.project_dir)
            .with_args(arguments)
            .with_timeout(self.checker_config.execution_timeout)
            .in_release()
            .with_explicit_clean_zombies()
            .execute()
        )

    @abstractmethod
    def get_outputs_from_record(self, record: Record) -> dict[str, str]:
        """Given a `Record` this function returns a dictionary containing
        output values. Note that these values are relevant for fault
        injection compares."""
        raise NotImplementedError()

    @property
    def checker_config(self) -> CheckerConfig[InstrKind, InjectionKind]:
        return self.__checker_config

    @property
    def project_dir(self) -> Path:
        return self.__project_dir

    @property
    def zkvm_dir(self) -> Path:
        return self.__zkvm_dir

    @property
    def active_finding(self) -> ParsedFinding:
        assert self.__active_finding, "no active finding"
        return self.__active_finding

    @property
    def outputs_for_execution(self) -> dict[str, str] | None:
        return self.__outputs_for_execution


# ---------------------------------------------------------------------------- #
#                              Circuit Fuzzer Base                             #
# ---------------------------------------------------------------------------- #


class CircuitCheckerBase(CheckerCore[InstrKind, InjectionKind]):
    __circuit_config: CircuitGenerationConfig

    def __init__(
        self,
        project_dir: Path,
        zkvm_dir: Path,
        findings_csv: Path,
        checker_config: CheckerConfig[InstrKind, InjectionKind],
        circuit_config: CircuitGenerationConfig,
    ):
        super().__init__(project_dir, zkvm_dir, findings_csv, checker_config)
        self.__circuit_config = circuit_config

    def get_outputs_from_record(self, record: Record) -> dict[str, str]:
        output = {}
        output_value = record.search_by_key("output")
        if output_value is not None:
            output["output"] = output_value
        return output

    @property
    def circuit_candidate(self) -> Circuit:
        return self.circuits[0]

    @property
    def circuits(self) -> list[Circuit]:
        return generate_metamorphic_bundle_from_config(self.__circuit_config, self.circuits_seed)

    @property
    def circuits_seed(self) -> float:
        return self.active_finding.circuit_seed


# ---------------------------------------------------------------------------- #
