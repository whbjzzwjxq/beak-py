#!/usr/bin/env python3

import logging
from random import Random

from jolt_fuzzer.fuzzer import CircuitChecker, CircuitFuzzer, create_circuit_config
from jolt_fuzzer.settings import JOLT_AVAILABLE_COMMITS_OR_BRANCHES
from jolt_fuzzer.zkvm_project import CircuitProjectGenerator
from jolt_fuzzer.zkvm_repository.install import install_jolt
from zkvm_fuzzer_utils.cli import FuzzerClient
from zkvm_fuzzer_utils.fuzzer import generate_metamorphic_bundle_from_config

logger = logging.getLogger("fuzzer")


class JoltFuzzerClient(FuzzerClient):
    def run(self):
        assert self.out_dir, "no output directory"
        assert self.zkvm_dir, "no zkvm library"

        logger.info(f"=== Start {self.logger_prefix} Fuzzing Campaign ===")
        logger.info(f" * seed: {self.seed}")
        logger.info(f" * output: {self.out_dir})")
        logger.info(f" * library: {self.zkvm_dir})")
        logger.info(f" * trace: {self.is_trace_collection}")
        logger.info(f" * injection: {self.is_fault_injection}")
        logger.info(f" * schedular: {self.is_no_schedular}")
        logger.info(f" * commit: {self.commit_or_branch}")
        logger.info("===")

        fuzzer = CircuitFuzzer(
            self.out_dir,
            self.zkvm_dir,
            Random(self.seed),
            self.commit_or_branch,
            self.is_only_modify_word,
            self.is_no_inline_assembly,
        )

        if self.is_fault_injection:
            fuzzer.enable_fault_injection()

        if self.is_trace_collection:
            fuzzer.enable_trace_collection()

        if self.timeout is not None and self.timeout > 0:
            fuzzer.enable_timeout(self.timeout)

        if self.is_no_schedular:
            fuzzer.disable_injection_schedular()

        fuzzer.loop()

        logger.info(f"=== End {self.logger_prefix} Fuzzing Campaign ===")

    def install(self):
        assert self.zkvm_dir, "no zkvm library"
        install_jolt(
            self.zkvm_dir,
            self.commit_or_branch,
            enable_zkvm_modification=(not self.is_zkvm_modification),
        )

    def check(self):
        assert self.out_dir, "no output directory"
        assert self.zkvm_dir, "no zkvm library"
        assert self.findings_csv, "no findings csv"

        CircuitChecker(
            self.out_dir,
            self.zkvm_dir,
            self.commit_or_branch,
            self.findings_csv,
            self.is_no_inline_assembly,
        ).loop()

    def generate(self):
        assert self.out_dir, "no output directory"
        assert self.zkvm_dir, "no zkvm library"
        circuit_config = create_circuit_config(self.no_inline_assembly)
        circuits = generate_metamorphic_bundle_from_config(circuit_config, self.seed)
        CircuitProjectGenerator(
            self.out_dir,
            self.zkvm_dir,
            circuits,
            self.is_fault_injection,
            self.is_trace_collection,
            self.commit_or_branch,
        ).create()


def app():
    cli = JoltFuzzerClient("Jolt", "JOLT", JOLT_AVAILABLE_COMMITS_OR_BRANCHES)
    cli.start()


if __name__ == "__main__":
    app()
