#!/usr/bin/env python3

import logging
from random import Random
from pathlib import Path

from openvm_fuzzer.fuzzer import BeakFuzzer
from openvm_fuzzer.settings import (
    OPENVM_AVAILABLE_COMMITS_OR_BRANCHES,
    resolve_openvm_commit,
)
from openvm_fuzzer.zkvm_repository.install import install_openvm
from zkvm_fuzzer_utils.cli import FuzzerClient

logger = logging.getLogger("fuzzer")


class OpenVMFuzzerClient(FuzzerClient):
    def install(self):
        assert self.zkvm_dir, "no zkvm library"
        resolved = resolve_openvm_commit(self.commit_or_branch)
        install_openvm(
            self.zkvm_dir,
            resolved,
            enable_zkvm_modification=self.enable_zkvm_modification,
        )

    def run_loop1(self):
        """Loop 1: Seed Expansion using libAFL"""
        logger.info(f"=== Start {self.logger_prefix} Loop 1 (Expansion) ===")
        
        resolved = resolve_openvm_commit(self.commit_or_branch)
        # Ensure environment is installed/ready
        install_openvm(self.zkvm_dir, resolved, enable_zkvm_modification=self.enable_zkvm_modification)

        fuzzer = self._create_fuzzer(resolved)
        
        # Here we will eventually call the libAFL orchestration logic
        logger.info(f"Loading seeds from: {self.args.seeds}")
        logger.info(f"Iterations: {self.args.iterations}")
        
        # TODO: Implement libAFL integration
        # from openvm_fuzzer.libafl import start_expansion
        # start_expansion(fuzzer, self.args.seeds, self.args.iterations)
        
        logger.info(f"=== End {self.logger_prefix} Loop 1 ===")

    def run_loop2(self):
        """Loop 2: Fault Injection on expanded corpus"""
        logger.info(f"=== Start {self.logger_prefix} Loop 2 (Injection) ===")
        
        resolved = resolve_openvm_commit(self.commit_or_branch)
        install_openvm(self.zkvm_dir, resolved, enable_zkvm_modification=self.enable_zkvm_modification)

        fuzzer = self._create_fuzzer(resolved)
        
        logger.info(f"Running injection on corpus: {self.args.input_corpus}")
        
        # TODO: Implement batch injection logic
        # from openvm_fuzzer.injection import run_batch_injection
        # run_batch_injection(fuzzer, self.args.input_corpus)

        logger.info(f"=== End {self.logger_prefix} Loop 2 ===")

    def _create_fuzzer(self, resolved_commit: str) -> BeakFuzzer:
        label = (
            self.commit_or_branch
            if self.commit_or_branch in {"regzero", "audit-336", "audit-f038"}
            else self.commit_or_branch[:7]
        )
        fuzzer_out = self.out_dir / f"openvm-{label}"
        fuzzer_out.mkdir(parents=True, exist_ok=True)
        
        return BeakFuzzer(
            fuzzer_out,
            self.zkvm_dir,
            Random(self.seed),
            resolved_commit,
        )


def app():
    cli = OpenVMFuzzerClient("OpenVM", "OPENVM", OPENVM_AVAILABLE_COMMITS_OR_BRANCHES)
    cli.start()


if __name__ == "__main__":
    app()
