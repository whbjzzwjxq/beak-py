#!/usr/bin/env python3

import logging
from random import Random

from openvm_fuzzer.fuzzer import BeakFuzzer
from openvm_fuzzer.settings import (
    OPENVM_AVAILABLE_COMMITS_OR_BRANCHES,
    iter_openvm_snapshots,
    resolve_openvm_commit,
)
from openvm_fuzzer.zkvm_project import CircuitProjectGenerator
from openvm_fuzzer.zkvm_repository.install import install_openvm
from zkvm_fuzzer_utils.cli import FuzzerClient

logger = logging.getLogger("fuzzer")


class OpenVMFuzzerClient(FuzzerClient):
    def run(self):
        assert self.out_dir, "no output directory"
        assert self.zkvm_dir, "no zkvm library"

        logger.info(f"=== Start {self.logger_prefix} Fuzzing Loop ===")
        logger.info(f" * seed: {self.seed}")
        logger.info(f" * output: {self.out_dir}")
        logger.info(f" * library: {self.zkvm_dir}")
        logger.info(f" * commit: {self.commit_or_branch}")
        logger.info("===")

        commits = (
            iter_openvm_snapshots()
            if self.commit_or_branch == "all"
            else [self.commit_or_branch]
        )

        for commit in commits:
            resolved = resolve_openvm_commit(commit)
            install_openvm(self.zkvm_dir, resolved, enable_zkvm_modification=(not self.is_zkvm_modification))

            label = commit if commit in {"regzero", "audit-336", "audit-f038"} else commit[:7]
            fuzzer_out = self.out_dir / f"openvm-{label}"
            fuzzer_out.mkdir(parents=True, exist_ok=True)
            fuzzer = BeakFuzzer(
                fuzzer_out,
                self.zkvm_dir,
                Random(self.seed),
                resolved,
            )

            if self.timeout is not None and self.timeout > 0:
                fuzzer.enable_timeout(self.timeout)

            # For snapshot runs, default to a single loop1 iteration.
            if self.commit_or_branch == "all" or self.timeout is None or self.timeout <= 0:
                fuzzer.run()
            else:
                fuzzer.loop()

        logger.info(f"=== End {self.logger_prefix} Fuzzing Campaign ===")

    def install(self):
        assert self.zkvm_dir, "no zkvm library"
        commits = (
            iter_openvm_snapshots()
            if self.commit_or_branch == "all"
            else [self.commit_or_branch]
        )
        for commit in commits:
            install_openvm(
                self.zkvm_dir,
                resolve_openvm_commit(commit),
                enable_zkvm_modification=(not self.is_zkvm_modification),
            )

    def check(self):
        raise NotImplementedError("No bugs to check yet!")

    def generate(self):
        assert self.out_dir, "no output directory"
        assert self.zkvm_dir, "no zkvm library"
        
        fuzzer = BeakFuzzer(
            self.out_dir,
            self.zkvm_dir,
            Random(self.seed),
            self.commit_or_branch,
        )
        # Manually trigger one generation run for the 'generate' command
        fuzzer.run()


def app():
    cli = OpenVMFuzzerClient("OpenVM", "OPENVM", OPENVM_AVAILABLE_COMMITS_OR_BRANCHES)
    cli.start()


if __name__ == "__main__":
    app()
