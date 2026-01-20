#!/usr/bin/env python3

import logging
from random import Random

from nexus_fuzzer.fuzzer import NexusBeakFuzzer
from nexus_fuzzer.settings import NEXUS_AVAILABLE_COMMITS_OR_BRANCHES
from nexus_fuzzer.zkvm_repository.install import install_nexus
from zkvm_fuzzer_utils.cli import FuzzerClient

logger = logging.getLogger("fuzzer")


def _iter_supported_commits() -> list[str]:
    return [c for c in NEXUS_AVAILABLE_COMMITS_OR_BRANCHES if c != "all"]


class NexusFuzzerClient(FuzzerClient):
    def run(self):
        assert self.out_dir, "no output directory"
        assert self.zkvm_dir, "no zkvm library"

        logger.info(f"=== Start {self.logger_prefix} Fuzzing Campaign ===")
        logger.info(f" * seed: {self.seed}")
        logger.info(f" * output: {self.out_dir}")
        logger.info(f" * library: {self.zkvm_dir}")
        logger.info(f" * commit: {self.commit_or_branch}")
        logger.info("===")

        commits = _iter_supported_commits() if self.commit_or_branch == "all" else [self.commit_or_branch]

        for commit in commits:
            install_nexus(self.zkvm_dir, commit)

            fuzzer_out = self.out_dir / f"nexus-{commit[:7]}"
            fuzzer_out.mkdir(parents=True, exist_ok=True)
            fuzzer = NexusBeakFuzzer(fuzzer_out, self.zkvm_dir, Random(self.seed), commit)

            if self.commit_or_branch == "all" or self.timeout is None or self.timeout <= 0:
                fuzzer.run()
            else:
                fuzzer.enable_timeout(self.timeout)
                fuzzer.loop()

        logger.info(f"=== End {self.logger_prefix} Fuzzing Campaign ===")

    def install(self):
        assert self.zkvm_dir, "no zkvm library"
        commits = _iter_supported_commits() if self.commit_or_branch == "all" else [self.commit_or_branch]
        for commit in commits:
            install_nexus(self.zkvm_dir, commit)

    def check(self):
        raise NotImplementedError("No bugs to check yet!")

    def generate(self):
        raise NotImplementedError("Use 'run' for loop1 generation+execution.")


def app():
    cli = NexusFuzzerClient("NEXUS", "Nexus", NEXUS_AVAILABLE_COMMITS_OR_BRANCHES)
    cli.start()


if __name__ == "__main__":
    app()

