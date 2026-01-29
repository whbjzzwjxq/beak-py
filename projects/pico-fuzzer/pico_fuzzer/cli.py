#!/usr/bin/env python3

import logging
from random import Random

from pico_fuzzer.fuzzer import PicoBeakFuzzer
from pico_fuzzer.settings import PICO_AVAILABLE_COMMITS_OR_BRANCHES
from pico_fuzzer.zkvm_repository.install import install_pico
from zkvm_fuzzer_utils.cli import FuzzerClient

logger = logging.getLogger("fuzzer")


def _iter_supported_commits() -> list[str]:
    return [c for c in PICO_AVAILABLE_COMMITS_OR_BRANCHES if c != "all"]


class PicoFuzzerClient(FuzzerClient):
    def run(self):
        assert self.out_dir, "no output directory"
        assert self.zkvm_dir, "no zkvm library"

        logger.info(f"=== Start {self.logger_prefix} Fuzzing Campaign ===")
        logger.info(f" * seed: {self.seed}")
        logger.info(f" * output: {self.out_dir}")
        logger.info(f" * library: {self.zkvm_dir}")
        logger.info(f" * commit: {self.commit_or_branch}")
        logger.info("===")

        commits = (
            _iter_supported_commits()
            if self.commit_or_branch == "all"
            else [self.commit_or_branch]
        )

        for commit in commits:
            install_pico(self.zkvm_dir, commit, enable_zkvm_modification=(not self.is_zkvm_modification))

            fuzzer_out = self.out_dir / f"pico-{commit[:7]}"
            fuzzer_out.mkdir(parents=True, exist_ok=True)
            fuzzer = PicoBeakFuzzer(fuzzer_out, self.zkvm_dir, Random(self.seed), commit)

            if self.commit_or_branch == "all" or self.timeout is None or self.timeout <= 0:
                fuzzer.run()
            else:
                fuzzer.enable_timeout(self.timeout)
                fuzzer.loop()

        logger.info(f"=== End {self.logger_prefix} Fuzzing Campaign ===")

    def install(self):
        assert self.zkvm_dir, "no zkvm library"
        commits = (
            _iter_supported_commits()
            if self.commit_or_branch == "all"
            else [self.commit_or_branch]
        )
        for commit in commits:
            install_pico(self.zkvm_dir, commit, enable_zkvm_modification=(not self.is_zkvm_modification))

    def check(self):
        raise NotImplementedError("No bugs to check yet!")

    def generate(self):
        raise NotImplementedError("Use 'run' for loop1 generation+execution.")


def app():
    cli = PicoFuzzerClient("PICO", "Pico", PICO_AVAILABLE_COMMITS_OR_BRANCHES)
    cli.start()


if __name__ == "__main__":
    app()
