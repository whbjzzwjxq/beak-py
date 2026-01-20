#!/usr/bin/env python3

import logging
from random import Random

from sp1_fuzzer.fuzzer import Sp1BeakFuzzer
from sp1_fuzzer.settings import SP1_AVAILABLE_COMMITS_OR_BRANCHES, iter_sp1_snapshots, resolve_sp1_commit
from sp1_fuzzer.zkvm_repository.install import install_sp1
from zkvm_fuzzer_utils.cli import FuzzerClient

logger = logging.getLogger("fuzzer")


def _iter_supported_commits() -> list[str]:
    # For "all", we want a stable set of named snapshots (no duplicate aliases/hashes).
    return iter_sp1_snapshots()


class SP1FuzzerClient(FuzzerClient):
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
            resolved = resolve_sp1_commit(commit)
            # Ensure repo is on the correct commit before building.
            install_sp1(self.zkvm_dir, resolved)

            # Keep output dirs stable and human-readable for snapshot aliases.
            label = commit if commit in {"s26", "s27", "s29"} else commit[:7]
            fuzzer_out = self.out_dir / f"sp1-{label}"
            fuzzer_out.mkdir(parents=True, exist_ok=True)
            fuzzer = Sp1BeakFuzzer(fuzzer_out, self.zkvm_dir, Random(self.seed), resolved)

            # For "all" we do a single loop-1 pass per snapshot (initial internal loop).
            # For a single commit, default to a single pass unless a timeout is explicitly set.
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
            install_sp1(self.zkvm_dir, resolve_sp1_commit(commit))

    def check(self):
        raise NotImplementedError("No bugs to check yet!")

    def generate(self):
        raise NotImplementedError("Use 'run' for loop1 generation+execution.")


def app():
    cli = SP1FuzzerClient("SP1", "SP1", SP1_AVAILABLE_COMMITS_OR_BRANCHES)
    cli.start()


if __name__ == "__main__":
    app()
