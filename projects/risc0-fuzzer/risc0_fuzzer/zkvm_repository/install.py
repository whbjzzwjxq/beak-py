import logging
from pathlib import Path

from risc0_fuzzer.settings import RISC0_ZKVM_GIT_REPOSITORY
from risc0_fuzzer.zkvm_repository.injection import risc0_fault_injection
from zkvm_fuzzer_utils.git import (
    git_clone_and_switch,
    git_reset_and_switch,
    is_git_repository,
)

logger = logging.getLogger("fuzzer")


def install_risc0(
    risc0_install_path: Path,
    commit_or_branch: str,
    *,
    enable_zkvm_modification: bool = False,
):
    # check if we already have the repository
    if not is_git_repository(risc0_install_path):
        # pull the repository from the official risc0 github page
        logger.info(f"cloning risc0 repo to {risc0_install_path}")
        git_clone_and_switch(risc0_install_path, RISC0_ZKVM_GIT_REPOSITORY, commit_or_branch)
    else:
        # reset all current changes and pull the newest version
        logger.info(f"resetting and pulling changes for risc0 repo @ {risc0_install_path}")
        git_reset_and_switch(risc0_install_path, commit_or_branch)

    # if fault injection is enabled, replace files
    if enable_zkvm_modification:
        logger.info(f"apply fault injection to risc0 repo @ {risc0_install_path}")
        risc0_fault_injection(risc0_install_path, commit_or_branch)
