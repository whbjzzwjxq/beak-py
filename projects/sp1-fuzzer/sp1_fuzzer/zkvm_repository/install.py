import logging
from pathlib import Path

from sp1_fuzzer.settings import (
    SP1_ZKVM_GIT_REPOSITORY,
)
from sp1_fuzzer.zkvm_repository.injection import sp1_fault_injection
from zkvm_fuzzer_utils.git import (
    git_clone_and_switch,
    git_reset_and_switch,
    is_git_repository,
)

logger = logging.getLogger("fuzzer")


def install_sp1(
    sp1_install_path: Path,
    commit_or_branch: str,
    *,
    enable_zkvm_modification: bool = False,
):
    # check if we already have the repository
    if not is_git_repository(sp1_install_path):
        # pull the repository from the official sp1 github page
        logger.info(f"cloning sp1 repo to {sp1_install_path}")
        git_clone_and_switch(sp1_install_path, SP1_ZKVM_GIT_REPOSITORY, commit_or_branch)
    else:
        # reset all current changes and pull the newest version
        logger.info(f"resetting and pulling changes for sp1 repo @ {sp1_install_path}")
        git_reset_and_switch(sp1_install_path, commit_or_branch)

    # if fault injection is enabled, replace files
    if enable_zkvm_modification:
        logger.info(f"apply fault injection to sp1 repo @ {sp1_install_path}")
        sp1_fault_injection(sp1_install_path, commit_or_branch)
