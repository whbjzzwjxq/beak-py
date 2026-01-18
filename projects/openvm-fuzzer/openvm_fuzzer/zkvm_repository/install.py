import logging
from pathlib import Path

from openvm_fuzzer.settings import (
    OPENVM_ZKVM_GIT_REPOSITORY,
)
from openvm_fuzzer.zkvm_repository.injection import openvm_fault_injection
from zkvm_fuzzer_utils.git import (
    git_clone_and_switch,
    git_reset_and_switch,
    is_git_repository,
)

logger = logging.getLogger("fuzzer")


class OpenVMManagerException(Exception):
    pass


def install_openvm(
    openvm_install_path: Path,
    commit_or_branch: str,
    *,
    enable_zkvm_modification: bool = False,
):
    logger.info(f"installing openvm zkvm @ {openvm_install_path}")

    # check if we already have the repository
    if not is_git_repository(openvm_install_path):
        # pull the repository from the official openvm github page
        logger.info(f"cloning openvm repo to {openvm_install_path}")
        git_clone_and_switch(openvm_install_path, OPENVM_ZKVM_GIT_REPOSITORY, commit_or_branch)
    else:
        # reset all current changes and pull the newest version
        logger.info(f"resetting and pulling changes for openvm repo @ {openvm_install_path}")
        git_reset_and_switch(openvm_install_path, commit_or_branch)

    # if fault injection is enabled, replace files
    if enable_zkvm_modification:
        logger.info(f"apply fault injection to openvm repo @ {openvm_install_path}")
        openvm_fault_injection(openvm_install_path, commit_or_branch)
