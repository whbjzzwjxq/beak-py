import logging
from pathlib import Path

from nexus_fuzzer.settings import (
    NEXUS_ZKVM_GIT_REPOSITORY,
)
from nexus_fuzzer.zkvm_repository.injection import nexus_fault_injection
from zkvm_fuzzer_utils.git import (
    git_clone_and_switch,
    git_reset_and_switch,
    is_git_repository,
)

logger = logging.getLogger("fuzzer")


class NexusManagerException(Exception):
    pass


def install_nexus(
    nexus_install_path: Path,
    commit_or_branch: str,
    *,
    enable_zkvm_modification: bool = False,
):
    # check if we already have the repository
    if not is_git_repository(nexus_install_path):
        # pull the repository from the official nexus github page
        logger.info(f"cloning nexus repo to {nexus_install_path}")
        git_clone_and_switch(nexus_install_path, NEXUS_ZKVM_GIT_REPOSITORY, commit_or_branch)
    else:
        # reset all current changes and pull the newest version
        logger.info(f"resetting and pulling changes for nexus repo @ {nexus_install_path}")
        git_reset_and_switch(nexus_install_path, commit_or_branch)

    # if fault injection is enabled, replace files
    if enable_zkvm_modification:
        logger.info(f"apply fault injection to nexus repo @ {nexus_install_path}")
        nexus_fault_injection(nexus_install_path, commit_or_branch)
