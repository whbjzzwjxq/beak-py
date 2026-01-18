import logging
from pathlib import Path

from jolt_fuzzer.settings import (
    JOLT_ZKVM_GIT_REPOSITORY,
)
from jolt_fuzzer.zkvm_repository.injection import jolt_fault_injection
from zkvm_fuzzer_utils.file import replace_in_file
from zkvm_fuzzer_utils.git import (
    git_clone_and_switch,
    git_reset_and_switch,
    is_git_repository,
)

logger = logging.getLogger("fuzzer")


def install_jolt(
    jolt_install_path: Path,
    commit_or_branch: str,
    *,
    enable_zkvm_modification: bool = False,
):
    logger.info(f"installing jolt zkvm @ {jolt_install_path}")

    # check if we already have the repository
    if not is_git_repository(jolt_install_path):
        # pull the repository from the official jolt github page
        logger.info(f"cloning jolt repo to {jolt_install_path}")
        git_clone_and_switch(jolt_install_path, JOLT_ZKVM_GIT_REPOSITORY, commit_or_branch)
    else:
        # reset all current changes and pull the newest version
        logger.info(f"resetting and pulling changes for jolt repo @ {jolt_install_path}")
        git_reset_and_switch(jolt_install_path, commit_or_branch)

    # if fault injection is enabled, replace files
    if enable_zkvm_modification:
        logger.info(f"apply fault injection to jolt repo @ {jolt_install_path}")
        jolt_fault_injection(jolt_install_path, commit_or_branch)

    # NOTE: This hotfix is REQUIRED even if no modification is set.
    #       This is due to the lose dependency on the twist and shout branch
    #       instead of a concrete commit.
    if commit_or_branch in [
        "0582b2aa4a33944506d75ce891db7cf090814ff6",
        "57ea518d6d9872fb221bf6ac97df1456a5494cf2",
        "20ac6eb526af383e7b597273990b5e4b783cc2a6",
        "70c77337426615b67191b301e9175e2bb093830d",
    ]:
        logger.info("Set 'dev/twist-shout' commit to 'efc56e0d2f1129257a35c078b13dd017aeceff91'")
        replace_in_file(
            jolt_install_path / "Cargo.lock",
            [
                (
                    r"\?branch=dev%2Ftwist-shout\)",
                    "?branch=dev%2Ftwist-shout#efc56e0d2f1129257a35c078b13dd017aeceff91)",
                ),
            ],
        )
