import logging
from pathlib import Path

from pico_fuzzer.settings import (
    PICO_ZKVM_GIT_REPOSITORY,
    RUST_TOOLCHAIN_VERSION,
)
from pico_fuzzer.zkvm_repository.injection import pico_fault_injection
from zkvm_fuzzer_utils.git import (
    git_clone_and_switch,
    git_reset_and_switch,
    is_git_repository,
)
from zkvm_fuzzer_utils.rust.cargo import CargoCmd

logger = logging.getLogger("fuzzer")


def install_pico(
    pico_install_path: Path,
    commit_or_branch: str,
    *,
    enable_zkvm_modification: bool = False,
):
    logger.info(f"installing pico zkvm @ {pico_install_path}")

    # check if we already have the repository
    if not is_git_repository(pico_install_path):
        # pull the repository from the official pico github page
        logger.info(f"cloning pico repo to {pico_install_path}")
        git_clone_and_switch(pico_install_path, PICO_ZKVM_GIT_REPOSITORY, commit_or_branch)
    else:
        # reset all current changes and pull the newest version
        logger.info(f"resetting and pulling changes for pico repo @ {pico_install_path}")
        git_reset_and_switch(pico_install_path, commit_or_branch)

    # if fault injection is enabled, replace files
    if enable_zkvm_modification:
        logger.info(f"apply fault injection to pico repo @ {pico_install_path}")
        pico_fault_injection(pico_install_path, commit_or_branch)

    # install pico-cli cargo tool
    pico_cli_path = pico_install_path / "sdk" / "cli"
    install_run = (
        CargoCmd.install()
        .with_toolchain(RUST_TOOLCHAIN_VERSION)
        .with_path(Path("."))
        .with_cd(pico_cli_path)
        .use_force()
        .use_locked()
        .execute()
    )
    if install_run.is_failure():
        logger.info(install_run)
        logger.critical(f"Unable to install pico-cli binary from {pico_cli_path}")
        raise RuntimeError("failed to install pico client")
