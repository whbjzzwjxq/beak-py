import logging
import re
from pathlib import Path

from openvm_fuzzer.settings import (
    OPENVM_AUDIT_336_COMMIT,
    OPENVM_AUDIT_F038_COMMIT,
    OPENVM_REGZERO_COMMIT,
    OPENVM_ZKVM_GIT_REPOSITORY,
    resolve_openvm_commit,
)
from openvm_fuzzer.zkvm_repository.injection import openvm_fault_injection
from zkvm_fuzzer_utils.cmd import invoke_command
from zkvm_fuzzer_utils.git import (
    git_clone_and_switch,
    git_reset_and_switch,
    is_git_repository,
)

logger = logging.getLogger("fuzzer")


class OpenVMManagerException(Exception):
    pass


def _ensure_origin_repo(openvm_install_path: Path):
    status = invoke_command(["git", "remote", "get-url", "origin"], cwd=openvm_install_path)
    if status.is_failure() or not status.stdout:
        invoke_command(
            ["git", "remote", "set-url", "origin", OPENVM_ZKVM_GIT_REPOSITORY],
            cwd=openvm_install_path,
        )
        return

    origin_url = status.stdout.strip()
    if origin_url.startswith("/") and not Path(origin_url).exists():
        invoke_command(
            ["git", "remote", "set-url", "origin", OPENVM_ZKVM_GIT_REPOSITORY],
            cwd=openvm_install_path,
        )


_PLONKY3_TAG_BY_REV = {
    "539bbc84085efb609f4f62cb03cf49588388abdb": "v1.2.0-rc.0",
    "b0591e9": "v1.0.0-rc.0",
    "88d7f05": "v1.0.0-rc.2",
}

_STARK_BACKEND_TAG_BY_COMMIT = {
    OPENVM_REGZERO_COMMIT: "v1.2.0-rc.0",
    OPENVM_AUDIT_336_COMMIT: "v1.0.0-rc.0",
    OPENVM_AUDIT_F038_COMMIT: "v1.0.0-rc.2",
}


def _resolve_stark_backend_tag(contents: str, commit_or_branch: str) -> str:
    resolved_commit = resolve_openvm_commit(commit_or_branch)
    if resolved_commit in _STARK_BACKEND_TAG_BY_COMMIT:
        return _STARK_BACKEND_TAG_BY_COMMIT[resolved_commit]

    match = re.search(r'Plonky3\\.git", rev = "([0-9a-f]+)"', contents)
    if match:
        plonky3_rev = match.group(1)
        if plonky3_rev in _PLONKY3_TAG_BY_REV:
            return _PLONKY3_TAG_BY_REV[plonky3_rev]

    return "v1.0.0-rc.2"


def _rewrite_private_stark_backend(openvm_install_path: Path, commit_or_branch: str):
    cargo_toml = openvm_install_path / "Cargo.toml"
    if not cargo_toml.exists():
        return
    contents = cargo_toml.read_text()
    if "stark-backend-private" not in contents:
        return
    tag = _resolve_stark_backend_tag(contents, commit_or_branch)
    logger.info(
        "openvm Cargo.toml depends on private stark-backend; rewriting to public tag %s",
        tag,
    )
    contents = contents.replace(
        "ssh://git@github.com/axiom-crypto/stark-backend-private.git",
        "https://github.com/openvm-org/stark-backend.git",
    )
    contents = re.sub(
        r"(openvm-stark-(?:backend|sdk) = \\{[^\\n]*?)(?:rev|tag) = \"[^\"]+\"",
        rf'\\1tag = "{tag}"',
        contents,
    )
    cargo_toml.write_text(contents)


def install_openvm(
    openvm_install_path: Path,
    commit_or_branch: str,
    *,
    enable_zkvm_modification: bool = False,
):
    logger.info(f"installing openvm zkvm @ {openvm_install_path}")

    if commit_or_branch == "all":
        raise OpenVMManagerException("'all' is not a valid install target; pick a concrete commit")

    commit_or_branch = resolve_openvm_commit(commit_or_branch)

    # check if we already have the repository
    if not is_git_repository(openvm_install_path):
        # pull the repository from the official openvm github page
        logger.info(f"cloning openvm repo to {openvm_install_path}")
        git_clone_and_switch(openvm_install_path, OPENVM_ZKVM_GIT_REPOSITORY, commit_or_branch)
    else:
        _ensure_origin_repo(openvm_install_path)
        # reset all current changes and pull the newest version
        logger.info(f"resetting and pulling changes for openvm repo @ {openvm_install_path}")
        git_reset_and_switch(openvm_install_path, commit_or_branch)

    _rewrite_private_stark_backend(openvm_install_path, commit_or_branch)

    # if fault injection is enabled, replace files
    if enable_zkvm_modification:
        logger.info(f"apply fault injection to openvm repo @ {openvm_install_path}")
        openvm_fault_injection(openvm_install_path, commit_or_branch)
