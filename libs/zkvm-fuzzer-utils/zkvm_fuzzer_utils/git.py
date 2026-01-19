import logging
from pathlib import Path

from zkvm_fuzzer_utils.cmd import ExecStatus, invoke_command
from zkvm_fuzzer_utils.file import path_to_binary

GIT = path_to_binary("git")

logger = logging.getLogger("fuzzer")


# ---------------------------------------------------------------------------- #
#                                 Git Exception                                #
# ---------------------------------------------------------------------------- #


class GitException(Exception):
    pass


# ---------------------------------------------------------------------------- #
#                           Git Private Local Helper                           #
# ---------------------------------------------------------------------------- #


def __git_check_for_failure(status: ExecStatus, error_msg: str, exception_msg: str):
    if status.is_failure():
        logger.critical(error_msg)
        logger.info("=== STDOUT ===")
        logger.info(status.stdout)
        logger.info("=== STDERR ===")
        logger.info(status.stderr)
        logger.info("==============")
        raise GitException(exception_msg)


# ---------------------------------------------------------------------------- #
#                             Git Helper Functions                             #
# ---------------------------------------------------------------------------- #


def is_git_repository(path: Path) -> bool:
    git_entry = path / ".git"
    # Worktrees store a `.git` *file* that points to the real gitdir.
    return git_entry.is_dir() or git_entry.is_file()


# ---------------------------------------------------------------------------- #


def git_clone(repo_url: str, target: Path, branch: str | None = None):
    cmd = ["git", "clone"]
    if branch:
        cmd += ["-b", branch]
    cmd += [repo_url, str(target)]
    __git_check_for_failure(
        invoke_command(cmd),
        f"Unable to clone git repository {repo_url} to {target}",
        f"Unable to clone git repository {repo_url}",
    )


# ---------------------------------------------------------------------------- #


def git_pull(repo_dir: Path):
    __git_check_for_failure(
        invoke_command(["git", "pull"], cwd=repo_dir),
        f"Unable to pull git repository {repo_dir}",
        f"Unable to pull git repository {repo_dir}",
    )


# ---------------------------------------------------------------------------- #


def git_fetch(repo_dir: Path):
    __git_check_for_failure(
        invoke_command(["git", "fetch", "origin"], cwd=repo_dir),
        f"Unable to fetch git origin for repository {repo_dir}",
        f"Unable to fetch git origin for repository {repo_dir}",
    )


# ---------------------------------------------------------------------------- #


def git_reset_hard(repo_dir: Path):
    __git_check_for_failure(
        invoke_command(["git", "reset", "--hard", "HEAD"], cwd=repo_dir),
        f"Unable to hard reset git repository {repo_dir}",
        f"Unable to hard reset git repository {repo_dir}",
    )


# ---------------------------------------------------------------------------- #


def git_clean(repo_dir: Path):
    __git_check_for_failure(
        invoke_command(["git", "clean", "-fdx"], cwd=repo_dir),
        f"Unable to clean files of git repository {repo_dir}",
        f"Unable to clean files of git repository {repo_dir}",
    )


# ---------------------------------------------------------------------------- #


def git_checkout(repo_dir: Path, commit: str):
    status = invoke_command(["git", "checkout", f"{commit}"], cwd=repo_dir)
    if not status.is_failure():
        return

    # If this repo is a git worktree, a branch may already be checked out in a
    # different worktree. In that case, fall back to a detached checkout of the
    # corresponding remote branch.
    #
    # Example stderr:
    #   fatal: 'main' is already checked out at '/path/to/other/worktree'
    if "already checked out at" in (status.stderr or ""):
        logger.info(
            "Branch '%s' is already checked out in another worktree; falling back to detached checkout.",
            commit,
        )
        detached_status = invoke_command(["git", "checkout", "--detach", f"origin/{commit}"], cwd=repo_dir)
        __git_check_for_failure(
            detached_status,
            f"Unable to detached-checkout origin/{commit} for {repo_dir}",
            f"Unable to checkout git commit / branch {commit} for {repo_dir.name}",
        )
        return

    __git_check_for_failure(
        status,
        f"Unable to checkout git commit / branch {commit} for {repo_dir}",
        f"Unable to checkout git commit / branch {commit} for {repo_dir.name}",
    )


# ---------------------------------------------------------------------------- #
#                               Combined Actions                               #
# ---------------------------------------------------------------------------- #


def git_clone_and_switch(repo_dir: Path, repo_url: str, commit: str = "main"):
    git_clone(repo_url, repo_dir)
    git_checkout(repo_dir, commit)


# ---------------------------------------------------------------------------- #


def git_reset_and_switch(repo_dir: Path, commit: str = "main"):
    git_reset_hard(repo_dir)
    git_clean(repo_dir)
    git_fetch(repo_dir)
    git_checkout(repo_dir, commit)


# ---------------------------------------------------------------------------- #
