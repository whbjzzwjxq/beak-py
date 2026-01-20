from nexus_fuzzer.kinds import InjectionKind, InstrKind

#
# ZKVM Specific Versions and URLs
#

# NOTE: "all" is a convenience option that iterates over the supported commits.
NEXUS_AVAILABLE_COMMITS_OR_BRANCHES = [
    "all",
    "main",
    # Keep parity with arguzz's curated snapshots.
    "8f4ba5699abba2b6243027c8b455305746afb1bf",
    "c684c4e78b3a79fd0d6b0bebcce298bce4087cff",
    "f1b895b868915fd4d0a794a5bc730e6cb8d840f6",
    "62e3abc27fe41fe474822e398756bf8b60b53e7b",
    "be32013bc6215155e95774f3476f734b1c66f870",
    "54cebc74228654e2718457f7dc398b66de44bbec",
    "41c6c6080f46b97980053c47b078321225b4338a",
]
NEXUS_ZKVM_GIT_REPOSITORY = "https://github.com/DanielHoffmann91/nexus-zkvm.git"


def get_rust_toolchain_version(commit_or_branch: str) -> str:
    if commit_or_branch in [
        "54cebc74228654e2718457f7dc398b66de44bbec",
        "41c6c6080f46b97980053c47b078321225b4338a",
    ]:
        return "nightly-2025-01-02"
    return "nightly-2025-04-06"


def get_riscv_target(commit_or_branch: str) -> str:
    if commit_or_branch in [
        "62e3abc27fe41fe474822e398756bf8b60b53e7b",
        "be32013bc6215155e95774f3476f734b1c66f870",
        "54cebc74228654e2718457f7dc398b66de44bbec",
        "41c6c6080f46b97980053c47b078321225b4338a",
    ]:
        return "riscv32i-unknown-none-elf"
    return "riscv32im-unknown-none-elf"


#
# Special Timeout handling
#

TIMEOUT_PER_RUN = 60 * 4  # 4 min, in seconds
TIMEOUT_PER_BUILD = 60 * 30  # 30 min, in seconds

#
# Injection Specifics (unused for loop1 baseline)
#

ENABLED_INJECTION_KINDS: list[InjectionKind] = [InjectionKind.NONE]
PREFERRED_INSTRUCTIONS: list[InstrKind] = []

