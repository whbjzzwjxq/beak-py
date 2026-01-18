from nexus_fuzzer.kinds import InjectionKind, InstrKind

#
# ZKVM Specific Versions and URLs
#

NEXUS_AVAILABLE_COMMITS_OR_BRANCHES = [
    "main",
    "8f4ba5699abba2b6243027c8b455305746afb1bf",
    # Title: Multiplication triggers Prover Crash #413
    # Links:
    #   - https://github.com/nexus-xyz/nexus-zkvm/issues/413
    # Type: completeness / fuzzer
    "c684c4e78b3a79fd0d6b0bebcce298bce4087cff",  # <= fix
    "f1b895b868915fd4d0a794a5bc730e6cb8d840f6",  # <= bug
    # Title: Bug: Prover and Verifier Succeed Despite Invalid Execution #404
    # Links:
    #   - https://github.com/nexus-xyz/nexus-zkvm/issues/404
    # Type: soundness / injection
    "62e3abc27fe41fe474822e398756bf8b60b53e7b",  # <= fix
    "be32013bc6215155e95774f3476f734b1c66f870",  # <= bug
    # Title: Prover Panic: index out of bounds #368
    # Links:
    #   - https://github.com/nexus-xyz/nexus-zkvm/issues/368
    # Type: completeness / fuzzer
    "54cebc74228654e2718457f7dc398b66de44bbec",  # <= fix
    "41c6c6080f46b97980053c47b078321225b4338a",  # <= bug
]
NEXUS_ZKVM_GIT_REPOSITORY = "https://github.com/DanielHoffmann91/nexus-zkvm.git"


# sets the appropriate rust toolchain version
def get_rust_toolchain_version(commit_or_branch: str) -> str:
    # sets the appropriate rust toolchain and target versions
    if commit_or_branch in [
        "54cebc74228654e2718457f7dc398b66de44bbec",
        "41c6c6080f46b97980053c47b078321225b4338a",
    ]:
        return "nightly-2025-01-02"
    else:
        return "nightly-2025-04-06"


# sets the appropriate riscv target versions
def get_riscv_target(commit_or_branch: str) -> str:

    if commit_or_branch in [
        "62e3abc27fe41fe474822e398756bf8b60b53e7b",
        "be32013bc6215155e95774f3476f734b1c66f870",
        "54cebc74228654e2718457f7dc398b66de44bbec",
        "41c6c6080f46b97980053c47b078321225b4338a",
    ]:
        return "riscv32i-unknown-none-elf"
    else:
        return "riscv32im-unknown-none-elf"


#
# Rust Magic Values
#

RUST_GUEST_RETURN_TYPE = "u32"
RUST_GUEST_CORRECT_VALUE = 0xDEADBEEF

#
# Flag to decide if division and modulo of 0 should be transformed
#

APPLY_SAFE_REM_DIV_TRANSFORMATION = True

#
# Special Timeout handling
#

TIMEOUT_PER_RUN = 60 * 4  # 4 min, in seconds
TIMEOUT_PER_BUILD = 60 * 30  # 30 min, in seconds

#
# Injection Specifics
#

ENABLED_INJECTION_KINDS: list[InjectionKind] = [
    InjectionKind.POST_EXEC_PC_MOD,
    InjectionKind.INSTR_WORD_MOD,
]

# NOTE: empty list disables preferences
PREFERRED_INSTRUCTIONS: list[InstrKind] = []
