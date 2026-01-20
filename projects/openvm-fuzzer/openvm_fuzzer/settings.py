from openvm_fuzzer.kinds import InjectionKind, InstrKind

#
# ZKVM Specific Versions and URLs
#

OPENVM_REGZERO_COMMIT = "d7eab708f43487b2e7c00524ffd611f835e8e6b5"
OPENVM_AUDIT_336_COMMIT = "336f1a475e5aa3513c4c5a266399f4128c119bba"
OPENVM_AUDIT_F038_COMMIT = "f038f61d21db3aecd3029e1a23ba1ba0bb314800"

OPENVM_AVAILABLE_COMMITS_OR_BRANCHES = [
    "all",
    "main",
    "regzero",
    "audit-336",
    "audit-f038",
    "ca36de3803213da664b03d111801ab903d55e360",
    OPENVM_REGZERO_COMMIT,
    OPENVM_AUDIT_336_COMMIT,
    OPENVM_AUDIT_F038_COMMIT,
]
OPENVM_ZKVM_GIT_REPOSITORY = "https://github.com/DanielHoffmann91/openvm.git"
RUST_TOOLCHAIN_VERSION = "nightly-2025-02-14"


#
# Rust Magic Values
#

RUST_GUEST_RETURN_TYPE = "u32"
RUST_GUEST_CORRECT_VALUE = 0xDEADBEEF
RUST_GUEST_CORRECT_VALUE_AS_BYTES = [
    239,
    190,
    173,
    222,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
]

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
    InjectionKind.INSTR_WORD_MOD,
    # alu instructions,
    InjectionKind.BASE_ALU_RANDOM_OUTPUT,
    # load / store
    InjectionKind.LOADSTORE_SHIFT_MOD,
    InjectionKind.LOADSTORE_OPCODE_MOD,
    InjectionKind.LOADSTORE_SKIP_WRITE,
    InjectionKind.LOADSTORE_PC_MOD,
    # sign extend loads
    InjectionKind.LOAD_SIGN_EXTEND_SHIFT_MOD,
    InjectionKind.LOAD_SIGN_EXTEND_MSB_FLIPPED,
    InjectionKind.LOAD_SIGN_EXTEND_MSL_FLIPPED,
    # div / rem chip
    InjectionKind.DIVREM_FLIP_IS_SIGNED,
    InjectionKind.DIVREM_FLIP_IS_DIV,
    # auipc
    InjectionKind.AUIPC_PC_LIMBS_MODIFICATION,
    InjectionKind.AUIPC_IMM_LIMBS_MODIFICATION,
]

# NOTE: empty list disables preferences
PREFERRED_INSTRUCTIONS: list[InstrKind] = []


def resolve_openvm_commit(commit_or_branch: str) -> str:
    if commit_or_branch == "regzero":
        return OPENVM_REGZERO_COMMIT
    if commit_or_branch == "audit-336":
        return OPENVM_AUDIT_336_COMMIT
    if commit_or_branch == "audit-f038":
        return OPENVM_AUDIT_F038_COMMIT
    return commit_or_branch


def iter_openvm_snapshots() -> list[str]:
    return ["regzero", "audit-336", "audit-f038"]
