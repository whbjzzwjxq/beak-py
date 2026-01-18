from sp1_fuzzer.kinds import InjectionKind, InstrKind

#
# ZKVM Specific Versions and URLs
#

SP1_AVAILABLE_COMMITS_OR_BRANCHES = [
    "dev",
    "429e95e00a51db1f3d7257e7db73c7fe0fd40801",
]
SP1_ZKVM_GIT_REPOSITORY = "https://github.com/DanielHoffmann91/sp1.git"
RUST_TOOLCHAIN_VERSION = "stable"

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
    InjectionKind.POST_EXEC_PRE_COMMIT_PC_MOD,
    InjectionKind.POST_EXEC_POST_COMMIT_PC_MOD,
    InjectionKind.INSTR_WORD_MOD,
    InjectionKind.ALU_RESULT_MOD,
    InjectionKind.ALU_RESULT_LOC_MOD,
    InjectionKind.ALU_PARSED_OPERAND_MOD,
    InjectionKind.EXECUTE_INSTRUCTION_AGAIN,
    InjectionKind.ALU_LOAD_OPERAND_MOD,
    InjectionKind.SYS_CALL_MOD_ECALL_ID,
]

# NOTE: empty list disables preferences
PREFERRED_INSTRUCTIONS: list[InstrKind] = []
