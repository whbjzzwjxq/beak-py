from pico_fuzzer.kinds import InjectionKind, InstrKind

#
# ZKVM Specific Versions and URLs
#

PICO_AVAILABLE_COMMITS_OR_BRANCHES = [
    "main",
    "dd5b7d1f4e164d289d110f1688509a22af6b241c",
]
PICO_ZKVM_GIT_REPOSITORY = "https://github.com/DanielHoffmann91/pico.git"
RUST_TOOLCHAIN_VERSION = "nightly-2024-11-27"

#
# Rust Magic Values
#

RUST_GUEST_RETURN_TYPE = "u32"
RUST_GUEST_CORRECT_VALUE = 0xDEADBEEF
RUST_GUEST_CORRECT_VALUE_AS_BYTES = [239, 190, 173, 222]

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
    InjectionKind.EMULATE_RANDOM_INSTRUCTION,
    InjectionKind.MODIFY_OUTPUT_VALUE,
]

# NOTE: empty list disables preferences
PREFERRED_INSTRUCTIONS: list[InstrKind] = []
