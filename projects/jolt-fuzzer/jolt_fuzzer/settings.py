from jolt_fuzzer.kinds import InjectionKind, InstrKind

#
# ZKVM Specific Versions and URLs
#

JOLT_AVAILABLE_COMMITS_OR_BRANCHES = [
    "main",
    "1687134d117a19d1f6c6bd03fd23191013c53d1b",
    # Title: Sumcheck verification failed for MULHSU Instruction #833
    # Link:
    #   - https://github.com/a16z/jolt/issues/833
    # Type: completeness / fuzzer
    "0369981446471c2ed2c4a4d2f24d61205a2d0853",  # <= fix
    "d59219a0633d91dc5dbe19ade5f66f179c27c834",  # <= bug
    # Title: Panic in bytecode module during preprocessing #824
    # Link:
    #   - https://github.com/a16z/jolt/issues/824
    # Type: completeness / fuzzer
    "0582b2aa4a33944506d75ce891db7cf090814ff6",  # <= fix
    "57ea518d6d9872fb221bf6ac97df1456a5494cf2",  # <= bug
    # Title: Prover and/or Verifier Fail on Correct Program for Specific Arguments #741 (2/2)
    # Additional Info: Problem 1
    # Link:
    #   - https://github.com/a16z/jolt/issues/741
    # Type: completeness / fuzzer
    "20ac6eb526af383e7b597273990b5e4b783cc2a6",  # <= fix
    "70c77337426615b67191b301e9175e2bb093830d",  # <= bug
    # Title: Prover and/or Verifier Fail on Correct Program for Specific Arguments #741 (1/2)
    # Additional Info: Problem 2
    # Link:
    #   - https://github.com/a16z/jolt/issues/741
    # Type: completeness / fuzzer
    "55b9830a3944dde55d33a55c42522b81dd49f87a",  # <= fix
    "42de0ca1f581dd212dda7ff44feee806556531d2",  # <= bug
    # Title: Soundness Issue with LUI #719
    # Link:
    #   - https://github.com/a16z/jolt/issues/719
    # Type: soundness / injection
    "85bf51da10efa9c679c35ffc1a8d45cc6cb1c788",  # <= fix
    "e9caa23565dbb13019afe61a2c95f51d1999e286",  # <= bug
]
JOLT_ZKVM_GIT_REPOSITORY = "https://github.com/DanielHoffmann91/jolt.git"


# sets the appropriate rust toolchain version
def get_rust_toolchain_version(commit_or_branch: str) -> str:
    # sets the appropriate rust toolchain and target versions
    if commit_or_branch in [
        "55b9830a3944dde55d33a55c42522b81dd49f87a",
        "42de0ca1f581dd212dda7ff44feee806556531d2",
        "85bf51da10efa9c679c35ffc1a8d45cc6cb1c788",
        "e9caa23565dbb13019afe61a2c95f51d1999e286",
    ]:
        return "nightly-2025-04-06"
    else:
        return "1.88"


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
    InjectionKind.INSTR_WORD_MOD,
]

# NOTE: empty list disables preferences
PREFERRED_INSTRUCTIONS: list[InstrKind] = [
    # InstrKind.LUI,
]
