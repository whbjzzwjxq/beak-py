from sp1_fuzzer.kinds import InjectionKind, InstrKind

#
# ZKVM Specific Versions and URLs
#

# NOTE: "all" is a convenience option that iterates over the supported commits.
SP1_AVAILABLE_COMMITS_OR_BRANCHES = [
    "all",
    # Fuzzer-maintained vulnerable snapshots (from audit mapping):
    # - `7f643da...`: S26 + S28 family (old architecture)
    # - `f3326e6...`: S27 (v4 CPU chip; is_memory not sent in instruction interaction ABI)
    # - `811a3f2...`: S29 (global interaction kind missing from message)
    "7f643da16813af4c0fbaad4837cd7409386cf38c",
    "f3326e6d0bf78d6b4650ea1e26c501d72fb3c90b",
    "811a3f2c03914088c7c9e1774266934a3f9f5359",
]
SP1_ZKVM_GIT_REPOSITORY = "https://github.com/succinctlabs/sp1.git"
RUST_TOOLCHAIN_VERSION = "stable"

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
