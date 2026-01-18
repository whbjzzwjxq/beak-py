# ---------------------------------------------------------------------------- #
#                               Default Settings                               #
# ---------------------------------------------------------------------------- #

: "${ZKVM_NAME:=nexus}"
: "${VERBOSITY:=0}"
: "${TRACE_COLLECTION:=true}"
: "${FAULT_INJECTION:=true}"
: "${ZKVM_MODIFICATION:=true}"
: "${PODMAN_PODS:=5}"
: "${PODMAN_CPUS:=4}"
: "${FINDINGS_COMMIT_OR_BRANCH:=todo-set-me}"
: "${COMMIT_OR_BRANCH:=8f4ba5699abba2b6243027c8b455305746afb1bf}"
: "${FUZZER_TIMEOUT:=0}"
: "${DEFAULT_MASTER_SEED:=789123}"
: "${ONLY_MOD_WORD:=true}"
: "${NO_INLINE_ASSEMBLY:=false}"
: "${NO_SCHEDULAR:=false}"

# ---------------------------------------------------------------------------- #
#                                    Commits                                   #
# ---------------------------------------------------------------------------- #

BUG_COMMITS=(
    # Title: Multiplication triggers Prover Crash #413
    f1b895b868915fd4d0a794a5bc730e6cb8d840f6
    # Title: Bug: Prover and Verifier Succeed Despite Invalid Execution #404
    be32013bc6215155e95774f3476f734b1c66f870
    # Title: Prover Panic: index out of bounds #368
    41c6c6080f46b97980053c47b078321225b4338a
)

FIX_COMMITS=(
    # Title: Multiplication triggers Prover Crash #413
    c684c4e78b3a79fd0d6b0bebcce298bce4087cff
    # Title: Bug: Prover and Verifier Succeed Despite Invalid Execution #404
    62e3abc27fe41fe474822e398756bf8b60b53e7b
    # Title: Prover Panic: index out of bounds #368
    54cebc74228654e2718457f7dc398b66de44bbec
)

# ---------------------------------------------------------------------------- #
#                                    Banner                                    #
# ---------------------------------------------------------------------------- #

banner() {
echo ""
echo "███╗   ██╗███████╗██╗  ██╗██╗   ██╗███████╗    ███████╗██╗   ██╗███████╗███████╗██╗███╗   ██╗ ██████╗ "
echo "████╗  ██║██╔════╝╚██╗██╔╝██║   ██║██╔════╝    ██╔════╝██║   ██║╚══███╔╝╚══███╔╝██║████╗  ██║██╔════╝ "
echo "██╔██╗ ██║█████╗   ╚███╔╝ ██║   ██║███████╗    █████╗  ██║   ██║  ███╔╝   ███╔╝ ██║██╔██╗ ██║██║  ███╗"
echo "██║╚██╗██║██╔══╝   ██╔██╗ ██║   ██║╚════██║    ██╔══╝  ██║   ██║ ███╔╝   ███╔╝  ██║██║╚██╗██║██║   ██║"
echo "██║ ╚████║███████╗██╔╝ ██╗╚██████╔╝███████║    ██║     ╚██████╔╝███████╗███████╗██║██║ ╚████║╚██████╔╝"
echo "╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝    ╚═╝      ╚═════╝ ╚══════╝╚══════╝╚═╝╚═╝  ╚═══╝ ╚═════╝ "
echo ""
}

# ---------------------------------------------------------------------------- #
