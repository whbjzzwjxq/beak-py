# ---------------------------------------------------------------------------- #
#                               Default Settings                               #
# ---------------------------------------------------------------------------- #

: "${ZKVM_NAME:=risc0}"
: "${VERBOSITY:=0}"
: "${TRACE_COLLECTION:=true}"
: "${FAULT_INJECTION:=true}"
: "${ZKVM_MODIFICATION:=true}"
: "${PODMAN_PODS:=5}"
: "${PODMAN_CPUS:=4}"
: "${FINDINGS_COMMIT_OR_BRANCH:=todo-set-me}"
: "${COMMIT_OR_BRANCH:=ebd64e43e7d953e0edcee2d4e0225b75458d80b5}"
: "${FUZZER_TIMEOUT:=0}"
: "${DEFAULT_MASTER_SEED:=789123}"
: "${ONLY_MOD_WORD:=true}"
: "${NO_INLINE_ASSEMBLY:=false}"
: "${NO_SCHEDULAR:=false}"

# ---------------------------------------------------------------------------- #
#                                    Commits                                   #
# ---------------------------------------------------------------------------- #

BUG_COMMITS=(
    # Title: ZKVM-1392: Disallow memory I/O to same address in the same memory cycle #3181
    98387806fe8348d87e32974468c6f35853356ad5
    # Title: ZKVM-1260: Account for missing ControlDone cycle in executor #3015
    4c65c85a1ec6ce7df165ef9c57e1e13e323f7e01
)

FIX_COMMITS=(
    # Title: ZKVM-1392: Disallow memory I/O to same address in the same memory cycle #3181
    67f2d81c638bff5f4fcfe11a084ebb34799b7a89
    # Title: ZKVM-1260: Account for missing ControlDone cycle in executor #3015
    31f657014488940913e3ced0367610225ab32ada
)

# ---------------------------------------------------------------------------- #
#                                    Banner                                    #
# ---------------------------------------------------------------------------- #

banner() {
echo ""
echo "██████╗ ██╗███████╗ ██████╗ ██████╗     ███████╗██╗   ██╗███████╗███████╗██╗███╗   ██╗ ██████╗ "
echo "██╔══██╗██║██╔════╝██╔════╝██╔═████╗    ██╔════╝██║   ██║╚══███╔╝╚══███╔╝██║████╗  ██║██╔════╝ "
echo "██████╔╝██║███████╗██║     ██║██╔██║    █████╗  ██║   ██║  ███╔╝   ███╔╝ ██║██╔██╗ ██║██║  ███╗"
echo "██╔══██╗██║╚════██║██║     ████╔╝██║    ██╔══╝  ██║   ██║ ███╔╝   ███╔╝  ██║██║╚██╗██║██║   ██║"
echo "██║  ██║██║███████║╚██████╗╚██████╔╝    ██║     ╚██████╔╝███████╗███████╗██║██║ ╚████║╚██████╔╝"
echo "╚═╝  ╚═╝╚═╝╚══════╝ ╚═════╝ ╚═════╝     ╚═╝      ╚═════╝ ╚══════╝╚══════╝╚═╝╚═╝  ╚═══╝ ╚═════╝ "
echo ""
}

# ---------------------------------------------------------------------------- #
