# ---------------------------------------------------------------------------- #
#                               Default Settings                               #
# ---------------------------------------------------------------------------- #

: "${ZKVM_NAME:=jolt}"
: "${VERBOSITY:=0}"
: "${TRACE_COLLECTION:=true}"
: "${FAULT_INJECTION:=true}"
: "${ZKVM_MODIFICATION:=true}"
: "${PODMAN_PODS:=5}"
: "${PODMAN_CPUS:=4}"
: "${FINDINGS_COMMIT_OR_BRANCH:=todo-set-me}"
: "${COMMIT_OR_BRANCH:=1687134d117a19d1f6c6bd03fd23191013c53d1b}"
: "${FUZZER_TIMEOUT:=0}"
: "${DEFAULT_MASTER_SEED:=789123}"
: "${ONLY_MOD_WORD:=true}"
: "${NO_INLINE_ASSEMBLY:=false}"
: "${NO_SCHEDULAR:=false}"

# ---------------------------------------------------------------------------- #
#                                    Commits                                   #
# ---------------------------------------------------------------------------- #

BUG_COMMITS=(
    # Title: Sumcheck verification failed for MULHSU Instruction #833
    d59219a0633d91dc5dbe19ade5f66f179c27c834
    # Title: Panic in bytecode module during preprocessing #824
    57ea518d6d9872fb221bf6ac97df1456a5494cf2
    # Title: Prover and/or Verifier Fail on Correct Program for Specific Arguments #741 (2/2)
    70c77337426615b67191b301e9175e2bb093830d
    # Title: Prover and/or Verifier Fail on Correct Program for Specific Arguments #741 (1/2)
    42de0ca1f581dd212dda7ff44feee806556531d2
    # Title: Soundness Issue with LUI #719
    e9caa23565dbb13019afe61a2c95f51d1999e286
)

FIX_COMMITS=(
    # Title: Sumcheck verification failed for MULHSU Instruction #833
    0369981446471c2ed2c4a4d2f24d61205a2d0853
    # Title: Panic in bytecode module during preprocessing #824
    0582b2aa4a33944506d75ce891db7cf090814ff6
    # Title: Prover and/or Verifier Fail on Correct Program for Specific Arguments #741 (2/2)
    20ac6eb526af383e7b597273990b5e4b783cc2a6
    # Title: Prover and/or Verifier Fail on Correct Program for Specific Arguments #741 (1/2)
    55b9830a3944dde55d33a55c42522b81dd49f87a
    # Title: Soundness Issue with LUI #719
    85bf51da10efa9c679c35ffc1a8d45cc6cb1c788
)

# ---------------------------------------------------------------------------- #
#                                    Banner                                    #
# ---------------------------------------------------------------------------- #

banner() {
echo ""
echo "     ██╗ ██████╗ ██╗  ████████╗     ███████╗██╗   ██╗███████╗███████╗██╗███╗   ██╗ ██████╗ "
echo "     ██║██╔═══██╗██║  ╚══██╔══╝     ██╔════╝██║   ██║╚══███╔╝╚══███╔╝██║████╗  ██║██╔════╝ "
echo "     ██║██║   ██║██║     ██║        █████╗  ██║   ██║  ███╔╝   ███╔╝ ██║██╔██╗ ██║██║  ███╗"
echo "██   ██║██║   ██║██║     ██║        ██╔══╝  ██║   ██║ ███╔╝   ███╔╝  ██║██║╚██╗██║██║   ██║"
echo "╚█████╔╝╚██████╔╝███████╗██║        ██║     ╚██████╔╝███████╗███████╗██║██║ ╚████║╚██████╔╝"
echo " ╚════╝  ╚═════╝ ╚══════╝╚═╝        ╚═╝      ╚═════╝ ╚══════╝╚══════╝╚═╝╚═╝  ╚═══╝ ╚═════╝ "
echo ""
}

# ---------------------------------------------------------------------------- #
