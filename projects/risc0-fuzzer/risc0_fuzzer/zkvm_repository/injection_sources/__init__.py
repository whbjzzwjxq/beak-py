from risc0_fuzzer.zkvm_repository.injection_sources.rv32im_rs_4c65c85 import (  # noqa: F401
    rv32im_rs as rv32im_rs_4c65c85,
)
from risc0_fuzzer.zkvm_repository.injection_sources.rv32im_rs_31f6570 import (  # noqa: F401
    rv32im_rs as rv32im_rs_31f6570,
)
from risc0_fuzzer.zkvm_repository.injection_sources.rv32im_rs_67f2d81 import (  # noqa: F401
    rv32im_rs as rv32im_rs_67f2d81,
)
from risc0_fuzzer.zkvm_repository.injection_sources.rv32im_rs_9838780 import (  # noqa: F401
    rv32im_rs as rv32im_rs_9838780,
)
from risc0_fuzzer.zkvm_repository.injection_sources.rv32im_rs_ebd64e4 import (  # noqa: F401
    rv32im_rs as rv32im_rs_ebd64e4,
)


def risc0_circuit_rv32im_src_execute_rv32im_rs(commit_or_branch: str) -> str:
    match commit_or_branch:
        case "main":
            return rv32im_rs_ebd64e4()
        case "ebd64e43e7d953e0edcee2d4e0225b75458d80b5":
            return rv32im_rs_ebd64e4()
        case "67f2d81c638bff5f4fcfe11a084ebb34799b7a89":
            return rv32im_rs_67f2d81()
        case "98387806fe8348d87e32974468c6f35853356ad5":
            return rv32im_rs_9838780()
        case "31f657014488940913e3ced0367610225ab32ada":
            return rv32im_rs_31f6570()
        case "4c65c85a1ec6ce7df165ef9c57e1e13e323f7e01":
            return rv32im_rs_4c65c85()
        case _:
            raise NotImplementedError(f"unknown commit or branch {commit_or_branch}")
