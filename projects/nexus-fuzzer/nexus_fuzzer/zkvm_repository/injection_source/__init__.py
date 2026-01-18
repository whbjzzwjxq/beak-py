from nexus_fuzzer.zkvm_repository.injection_source.executor_rs_8f4ba56 import (
    executor_rs as executor_rs_8f4ba56,
)
from nexus_fuzzer.zkvm_repository.injection_source.executor_rs_41c6c60 import (
    executor_rs as executor_rs_41c6c60,
)
from nexus_fuzzer.zkvm_repository.injection_source.executor_rs_54cebc7 import (
    executor_rs as executor_rs_54cebc7,
)
from nexus_fuzzer.zkvm_repository.injection_source.executor_rs_62e3abc import (
    executor_rs as executor_rs_62e3abc,
)
from nexus_fuzzer.zkvm_repository.injection_source.executor_rs_be32013 import (
    executor_rs as executor_rs_be32013,
)
from nexus_fuzzer.zkvm_repository.injection_source.executor_rs_c684c4e import (
    executor_rs as executor_rs_c684c4e,
)
from nexus_fuzzer.zkvm_repository.injection_source.executor_rs_f1b895b import (
    executor_rs as executor_rs_f1b895b,
)


def nexus_vm_src_emulator_executor_rs(commit: str) -> str:
    match commit:
        case "main":
            return executor_rs_8f4ba56()
        case "8f4ba5699abba2b6243027c8b455305746afb1bf":
            return executor_rs_8f4ba56()
        case "f1b895b868915fd4d0a794a5bc730e6cb8d840f6":
            return executor_rs_f1b895b()
        case "c684c4e78b3a79fd0d6b0bebcce298bce4087cff":
            return executor_rs_c684c4e()
        case "62e3abc27fe41fe474822e398756bf8b60b53e7b":
            return executor_rs_62e3abc()
        case "be32013bc6215155e95774f3476f734b1c66f870":
            return executor_rs_be32013()
        case "54cebc74228654e2718457f7dc398b66de44bbec":
            return executor_rs_54cebc7()
        case "41c6c6080f46b97980053c47b078321225b4338a":
            return executor_rs_41c6c60()
        case _:
            raise NotImplementedError(f"unknown commit or branch '{commit}'")
