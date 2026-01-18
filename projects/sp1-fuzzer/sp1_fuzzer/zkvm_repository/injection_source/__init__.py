from sp1_fuzzer.zkvm_repository.injection_source.executor_rs_429e95e import (
    executor_rs as executor_rs_429e95e,
)


def sp1_crates_core_executor_src_executor_rs(commit_or_branch: str) -> str:
    match commit_or_branch:
        case "dev":
            return executor_rs_429e95e()
        case "429e95e00a51db1f3d7257e7db73c7fe0fd40801":
            return executor_rs_429e95e()
        case _:
            raise NotImplementedError(f"unknown commit {commit_or_branch}")
