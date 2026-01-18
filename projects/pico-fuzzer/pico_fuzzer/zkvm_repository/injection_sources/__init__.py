from pico_fuzzer.zkvm_repository.injection_sources.dd5b7d1 import (
    instruction_rs_dd5b7d1,
    register_rs_dd5b7d1,
)


def pico_vm_src_emulator_riscv_emulator_instruction_rs(commit_or_branch: str) -> str:
    match commit_or_branch:
        case "main":
            return instruction_rs_dd5b7d1()
        case "dd5b7d1f4e164d289d110f1688509a22af6b241c":
            return instruction_rs_dd5b7d1()
        case _:
            raise NotImplementedError(f"unknown commit or branch {commit_or_branch}")


def pico_vm_src_compiler_riscv_register_rs(commit_or_branch: str) -> str:
    match commit_or_branch:
        case "main":
            return register_rs_dd5b7d1()
        case "dd5b7d1f4e164d289d110f1688509a22af6b241c":
            return register_rs_dd5b7d1()
        case _:
            raise NotImplementedError(f"unknown commit or branch {commit_or_branch}")
