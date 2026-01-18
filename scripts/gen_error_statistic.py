import csv
import io
import os
from pathlib import Path

from tabulate import tabulate


def csv_to_dict(csv_file: Path) -> dict[str, list[str]]:
    result = {}
    with open(csv_file) as file_handle:
        reader = csv.reader(file_handle, delimiter=",", quotechar="|")
        header = reader.__next__()
        result = {name: [] for name in header}
        for row_values in reader:
            for header_index, value in enumerate(row_values):
                header_key = header[header_index]
                result[header_key].append(value)
    return result


ERROR_GROUPS = {
    "Invalid trap address: <ADDR>, cause: StoreAddressMisaligned( <ARGS> )": [
        "Invalid trap address:",
        "cause: StoreAddressMisaligned",
    ],
    "Invalid trap address: <ADDR>, cause: LoadAccessFault( <ARGS> )": [
        "Invalid trap address:",
        "cause: LoadAccessFault",
    ],
    "Invalid trap address: <ADDR>, cause: UserEnvCall( <ARGS> )": [
        "Invalid trap address:",
        "cause: UserEnvCall",
    ],
    "Invalid trap address: <ADDR>, cause: IllegalInstruction": [
        "Invalid trap address:",
        "cause: IllegalInstruction",
    ],
    "Invalid trap address: <ADDR>, cause: InstructionMisaligned": [
        "Invalid trap address",
        "cause: InstructionMisaligned",
    ],
    "Invalid trap address: <ADDR>, cause: InstructionFault": [
        "Invalid trap address",
        "cause: InstructionFault",
    ],
    "Invalid trap address: <ADDR>, cause: Breakpoint": [
        "Invalid trap address:",
        "cause: Breakpoint",
    ],
    "Invalid trap address: <ADDR>, cause: StoreAccessFault": [
        "Invalid trap address:",
        "cause: StoreAccessFault",
    ],
    "Invalid trap address: <ADDR>, cause: LoadAddressMisaligned": [
        "Invalid trap address:",
        "cause: LoadAddressMisaligned",
    ],
    "Bad read file descriptor <INT>": ["Bad read file descriptor"],
    "Invalid length in host read: <INT>": ["Invalid length in host read:"],
    "Unknown syscall: <SYSCALL>": ["Unknown syscall:"],
    "Illegal halt type: <INT>": ["Illegal halt type:"],
    "Invalid count (too big) in sha2 ecall: <INT>": ["Invalid count (too big) in sha2 ecall:"],
    "<ADDR> is an invalid guest address": ["is an invalid guest address"],
    "Bad write file descriptor <INT>": ["Bad write file descriptor"],
    "Invalid load address: <ADDR>": ["Invalid load address:"],
    "Invalid length (too big) in host read: <ADDR>": ["Invalid length (too big) in host read:"],
    "invalid utf-8 sequence of <NUM> bytes from index <NUM>": [
        "invalid utf-8 sequence of",
        "bytes from index",
    ],
    "<ADDR> is an unaligned address": ["is an unaligned address"],
    "Guest panicked: index out of bounds: the len is <NUM> but the index is <NUM>": [
        "Guest panicked: index out of bounds: the len is",
        "but the index is",
    ],
    "Invalid store address: <ADDR>": ["Invalid store address:"],
    "Guest panicked: copy_from_slice: ...": [
        "Guest panicked: copy_from_slice: source slice length",
        "does not match destination slice length",
    ],
    "Guest panicked: range start index <NUM> out of range for slice of length <NUM>": [
        "Guest panicked: range start index",
        "out of range for slice of length",
    ],
    "Guest panicked: Out of memory! ...": [
        "Guest panicked: Out of memory! You have been using the default bump "
        "allocator which does not reclaim memory. Enable the `heap-embedded-alloc` "
        "feature to reclaim memory. This will result in extra cycle cost."
    ],
    "Guest panicked: sys_getenv is disabled; ...": [
        "Guest panicked: sys_getenv is disabled; can be enabled with the sys-getenv "
        "feature flag on risc0-z"
    ],
    "claim digest does not match the expected digest": [
        "claim digest does not match the expected digest",
    ],
    "Guest panicked: assertion `left == right` failed ...": [
        "Guest panicked: assertion `left == right` failed"
    ],
    "Wrapped MemoryError: Invalid memory access at <ADDR>": [
        "Wrapped MemoryError: Invalid memory access at",
    ],
    "Wrapped MemoryError: Unaligned memory read: <ADDR>": [
        "Wrapped MemoryError: Unaligned memory read:"
    ],
    "Wrapped MemoryError: Unauthorized write access": [
        "Wrapped MemoryError: Unauthorized write access:"
    ],
    "Wrapped MemoryError: Unauthorized read access": [
        "Wrapped MemoryError: Unauthorized read access"
    ],
    "Wrapped MemoryError: Unaligned memory write: <ADDR>": [
        "Wrapped MemoryError: Unaligned memory write"
    ],
    'Undefined instruction "dynamic: ..."': [
        'Undefined instruction "dynamic:',
    ],
    "Instruction called as a syscall <INSTR>": ["Instruction called as a syscall"],
    "Unimplemented syscall: <INSRT>": ["Unimplemented syscall:"],
    "Condition failed: `txn.cycle != txn.prev_cycle`": [
        "Condition failed: `txn.cycle != txn.prev_cycle`"
    ],
    "slice index starts at <INDEX> but ends at <INDEX>": ["slice index starts at", "but ends at"],
    "Wrapped MemoryError: Address calculation overflow at <SOURCE>": [
        "Wrapped MemoryError: Address calculation overflow at"
    ],
    "Wrapped MemoryError: Address calculation underflow at <SOURCE>": [
        "Wrapped MemoryError: Address calculation underflow at"
    ],
    "<PC-VALUE> is not aligned to 4": ["is not aligned to 4"],
    "Unknown syscall number: <ADDR> and result: <VALUE>, on row <VALUE>": [
        "Unknown syscall number:",
        "and result: ",
        ", on row",
    ],
    "start address <ADDR> should be at least 0x88": [
        "start address",
        "should be at least 0x88",
    ],
    "invalid register <REG>": ["invalid register"],
    "ExecutionError(InvalidMemoryAccess(...))": [
        "called `Result::unwrap()` on an `Err` value: ExecutionError(InvalidMemoryAccess"
    ],
    "ExecutionError(Breakpoint)": [
        "called `Result::unwrap()` on an `Err` value: ExecutionError(Breakpoint)"
    ],
    "ExecutionError(Unimplemented)": [
        "called `Result::unwrap()` on an `Err` value: ExecutionError(Unimplemented)"
    ],
    "Utf8Error {...}": ["called `Result::unwrap()` on an `Err` value: Utf8Error"],
    "InvalidBoolEncoding(...)": ["stderr: deserialization failed: InvalidBoolEncoding("],
    "Invalid memory access: addr= <ADDR>": ["Invalid memory access: addr="],
    "index out of bounds: the len is <VALUE> but the index is <VALUE>": [
        "index out of bounds: the len is",
        "but the index is",
    ],
    "Out-of-domain evaluation mismatch on chip Cpu": [
        "Core machine verification error: Invalid shard proof: "
        "Out-of-domain evaluation mismatch on chip Cpu"
    ],
    "Out-of-domain evaluation mismatch on chip SyscallInstrs": [
        "Core machine verification error: Invalid shard proof: "
        "Out-of-domain evaluation mismatch on chip SyscallInstrs"
    ],
    "Out-of-domain evaluation mismatch on chip Branch": [
        "Core machine verification error: Invalid shard proof: "
        "Out-of-domain evaluation mismatch on chip Branch"
    ],
    "Out-of-domain evaluation mismatch on chip MemoryInstrs": [
        "Core machine verification error: Invalid shard proof: "
        "Out-of-domain evaluation mismatch on chip MemoryInstrs"
    ],
    "cumulative sums error: local cumulative sum is not zero": [
        "Core machine verification error: Invalid shard proof: "
        "cumulative sums error: local cumulative sum is not zero"
    ],
    "Invalid public values": ["Invalid public values"],
    "You are using reserved file descriptor <VALUE> that is"
    " not supported on SP1 versions >= <VERSION>": [
        "You are using reserved file descriptor ",
        "that is not supported on SP1 versions >=",
    ],
    "hint input stream exhausted": ["hint input stream exhausted"],
    "assertion `left == right` failed: hint read address not aligned to 4 bytes": [
        "assertion `left == right` failed: hint read address not aligned to 4 bytes"
    ],
    "assertion `left == right` failed: hint input stream read length mismatch": [
        "assertion `left == right` failed: hint input stream read length mismatch"
    ],
    "invalid syscall number: <NUMBER>": ["invalid syscall number:"],
    "assertion `left != right` failed": ["assertion `left != right` failed", "left:", "right:"],
    "assertion `left == right` failed: diverging circuit input": [
        "stderr: assertion `left == right` failed: diverging circuit input"
    ],
    "Tried to read from the input stream, but it was empty (guest error)": [
        "stderr: Tried to read from the input stream, but it was empty @ guest"
    ],
    "attempt to calculate the remainder with a divisor of zero": [
        "attempt to calculate the remainder with a divisor of zero"
    ],
    "vec is too large: LayoutError": ["vec is too large: LayoutError"],
    "InvalidMemoryAccess": ["InvalidMemoryAccess"],
    "InstructionNotSyscall": ["InstructionNotSyscall"],
    "UndefinedInstruction": ["UndefinedInstruction"],
    "UnauthorizedRead": ["UnauthorizedRead"],
    "UnauthorizedWrite": ["UnauthorizedWrite"],
    "AddressCalculationOverflow": ["AddressCalculationOverflow"],
    "AddressCalculationUnderflow": ["AddressCalculationUnderflow"],
    "UnalignedMemoryRead": ["UnalignedMemoryRead"],
    "UnalignedMemoryWrite": ["UnalignedMemoryWrite"],
    "UnimplementedSyscall": ["UnimplementedSyscall"],
    "UnimplementedInstruction": ["UnimplementedInstruction"],
    "assertion `left == right` failed: Multiset hashes don't match": [
        "assertion `left == right` failed: Multiset hashes don't match"
    ],
    "execution error: pc <PC> out of bounds for program of length <LEN>": [
        "execution error: pc",
        "out of bounds for program of length",
    ],
    "execution error: at pc <PC>, phantom sub-instruction not found for discriminant <DISCR>": [
        "execution error: at pc",
        ", phantom sub-instruction not found for discriminant",
    ],
    "execution error: at pc = <PC>": ["execution error: at pc ="],
    "internal error: entered unreachable code: unaligned memory access": [
        "internal error: entered unreachable code: unaligned memory access",
        "not supported by this execution environment",
    ],
    "execution error: at pc <PC>, opcode was not enabled": [
        "execution error: at pc",
        ", opcode",
        "was not enabled",
    ],
    "execution error: execution failed at pc": ["execution error: execution failed at pc"],
    "failed to deserialize: InvalidBoolEncoding": ["failed to deserialize: InvalidBoolEncoding"],
    "Failed to convert usize <USIZE> to opcode <OPCODE>": [
        "Failed to convert usize",
        "to opcode",
    ],
    "range exceeded: <LHS> >= <RHS>": [
        "range exceeded: ",
        ">=",
    ],
    "execution error: at pc <PC>, discriminant <DISCR>, phantom error: <ERR>": [
        "execution error: at pc",
        "discriminant",
        "phantom error",
    ],
    "attempt to divide by zero": [
        "attempt to divide by zero",
    ],
    "deserialization failed: Io(Kind(UnexpectedEof))": [
        "deserialization failed: Io(Kind(UnexpectedEof))",
    ],
    "Out-of-domain evaluation mismatch on chip ShiftRight": [
        "Core machine verification error: Invalid shard proof:",
        "Out-of-domain evaluation mismatch on chip ShiftRight",
    ],
    "Out-of-domain evaluation mismatch on chip Lt": [
        "Core machine verification error: Invalid shard proof:",
        "Out-of-domain evaluation mismatch on chip Lt",
    ],
    "Out-of-domain evaluation mismatch on chip DivRem": [
        "Core machine verification error: Invalid shard proof:",
        "Out-of-domain evaluation mismatch on chip DivRem",
    ],
    "Out-of-domain evaluation mismatch on chip Mul": [
        "Core machine verification error: Invalid shard proof:",
        "Out-of-domain evaluation mismatch on chip Mul",
    ],
    "public output memory wasn't written by the prover (...)": [
        "public output memory wasn't written by the prover",
    ],
}


def print_error_statistic(
    panic_messages: list[str], last_contexts: list[str], exit_codes: list[str]
) -> str:
    errors_lookup: dict[tuple[str, str, str], int] = {}
    entries_num = len(panic_messages)
    assert (
        entries_num == len(panic_messages)
        and entries_num == len(last_contexts)
        and entries_num == len(exit_codes)
    )

    for index in range(entries_num):
        panic_message = panic_messages[index]
        last_context = last_contexts[index]
        exitcode = exit_codes[index]

        # group common errors
        for error_group, match_values in ERROR_GROUPS.items():
            is_match = True
            for match_value in match_values:
                if match_value not in panic_message:
                    is_match = False
            if is_match:
                panic_message = error_group
                break

        # create entry and increase counter
        if (panic_message, last_context, exitcode) not in errors_lookup:
            errors_lookup[(panic_message, last_context, exitcode)] = 0
        errors_lookup[(panic_message, last_context, exitcode)] += 1

    errors_num = len([exitcode for exitcode in exit_codes if exitcode != "0"])

    buffer = io.StringIO()
    buffer.write("------------------------------------------\n")
    buffer.write(f"Overall runs:   {entries_num}\n")
    buffer.write(f"Overall errors: {errors_num}\n")
    buffer.write("------------------------------------------\n\n")

    headers = ["absolute", "percent", "context", "message", "exitcode"]
    table = []
    for (panic_message, last_context, exitcode), count in sorted(
        errors_lookup.items(), key=lambda x: x[1], reverse=True
    ):
        percentage = count / entries_num * 100
        table.append([count, percentage, last_context, panic_message, exitcode])

    buffer.write(tabulate(table, headers, tablefmt="fancy_grid"))
    return buffer.getvalue()


def generate_error_statistic(csv_path: Path, output_file: Path | None = None):
    last_contexts = csv_to_dict(csv_path)["last_context"]
    panic_messages = csv_to_dict(csv_path)["panic_message"]
    exit_codes = csv_to_dict(csv_path)["execution_exitcode"]
    output_str = print_error_statistic(panic_messages, last_contexts, exit_codes)

    if output_file is None:
        print(output_str)
    else:
        os.makedirs(output_file.parent, exist_ok=True)
        output_file.write_text(output_str)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Prints statistics about the occurred errors in runs."
    )
    parser.add_argument("csv_file", help="Path to the CSV file containing run data.")
    args = parser.parse_args()

    csv_path = Path(args.csv_file)
    if not csv_path.is_file():
        print(f"ERROR: unable to find {csv_path}!")
        exit(1)
    elif csv_path.suffix != ".csv":
        print(f"ERROR: Expected file extension: '.csv', but got {csv_path.suffix}!")
        exit(1)

    try:
        generate_error_statistic(csv_path)
    except Exception as e:
        print(f"ERROR: {e}")
        exit(1)
