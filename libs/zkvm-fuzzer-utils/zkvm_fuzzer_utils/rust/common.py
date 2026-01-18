import io
import re
from typing import Callable

from circil.ir.node import (
    Circuit,
    Identifier,
    IRType,
)

# ---------------------------------------------------------------------------- #
#                            Function Commenter Util                           #
# ---------------------------------------------------------------------------- #


def comment_func_call_stmts(func: str, code: str) -> str:
    """
    Given a rust source, this function will replace any occurrence of the provided `func`
    with `/* <func>( ... ); */`. The internal body of the function can be in multiline form.

    NOTE: There is a limitation on nested bodies.
    """

    # NOTE:
    #   - Flag 'MULTILINE' makes '^' and '$' work with start and end of lines.
    #   - Flag 'DOTALL' makes '.' match everything
    flags = re.DOTALL | re.MULTILINE

    # Pattern for the assert. It is important to use the provided flags such that
    # multiline is enabled capturing of '.' is enabled.
    pattern = re.compile(func + r"\s*\((.*?)\);", flags=flags)

    # Replace function which replaces the assertion with a commented version and
    def replacer(m: re.Match[str]) -> str:
        return f"/* {func}({m.group(1)}); */"

    return re.sub(pattern, replacer, code)


# ---------------------------------------------------------------------------- #
#                               Rust Emit Helper                               #
# ---------------------------------------------------------------------------- #


def ir_type_byte_size(ir_type: IRType) -> int:
    match ir_type:
        case IRType.Field:
            return 4
        case IRType.Bool:
            return 1
        case _:
            raise NotImplementedError(f"unexpected type '{ir_type}'")


# ---------------------------------------------------------------------------- #


def default_value_for_ir_type(ir_type: IRType) -> str:
    match ir_type:
        case IRType.Field:
            return "0"
        case IRType.Bool:
            return "false"
        case _:
            raise NotImplementedError(f"unexpected type '{ir_type}'")


# ---------------------------------------------------------------------------- #


def ir_type_to_str(ir_type: IRType) -> str:
    match ir_type:
        case IRType.Field:
            return "u32"
        case IRType.Bool:
            return "bool"
        case _:
            raise NotImplementedError(f"unexpected type '{ir_type}'")


# ---------------------------------------------------------------------------- #


def stream_list_of_names(
    buffer: io.StringIO,
    identifiers: list[Identifier],
    always_bracketed: bool = False,
    borrow_prefix: bool = False,
    name_prefix: str | None = None,
):
    is_bracket = (len(identifiers) > 1) or always_bracketed
    if is_bracket:
        buffer.write("(")
    is_tail = False
    for e in identifiers:
        if is_tail:
            buffer.write(", ")
        if borrow_prefix:
            buffer.write("&")
        if name_prefix is not None:
            buffer.write(name_prefix)
        buffer.write(e.name)
        is_tail = True
    if is_bracket:
        buffer.write(")")


# ---------------------------------------------------------------------------- #


def stream_list_of_types(
    buffer: io.StringIO, identifiers: list[Identifier], always_bracketed: bool = False
):
    is_bracket = (len(identifiers) > 1) or always_bracketed
    if is_bracket:
        buffer.write("(")
    is_tail = False
    for e in identifiers:
        if is_tail:
            buffer.write(", ")
        buffer.write(ir_type_to_str(e.ty_hint))
        is_tail = True
    if is_bracket:
        buffer.write(")")


# ---------------------------------------------------------------------------- #


def stream_list_of_typed_identifiers(
    buffer: io.StringIO,
    identifiers: list[Identifier],
    always_bracketed: bool = False,
):
    is_bracket = (len(identifiers) > 1) or always_bracketed
    if is_bracket:
        buffer.write("(")
    is_tail = False
    for e in identifiers:
        if is_tail:
            buffer.write(", ")
        buffer.write(e.name)
        buffer.write(": ")
        buffer.write(ir_type_to_str(e.ty_hint))
        is_tail = True
    if is_bracket:
        buffer.write(")")


# ---------------------------------------------------------------------------- #


def stream_list_of_default_values(
    buffer: io.StringIO, identifiers: list[Identifier], always_bracketed: bool = False
):
    is_bracket = (len(identifiers) > 1) or always_bracketed
    if is_bracket:
        buffer.write("(")
    is_tail = False
    for e in identifiers:
        if is_tail:
            buffer.write(", ")
        buffer.write(default_value_for_ir_type(e.ty_hint))
        is_tail = True
    if is_bracket:
        buffer.write(")")


# ---------------------------------------------------------------------------- #


def stream_circuit_output_and_compare_routine(
    buffer: io.StringIO,
    circuits: list[Circuit],
    expected_value: int,
    func_helper_commit_and_exit: Callable[[int, bool], list[str]],
):
    """Prints boilerplate rust code that calls circuit functions and compares their output.

    It is expected that the input variables are in the namespace in the form of
    `<circuit_name>_<input_name>` already in the correct rust type.

    `func_commit_and_exit` should generate rust code that either commits and returns or just
    returns the given integer value directly depending on the ZKVM. It is expected that the
    list elements are a rust statements for a single line.
    """

    buffer.write("\n")
    buffer.write("    //\n")
    buffer.write("    // Compute Circuit Outputs\n")
    buffer.write("    //\n\n")

    for circuit in circuits:
        buffer.write(f"    // -- {circuit.name} --\n")
        if len(circuit.outputs) > 1:
            buffer.write("    let (\n")
            for circuit_output in circuit.outputs:
                out_var = f"{circuit.name}_{circuit_output.name}"
                buffer.write(f"        {out_var},\n")
            buffer.write("    ) : (\n")
            for circuit_output in circuit.outputs:
                ir_type = ir_type_to_str(circuit_output.ty_hint)
                buffer.write(f"        {ir_type},\n")
            buffer.write(f"    ) = {circuit.name}(\n")
        else:
            single_out = circuit.outputs[0]
            out_var = f"{circuit.name}_{single_out.name}"
            ir_type = ir_type_to_str(single_out.ty_hint)
            buffer.write(f"    let {out_var}: {ir_type} = {circuit.name}(\n")

        for circuit_input in circuit.inputs:
            buffer.write(f"        {circuit.name}_{circuit_input.name},\n")
        buffer.write("    );\n")
        buffer.write("\n")

    buffer.write("    //\n")
    buffer.write("    // Compare Outputs\n")
    buffer.write("    //\n\n")

    # shift in a window of size two over the circuits and compare them.
    for c_idx, (c0, c1) in enumerate(zip(circuits[:-1], circuits[1:])):
        buffer.write(f"    // -- {c0.name} x {c1.name} --\n")
        for o_idx, (c0_out, c1_out) in enumerate(zip(c0.outputs, c1.outputs)):
            unique_error_id = c_idx * 1000 + o_idx
            tmp_var = f"diff_{c_idx}_{o_idx}"
            buffer.write(f"    let {tmp_var} = ")
            buffer.write(f"{c0.name}_{c0_out.name} ^ {c1.name}_{c1_out.name};\n")
            is_property_violated = tmp_var if c0_out.ty_hint == IRType.Bool else f"{tmp_var} != 0"
            buffer.write(f"    if {is_property_violated} {{\n")

            for statement in func_helper_commit_and_exit(unique_error_id, False):
                buffer.write(f"        {statement}\n")
            buffer.write("    }\n\n")

    for statement in func_helper_commit_and_exit(expected_value, True):
        buffer.write(f"    {statement}\n")
    buffer.write("\n")


# ---------------------------------------------------------------------------- #
