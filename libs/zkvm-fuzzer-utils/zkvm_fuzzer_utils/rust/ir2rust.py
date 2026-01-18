import io

from circil.ir.node import (
    Assertion,
    Assignment,
    BinaryExpression,
    Boolean,
    CallExpression,
    Circuit,
    Identifier,
    Integer,
    Operator,
    TernaryExpression,
    UnaryExpression,
)
from circil.ir.visitor import EmptyVisitor
from zkvm_fuzzer_utils.circil import FunctionCollector, SSATransformer
from zkvm_fuzzer_utils.risc32_im import (
    risc32_function_definition_requires_memory,
    risc32_function_definition_to_rust_macros,
)
from zkvm_fuzzer_utils.rust.common import (
    ir_type_to_str,
    stream_list_of_names,
    stream_list_of_typed_identifiers,
    stream_list_of_types,
)

# ---------------------------------------------------------------------------- #
#                  CircIL To Rust (with checked and wrapping)                  #
# ---------------------------------------------------------------------------- #


class CircIL2RustEmitter(EmptyVisitor):
    """Helper visitor to generate rust code out of CircIL IR Nodes"""

    _buffer: io.StringIO
    _indent: str
    _ignore_next_expr_brackets: bool

    _map_div_by_zero_to_zero: bool

    def __init__(self, map_div_by_zero_to_zero: bool = True):
        self._buffer = io.StringIO()
        self._indent = ""
        self._map_div_by_zero_to_zero = map_div_by_zero_to_zero

    def run(self, node: Circuit) -> str:
        self._reset()
        self.visit(node)
        return self._buffer.getvalue()

    def _reset(self):
        self._buffer.truncate(0)
        self._buffer.seek(0)
        self._indent = ""

    def visit_identifier(self, node: Identifier):
        self._buffer.write(node.name)

    def visit_boolean(self, node: Boolean):
        self._buffer.write("true" if node.value else "false")

    def visit_integer(self, node: Integer):
        self._buffer.write(str(node.value))
        if node.value >= 0:
            self._buffer.write("_u32")
        else:
            self._buffer.write("_i32")

    def visit_unary_expression(self, node: UnaryExpression):
        self._buffer.write("(")
        match node.op:
            case Operator.COMP:
                self._buffer.write("!")
            case _:
                self._buffer.write(node.op.value)
        self._buffer.write(" ")
        self.visit(node.value)
        self._buffer.write(")")

    def visit_binary_expression(self, node: BinaryExpression):
        WRAPPER_OPERATORS = [
            Operator.ADD,
            Operator.SUB,
            Operator.MUL,
            Operator.DIV,
            Operator.REM,
            Operator.POW,
        ]
        if node.op in WRAPPER_OPERATORS:
            self.visit(node.lhs)
            match node.op:
                case Operator.ADD:
                    self._buffer.write(".wrapping_add(")
                case Operator.SUB:
                    self._buffer.write(".wrapping_sub(")
                case Operator.MUL:
                    self._buffer.write(".wrapping_mul(")
                case Operator.DIV:
                    self._buffer.write(".checked_div(")  # no wrapping --> unsigned can not overflow
                case Operator.REM:
                    self._buffer.write(".checked_rem(")  # no wrapping --> unsigned can not overflow
                case Operator.POW:
                    self._buffer.write(".wrapping_pow(")
                case _:
                    raise NotImplementedError(f"unexpected binary operator '{node.op}'")
            self.visit(node.rhs)
            self._buffer.write(")")

            # special handling for division
            if node.op in [Operator.DIV, Operator.REM]:
                if self._map_div_by_zero_to_zero:
                    self._buffer.write(".unwrap_or(0)")
                else:
                    self._buffer.write(".unwrap()")
        else:
            self._buffer.write("(")
            self.visit(node.lhs)
            match node.op:
                case Operator.LXOR:
                    self._buffer.write(" ^ ")
                case _:
                    self._buffer.write(f" {node.op} ")
            self.visit(node.rhs)
            self._buffer.write(")")

    def visit_ternary_expression(self, node: TernaryExpression):
        self._buffer.write("(")
        self._buffer.write("if ")
        self.visit(node.cond)
        self._buffer.write(" { ")
        self.visit(node.if_expr)
        self._buffer.write(" } else { ")
        self.visit(node.else_expr)
        self._buffer.write(" }")
        self._buffer.write(")")

    def visit_call_expression(self, node: CallExpression):
        self._buffer.write(f"{node.function.name}!(")
        arguments = node.arguments
        if risc32_function_definition_requires_memory(node.function):
            arguments.insert(0, Identifier("memory_ptr"))
        is_first = True
        for e in arguments:
            if not is_first:
                self._buffer.write(", ")
            self.visit(e)
            is_first = False
        self._buffer.write(")")

    def visit_assertion(self, node: Assertion):
        self._buffer.write(self._indent)
        self._buffer.write("assert!(")
        self.visit(node.value)
        self._buffer.write(', "')
        self._buffer.write(node.tag)
        self._buffer.write('")')
        self._buffer.write(";\n")

    def visit_assignment(self, node: Assignment):
        self._buffer.write(self._indent)
        self.visit(node.lhs)
        self._buffer.write(" = ")
        self.visit(node.rhs)
        self._buffer.write(";\n")

    def visit_circuit(self, node: Circuit):
        self._buffer.write(f"/*\n{node.__str__()}\n*/\n\n")
        self._buffer.write(
            "#[allow(non_snake_case, unused_comparisons, unused_parens, unused_variables)]\n"
        )
        self._buffer.write("pub fn ")
        self._buffer.write(node.name)
        stream_list_of_typed_identifiers(self._buffer, node.inputs, always_bracketed=True)

        if len(node.outputs) > 0:
            self._buffer.write(" -> ")
            stream_list_of_types(self._buffer, node.outputs)

        self._buffer.write(" {\n")
        self._indent = "    "

        # emit all the builtin rust functions inside of the function
        builtin_functions = FunctionCollector().collect(node)
        for builtin_function in builtin_functions:
            temporary_source = risc32_function_definition_to_rust_macros(builtin_function)
            for line in temporary_source.split("\n"):
                self._buffer.write(f"{self._indent}{line}\n")

        # if any memory read and write instructions are present we need a defined memory.
        if any([risc32_function_definition_requires_memory(f) for f in builtin_functions]):
            self._buffer.write("    let mut memory: [u8; 32] = [0; 32];\n")
            self._buffer.write("    let memory_ptr: *mut u8 = memory.as_mut_ptr();\n\n")

        for e in node.outputs:
            self._buffer.write(f"    let {e.name}: {ir_type_to_str(e.ty_hint)};\n")

        for stmt in node.statements:
            self.visit(stmt)

        if len(node.outputs) > 0:
            self._buffer.write("    return ")
            stream_list_of_names(self._buffer, node.outputs)
            self._buffer.write(";\n")

        self._buffer.write("}\n")


# ---------------------------------------------------------------------------- #
#                       CircIL To Rust (without checks)                        #
# ---------------------------------------------------------------------------- #


class CircIL2UnsafeRustEmitter(EmptyVisitor):
    """Helper visitor to generate rust code out of CircIL IR Nodes"""

    _buffer: io.StringIO
    _indent: str
    _ignore_next_expr_brackets: bool

    # If this is set, the function is treated as rust `println!` and
    # is executed at the end of every statement.
    #
    # NOTE: this is not reset with the reset function!
    _print_func: str | None

    # scoping state variable, it is the first thing set if a circuit is
    # entered and the last thing cleared at the end of the visit function.
    _active_circuit_scope: Circuit | None

    def __init__(self):
        self._buffer = io.StringIO()
        self._indent = ""
        self._print_func = None
        self._active_circuit_scope = None

    def _reset(self):
        self._buffer.truncate(0)
        self._buffer.seek(0)
        self._indent = ""
        self._active_circuit_scope = None

    def _scope_prefix(self) -> str:
        if self._active_circuit_scope:
            return self._active_circuit_scope.name
        return ""  # no scope prefix

    def with_print(self, print_func: str) -> "CircIL2UnsafeRustEmitter":
        self._print_func = print_func
        return self

    def run(self, node: Circuit) -> str:
        self._reset()
        self.visit(SSATransformer().transform(node))
        return self._buffer.getvalue()

    def visit_identifier(self, node: Identifier):
        self._buffer.write(node.name)

    def visit_boolean(self, node: Boolean):
        self._buffer.write("true" if node.value else "false")

    def visit_integer(self, node: Integer):
        self._buffer.write(str(node.value))
        if node.value >= 0:
            self._buffer.write("_u32")
        else:
            self._buffer.write("_i32")

    def visit_unary_expression(self, node: UnaryExpression):
        self._buffer.write("(")
        match node.op:
            case Operator.COMP:
                self._buffer.write("!")
            case _:
                self._buffer.write(node.op.value)
        self._buffer.write(" ")
        self.visit(node.value)
        self._buffer.write(")")

    def visit_binary_expression(self, node: BinaryExpression):
        WRAPPER_OPERATORS = [
            Operator.ADD,
            Operator.SUB,
            Operator.MUL,
            Operator.DIV,
            Operator.REM,
            Operator.POW,
        ]
        if node.op in WRAPPER_OPERATORS:
            if node.op != Operator.POW:
                self._buffer.write("(")
            self.visit(node.lhs)
            match node.op:
                case Operator.ADD:
                    self._buffer.write(" + ")
                case Operator.SUB:
                    self._buffer.write(" - ")
                case Operator.MUL:
                    self._buffer.write(" * ")
                case Operator.DIV:
                    self._buffer.write(" / ")  # no wrapping --> unsigned can not overflow
                case Operator.REM:
                    self._buffer.write(" % ")  # no wrapping --> unsigned can not overflow
                case Operator.POW:
                    self._buffer.write(".pow(")
                case _:
                    raise NotImplementedError(f"unexpected binary operator '{node.op}'")
            self.visit(node.rhs)
            self._buffer.write(")")

        else:
            self._buffer.write("(")
            self.visit(node.lhs)
            match node.op:
                case Operator.LXOR:
                    self._buffer.write(" ^ ")
                case _:
                    self._buffer.write(f" {node.op} ")
            self.visit(node.rhs)
            self._buffer.write(")")

    def visit_ternary_expression(self, node: TernaryExpression):
        self._buffer.write("(")
        self._buffer.write("if ")
        self.visit(node.cond)
        self._buffer.write(" { ")
        self.visit(node.if_expr)
        self._buffer.write(" } else { ")
        self.visit(node.else_expr)
        self._buffer.write(" }")
        self._buffer.write(")")

    def visit_call_expression(self, node: CallExpression):
        self._buffer.write(f"{node.function.name}!(")
        arguments = node.arguments
        if risc32_function_definition_requires_memory(node.function):
            arguments.insert(0, Identifier("memory_ptr"))
        is_first = True
        for e in node.arguments:
            if not is_first:
                self._buffer.write(", ")
            self.visit(e)
            is_first = False
        self._buffer.write(")")

    def visit_assertion(self, node: Assertion):
        self._buffer.write(self._indent)
        self._buffer.write("assert!(")
        self.visit(node.value)
        self._buffer.write(', "')
        self._buffer.write(node.tag)
        self._buffer.write('")')
        self._buffer.write(";\n")

    def visit_assignment(self, node: Assignment):
        self._buffer.write(self._indent)
        self._buffer.write("let ")
        self.visit(node.lhs)
        self._buffer.write(" = ")
        self.visit(node.rhs)
        self._buffer.write(";\n")

        # provides debug info if enabled
        if self._print_func:
            self._buffer.write(self._indent)
            self._buffer.write(f'{self._print_func}("')
            self._buffer.write(f"{self._scope_prefix()}::")
            self.visit(node.lhs)
            self._buffer.write(' = {}", ')
            self.visit(node.lhs)
            self._buffer.write(");\n")

    def visit_circuit(self, node: Circuit):

        # check and set circuit scope
        assert self._active_circuit_scope is None, "multiple circuits are active in scope"
        self._active_circuit_scope = node

        self._buffer.write(f"/*\n{node.__str__()}\n*/\n\n")
        self._buffer.write(
            "#[allow(non_snake_case, unused_comparisons, unused_parens, unused_variables)]\n"
        )

        self._buffer.write("pub fn ")
        self._buffer.write(node.name)
        stream_list_of_typed_identifiers(self._buffer, node.inputs, always_bracketed=True)

        if len(node.outputs) > 0:
            self._buffer.write(" -> ")
            stream_list_of_types(self._buffer, node.outputs)

        self._buffer.write(" {\n")
        self._indent = "    "

        # emit all the builtin rust functions inside of the function
        builtin_functions = FunctionCollector().collect(node)
        for builtin_function in builtin_functions:
            temporary_source = risc32_function_definition_to_rust_macros(builtin_function)
            for line in temporary_source.split("\n"):
                self._buffer.write(f"{self._indent}{line}\n")

        # if any memory read and write instructions are present we need a defined memory.
        if any([risc32_function_definition_requires_memory(f) for f in builtin_functions]):
            self._buffer.write("    let mut memory: [u8; 32] = [0; 32];\n")
            self._buffer.write("    let memory_ptr: *mut u8 = memory.as_mut_ptr();\n\n")

        for stmt in node.statements:
            self.visit(stmt)

        if len(node.outputs) > 0:
            self._buffer.write("    return ")
            stream_list_of_names(self._buffer, node.outputs)
            self._buffer.write(";\n")

        self._buffer.write("}\n")

        # unset circuit scope
        self._active_circuit_scope = None
