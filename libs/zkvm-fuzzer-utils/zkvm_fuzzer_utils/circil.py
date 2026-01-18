from random import Random
from uuid import UUID

from circil.ir.node import (
    Assertion,
    Assignment,
    BinaryExpression,
    Boolean,
    CallExpression,
    Circuit,
    Expression,
    FunctionDefinition,
    Identifier,
    Integer,
    TernaryExpression,
    UnaryExpression,
)
from circil.ir.operator import Operator
from circil.ir.type import IRType
from circil.ir.visitor import IRWalker
from zkvm_fuzzer_utils.risc32_im import (
    risc32_function_definition_random_immediate,
    risc32_function_definition_requires_immediate,
)

# ---------------------------------------------------------------------------- #
#                                    Helper                                    #
# ---------------------------------------------------------------------------- #


def is_constant(expr: Expression) -> bool:
    match expr:
        case Identifier():
            return False
        case Integer():
            return True
        case Boolean():
            return True
        case UnaryExpression():
            return is_constant(expr.value)
        case BinaryExpression():
            return is_constant(expr.rhs) and is_constant(expr.lhs)
        case TernaryExpression():
            return (
                is_constant(expr.cond) and is_constant(expr.if_expr) and is_constant(expr.else_expr)
            )
        case CallExpression():
            return any([is_constant(e) for e in expr.arguments])
        case _:
            return False


# ---------------------------------------------------------------------------- #
#                                   Visitors                                   #
# ---------------------------------------------------------------------------- #


class SSATransformer(IRWalker):

    _ssa_variable_counter = 0
    _collected_assignments: list[Assignment]
    _expression_reference_lookup: dict[UUID, Identifier]
    _is_parent_assignment: bool

    def __init__(self):
        self._ssa_variable_counter = 0
        self._collected_assignments = []
        self._expression_reference_lookup = {}
        self._is_parent_assignment = False

    def _next_variable(self, ty: IRType) -> Identifier:
        name = f"var{self._ssa_variable_counter}"
        self._ssa_variable_counter += 1
        return Identifier(name, ty)

    def _try_hoist_expression(self, expr: Expression):
        # if is_constant(expr) or self._is_parent_assignment:
        #     return  # early abort -> no need to hoist

        def skip_hoisting(e: Expression) -> bool:
            return isinstance(e, Integer) or isinstance(e, Boolean) or isinstance(e, Identifier)

        if self._is_parent_assignment or skip_hoisting(expr):
            return  # early abort -> no need to hoist
        reference = self._next_variable(expr.type_hint())
        assignment = Assignment(reference, expr)
        self._collected_assignments.append(assignment)
        self._store_reference(expr, reference)

    def _store_reference(self, expr: Expression, identifier: Identifier):
        self._expression_reference_lookup[expr.node_id] = identifier

    def _get_reference(
        self, expr: Expression, is_parent_assignment: bool = False
    ) -> Identifier | None:
        cached_is_parent_assignment = self._is_parent_assignment
        self._is_parent_assignment = is_parent_assignment
        super().visit(expr)
        self._is_parent_assignment = cached_is_parent_assignment
        return self._expression_reference_lookup.get(expr.node_id, None)

    def transform(self, circuit: Circuit) -> Circuit:
        self._ssa_variable_counter = 0
        self._expression_reference_lookup = {}
        self._collected_assignments = []
        self._is_parent_assignment = False

        copy = circuit.copy()

        new_statements = []
        for statement in copy.statements:
            self._collected_assignments = []
            super().visit(statement)
            new_statements += self._collected_assignments
            new_statements.append(statement)
        copy.statements = new_statements

        return copy

    def visit_unary_expression(self, node: UnaryExpression):
        val_ref = self._get_reference(node.value)
        if val_ref:
            node.value = val_ref.copy()
        self._try_hoist_expression(node)

    def visit_binary_expression(self, node: BinaryExpression):
        lhs_ref = self._get_reference(node.lhs)
        rhs_ref = self._get_reference(node.rhs)
        if lhs_ref:
            node.lhs = lhs_ref.copy()
        if rhs_ref:
            node.rhs = rhs_ref.copy()
        self._try_hoist_expression(node)

    def visit_ternary_expression(self, node: TernaryExpression):
        cond_ref = self._get_reference(node.cond)
        if_expr_ref = self._get_reference(node.if_expr)
        else_expr_ref = self._get_reference(node.else_expr)
        if cond_ref:
            node.cond = cond_ref.copy()
        if if_expr_ref:
            node.if_expr = if_expr_ref.copy()
        if else_expr_ref:
            node.else_expr = else_expr_ref.copy()
        self._try_hoist_expression(node)

    def visit_call_expression(self, node: CallExpression):
        for idx, elem in enumerate(node.arguments):
            elem_ref = self._get_reference(elem)
            if elem_ref:
                node.arguments[idx] = elem_ref.copy()
        self._try_hoist_expression(node)

    def visit_assertion(self, node: Assertion):
        pass  # do nothing for assertions

    def visit_assignment(self, node: Assignment):
        # call the get reference to start the hoisting, but since we are
        assert self._get_reference(node.rhs, is_parent_assignment=True) is None


# ---------------------------------------------------------------------------- #


class InputDependencyCollector(IRWalker):
    _used_input_signals: set[str]
    _input_signals: set[str]

    def __init__(self):
        self._used_input_signals = set()
        self._input_signals = set()

    def collect(self, circuit: Circuit) -> set[str]:
        self._used_input_signals = set()
        self._input_signals = {e.name for e in circuit.inputs}
        for assignment in circuit.assignments:
            super().visit(assignment)
        return self._used_input_signals

    def visit_function_definition(self, node: FunctionDefinition):
        pass  # do not visit functions

    def visit_identifier(self, node: Identifier):
        if node.name in self._input_signals:
            self._used_input_signals.add(node.name)


# ---------------------------------------------------------------------------- #


class Risc32IMImmediateRepair(IRWalker):
    """This transformer adds a random immediate value to the risc32 instructions
    that use a constant immediate value. It manipulates the `CallExpression` as well
    as the underlying `FunctionDefinition`.
    """

    _rng: Random

    # NOTE: the visited set should not be necessary, but we keep
    #       it for an extra safety measure!
    _visited: set[UUID]

    def __init__(self, rng: Random):
        self._rng = rng
        self._visited = set()

    def transform(self, circuit: Circuit) -> Circuit:
        copy = circuit.copy()
        for statements in copy.statements:
            super().visit(statements)
        return copy

    def visit_call_expression(self, node: CallExpression):
        super().visit_call_expression(node)
        if risc32_function_definition_requires_immediate(node.function):
            if node.node_id not in self._visited:
                self._visited.add(node.node_id)
                imm = risc32_function_definition_random_immediate(node.function, self._rng)
                # do not allow any rewrites as this has to stay constant
                node.arguments.append(Integer(imm, disable_rewrite=True))
            if node.function.node_id not in self._visited:
                self._visited.add(node.function.node_id)
                node.function.parameters.append(Identifier("imm"))


# ---------------------------------------------------------------------------- #


class FunctionCollector(IRWalker):
    """Traverses the provided circuit and returns a list of used `FunctionDefinition`."""

    _function_lookup: dict[str, FunctionDefinition]

    def __init__(self):
        self._function_lookup = {}

    def collect(self, circuit: Circuit) -> list[FunctionDefinition]:
        self._function_lookup = {}
        for statements in circuit.statements:
            super().visit(statements)
        return list(self._function_lookup.values())

    def visit_function_definition(self, node: FunctionDefinition):
        if node.name not in self._function_lookup:
            self._function_lookup[node.name] = node
        else:
            candidate = self._function_lookup[node.name]
            if len(candidate.parameters) != len(node.parameters) or len(candidate.results) != len(
                node.results
            ):
                if any(
                    [
                        c.type_hint() != n.type_hint()
                        for (c, n) in zip(
                            candidate.parameters + candidate.results, node.parameters + node.results
                        )
                    ]
                ):
                    raise RuntimeError(
                        f"Multiple functions '{node.name}' with different signatures detected!"
                    )


# ---------------------------------------------------------------------------- #


class SafeRemAndDivTransformer(IRWalker):
    """Checks if the right hand side of a DIV or REM binary expression or
    custom function is zero. If this is the case, it replaces the rhs by 1.

    NOTE: An outer check would be better, but this would require more logic because of the
    reference replacement in the parent.
    """

    def transform(self, circuit: Circuit) -> Circuit:
        result = circuit.copy()
        self.visit(result)
        return result

    def visit_binary_expression(self, node: BinaryExpression):
        # visit all children first
        super().visit_binary_expression(node)

        # replace DIV and REM
        if node.op in {Operator.DIV, Operator.REM}:
            is_rhs_zero = BinaryExpression(Operator.EQU, node.rhs.copy(), Integer(0))
            constant_one = Integer(1)
            updated_rhs = TernaryExpression(is_rhs_zero, constant_one, node.rhs)
            node.rhs = updated_rhs

    def visit_call_expression(self, node: CallExpression):
        # visit all children first
        super().visit_call_expression(node)

        # replace special DIV and REM
        if node.function.name in ["div", "divu", "rem", "remu"]:
            is_rhs_zero = BinaryExpression(Operator.EQU, node.arguments[1].copy(), Integer(0))
            constant_one = Integer(1)
            updated_rhs = TernaryExpression(is_rhs_zero, constant_one, node.arguments[1])
            node.arguments[1] = updated_rhs


# ---------------------------------------------------------------------------- #
