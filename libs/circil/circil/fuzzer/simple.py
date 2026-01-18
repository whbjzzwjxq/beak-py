from random import Random

from circil.fuzzer.base import BaseCircuitFuzzer, ExpressionKind
from circil.fuzzer.config import FuzzerConfig
from circil.ir.node import (
    Assertion,
    Assignment,
    BinaryExpression,
    CallExpression,
    Circuit,
    Expression,
    Identifier,
    Integer,
    Statement,
    TernaryExpression,
    UnaryExpression,
)
from circil.ir.operator import Operator
from circil.ir.type import IRType


class SimpleCircuitFuzzer(BaseCircuitFuzzer):
    """Simple fuzzer for CircIL `Circuit`s implementation"""

    _assertion_ordering: int  # tracks identification number of assertions
    _unassigned_identifiers: list[Identifier]  # list of identifiers not yet assigned
    _pre_statements: list[
        Statement
    ]  # list of statements that should be placed before the current one
    _post_statements: list[
        Statement
    ]  # list of statements that should be placed after the current one

    _assertion_budget: int  # amount of assertions that should be placed

    def __init__(self, field_modulo: int, rng: Random, fuzzer_config: FuzzerConfig):

        # init the abstract base fuzzer
        super().__init__(field_modulo, rng, fuzzer_config)

        # init internal variable
        self._assertion_budget = 0
        self._assertion_ordering = 0
        self._unassigned_identifiers = []
        self._pre_statements = []
        self._post_statements = []

    def run(self) -> Circuit:
        input_signal_amount = self.rng.randint(
            self.fuzzer_config.min_circuit_input_signals,
            self.fuzzer_config.max_circuit_input_signals,
        )
        input_signals = [
            Identifier(f"in{i}", self.rng.choice(self.fuzzer_config.input_signal_types))
            for i in range(input_signal_amount)
        ]
        output_signal_amount = self.rng.randint(
            self.fuzzer_config.min_circuit_output_signals,
            self.fuzzer_config.max_circuit_output_signals,
        )
        output_signals = [
            Identifier(f"out{i}", self.rng.choice(self.fuzzer_config.output_signal_types))
            for i in range(output_signal_amount)
        ]

        self._assertion_ordering = 0
        self._assertion_budget = self.rng.randint(
            self.fuzzer_config.min_assertions, self.fuzzer_config.max_assertions
        )

        # create proper copy for unassigned identifiers such that they do not
        # have to be copied inside of the assignment method
        self._unassigned_identifiers = [x.copy() for x in output_signals]
        self._available_identifier = input_signals[::]

        statements = self._random_statements()

        circuit_name = f"circuit_{self._random_id(10)}"
        return Circuit(circuit_name, self.field_modulo, input_signals, output_signals, statements)

    def _random_boolean_logic_unary_expression(self, depth: int = 0) -> Expression:
        op = self._random_boolean_unary_operation()
        return UnaryExpression(op, self._random_boolean_expression(depth + 1))

    def _random_boolean_logic_binary_expression(self, depth: int = 0) -> Expression:
        op = self._random_boolean_binary_operation()
        lhs = self._random_boolean_expression(depth + 1)
        rhs = self._random_boolean_expression(depth + 1)
        return BinaryExpression(op, lhs, rhs)

    def _random_boolean_logic_ternary_expression(self, depth: int = 0) -> Expression:
        condition = self._random_boolean_expression(depth + 1)
        true_val = self._random_boolean_expression(depth + 1)
        false_val = self._random_boolean_expression(depth + 1)
        return TernaryExpression(condition, true_val, false_val)

    def _random_boolean_custom_function_expression(self, depth: int = 0) -> Expression:
        allowed_functions = [
            f for f in self.fuzzer_config.custom_functions if f.has_return_type(IRType.Bool)
        ]
        selected_function = self.rng.choice(allowed_functions).copy()
        arguments = [
            self._random_arithmetic_expression(depth + 1) for _ in selected_function.parameters
        ]
        return CallExpression(selected_function, arguments)

    def _random_compare_expression(self, depth: int = 0) -> BinaryExpression:
        op = self._random_comparator()
        lhs = self._random_arithmetic_expression(depth + 1)
        rhs = self._random_arithmetic_expression(depth + 1)
        return BinaryExpression(op, lhs, rhs)

    def _random_boolean_expression(self, depth: int = 0) -> Expression:
        kinds = self._allowed_boolean_expression_kinds(depth)
        kind = self._random_expr_kind_with_weight(kinds)
        match kind:
            case ExpressionKind.CONSTANT:
                return self._random_boolean()
            case ExpressionKind.VARIABLE:
                return self._random_boolean_identifier()
            case ExpressionKind.COMPARE:
                return self._random_compare_expression(depth)
            case ExpressionKind.UNARY:
                return self._random_boolean_logic_unary_expression(depth)
            case ExpressionKind.BINARY:
                return self._random_boolean_logic_binary_expression(depth)
            case ExpressionKind.TERNARY:
                return self._random_boolean_logic_ternary_expression(depth)
            case ExpressionKind.CUSTOM:
                return self._random_boolean_custom_function_expression(depth)
            case _:
                raise NotImplementedError(f"Unimplemented Boolean Expression {kind}")

    def _random_arithmetic_unary_expression(self, depth: int = 0) -> Expression:
        op = self._random_arithmetic_unary_operation()
        return UnaryExpression(op, self._random_arithmetic_expression(depth + 1))

    def _random_arithmetic_binary_expression(self, depth: int = 0) -> Expression:
        op = self._random_arithmetic_binary_operation()

        # special handling for power (**)
        # if enabled, the right side is a bounded constant number
        if op == Operator.POW and self.fuzzer_config.enable_constant_exponent:
            return BinaryExpression(
                op,
                self._random_arithmetic_expression(depth + 1),
                self._random_number_for_exponent(),
            )

        # special handling for remainder (%) and division (/)
        # if enabled the divisor is either non zero constant or
        # an expression with an assertion before.
        if op in [Operator.REM, Operator.DIV]:

            divisor = self._random_arithmetic_expression(depth + 1)

            # in the very unlikely event that the divisor is zero exactly
            # zero, redo the random integer generation with the non-zero
            # integer method.
            if self.fuzzer_config.enable_divisor_non_zero_constant:
                if isinstance(divisor, Integer):
                    if divisor.value == 0:
                        divisor = self._random_non_zero_number()

            # if enabled this will add an assertion before the statement
            # containing this expression to assert that the divisor is
            # not zero.
            if self.fuzzer_config.enable_divisor_assertion:
                precondition = BinaryExpression(Operator.NEQ, divisor, Integer(0))
                assertion = Assertion(
                    precondition, f"division-by-zero (id: {self._assertion_ordering})"
                )
                self._assertion_ordering += 1
                self._pre_statements.append(assertion)

            # special early return for "/" and "%"
            return BinaryExpression(op, self._random_arithmetic_expression(depth + 1), divisor)

        # default operator and recurse generation
        return BinaryExpression(
            op,
            self._random_arithmetic_expression(depth + 1),
            self._random_arithmetic_expression(depth + 1),
        )

    def _random_arithmetic_ternary_expression(self, depth: int = 0) -> Expression:
        condition = self._random_boolean_expression(depth + 1)
        true_val = self._random_arithmetic_expression(depth + 1)
        false_val = self._random_arithmetic_expression(depth + 1)
        return TernaryExpression(condition, true_val, false_val)

    def _random_arithmetic_custom_function_expression(self, depth: int = 0) -> Expression:
        allowed_functions = [
            f for f in self.fuzzer_config.custom_functions if f.has_return_type(IRType.Field)
        ]
        selected_function = self.rng.choice(allowed_functions).copy()
        arguments = [
            self._random_arithmetic_expression(depth + 1) for _ in selected_function.parameters
        ]
        return CallExpression(selected_function, arguments)

    def _random_arithmetic_expression(self, depth: int = 0) -> Expression:
        kinds = self._allowed_arithmetic_expression_kinds(depth)
        kind = self._random_expr_kind_with_weight(kinds)
        match kind:
            case ExpressionKind.CONSTANT:
                return self._random_number()
            case ExpressionKind.VARIABLE:
                return self._random_arithmetic_identifier()
            case ExpressionKind.UNARY:
                return self._random_arithmetic_unary_expression(depth)
            case ExpressionKind.BINARY:
                return self._random_arithmetic_binary_expression(depth)
            case ExpressionKind.TERNARY:
                return self._random_arithmetic_ternary_expression(depth)
            case ExpressionKind.CUSTOM:
                return self._random_arithmetic_custom_function_expression(depth)
            case _:
                raise NotImplementedError(f"Unimplemented Arithmetic Expression {kind}")

    def _random_assignment(self) -> Assignment:
        assert (
            len(self._unassigned_identifiers) > 0
        ), "no unassigned variables left to create an assignment"

        # no need to copy here, because it already is a copy of output signals
        identifier = self._unassigned_identifiers.pop(0)

        # split the defining expression based on the type of the identifier
        if identifier.type_hint() == IRType.Field:
            assignment = Assignment(identifier, self._random_arithmetic_expression())
        else:
            assignment = Assignment(identifier, self._random_boolean_expression())

        # no need to copy here as the identifier is only used to filer per type
        # and the name is returned directly
        self._available_identifier.append(identifier)
        return assignment

    def _random_assertion(self) -> Assertion:
        assert self._assertion_budget > 0, "no budget left to create an assertion"
        self._assertion_budget -= 1
        condition = (
            self._random_boolean_expression()
        )  # visit this first to have a correct assertion id ordering
        assertion_id = self._assertion_ordering
        self._assertion_ordering += 1
        return Assertion(condition, f"assertion (id: {assertion_id})")

    def _random_statements(self) -> list[Statement]:
        statements = []

        for _ in range(len(self._unassigned_identifiers)):
            assignment = self._random_assignment()
            statements += self._pre_statements
            statements.append(assignment)
            self._pre_statements = []

        for _ in range(self._assertion_budget):
            assertion = self._random_assertion()
            statements += self._pre_statements
            statements.append(assertion)
            self._pre_statements = []

        # implementation correctness check
        assert self._assertion_budget == 0, "still available budget for assertions"
        assert len(self._unassigned_identifiers) == 0, "still pending variable assignments"

        return statements
