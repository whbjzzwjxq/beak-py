from abc import ABC, abstractmethod
from enum import StrEnum
from random import Random
from typing import Type

from circil.fuzzer.config import FuzzerConfig
from circil.ir.node import (
    Boolean,
    Circuit,
    FunctionDefinition,
    Identifier,
    Integer,
    IRNode,
)
from circil.ir.operator import Operator
from circil.ir.type import IRType
from circil.utils import bernoulli, weighted_select


class ExpressionKind(StrEnum):
    CONSTANT = "constant"
    VARIABLE = "variable"
    UNARY = "unary"
    BINARY = "binary"
    COMPARE = "compare"
    TERNARY = "ternary"
    CUSTOM = "custom"


class BaseCircuitFuzzer(ABC):
    """Abstract fuzzer class for CircIL `Circuit`s.

    This abstract class provides a lot of useful helper for
    any kind of generation strategy.
    """

    # Following fields are provided by the fuzzer caller
    field_modulo: int  # selected field modulo
    rng: Random  # Random object for the fuzzer
    fuzzer_config: FuzzerConfig  # config controlling randomness and features

    # List of variables that are available in the current scope.
    # It is important that this list is updated from child fuzzers
    # as the generation depends on it. Furthermore, before using
    # an identifier, its type should be checked!
    _available_identifier: list[Identifier]

    def __init__(self, field_modulo: int, rng: Random, fuzzer_config: FuzzerConfig):
        self.field_modulo = field_modulo
        self.rng = rng
        self.fuzzer_config = fuzzer_config
        self._available_identifier = []

    @abstractmethod
    def run(self) -> Circuit:
        raise NotImplementedError()

    def _random_id(self, size: int) -> str:
        name = ""
        for _ in range(size):
            name += self.rng.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890")
        return name

    def _random_expr_kind_with_weight(self, allowed_exprs: list[ExpressionKind]) -> ExpressionKind:
        weight_lookup = {
            ExpressionKind.CONSTANT: self.fuzzer_config.probability_weight_constant,
            ExpressionKind.VARIABLE: self.fuzzer_config.probability_weight_identifier,
            ExpressionKind.UNARY: self.fuzzer_config.probability_weight_unary,
            ExpressionKind.BINARY: self.fuzzer_config.probability_weight_binary,
            ExpressionKind.COMPARE: self.fuzzer_config.probability_weight_compare,
            ExpressionKind.TERNARY: self.fuzzer_config.probability_weight_ternary,
            ExpressionKind.CUSTOM: self.fuzzer_config.probability_weight_custom,
        }
        return weighted_select(allowed_exprs, weight_lookup, self.rng)

    def _random_number(self) -> Integer:
        if bernoulli(self.fuzzer_config.probability_boundary_value, self.rng):
            if self.fuzzer_config.disable_field_modulo_boundary_value:
                return Integer(self.rng.choice([0, 1, self.field_modulo - 1]))
            else:
                return Integer(self.rng.choice([0, 1, self.field_modulo - 1, self.field_modulo]))
        else:
            if self.fuzzer_config.disable_field_modulo_boundary_value:
                return Integer(self.rng.randint(0, self.field_modulo))
            else:
                return Integer(self.rng.randint(0, self.field_modulo - 1))

    def _random_non_zero_number(self) -> Integer:
        if bernoulli(self.fuzzer_config.probability_boundary_value, self.rng):
            return Integer(self.rng.choice([1, self.field_modulo - 1]))
        else:
            return Integer(self.rng.randint(1, self.field_modulo - 1))

    def _random_number_for_exponent(self) -> Integer:
        return Integer(
            self.rng.randint(
                self.fuzzer_config.min_exponent_value, self.fuzzer_config.max_exponent_value
            )
        )

    def _random_boolean(self) -> Boolean:
        return Boolean(self.rng.choice([True, False]))

    def _random_boolean_identifier(self) -> Identifier:
        tmp_variable_list = self._available_boolean_identifier_names
        assert len(tmp_variable_list) > 0, "no boolean variables available"
        return Identifier(self.rng.choice(tmp_variable_list), ty_hint=IRType.Bool)

    def _random_arithmetic_identifier(self) -> Identifier:
        tmp_variable_list = self._available_field_identifier_names
        assert len(tmp_variable_list) > 0, "no arithmetic variables available"
        return Identifier(self.rng.choice(tmp_variable_list), ty_hint=IRType.Field)

    def _random_comparator(self) -> Operator:
        return self.rng.choice(self.fuzzer_config.comparators)

    def _random_boolean_unary_operation(self) -> Operator:
        return self.rng.choice(self.fuzzer_config.boolean_unary_operators)

    def _random_boolean_binary_operation(self) -> Operator:
        return self.rng.choice(self.fuzzer_config.boolean_binary_operators)

    def _random_arithmetic_unary_operation(self) -> Operator:
        return self.rng.choice(self.fuzzer_config.arithmetic_unary_operators)

    def _random_arithmetic_binary_operation(self) -> Operator:
        return self.rng.choice(self.fuzzer_config.arithmetic_binary_operators)

    def _allowed_boolean_expression_kinds(self, depth: int) -> list[ExpressionKind]:
        allowed_expr = list()
        allowed_expr.append(ExpressionKind.CONSTANT)
        if len(self._available_boolean_identifier_names) > 0:
            allowed_expr.append(ExpressionKind.VARIABLE)
        if depth < self.fuzzer_config.max_expression_depth:
            if len(self.fuzzer_config.comparators) > 0:
                allowed_expr.append(ExpressionKind.COMPARE)
            if len(self.fuzzer_config.boolean_unary_operators):
                allowed_expr.append(ExpressionKind.UNARY)
            if len(self.fuzzer_config.boolean_binary_operators):
                allowed_expr.append(ExpressionKind.BINARY)
            if IRType.Bool in self.fuzzer_config.ternary_expression_types:
                allowed_expr.append(ExpressionKind.TERNARY)
            if any(
                [f for f in self.fuzzer_config.custom_functions if f.has_return_type(IRType.Bool)]
            ):
                allowed_expr.append(ExpressionKind.CUSTOM)
        return allowed_expr

    def _allowed_arithmetic_expression_kinds(self, depth: int) -> list[ExpressionKind]:
        allowed_expr = list()
        allowed_expr.append(ExpressionKind.CONSTANT)
        if len(self._available_field_identifier_names) > 0:
            allowed_expr.append(ExpressionKind.VARIABLE)
        if depth < self.fuzzer_config.max_expression_depth:
            if len(self.fuzzer_config.arithmetic_unary_operators):
                allowed_expr.append(ExpressionKind.UNARY)
            if len(self.fuzzer_config.arithmetic_binary_operators):
                allowed_expr.append(ExpressionKind.BINARY)
            if IRType.Field in self.fuzzer_config.ternary_expression_types:
                allowed_expr.append(ExpressionKind.TERNARY)
            if any(
                [f for f in self.fuzzer_config.custom_functions if f.has_return_type(IRType.Field)]
            ):
                allowed_expr.append(ExpressionKind.CUSTOM)
        return allowed_expr

    @property
    def _available_boolean_identifier_names(self) -> list[str]:
        return [x.name for x in self._available_identifier if x.type_hint() == IRType.Bool]

    @property
    def _available_field_identifier_names(self) -> list[str]:
        return [x.name for x in self._available_identifier if x.type_hint() == IRType.Field]
