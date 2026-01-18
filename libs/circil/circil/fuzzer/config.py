from dataclasses import asdict, dataclass, field
from typing import Any

from circil.ir.node import FunctionDefinition
from circil.ir.operator import Operator
from circil.ir.type import IRType

# -----------------------------------------------------------------------------------


class InvalidFuzzerConfigError(Exception):
    """Exception thrown by the rewrite pattern parser (matcher / rewrite generator)"""

    # uses dictionary as config to break circular dependency
    def __init__(self, config: dict[str, Any], message: str):
        super().__init__(message)
        self.config = config
        self.message = message


# -----------------------------------------------------------------------------------


@dataclass(kw_only=True)
class FuzzerConfig:

    # probability weights for randomly picking one
    # of the listed expressions.
    probability_weight_constant: float = 1
    probability_weight_identifier: float = 1
    probability_weight_unary: float = 1
    probability_weight_binary: float = 1
    probability_weight_ternary: float = 1
    probability_weight_compare: float = 1
    probability_weight_custom: float = 1

    # absolute values to control the circuit shape
    max_expression_depth: int
    min_assertions: int
    max_assertions: int
    min_circuit_input_signals: int
    max_circuit_input_signals: int
    min_circuit_output_signals: int
    max_circuit_output_signals: int

    # This is a very specific options for configuring the generation
    # of a binary expression using the power operator. If
    # "enable_constant_exponent" is true, the specified min and max
    # values are used to determine the exponent.
    enable_constant_exponent: bool = False
    min_exponent_value: int = 0
    max_exponent_value: int = 0

    # To make the generated random numbers interesting, boundary values
    # are picked with a specific probability. Currently the boundaries are
    # 0, 1, (modulo-1) and modulo.
    probability_boundary_value: float  # probability to pick boundaries
    disable_field_modulo_boundary_value: bool  # if True, the modulo values are excluded
    # from boundary values

    # list of enabled operators to chose from for the specific expressions
    comparators: list[Operator]
    boolean_unary_operators: list[Operator]
    boolean_binary_operators: list[Operator]
    arithmetic_unary_operators: list[Operator]
    arithmetic_binary_operators: list[Operator]
    # bitwise_unary_operators     : list[Operator] # future work
    # bitwise_binary_operators    : list[Operator] # future work

    # List of result types that are allowed for the ternary operator.
    # If the list is empty, the ternary operation is disabled.
    ternary_expression_types: list[IRType]

    # this setting controls the types of the input and output of the circuits
    input_signal_types: list[IRType]
    output_signal_types: list[IRType]

    # special division handling
    enable_divisor_assertion: bool = False
    enable_divisor_non_zero_constant: bool = False

    # special custom functions to use
    custom_functions: list[FunctionDefinition] = field(default_factory=list)


def validate_fuzzer_config(config: FuzzerConfig):

    if config.max_assertions < config.min_assertions:
        raise InvalidFuzzerConfigError(
            asdict(config),
            (
                f"unsatisfiable min ({config.max_assertions}) and max "
                f"({config.min_assertions}) for assertions"
            ),
        )

    if config.max_circuit_input_signals < config.min_circuit_input_signals:
        raise InvalidFuzzerConfigError(
            asdict(config),
            (
                f"unsatisfiable min ({config.max_circuit_input_signals}) and max "
                f"({config.min_circuit_input_signals}) for circuit inputs"
            ),
        )

    if config.max_circuit_input_signals < config.min_circuit_input_signals:
        raise InvalidFuzzerConfigError(
            asdict(config),
            (
                f"unsatisfiable min ({config.max_circuit_input_signals}) and max "
                f"({config.min_circuit_input_signals}) for circuit inputs"
            ),
        )

    if config.max_circuit_output_signals < config.min_circuit_output_signals:
        raise InvalidFuzzerConfigError(
            asdict(config),
            (
                f"unsatisfiable min ({config.max_circuit_output_signals}) and max "
                f"({config.min_circuit_output_signals}) for circuit outputs"
            ),
        )

    if config.enable_constant_exponent:
        if config.max_exponent_value < config.min_exponent_value:
            raise InvalidFuzzerConfigError(
                asdict(config),
                (
                    f"unsatisfiable min ({config.max_exponent_value}) and max "
                    f"({config.min_exponent_value}) for exponent"
                ),
            )

    if config.min_circuit_input_signals < 0:
        raise InvalidFuzzerConfigError(
            asdict(config),
            (
                f"minimum value for circuit inputs must be a positive number "
                f"(found '{config.min_circuit_input_signals}')"
            ),
        )

    if config.min_circuit_output_signals < 0:
        raise InvalidFuzzerConfigError(
            asdict(config),
            (
                f"minimum value for circuit outputs must be a positive number "
                f"(found '{config.min_circuit_output_signals}')"
            ),
        )

    if config.min_exponent_value < 0:
        raise InvalidFuzzerConfigError(
            asdict(config),
            (
                f"minimum value for exponent must be a positive number "
                f"(found '{config.min_exponent_value}')"
            ),
        )

    if config.probability_weight_constant + config.probability_weight_identifier <= 0:
        raise InvalidFuzzerConfigError(
            asdict(config),
            "sum of weighted probabilities for leaf nodes must not be greater than '0'",
        )

    if len(config.input_signal_types) == 0:
        raise InvalidFuzzerConfigError(
            asdict(config), "input signal must have at least '1' available type"
        )

    if len(config.output_signal_types) == 0:
        raise InvalidFuzzerConfigError(
            asdict(config), "output signal must have at least '1' available type"
        )

    for custom_function in config.custom_functions:
        if len(custom_function.results) != 1:
            raise InvalidFuzzerConfigError(
                asdict(config), "custom functions must contain a single result"
            )


# -----------------------------------------------------------------------------------
