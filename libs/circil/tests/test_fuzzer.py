import unittest
from random import Random

from circil.fuzzer.config import FuzzerConfig
from circil.fuzzer.simple import SimpleCircuitFuzzer
from circil.ir.node import FunctionDefinition, Identifier, IRType
from circil.ir.operator import Operator


class TestCircuitFuzzer(unittest.TestCase):

    BN254 = 21888242871839275222246405745257275088548364400416034343698204186575808495617

    rng = Random(100)
    config = FuzzerConfig(
        probability_weight_constant=1,
        probability_weight_identifier=1,
        probability_weight_unary=1,
        probability_weight_binary=1,
        probability_weight_ternary=1,
        probability_weight_compare=1,
        probability_weight_custom=1,
        max_expression_depth=3,
        min_assertions=1,
        max_assertions=3,
        min_circuit_input_signals=0,
        max_circuit_input_signals=3,
        min_circuit_output_signals=0,
        max_circuit_output_signals=3,
        enable_constant_exponent=True,
        min_exponent_value=2,
        max_exponent_value=4,
        probability_boundary_value=0.5,
        disable_field_modulo_boundary_value=False,
        comparators=[Operator.EQU, Operator.LTH],
        boolean_unary_operators=[Operator.NOT],
        boolean_binary_operators=[Operator.LAND, Operator.LOR],
        arithmetic_unary_operators=[Operator.SUB],
        arithmetic_binary_operators=[Operator.ADD, Operator.AND, Operator.OR],
        ternary_expression_types=[IRType.Field],
        input_signal_types=[IRType.Bool, IRType.Field],
        output_signal_types=[IRType.Bool, IRType.Field],
        enable_divisor_assertion=False,
        enable_divisor_non_zero_constant=True,
        custom_functions=[
            FunctionDefinition("custom-1", [], [Identifier("r")]),
            FunctionDefinition(
                "custom-2", [Identifier("a"), Identifier("b", IRType.Bool)], [Identifier("r")]
            ),
        ],
    )

    def test_fuzzer_run_with_default_config_impl(self):
        # 100 fuzzer runs to get some variety
        for _ in range(100):
            fuzzer = SimpleCircuitFuzzer(self.BN254, self.rng, self.config)
            circuit = fuzzer.run()
            self.assertGreater(circuit.size(), 0)


if __name__ == "__main__":
    unittest.main()
