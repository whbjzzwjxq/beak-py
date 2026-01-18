import unittest
from random import Random
from typing import cast

from circil.fuzzer.config import FuzzerConfig
from circil.fuzzer.simple import SimpleCircuitFuzzer
from circil.ir.node import (
    BinaryExpression,
    Boolean,
    CallExpression,
    Identifier,
    Integer,
    UnaryExpression,
)
from circil.ir.operator import Operator
from circil.ir.serialize import (
    IRDictDeserializer,
    IRDictSerializer,
    IRJSONDeserializer,
    IRJSONSerializer,
)
from circil.ir.type import IRType


class TestCircuitSerialize(unittest.TestCase):

    BN254 = 21888242871839275222246405745257275088548364400416034343698204186575808495617
    rng = Random(100)
    config = FuzzerConfig(
        probability_weight_constant=1,
        probability_weight_identifier=1,
        probability_weight_unary=1,
        probability_weight_binary=1,
        probability_weight_ternary=1,
        probability_weight_compare=1,
        max_expression_depth=5,
        min_assertions=3,
        max_assertions=3,
        min_circuit_input_signals=3,
        max_circuit_input_signals=3,
        min_circuit_output_signals=3,
        max_circuit_output_signals=3,
        enable_constant_exponent=True,
        min_exponent_value=2,
        max_exponent_value=4,
        probability_boundary_value=0.5,
        disable_field_modulo_boundary_value=False,
        comparators=[Operator.EQU, Operator.LTH, Operator.GTH],
        boolean_unary_operators=[Operator.NOT],
        boolean_binary_operators=[Operator.LAND, Operator.LOR],
        arithmetic_unary_operators=[Operator.SUB],
        arithmetic_binary_operators=[Operator.ADD, Operator.AND, Operator.OR],
        ternary_expression_types=[IRType.Field],
        input_signal_types=[IRType.Bool, IRType.Field],
        output_signal_types=[IRType.Bool, IRType.Field],
        enable_divisor_assertion=False,
        enable_divisor_non_zero_constant=True,
    )

    def test_random_dict_serializer_deserialize(self):

        for _ in range(20):
            circuit = SimpleCircuitFuzzer(self.BN254, self.rng, self.config).run()
            serialized_circuit = IRDictSerializer().serialize(circuit)
            deserialized_circuit = IRDictDeserializer().deserialize(serialized_circuit)
            self.assertEqual(circuit, deserialized_circuit)

    def test_random_json_serializer_deserialize(self):

        for _ in range(20):
            circuit = SimpleCircuitFuzzer(self.BN254, self.rng, self.config).run()
            serialized_circuit = IRJSONSerializer().serialize(circuit)
            deserialized_circuit = IRJSONDeserializer().deserialize(serialized_circuit)
            self.assertEqual(circuit, deserialized_circuit)

            snd_serialized_circuit = IRJSONSerializer().serialize(deserialized_circuit)
            self.assertEqual(serialized_circuit, snd_serialized_circuit)

    def test_identifier_json_deserialization(self):

        json_test_1 = """
        {
            "kind"   : "Identifier",
            "object" : {
                "node_id" : "00000000-0000-0000-0000-000000000000",
                "name"    : "test_identifier_1",
                "ty_hint" : "Bool",
                "disable_rewrite" : false
            }
        }
        """
        node_test_1 = IRJSONDeserializer().deserialize(json_test_1)
        self.assertTrue(isinstance(node_test_1, Identifier))

        identifier_test_1 = cast(Identifier, node_test_1)
        self.assertEqual(identifier_test_1.name, "test_identifier_1")
        self.assertEqual(identifier_test_1.ty_hint, IRType.Bool)

    def test_integer_json_deserialization(self):

        json_test_1 = """
        {
            "kind"   : "Integer",
            "object" : {
                "node_id" : "00000000-0000-0000-0000-000000000000",
                "value"    : "1234567890123456789",
                "disable_rewrite" : false
            }
        }
        """
        node_test_1 = IRJSONDeserializer().deserialize(json_test_1)
        self.assertTrue(isinstance(node_test_1, Integer))

        integer_test_1 = cast(Integer, node_test_1)
        self.assertEqual(integer_test_1.value, 1234567890123456789)

        json_test_2 = """
        {
            "kind"   : "Integer",
            "object" : {
                "node_id" : "00000000-0000-0000-0000-000000000000",
                "value"    : 9876543210,
                "disable_rewrite" : true
            }
        }
        """
        node_test_2 = IRJSONDeserializer().deserialize(json_test_2)
        self.assertTrue(isinstance(node_test_2, Integer))
        self.assertTrue(node_test_2.disable_rewrite)

        integer_test_2 = cast(Integer, node_test_2)
        self.assertEqual(integer_test_2.value, 9876543210)

    def test_boolean_json_deserialization(self):

        json_test_1 = """
        {
            "kind"   : "Boolean",
            "object" : {
                "node_id" : "00000000-0000-0000-0000-000000000000",
                "value"    : true,
                "disable_rewrite" : false
            }
        }
        """
        node_test_1 = IRJSONDeserializer().deserialize(json_test_1)
        self.assertTrue(isinstance(node_test_1, Boolean))

        boolean_test_1 = cast(Boolean, node_test_1)
        self.assertEqual(boolean_test_1.value, True)

        json_test_2 = """
        {
            "kind"   : "Boolean",
            "object" : {
                "node_id" : "00000000-0000-0000-0000-000000000000",
                "value"    : false,
                "disable_rewrite" : false
            }
        }
        """
        node_test_2 = IRJSONDeserializer().deserialize(json_test_2)
        self.assertTrue(isinstance(node_test_2, Boolean))

        boolean_test_2 = cast(Boolean, node_test_2)
        self.assertEqual(boolean_test_2.value, False)

    def test_unary_json_deserialization(self):

        json_test_1 = """
        {
            "kind"   : "UnaryExpression",
            "object" : {
                "node_id" : "00000000-0000-0000-0000-000000000000",
                "op"      : "NOT",
                "value"   : {
                    "kind"   : "Boolean",
                    "object" : {
                        "node_id" : "00000000-0000-0000-0000-000000000001",
                        "value"   : false,
                        "disable_rewrite" : false
                    }
                },
                "disable_rewrite" : false
            }
        }
        """
        node_test_1 = IRJSONDeserializer().deserialize(json_test_1)
        self.assertTrue(isinstance(node_test_1, UnaryExpression))

        unary_test_1 = cast(UnaryExpression, node_test_1)
        self.assertEqual(unary_test_1.op, Operator.NOT)
        self.assertTrue(isinstance(unary_test_1.value, Boolean))

    def test_binary_json_deserialization(self):

        json_test_1 = """
        {
            "kind"   : "BinaryExpression",
            "object" : {
                "node_id" : "00000000-0000-0000-0000-000000000000",
                "op"      : "ADD",
                "lhs"     : {
                    "kind"   : "Integer",
                    "object" : {
                        "node_id" : "00000000-0000-0000-0000-000000000001",
                        "value"   : 1,
                        "disable_rewrite" : false
                    }
                },
                "rhs"     : {
                    "kind"   : "Integer",
                    "object" : {
                        "node_id" : "00000000-0000-0000-0000-000000000002",
                        "value"   : 2,
                        "disable_rewrite" : false
                    }
                },
                "disable_rewrite" : false
            }
        }
        """
        node_test_1 = IRJSONDeserializer().deserialize(json_test_1)
        self.assertTrue(isinstance(node_test_1, BinaryExpression))

        unary_test_1 = cast(BinaryExpression, node_test_1)
        self.assertEqual(unary_test_1.op, Operator.ADD)
        self.assertTrue(isinstance(unary_test_1.lhs, Integer))
        self.assertTrue(isinstance(unary_test_1.rhs, Integer))

    def test_call_expression_json_deserialization(self):
        json_test_1 = """
        {
            "kind" : "CallExpression",
            "object" : {
                "node_id" : "00000000-0000-0000-0000-000000000000",
                "arguments" : [],
                "function" : {
                    "kind" : "FunctionDefinition",
                    "object" : {
                        "node_id" : "00000000-0000-0000-0000-000000000001",
                        "name": "test_function",
                        "parameters" : [],
                        "results" : [
                            {
                                "kind"   : "Identifier",
                                "object" : {
                                    "node_id" : "00000000-0000-0000-0000-000000000002",
                                    "name"    : "a",
                                    "ty_hint" : "Bool",
                                    "disable_rewrite" : false
                                }
                            }
                        ],
                        "disable_rewrite" : false
                    }
                },
                "disable_rewrite" : false
            }
        }
        """

        node_test_1 = IRJSONDeserializer().deserialize(json_test_1)
        self.assertTrue(isinstance(node_test_1, CallExpression))

        call_expr = cast(CallExpression, node_test_1)

        self.assertTrue(call_expr.function.name == "test_function")
        self.assertTrue(len(call_expr.function.parameters) == 0)
        self.assertTrue(len(call_expr.function.results) == 1)


if __name__ == "__main__":
    unittest.main()
