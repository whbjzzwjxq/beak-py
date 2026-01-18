import unittest

from circil.ir.node import (
    BinaryExpression,
    Boolean,
    Circuit,
    Identifier,
    Integer,
    Operator,
    UnaryExpression,
)
from circil.ir.type import IRType


class TestCircuitFuzzer(unittest.TestCase):
    def test_type_hint_impl(self):
        field_unary_expr = UnaryExpression(Operator.COMP, Integer(2))
        self.assertEqual(field_unary_expr.type_hint(), IRType.Field)
        field_binary_expr = BinaryExpression(Operator.ADD, Integer(1), Integer(2))
        self.assertEqual(field_binary_expr.type_hint(), IRType.Field)

        boolean_unary_expr = UnaryExpression(Operator.NOT, Boolean(False))
        self.assertEqual(boolean_unary_expr.type_hint(), IRType.Bool)
        boolean_binary_expr = BinaryExpression(Operator.LAND, Boolean(False), Boolean(True))
        self.assertEqual(boolean_binary_expr.type_hint(), IRType.Bool)

        field_cmp_op_lhs = BinaryExpression(Operator.ADD, Integer(1), Integer(2))
        field_cmp_op_rhs = BinaryExpression(Operator.ADD, Integer(1), Integer(2))
        boolean_cmp_expr = BinaryExpression(Operator.EQU, field_cmp_op_lhs, field_cmp_op_rhs)
        self.assertEqual(boolean_cmp_expr.type_hint(), IRType.Bool)

    def test_equality_impl(self):
        first_expr = UnaryExpression(Operator.COMP, Integer(2))
        second_expr = UnaryExpression(Operator.COMP, Integer(2))
        self.assertNotEqual(first_expr, second_expr)
        self.assertEqual(first_expr, first_expr)
        self.assertEqual(second_expr, second_expr)

    def test_circuit_type_compatible(self):
        c1 = Circuit(
            "c1",
            3,
            [Identifier("a", IRType.Bool), Identifier("b", IRType.Field)],
            [Identifier("c", IRType.Field)],
            [],
        )
        c2 = Circuit(
            "c2",
            11,
            [Identifier("d", IRType.Bool), Identifier("e", IRType.Field)],
            [Identifier("f", IRType.Field)],
            [],
        )
        c3 = Circuit(
            "c3",
            23,
            [Identifier("g", IRType.Field), Identifier("h", IRType.Field)],
            [Identifier("i", IRType.Field)],
            [],
        )
        c4 = Circuit(
            "c4",
            23,
            [Identifier("j", IRType.Bool), Identifier("k", IRType.Bool)],
            [Identifier("l", IRType.Bool)],
            [],
        )
        c5 = Circuit(
            "c5",
            101,
            [Identifier("m", IRType.Bool), Identifier("n", IRType.Bool)],
            [Identifier("o", IRType.Bool)],
            [],
        )
        c6 = Circuit("c6", 101, [], [], [])

        self.assertTrue(c1.is_type_compatible_with(c1))
        self.assertTrue(c1.is_type_compatible_with(c2))
        self.assertTrue(c2.is_type_compatible_with(c1))
        self.assertTrue(c4.is_type_compatible_with(c5))
        self.assertTrue(c5.is_type_compatible_with(c4))
        self.assertTrue(c6.is_type_compatible_with(c6))

        self.assertFalse(c1.is_type_compatible_with(c3))
        self.assertFalse(c1.is_type_compatible_with(c4))
        self.assertFalse(c2.is_type_compatible_with(c3))
        self.assertFalse(c2.is_type_compatible_with(c4))
        self.assertFalse(c3.is_type_compatible_with(c1))
        self.assertFalse(c3.is_type_compatible_with(c2))
        self.assertFalse(c1.is_type_compatible_with(c6))
        self.assertFalse(c2.is_type_compatible_with(c6))
        self.assertFalse(c3.is_type_compatible_with(c6))
        self.assertFalse(c4.is_type_compatible_with(c6))
        self.assertFalse(c5.is_type_compatible_with(c6))
