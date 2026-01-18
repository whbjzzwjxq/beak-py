import unittest
from random import Random

from circil.ir.node import (
    Assignment,
    BinaryExpression,
    CallExpression,
    Circuit,
    FunctionDefinition,
    Identifier,
    Integer,
    UnaryExpression,
)
from circil.ir.operator import Operator
from circil.rewrite.rewriter import RuleBasedRewriter
from circil.rewrite.rule import Rule
from circil.rewrite.utils import SimpleRNGUtil


class TestCircuitRewriter(unittest.TestCase):

    rng = Random(100)

    def test_rewrite_disabled(self):
        circuit = Circuit(
            "test-circuit",
            13,
            [Identifier("a"), Identifier("b")],
            [Identifier("d")],
            [
                Assignment(
                    Identifier("c"),
                    BinaryExpression(
                        Operator.ADD,
                        BinaryExpression(
                            Operator.ADD,
                            Identifier("a"),
                            UnaryExpression(
                                Operator.SUB, UnaryExpression(Operator.SUB, Integer(0))
                            ),
                            disable_rewrite=True,
                        ),
                        BinaryExpression(
                            Operator.MUL,
                            Identifier("b"),
                            BinaryExpression(
                                Operator.ADD,
                                Integer(0),
                                Integer(0),
                                disable_rewrite=True
                            ),
                            disable_rewrite=True,
                        ),
                        disable_rewrite=True,
                    ),
                )
            ],
        )

        assoc_rules = [
            Rule("assoc-add", "(?a + ?b)", "(?b + ?a)"),
            Rule("assoc-mul", "(?a * ?b)", "(?b * ?a)"),
        ]

        shuffler = RuleBasedRewriter(assoc_rules, SimpleRNGUtil(0, 12, self.rng), self.rng)
        _, applied_rules = shuffler.run(circuit)

        self.assertEqual(len(applied_rules), 0)

    def test_rewrite_with_fix_point(self):

        circuit = Circuit(
            "test-circuit",
            13,
            [Identifier("a"), Identifier("b")],
            [Identifier("d")],
            [
                Assignment(
                    Identifier("c"),
                    BinaryExpression(
                        Operator.ADD,
                        BinaryExpression(
                            Operator.ADD,
                            Identifier("a"),
                            UnaryExpression(
                                Operator.SUB, UnaryExpression(Operator.SUB, Integer(0))
                            ),
                        ),
                        BinaryExpression(
                            Operator.MUL,
                            Identifier("b"),
                            BinaryExpression(Operator.ADD, Integer(0), Integer(0)),
                        ),
                    ),
                )
            ],
        )

        assoc_rules = [
            Rule("assoc-add", "(?a + ?b)", "(?b + ?a)"),
            Rule("assoc-mul", "(?a * ?b)", "(?b * ?a)"),
        ]

        for _ in range(10):
            shuffler = RuleBasedRewriter(assoc_rules, SimpleRNGUtil(0, 12, self.rng), self.rng)
            shuffled_circuit, applied_rules = shuffler.run(circuit, 20)
            self.assertEqual(
                shuffled_circuit.size(), circuit.size()
            )  # size of circuit must stay the same
            self.assertEqual(
                len(applied_rules), 20
            )  # assoc can always be applied so we expect 20 rewrites

        optimize_rules = [
            Rule("one-mul", "(?a * 1)", "?a"),
            Rule("one-mul", "(1 * ?a)", "?a"),
            Rule("one-mul", "(?a * 0)", "0"),
            Rule("one-mul", "(0 * ?a)", "0"),
            Rule("zero-add", "(?a + 0)", "?a"),
            Rule("zero-add", "(0 + ?a)", "?a"),
            Rule("neg-neg", "(- (- ?a))", "?a"),
        ]

        for _ in range(10):
            optimizer = RuleBasedRewriter(optimize_rules, SimpleRNGUtil(0, 12, self.rng), self.rng)
            optimized_circuit, applied_rules = optimizer.run(circuit, 10)
            self.assertEqual(
                optimized_circuit.size(), 3
            )  # after reaching the fix-point it should have depth 3
            self.assertGreaterEqual(
                len(applied_rules), 4
            )  # maximal 4 rewrites before we derive at fix-point

    def test_call_expression_rewrite(self):
        circuit = Circuit(
            "test-circuit",
            13,
            [Identifier("a"), Identifier("b")],
            [Identifier("c")],
            [
                Assignment(
                    Identifier("c"),
                    CallExpression(
                        FunctionDefinition(
                            "add",
                            [Identifier("a"), Identifier("b")],
                            [Identifier("c")],
                        ),
                        [Identifier("a"), Identifier("b")],
                    ),
                )
            ],
        )

        custom_add_to_sub = [
            Rule("func-add", "(add ?a ?b)", "(sub ?a (- ?b))"),
        ]

        rewriter = RuleBasedRewriter(custom_add_to_sub, SimpleRNGUtil(0, 12, self.rng), self.rng)
        shuffled_circuit, applied_rules = rewriter.run(circuit, 1)

        self.assertTrue(shuffled_circuit.size() > circuit.size())
        self.assertEqual(len(applied_rules), 1)

        non_custom_add_to_sub = [
            Rule("func-add", "(add:bool ?a ?b)", "(sub ?a (- ?b))"),
        ]

        rewriter = RuleBasedRewriter(
            non_custom_add_to_sub, SimpleRNGUtil(0, 12, self.rng), self.rng
        )
        shuffled_circuit, applied_rules = rewriter.run(circuit, 1)

        self.assertTrue(shuffled_circuit.size() == circuit.size())
        self.assertEqual(len(applied_rules), 0)


if __name__ == "__main__":
    unittest.main()
