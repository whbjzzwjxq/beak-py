from circil.ir.node import (
    Assignment,
    BinaryExpression,
    Circuit,
    Identifier,
    Integer,
    TernaryExpression,
)
from circil.ir.operator import Operator
from zkvm_fuzzer_utils.circil import SafeRemAndDivTransformer, SSATransformer


def test_safe_rem_and_div_transformer_with_div():
    circuit = Circuit(
        "test",
        11,
        [Identifier("a")],
        [Identifier("b")],
        [
            Assignment(
                Identifier("b"),
                BinaryExpression(Operator.DIV, Integer(10), Identifier("a")),
            )
        ],
    )

    circuit_safe = Circuit(
        "test",
        11,
        [Identifier("a")],
        [Identifier("b")],
        [
            Assignment(
                Identifier("b"),
                BinaryExpression(
                    Operator.DIV,
                    Integer(10),
                    TernaryExpression(
                        BinaryExpression(
                            Operator.EQU,
                            Identifier("a"),
                            Integer(0),
                        ),
                        Integer(1),
                        Identifier("a"),
                    ),
                ),
            )
        ],
    )

    circuit_transformed = SafeRemAndDivTransformer().transform(circuit)
    assert str(circuit_safe) == str(circuit_transformed), "unexpected transformation outcome"


def test_safe_rem_and_div_transformer_with_rem():
    circuit = Circuit(
        "test",
        11,
        [Identifier("a")],
        [Identifier("b")],
        [
            Assignment(
                Identifier("b"),
                BinaryExpression(Operator.REM, Integer(10), Identifier("a")),
            )
        ],
    )

    circuit_safe = Circuit(
        "test",
        11,
        [Identifier("a")],
        [Identifier("b")],
        [
            Assignment(
                Identifier("b"),
                BinaryExpression(
                    Operator.REM,
                    Integer(10),
                    TernaryExpression(
                        BinaryExpression(
                            Operator.EQU,
                            Identifier("a"),
                            Integer(0),
                        ),
                        Integer(1),
                        Identifier("a"),
                    ),
                ),
            )
        ],
    )

    circuit_transformed = SafeRemAndDivTransformer().transform(circuit)
    assert str(circuit_safe) == str(circuit_transformed), "unexpected transformation outcome"


def test_ssa_transformer():
    circuit = Circuit(
        "test",
        11,
        [Identifier("a")],
        [Identifier("b")],
        [
            Assignment(
                Identifier("b"),
                BinaryExpression(
                    Operator.REM,
                    Integer(10),
                    TernaryExpression(
                        BinaryExpression(
                            Operator.EQU,
                            Identifier("a"),
                            BinaryExpression(
                                Operator.ADD,
                                Integer(0),
                                Integer(0),
                            ),
                        ),
                        BinaryExpression(
                            Operator.ADD,
                            Identifier("a"),
                            Integer(1),
                        ),
                        Identifier("a"),
                    ),
                ),
            )
        ],
    )

    circuit_ssa = Circuit(
        "test",
        11,
        [Identifier("a")],
        [Identifier("b")],
        [
            Assignment(
                Identifier("var0"),
                BinaryExpression(
                    Operator.ADD,
                    Integer(0),
                    Integer(0),
                ),
            ),
            Assignment(
                Identifier("var1"),
                BinaryExpression(Operator.EQU, Identifier("a"), Identifier("var0")),
            ),
            Assignment(
                Identifier("var2"),
                BinaryExpression(
                    Operator.ADD,
                    Identifier("a"),
                    Integer(1),
                ),
            ),
            Assignment(
                Identifier("var3"),
                TernaryExpression(
                    Identifier("var1"),
                    Identifier("var2"),
                    Identifier("a"),
                ),
            ),
            Assignment(
                Identifier("b"),
                BinaryExpression(Operator.REM, Integer(10), Identifier("var3")),
            ),
        ],
    )

    circuit_transformed = SSATransformer().transform(circuit)
    assert str(circuit_ssa) == str(circuit_transformed), "unexpected transformation outcome"
