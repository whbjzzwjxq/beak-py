import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from circil.ir.operator import Operator
from circil.ir.type import IRType

# -----------------------------------------------------------------------------------


# The `kw_only=True` prevents the `node_id` form being required
# as first argument.
#
# Furthermore, the dataclass implements a lot of defaults (e.g. `__eq__`)
# that can be quit expensive.
@dataclass(kw_only=True)
class IRNode(ABC):
    """Base class of every CircIL IR node"""

    # Uses default_factory's count to automatically provide a unique
    # id for every node.
    node_id: uuid.UUID = field(default_factory=uuid.uuid4)

    # This flag is used to disable rewriting rules for this particular node
    disable_rewrite: bool = False

    @abstractmethod
    def copy(self) -> "IRNode":
        """Returns a deep copy of the node with a new `node_id`"""
        raise NotImplementedError()

    @abstractmethod
    def size(self) -> int:
        """Returns the amount of sub-nodes + 1"""
        raise NotImplementedError()


# -----------------------------------------------------------------------------------


@dataclass
class Statement(IRNode):
    """Base class of every CircIL Statement"""

    @abstractmethod
    def copy(self) -> "Statement":
        raise NotImplementedError()


# -----------------------------------------------------------------------------------


@dataclass
class Expression(IRNode):
    """Base class of every CircIL Expression"""

    @abstractmethod
    def copy(self) -> "Expression":
        raise NotImplementedError()

    @abstractmethod
    def type_hint(self) -> IRType:
        """Returns the type of the expression"""
        raise NotImplementedError()


# -----------------------------------------------------------------------------------


@dataclass
class Identifier(Expression):
    name: str
    ty_hint: IRType = IRType.Field

    def copy(self) -> "Identifier":
        return Identifier(self.name, self.ty_hint, disable_rewrite=self.disable_rewrite)

    def size(self) -> int:
        return 1

    def type_hint(self) -> IRType:
        """Returns the type of the `ty_hint` field (default is `Field`)"""
        return self.ty_hint

    def __str__(self):
        return self.name


# -----------------------------------------------------------------------------------


@dataclass
class Integer(Expression):
    value: int

    def copy(self) -> "Integer":
        return Integer(self.value, disable_rewrite=self.disable_rewrite)

    def size(self) -> int:
        return 1

    def type_hint(self) -> IRType:
        """Returns always the `Field` type"""
        return IRType.Field

    def __str__(self):
        return str(self.value)


# -----------------------------------------------------------------------------------


@dataclass
class Boolean(Expression):
    value: bool

    def copy(self) -> "Boolean":
        return Boolean(self.value, disable_rewrite=self.disable_rewrite)

    def size(self) -> int:
        return 1

    def type_hint(self) -> IRType:
        """Returns always the `Bool` type"""
        return IRType.Bool

    def __str__(self):
        return "T" if self.value else "F"


# -----------------------------------------------------------------------------------


@dataclass
class UnaryExpression(Expression):
    op: Operator
    value: Expression

    def copy(self) -> "UnaryExpression":
        return UnaryExpression(self.op, self.value.copy(), disable_rewrite=self.disable_rewrite)

    def size(self) -> int:
        return 1 + self.value.size()

    def type_hint(self) -> IRType:
        """Returns the type of the inner `value`"""
        return self.value.type_hint()

    def __str__(self):
        return f"({self.op.value} {self.value})"


# -----------------------------------------------------------------------------------


@dataclass
class BinaryExpression(Expression):
    op: Operator
    lhs: Expression
    rhs: Expression

    def copy(self) -> "BinaryExpression":
        return BinaryExpression(
            self.op, self.lhs.copy(), self.rhs.copy(), disable_rewrite=self.disable_rewrite
        )

    def size(self) -> int:
        return 1 + self.lhs.size() + self.rhs.size()

    def type_hint(self) -> IRType:
        """Returns the type of the `lhs` (`rhs` is implicitly casted),
        except for compare-expressions, where it always returns `IRType.Bool`
        """
        if self.op in Operator.comparators():
            return IRType.Bool
        else:
            return self.lhs.type_hint()

    def __str__(self):
        return f"({self.lhs} {self.op.value} {self.rhs})"


# -----------------------------------------------------------------------------------


@dataclass
class TernaryExpression(Expression):
    cond: Expression
    if_expr: Expression
    else_expr: Expression

    def copy(self) -> "TernaryExpression":
        return TernaryExpression(
            self.cond.copy(),
            self.if_expr.copy(),
            self.else_expr.copy(),
            disable_rewrite=self.disable_rewrite,
        )

    def size(self) -> int:
        return 1 + self.cond.size() + self.if_expr.size() + self.else_expr.size()

    def type_hint(self) -> IRType:
        """Returns the type of the if-expr (else-expr is implicitly casted)"""
        return self.if_expr.type_hint()

    def __str__(self):
        return f"({self.cond} ? {self.if_expr} : {self.else_expr})"


# -----------------------------------------------------------------------------------


@dataclass
class CastExpression(Expression):
    cast_ty: IRType
    expr: Expression

    def copy(self) -> "CastExpression":
        return CastExpression(self.cast_ty, self.expr.copy(), disable_rewrite=self.disable_rewrite)

    def size(self) -> int:
        return 1 + self.expr.size()

    def type_hint(self) -> IRType:
        """Returns the target type of cast"""
        return self.cast_ty

    def __str__(self):
        return f"cast<{self.cast_ty}>({self.expr})"


# -----------------------------------------------------------------------------------


@dataclass
class CallExpression(Expression):
    function: "FunctionDefinition"
    arguments: list[Expression]

    def copy(self) -> "CallExpression":
        return CallExpression(
            self.function.copy(),
            [e.copy() for e in self.arguments],
            disable_rewrite=self.disable_rewrite,
        )

    def size(self) -> int:
        return 1 + sum([e.size() for e in self.arguments])

    def type_hint(self) -> IRType:
        assert len(self.function.results) == 1, "unexpected result type"
        return self.function.results[0].type_hint()

    def __str__(self):
        arguments = ", ".join(f"{e}" for e in self.arguments)
        return f"{self.function.name}({arguments})"


# -----------------------------------------------------------------------------------


@dataclass
class Assertion(Statement):
    value: Expression
    tag: str

    def copy(self) -> "Assertion":
        return Assertion(self.value.copy(), self.tag, disable_rewrite=self.disable_rewrite)

    def size(self) -> int:
        return 1 + self.value.size()

    def __str__(self):
        return f'assert({self.value}, "{self.tag}")'


# -----------------------------------------------------------------------------------


@dataclass
class Assignment(Statement):
    lhs: Identifier
    rhs: Expression

    def copy(self) -> "Assignment":
        return Assignment(self.lhs.copy(), self.rhs.copy(), disable_rewrite=self.disable_rewrite)

    def size(self) -> int:
        return 1 + self.lhs.size() + self.rhs.size()

    def __str__(self):
        return f"{self.lhs} = {self.rhs}"


# -----------------------------------------------------------------------------------


@dataclass
class FunctionDefinition(IRNode):
    """Base class for function definitions."""

    name: str
    parameters: list[Identifier]
    results: list[Identifier]

    def copy(self) -> "FunctionDefinition":
        return FunctionDefinition(
            self.name,
            [parameter.copy() for parameter in self.parameters],
            [result.copy() for result in self.results],
            disable_rewrite=self.disable_rewrite,
        )

    def size(self) -> int:
        return 0  # NOTE: for now this is zero

    def return_type(self) -> None | IRType | list[IRType]:
        if len(self.results) == 0:
            return None
        if len(self.results) == 1:
            return self.results[0].type_hint()
        else:
            return [e.type_hint() for e in self.results]

    def has_return_type(self, ty: None | IRType | list[IRType]) -> bool:
        return self.return_type() == ty


# -----------------------------------------------------------------------------------


@dataclass
class Circuit(IRNode):
    name: str
    field_modulo: int
    inputs: list[Identifier]
    outputs: list[Identifier]
    statements: list[Statement]

    def copy(self) -> "Circuit":
        return Circuit(
            self.name,
            self.field_modulo,
            [x.copy() for x in self.inputs],
            [x.copy() for x in self.outputs],
            [x.copy() for x in self.statements],
            disable_rewrite=self.disable_rewrite,
        )

    @property
    def assignments(self) -> list[Assignment]:
        """Returns a list of all assignments of the circuit"""
        return [s for s in self.statements if isinstance(s, Assignment)]

    @property
    def assertions(self) -> list[Assertion]:
        """Returns a list of all assertions of the circuit"""
        return [s for s in self.statements if isinstance(s, Assertion)]

    def is_type_compatible_with(self, circuit: "Circuit") -> bool:
        """Returns `True` if the passed circuit has the same I/O types"""
        if len(circuit.inputs) != len(self.inputs) or len(circuit.outputs) != len(self.outputs):
            return False
        self_flattened_ids = self.inputs + self.outputs
        circuit_flattened_ids = circuit.inputs + circuit.outputs
        return all(
            [
                id1.ty_hint == id2.ty_hint
                for (id1, id2) in zip(self_flattened_ids, circuit_flattened_ids)
            ]
        )

    def size(self) -> int:
        """Returns the amount of nodes inside of the circuit"""
        return sum([s.size() for s in self.statements])

    def __str__(self):
        return """
@field({1})
circuit {0} ({2}) -> ({3}):
    {4}
""".format(
            self.name,
            self.field_modulo,
            ", ".join([f"{e.name}:{e.type_hint()}" for e in self.inputs]),
            ", ".join([f"{e.name}:{e.type_hint()}" for e in self.outputs]),
            "\n    ".join([str(e) for e in self.statements]),
        )


# -----------------------------------------------------------------------------------
