import json
from typing import Any, cast
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
    IRNode,
    Statement,
    TernaryExpression,
    UnaryExpression,
)
from circil.ir.operator import Operator
from circil.ir.type import IRType
from circil.ir.visitor import EmptyVisitor

# -----------------------------------------------------------------------------------


def serialize_ir_type(ty: IRType) -> str:
    """Helper function to serialize `IRType`"""
    return ty.name


def deserialize_ir_type(name: str) -> IRType:
    """Helper function to deserialize `IRType`"""
    return IRType[name]


def serialize_operator(op: Operator) -> str:
    """Helper function to serialize `Operator`"""
    return op.name


def deserialize_operator(name: str) -> Operator:
    """Helper function to deserialize `Operator`"""
    return Operator[name]


def serialize_uuid(uid: UUID) -> str:
    """Helper function to serialize `UUID`"""
    return str(uid)


def deserialize_uuid(value: str) -> UUID:
    """Helper function to deserialize `UUID`"""
    return UUID(value)


# -----------------------------------------------------------------------------------


class IRDictSerializer(EmptyVisitor):
    """Serializer to convert any `IRNode` into a python `dict[str, Any]`

    The resulting dictionary form nodes contain the keys `kind` and `object`.
    The `kind` value is the name of the node class and the `object` is
    a second dictionary containing the node fields as keys with the respective
    values.

    The values of the node fields may have custom serialization, which means that
    the resulting type might have been changed (e.g. `UUID` to `str`)
    """

    _cache: dict[UUID, dict[str, Any]]

    def serialize(self, node: IRNode) -> dict[str, Any]:
        self._cache = {}  # reset
        self.visit(node)  # generate for current node
        return self._fetch(node)  # remove from cache and return

    def _store(self, node: IRNode, data: dict[str, Any]):
        assert node.node_id not in self._cache, f"multiple store for '{node}' detected!"
        self._cache[node.node_id] = data

    def _fetch(self, node: IRNode) -> dict[str, Any]:
        if node.node_id not in self._cache:
            self.visit(node)
        return self._cache.pop(node.node_id)

    def _fetch_list(self, nodes: list[IRNode]) -> list[dict[str, Any]]:
        return [self._fetch(node) for node in nodes]

    def visit_identifier(self, node: Identifier):
        self._store(
            node,
            {
                "kind": "Identifier",
                "object": {
                    "node_id": serialize_uuid(node.node_id),
                    "name": node.name,
                    "ty_hint": serialize_ir_type(node.ty_hint),
                    "disable_rewrite": node.disable_rewrite,
                },
            },
        )

    def visit_boolean(self, node: Boolean):
        self._store(
            node,
            {
                "kind": "Boolean",
                "object": {
                    "node_id": serialize_uuid(node.node_id),
                    "value": node.value,
                    "disable_rewrite": node.disable_rewrite,
                },
            },
        )

    def visit_integer(self, node: Integer):
        self._store(
            node,
            {
                "kind": "Integer",
                "object": {
                    "node_id": serialize_uuid(node.node_id),
                    "value": node.value,
                    "disable_rewrite": node.disable_rewrite,
                },
            },
        )

    def visit_unary_expression(self, node: UnaryExpression):
        self._store(
            node,
            {
                "kind": "UnaryExpression",
                "object": {
                    "node_id": serialize_uuid(node.node_id),
                    "op": serialize_operator(node.op),
                    "value": self._fetch(node.value),
                    "disable_rewrite": node.disable_rewrite,
                },
            },
        )

    def visit_binary_expression(self, node: BinaryExpression):
        self._store(
            node,
            {
                "kind": "BinaryExpression",
                "object": {
                    "node_id": serialize_uuid(node.node_id),
                    "op": serialize_operator(node.op),
                    "lhs": self._fetch(node.lhs),
                    "rhs": self._fetch(node.rhs),
                    "disable_rewrite": node.disable_rewrite,
                },
            },
        )

    def visit_ternary_expression(self, node: TernaryExpression):
        self._store(
            node,
            {
                "kind": "TernaryExpression",
                "object": {
                    "node_id": serialize_uuid(node.node_id),
                    "cond": self._fetch(node.cond),
                    "if_expr": self._fetch(node.if_expr),
                    "else_expr": self._fetch(node.else_expr),
                    "disable_rewrite": node.disable_rewrite,
                },
            },
        )

    def visit_call_expression(self, node: CallExpression):
        self._store(
            node,
            {
                "kind": "CallExpression",
                "object": {
                    "node_id": serialize_uuid(node.node_id),
                    "function": self._fetch(node.function),
                    "arguments": [self._fetch(e) for e in node.arguments],
                    "disable_rewrite": node.disable_rewrite,
                },
            },
        )

    def visit_assertion(self, node: Assertion):
        self._store(
            node,
            {
                "kind": "Assertion",
                "object": {
                    "node_id": serialize_uuid(node.node_id),
                    "value": self._fetch(node.value),
                    "tag": node.tag,
                    "disable_rewrite": node.disable_rewrite,
                },
            },
        )

    def visit_assignment(self, node: Assignment):
        self._store(
            node,
            {
                "kind": "Assignment",
                "object": {
                    "node_id": serialize_uuid(node.node_id),
                    "lhs": self._fetch(node.lhs),
                    "rhs": self._fetch(node.rhs),
                    "disable_rewrite": node.disable_rewrite,
                },
            },
        )

    def visit_circuit(self, node: Circuit):
        self._store(
            node,
            {
                "kind": "Circuit",
                "object": {
                    "node_id": serialize_uuid(node.node_id),
                    "name": node.name,
                    "field_modulo": node.field_modulo,
                    "inputs": self._fetch_list(cast(list[IRNode], node.inputs)),
                    "outputs": self._fetch_list(cast(list[IRNode], node.outputs)),
                    "statements": self._fetch_list(cast(list[IRNode], node.statements)),
                    "disable_rewrite": node.disable_rewrite,
                },
            },
        )


# -----------------------------------------------------------------------------------


class IRDictDeserializer:
    """Deserializer to a `dict[str, Any]` generated by `IRDictSerializer` int `IRNode`

    If the dictionary can not be resolved, a`ValueError` is raised.
    """

    def deserialize(self, data: dict[str, Any]) -> IRNode:
        return self._deserialize_ir_node(data)

    def _deserialize_ir_node(self, data: dict[str, Any]) -> IRNode:
        kind = data["kind"]
        match kind:
            case "Circuit":
                return self.deserialize_circuit(data)
            case "Identifier":
                return self.deserialize_identifier(data)
            case "Integer":
                return self.deserialize_integer(data)
            case "Boolean":
                return self.deserialize_boolean(data)
            case "UnaryExpression":
                return self.deserialize_unary_expression(data)
            case "BinaryExpression":
                return self.deserialize_binary_expression(data)
            case "TernaryExpression":
                return self.deserialize_ternary_expression(data)
            case "CallExpression":
                return self.deserialize_call_expression(data)
            case "Assignment":
                return self.deserialize_assignment(data)
            case "Assertion":
                return self.deserialize_assertion(data)
            case "FunctionDefinition":
                return self.deserialize_function_definition(data)
            case _:
                raise ValueError(f"unexpected kind value '{kind}' for 'IRNode'")

    def _deserialize_statement(self, data: dict[str, Any]) -> Statement:
        kind = data["kind"]
        match kind:
            case "Assignment":
                return self.deserialize_assignment(data)
            case "Assertion":
                return self.deserialize_assertion(data)
            case _:
                raise ValueError(f"unexpected kind value '{kind}' for 'Statement'")

    def _deserialize_expression(self, data: dict[str, Any]) -> Expression:
        kind = data["kind"]
        match kind:
            case "Identifier":
                return self.deserialize_identifier(data)
            case "Integer":
                return self.deserialize_integer(data)
            case "Boolean":
                return self.deserialize_boolean(data)
            case "UnaryExpression":
                return self.deserialize_unary_expression(data)
            case "BinaryExpression":
                return self.deserialize_binary_expression(data)
            case "TernaryExpression":
                return self.deserialize_ternary_expression(data)
            case _:
                raise ValueError(f"unexpected kind value '{kind}' for 'Expression'")

    def __checked_unwrap_for_kind(self, expected: str, data: dict[str, Any]) -> dict[str, Any]:
        kind = data["kind"]
        obj = data["object"]
        if expected != kind:
            raise ValueError(f"unexpected kind '{expected}', but found '{kind}'")
        return obj

    def deserialize_identifier(self, data: dict[str, Any]) -> Identifier:
        obj = self.__checked_unwrap_for_kind("Identifier", data)
        return Identifier(
            node_id=deserialize_uuid(obj["node_id"]),
            name=obj["name"],
            ty_hint=deserialize_ir_type(obj["ty_hint"]),
            disable_rewrite=obj["disable_rewrite"],
        )

    def deserialize_integer(self, data: dict[str, Any]) -> Integer:
        obj = self.__checked_unwrap_for_kind("Integer", data)
        return Integer(
            node_id=deserialize_uuid(obj["node_id"]),
            value=int(obj["value"]),
            disable_rewrite=obj["disable_rewrite"],
        )

    def deserialize_boolean(self, data: dict[str, Any]) -> Boolean:
        obj = self.__checked_unwrap_for_kind("Boolean", data)
        return Boolean(
            node_id=deserialize_uuid(obj["node_id"]),
            value=obj["value"],
            disable_rewrite=obj["disable_rewrite"],
        )

    def deserialize_unary_expression(self, data: dict[str, Any]) -> UnaryExpression:
        obj = self.__checked_unwrap_for_kind("UnaryExpression", data)
        return UnaryExpression(
            node_id=deserialize_uuid(obj["node_id"]),
            op=deserialize_operator(obj["op"]),
            value=self._deserialize_expression(obj["value"]),
            disable_rewrite=obj["disable_rewrite"],
        )

    def deserialize_binary_expression(self, data: dict[str, Any]) -> BinaryExpression:
        obj = self.__checked_unwrap_for_kind("BinaryExpression", data)
        return BinaryExpression(
            node_id=deserialize_uuid(obj["node_id"]),
            op=deserialize_operator(obj["op"]),
            lhs=self._deserialize_expression(obj["lhs"]),
            rhs=self._deserialize_expression(obj["rhs"]),
            disable_rewrite=obj["disable_rewrite"],
        )

    def deserialize_ternary_expression(self, data: dict[str, Any]) -> TernaryExpression:
        obj = self.__checked_unwrap_for_kind("TernaryExpression", data)
        return TernaryExpression(
            node_id=deserialize_uuid(obj["node_id"]),
            cond=self._deserialize_expression(obj["cond"]),
            if_expr=self._deserialize_expression(obj["if_expr"]),
            else_expr=self._deserialize_expression(obj["else_expr"]),
            disable_rewrite=obj["disable_rewrite"],
        )

    def deserialize_call_expression(self, data: dict[str, Any]) -> CallExpression:
        obj = self.__checked_unwrap_for_kind("CallExpression", data)
        return CallExpression(
            node_id=deserialize_uuid(obj["node_id"]),
            function=self.deserialize_function_definition(obj["function"]),
            arguments=[self._deserialize_expression(e) for e in obj["arguments"]],
            disable_rewrite=obj["disable_rewrite"],
        )

    def deserialize_assignment(self, data: dict[str, Any]) -> Assignment:
        obj = self.__checked_unwrap_for_kind("Assignment", data)
        return Assignment(
            node_id=deserialize_uuid(obj["node_id"]),
            lhs=self.deserialize_identifier(obj["lhs"]),
            rhs=self._deserialize_expression(obj["rhs"]),
            disable_rewrite=obj["disable_rewrite"],
        )

    def deserialize_assertion(self, data: dict[str, Any]) -> Assertion:
        obj = self.__checked_unwrap_for_kind("Assertion", data)
        return Assertion(
            node_id=deserialize_uuid(obj["node_id"]),
            value=self._deserialize_expression(obj["value"]),
            tag=obj["tag"],
            disable_rewrite=obj["disable_rewrite"],
        )

    def deserialize_function_definition(self, data: dict[str, Any]) -> FunctionDefinition:
        obj = self.__checked_unwrap_for_kind("FunctionDefinition", data)
        return FunctionDefinition(
            node_id=deserialize_uuid(obj["node_id"]),
            name=obj["name"],
            parameters=[self.deserialize_identifier(e) for e in obj["parameters"]],
            results=[self.deserialize_identifier(e) for e in obj["results"]],
            disable_rewrite=obj["disable_rewrite"],
        )

    def deserialize_circuit(self, data: dict[str, Any]) -> Circuit:
        obj = self.__checked_unwrap_for_kind("Circuit", data)
        return Circuit(
            node_id=deserialize_uuid(obj["node_id"]),
            name=obj["name"],
            field_modulo=obj["field_modulo"],
            inputs=[self.deserialize_identifier(e) for e in obj["inputs"]],
            outputs=[self.deserialize_identifier(e) for e in obj["outputs"]],
            statements=[self._deserialize_statement(e) for e in obj["statements"]],
            disable_rewrite=obj["disable_rewrite"],
        )


# -----------------------------------------------------------------------------------


class IRJSONSerializer:
    """Serializes an `IRNode` into json format using `IRDictSerializer`"""

    def serialize(self, node: IRNode) -> str:
        return json.dumps(IRDictSerializer().serialize(node))


# -----------------------------------------------------------------------------------


class IRJSONDeserializer:
    """Deserializes json from `IRJSONSerializer` back into an `IRNode` node"""

    def deserialize(self, data: str) -> IRNode:
        return IRDictDeserializer().deserialize(json.loads(data))


# -----------------------------------------------------------------------------------
