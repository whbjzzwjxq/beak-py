from abc import ABC, abstractmethod
from typing import Callable, Generic, TypeVar, cast

from circil.ir.node import (
    Assertion,
    BinaryExpression,
    Boolean,
    CallExpression,
    Expression,
    FunctionDefinition,
    Identifier,
    Integer,
    IRNode,
    UnaryExpression,
)
from circil.ir.operator import Operator
from circil.ir.type import IRType
from circil.rewrite.tokenizer import Token, Tokenizer, TokenKind
from circil.rewrite.utils import RNGUtil

# -----------------------------------------------------------------------------------


class ParserException(Exception):
    """Exception thrown by the rewrite pattern parser (matcher / rewrite generator)"""

    def __init__(self, position: int, text: str, message: str):
        super().__init__(message)
        self.position = position
        self.text = text
        self.message = message


# -----------------------------------------------------------------------------------

MatchFunctionType = Callable[[dict, IRNode], bool]
RewriteFunctionType = Callable[[dict, RNGUtil], IRNode]

F = TypeVar("F")


class BaseParser(ABC, Generic[F]):
    """Generic base parser for patterns

    This parser already walks through each of the `Token`s
    and detects desired pattern structures. The matcher or
    rewrite only has to implement the `process_<name>` functions.

    The generic type `F` enables to return any kind of type.
    """

    @abstractmethod
    def process_number(self, number: int) -> F:
        pass

    @abstractmethod
    def process_boolean(self, boolean: bool) -> F:
        pass

    @abstractmethod
    def process_placeholder(self, identifier: str) -> F:
        pass

    @abstractmethod
    def process_random(self, hint: IRType, identifier: str) -> F:
        pass

    @abstractmethod
    def process_unary_expression(self, op: Operator, value: F) -> F:
        pass

    @abstractmethod
    def process_binary_expression(self, op: Operator, lhs: F, rhs: F) -> F:
        pass

    @abstractmethod
    def process_call_expression(self, name: str, arguments: list[F], result_type: IRType) -> F:
        pass

    @abstractmethod
    def process_type_hint(self, hint: IRType, value: F) -> F:
        pass

    @abstractmethod
    def process_assert(self, value: F) -> F:
        pass

    def parse(self, pattern: str) -> F:
        tokenizer = Tokenizer()
        tokens = tokenizer.tokenize(pattern)
        self._text_pattern = pattern

        ptr, func = self._consume_node(tokens, 0)
        if not ptr == len(tokens):
            msg = f"Unexpected remaining string: '{pattern[tokens[0].pos_start::]}'"
            raise ParserException(ptr, self._text_pattern, msg)
        return func

    def _is_unary_operator_lookahead(self, tokens: list[Token], ptr: int) -> bool:
        return (
            tokens[ptr].kind == TokenKind.OPERATOR
            and tokens[ptr].value in Operator.unary_operations()
        )

    def _is_binary_operator_lookahead(self, tokens: list[Token], ptr: int) -> bool:
        return (
            tokens[ptr].kind == TokenKind.OPERATOR
            and tokens[ptr].value in Operator.binary_operations()
        )

    def _is_type_hint_lookahead(self, tokens: list[Token], ptr: int) -> bool:
        return len(tokens) > ptr and tokens[ptr].kind == TokenKind.COLON

    def _consume_parenthesis_right(self, tokens: list[Token], ptr: int) -> int:
        return self.__consume_token(TokenKind.PARENTHESIS_RIGHT, tokens, ptr)

    def _consume_parenthesis_left(self, tokens: list[Token], ptr: int) -> int:
        return self.__consume_token(TokenKind.PARENTHESIS_LEFT, tokens, ptr)

    def _consume_curly_parenthesis_left(self, tokens: list[Token], ptr: int) -> int:
        return self.__consume_token(TokenKind.CURLY_PARENTHESIS_LEFT, tokens, ptr)

    def _consume_curly_parenthesis_right(self, tokens: list[Token], ptr: int) -> int:
        return self.__consume_token(TokenKind.CURLY_PARENTHESIS_RIGHT, tokens, ptr)

    def _consume_question_mark(self, tokens: list[Token], ptr: int) -> int:
        return self.__consume_token(TokenKind.QUESTION_MARK, tokens, ptr)

    def _consume_colon(self, tokens: list[Token], ptr: int) -> int:
        return self.__consume_token(TokenKind.COLON, tokens, ptr)

    def _consume_dollar(self, tokens: list[Token], ptr: int) -> int:
        return self.__consume_token(TokenKind.DOLLAR, tokens, ptr)

    def __consume_token(self, kind: TokenKind, tokens: list[Token], ptr: int) -> int:
        if not tokens[ptr].kind == kind:
            msg = f"Unexpected token {tokens[ptr]}, expects token of kind {kind.value}"
            raise ParserException(ptr, self._text_pattern, msg)
        return ptr + 1

    def __consume_and_get_type_hint(self, tokens: list[Token], ptr: int) -> tuple[int, IRType]:
        token = tokens[ptr]
        if token.kind == TokenKind.IDENTIFIER:
            type_hint = token.value
            match type_hint:
                case "int":
                    return ptr + 1, IRType.Field
                case "bool":
                    return ptr + 1, IRType.Bool
                case _unsupported:
                    msg = f"unsupported type hint '{_unsupported}'"
                    raise ParserException(ptr, self._text_pattern, msg)
        msg = f"expected a type hint identifier but got '{tokens[ptr]}'!"
        raise ParserException(ptr, self._text_pattern, msg)

    def _consume_number(self, tokens: list[Token], ptr: int) -> tuple[int, F]:
        assert tokens[ptr].kind == TokenKind.NUMBER and isinstance(
            tokens[ptr].value, int
        ), "unexpected token kind or value!"
        return ptr + 1, self.process_number(cast(int, tokens[ptr].value))

    def _consume_boolean(self, tokens: list[Token], ptr: int) -> tuple[int, F]:
        assert tokens[ptr].kind == TokenKind.BOOLEAN and isinstance(
            tokens[ptr].value, bool
        ), "unexpected token kind or value!"
        return ptr + 1, self.process_boolean(cast(bool, tokens[ptr].value))

    def _consume_placeholder(self, tokens: list[Token], ptr: int) -> tuple[int, F]:
        token = tokens[ptr]
        if token.kind == TokenKind.IDENTIFIER:
            ptr += 1
            func = self.process_placeholder(cast(str, token.value))

            if self._is_type_hint_lookahead(tokens, ptr):
                ptr = self._consume_colon(tokens, ptr)
                ptr, type_hint = self.__consume_and_get_type_hint(tokens, ptr)
                return ptr, self.process_type_hint(type_hint, func)
            else:
                return ptr, func

        msg = f"Unexpected token {tokens[ptr]}!"
        raise ParserException(ptr, self._text_pattern, msg)

    def _consume_random(self, tokens: list[Token], ptr: int) -> tuple[int, F]:
        token = tokens[ptr]
        if token.kind == TokenKind.IDENTIFIER:
            ptr += 1  # jump over token
            # expects a type hint after random and use it in process method
            if self._is_type_hint_lookahead(tokens, ptr):
                ptr = self._consume_colon(tokens, ptr)
                ptr, type_hint = self.__consume_and_get_type_hint(tokens, ptr)
                return ptr, self.process_random(type_hint, cast(str, token.value))

        msg = f"Unexpected token {tokens[ptr]}!"
        raise ParserException(ptr, self._text_pattern, msg)

    def _consume_expression(self, tokens: list[Token], ptr: int) -> tuple[int, F]:
        # unary expression
        if self._is_unary_operator_lookahead(tokens, ptr):
            op = cast(Operator, tokens[ptr].value)
            ptr += 1
            ptr, val_func = self._consume_node(tokens, ptr)
            return ptr, self.process_unary_expression(op, val_func)

        # call expression
        token = tokens[ptr]
        if token.kind == TokenKind.IDENTIFIER:
            ptr += 1
            if not isinstance(token.value, str):
                ParserException(
                    ptr, self._text_pattern, f"Unexpected token for function name {tokens[ptr]}!"
                )
            func_name = cast(str, token.value)

            # <func-name> : int arg1 arg2 arg3 ...
            #             ^
            #  parses optional type hints
            type_hint = IRType.Field
            if self._is_type_hint_lookahead(tokens, ptr):
                ptr = self._consume_colon(tokens, ptr)
                ptr, type_hint = self.__consume_and_get_type_hint(tokens, ptr)

            func_args = []
            while tokens[ptr].kind != TokenKind.PARENTHESIS_RIGHT:
                ptr, arg_func = self._consume_node(tokens, ptr)
                func_args.append(arg_func)
            return ptr, self.process_call_expression(func_name, func_args, type_hint)

        # first node of binary and ternary
        ptr, lhs_func = self._consume_node(tokens, ptr)

        # binary expression
        if self._is_binary_operator_lookahead(tokens, ptr):
            op = cast(Operator, tokens[ptr].value)
            ptr += 1
            ptr, rhs_func = self._consume_node(tokens, ptr)
            return ptr, self.process_binary_expression(op, lhs_func, rhs_func)

        # TODO: ternary!

        msg = f"Unexpected token {tokens[ptr]}"
        raise ParserException(ptr, self._text_pattern, msg)

    def _consume_statement(self, tokens: list[Token], ptr: int) -> tuple[int, F]:
        token = tokens[ptr]
        if token.kind == TokenKind.IDENTIFIER:
            if token.value == "assert":
                ptr += 1  # jump over token
                ptr, val_func = self._consume_node(tokens, ptr)
                return ptr, self.process_assert(val_func)
        msg = f"Unexpected token {tokens[ptr]}!"
        raise ParserException(ptr, self._text_pattern, msg)

    def _consume_node(self, tokens: list[Token], ptr: int) -> tuple[int, F]:
        token = tokens[ptr]
        match token.kind:
            case TokenKind.NUMBER:
                return self._consume_number(tokens, ptr)
            case TokenKind.BOOLEAN:
                return self._consume_boolean(tokens, ptr)
            case TokenKind.QUESTION_MARK:
                ptr = self._consume_question_mark(tokens, ptr)
                ptr, func = self._consume_placeholder(tokens, ptr)
                return ptr, func
            case TokenKind.DOLLAR:
                ptr = self._consume_dollar(tokens, ptr)
                ptr, func = self._consume_random(tokens, ptr)
                return ptr, func
            case TokenKind.PARENTHESIS_LEFT:
                ptr = self._consume_parenthesis_left(tokens, ptr)
                ptr, func = self._consume_expression(tokens, ptr)
                ptr = self._consume_parenthesis_right(tokens, ptr)
                return ptr, func
            case TokenKind.CURLY_PARENTHESIS_LEFT:
                ptr = self._consume_curly_parenthesis_left(tokens, ptr)
                ptr, func = self._consume_statement(tokens, ptr)
                ptr = self._consume_curly_parenthesis_right(tokens, ptr)
                return ptr, func
            case _:
                msg = f"Unexpected token {token} '{self._text_pattern}'"
                raise ParserException(ptr, self._text_pattern, msg)


# -----------------------------------------------------------------------------------


class MatchParser(BaseParser[MatchFunctionType]):
    """Pattern parser that generates a matcher in form of a function."""

    def process_number(self, number: int) -> MatchFunctionType:
        return lambda _, node: isinstance(node, Integer) and node.value == number

    def process_boolean(self, boolean: bool) -> MatchFunctionType:
        return lambda _, node: isinstance(node, Boolean) and node.value == boolean

    def process_placeholder(self, identifier: str) -> MatchFunctionType:
        def variable_closure(lookup: dict[str, IRNode], node: IRNode) -> bool:
            if identifier in lookup:
                return str(lookup[identifier]) == str(node)
            if not isinstance(node, Expression):  # only allow expressions for now
                return False
            lookup[identifier] = node
            return True

        return variable_closure

    def process_random(self, hint: IRType, identifier: str) -> MatchFunctionType:
        raise NotImplementedError  # unreachable

    def process_unary_expression(self, op: Operator, value: MatchFunctionType) -> MatchFunctionType:
        return (
            lambda lookup, node: isinstance(node, UnaryExpression)
            and node.op == op
            and value(lookup, node.value)
        )

    def process_binary_expression(
        self, op: Operator, lhs: MatchFunctionType, rhs: MatchFunctionType
    ) -> MatchFunctionType:
        return (
            lambda lookup, node: isinstance(node, BinaryExpression)
            and node.op == op
            and lhs(lookup, node.lhs)
            and rhs(lookup, node.rhs)
        )

    def process_call_expression(
        self, name: str, arguments: list[MatchFunctionType], result_type: IRType
    ) -> MatchFunctionType:
        return (
            lambda lookup, node: isinstance(node, CallExpression)
            and node.type_hint() == result_type
            and node.function.name == name
            and len(arguments) == len(node.function.parameters)
            and all([f_arg(lookup, arg) for (f_arg, arg) in zip(arguments, node.arguments)])
        )

    def process_type_hint(self, hint: IRType, value: MatchFunctionType) -> MatchFunctionType:
        def type_hint_closure(lookup: dict[str, IRNode], node: IRNode) -> bool:
            if isinstance(node, Expression):
                match hint:
                    case IRType.Field:
                        return node.type_hint() == IRType.Field and value(lookup, node)
                    case IRType.Bool:
                        return node.type_hint() == IRType.Bool and value(lookup, node)
                    case _:
                        return False
            return False

        return type_hint_closure

    def process_assert(self, value: MatchFunctionType) -> MatchFunctionType:
        def assert_closure(lookup: dict[str, IRNode], node: IRNode):
            if isinstance(node, Assertion) and value(lookup, node.value):
                # TODO: find a way to provide information about the insertion
                #       without hardcoded lookup
                if "__assert" in lookup:
                    raise NotImplementedError(
                        "currently only a single assertion is supported inside of a rule"
                    )
                lookup["__assert"] = node
                return True
            return False

        return assert_closure

    def _consume_random(self, tokens: list[Token], ptr: int) -> tuple[int, MatchFunctionType]:
        msg = f"Unexpected token {tokens[ptr]}! Unable to match on random values!"
        raise ParserException(ptr, self._text_pattern, msg)


# -----------------------------------------------------------------------------------


class RewriteParser(BaseParser[RewriteFunctionType]):
    """Pattern parser that generates a rewriter in form of a function."""

    def process_number(self, number: int) -> RewriteFunctionType:
        assert isinstance(number, int)
        return lambda _d, _r: Integer(number)

    def process_boolean(self, boolean: bool) -> RewriteFunctionType:
        return lambda _d, _r: Boolean(boolean)

    def process_placeholder(self, identifier: str) -> RewriteFunctionType:
        def variable_closure(lookup: dict[str, IRNode], _: RNGUtil) -> IRNode:
            if identifier not in lookup:
                raise ParserException(
                    -1,
                    self._text_pattern,
                    (
                        f"unable to find '{identifier}' for '{self._text_pattern}'"
                        " in original match pattern"
                    ),
                )
            return lookup[identifier].copy()

        return variable_closure

    def process_random(self, hint: IRType, identifier: str) -> RewriteFunctionType:
        def random_closure(lookup: dict[str, IRNode], rng_util: RNGUtil) -> IRNode:
            if identifier not in lookup:
                match hint:
                    case IRType.Field:
                        lookup[identifier] = Integer(rng_util.random_integer())
                    case IRType.Bool:
                        lookup[identifier] = Boolean(rng_util.random_boolean())
                    case _:
                        raise NotImplementedError(f"Unimplemented type hint {hint}")
            return lookup[identifier].copy()

        return random_closure

    def process_unary_expression(
        self, op: Operator, value: RewriteFunctionType
    ) -> RewriteFunctionType:
        return lambda lookup, rng_util: UnaryExpression(
            op, cast(Expression, value(lookup, rng_util))
        )

    def process_binary_expression(
        self, op: Operator, lhs: RewriteFunctionType, rhs: RewriteFunctionType
    ) -> RewriteFunctionType:
        return lambda lookup, rng_util: BinaryExpression(
            op, cast(Expression, lhs(lookup, rng_util)), cast(Expression, rhs(lookup, rng_util))
        )

    def process_call_expression(
        self, name: str, arguments: list[RewriteFunctionType], result_type: IRType
    ) -> RewriteFunctionType:
        def call_expression_closure(lookup: dict[str, IRNode], rng_util: RNGUtil):
            expr_args = [cast(Expression, f_arg(lookup, rng_util)) for f_arg in arguments]
            return CallExpression(
                FunctionDefinition(
                    name,
                    [Identifier(f"x{i}", e.type_hint()) for (i, e) in enumerate(expr_args)],
                    [Identifier("y", result_type)],
                ),
                expr_args,
            )

        return call_expression_closure

    def process_type_hint(self, hint: IRType, value: RewriteFunctionType) -> RewriteFunctionType:
        return lambda lookup, rng_util: value(lookup, rng_util)

    def process_assert(self, value: RewriteFunctionType) -> RewriteFunctionType:
        def assertion_closure(lookup: dict[str, IRNode], rng_util: RNGUtil):
            assertion_value = value(lookup, rng_util)
            assert isinstance(
                assertion_value, Expression
            ), "Internal rewrite rule error! Assertion condition was not an expression!"
            # TODO: find a way to provide information about the insertion without hardcoded lookup
            original_assertion = lookup["__assert"]
            assert isinstance(
                original_assertion, Assertion
            ), "Internal rewrite rule error! No or wrongly saved Assertion node!"
            return Assertion(assertion_value, original_assertion.tag)

        return assertion_closure


# -----------------------------------------------------------------------------------
