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

# -----------------------------------------------------------------------------------


class EmptyVisitor:
    """Base empty visitor for traversing the IR"""

    def visit(self, node: IRNode):
        match node:
            case Identifier():
                self.visit_identifier(node)
            case Boolean():
                self.visit_boolean(node)
            case Integer():
                self.visit_integer(node)
            case UnaryExpression():
                self.visit_unary_expression(node)
            case BinaryExpression():
                self.visit_binary_expression(node)
            case TernaryExpression():
                self.visit_ternary_expression(node)
            case CallExpression():
                self.visit_call_expression(node)
            case Assertion():
                self.visit_assertion(node)
            case Assignment():
                self.visit_assignment(node)
            case FunctionDefinition():
                self.visit_function_definition(node)
            case Circuit():
                self.visit_circuit(node)
            case _:
                raise NotImplementedError()

    def visit_identifier(self, node: Identifier):
        pass

    def visit_boolean(self, node: Boolean):
        pass

    def visit_integer(self, node: Integer):
        pass

    def visit_unary_expression(self, node: UnaryExpression):
        pass

    def visit_binary_expression(self, node: BinaryExpression):
        pass

    def visit_ternary_expression(self, node: TernaryExpression):
        pass

    def visit_call_expression(self, node: CallExpression):
        pass

    def visit_assertion(self, node: Assertion):
        pass

    def visit_assignment(self, node: Assignment):
        pass

    def visit_function_definition(self, node: FunctionDefinition):
        pass

    def visit_circuit(self, node: Circuit):
        pass


# -----------------------------------------------------------------------------------


class IRWalker(EmptyVisitor):
    """Base visitor implementation of a simple IR traversal"""

    def visit_identifier(self, node: Identifier):
        pass

    def visit_boolean(self, node: Boolean):
        pass

    def visit_integer(self, node: Integer):
        pass

    def visit_unary_expression(self, node: UnaryExpression):
        self.visit(node.value)

    def visit_binary_expression(self, node: BinaryExpression):
        self.visit(node.lhs)
        self.visit(node.rhs)

    def visit_ternary_expression(self, node: TernaryExpression):
        self.visit(node.cond)
        self.visit(node.if_expr)
        self.visit(node.else_expr)

    def visit_call_expression(self, node: CallExpression):
        self.visit(node.function)
        for e in node.arguments:
            self.visit(e)

    def visit_assertion(self, node: Assertion):
        self.visit(node.value)

    def visit_assignment(self, node: Assignment):
        self.visit(node.lhs)
        self.visit(node.rhs)

    def visit_function_definition(self, node: FunctionDefinition):
        for e in node.parameters:
            self.visit(e)
        for e in node.results:
            self.visit(e)

    def visit_circuit(self, node: Circuit):
        for i in node.inputs:
            self.visit_identifier(i)
        for i in node.outputs:
            self.visit_identifier(i)
        for statement in node.statements:
            self.visit(statement)


# -----------------------------------------------------------------------------------


class NodeReplacer(IRWalker):
    """Simple visitor to replace an `IRNode` by another `IRNode`.

    Given a parent node, `NodeReplacer` traverses the ir and tries
    to replace a unique `origin` node with its `replacement`.
    If the replacement was successful the `replace` method returns
    `True`.

    The visitor does NOT work if the `origin` node is the `parent` node.
    To find the `origin` node the `node_id`, which is why it is important
    to use a properly initialized IR.
    """

    __origin: IRNode
    __replacement: IRNode

    # used to propagate the result and short circuit the traversal
    __replaced: bool

    def replace(self, parent: IRNode, origin: IRNode, replacement: IRNode) -> bool:
        self.__origin = origin
        self.__replacement = replacement
        self.__replaced = False
        super().visit(parent)
        return self.__replaced

    def visit_binary_expression(self, node: BinaryExpression):
        if self.__replaced:
            return  # abort

        if node.lhs == self.__origin and isinstance(self.__replacement, Expression):
            node.lhs = self.__replacement
            self.__replaced = True
            return  # abort

        if node.rhs == self.__origin and isinstance(self.__replacement, Expression):
            node.rhs = self.__replacement
            self.__replaced = True
            return  # abort

        super().visit(node.lhs)
        super().visit(node.rhs)

    def visit_unary_expression(self, node: UnaryExpression):
        if self.__replaced:
            return  # abort

        if node.value == self.__origin and isinstance(self.__replacement, Expression):
            node.value = self.__replacement
            self.__replaced = True
            return  # abort

        super().visit(node.value)

    def visit_ternary_expression(self, node: TernaryExpression):
        if self.__replaced:
            return  # abort

        if node.cond == self.__origin and isinstance(self.__replacement, Expression):
            node.cond = self.__replacement
            self.__replaced = True
            return  # abort

        if node.if_expr == self.__origin and isinstance(self.__replacement, Expression):
            node.if_expr = self.__replacement
            self.__replaced = True
            return  # abort

        if node.else_expr == self.__origin and isinstance(self.__replacement, Expression):
            node.else_expr = self.__replacement
            self.__replaced = True
            return  # abort

        super().visit(node.cond)
        super().visit(node.if_expr)
        super().visit(node.else_expr)

    def visit_call_expression(self, node: CallExpression):
        if self.__replaced:
            return  # abort

        args_len = len(node.arguments)
        for idx in range(args_len):
            e = node.arguments[idx]
            if e == self.__origin and isinstance(self.__replacement, Expression):
                node.arguments[idx] = self.__replacement
                self.__replaced = True

        for e in node.arguments:
            super().visit(e)

    def visit_assignment(self, node: Assignment):
        if self.__replaced:
            return  # abort

        if node.lhs == self.__origin and isinstance(self.__replacement, Identifier):
            node.lhs = self.__replacement
            self.__replaced = True
            return  # abort

        if node.rhs == self.__origin and isinstance(self.__replacement, Expression):
            node.rhs = self.__replacement
            self.__replaced = True
            return  # abort

        super().visit(node.lhs)
        super().visit(node.rhs)

    def visit_assertion(self, node: Assertion):
        if self.__replaced:
            return  # abort

        if node.value == self.__origin and isinstance(self.__replacement, Expression):
            node.value = self.__replacement
            self.__replaced = True
            return  # abort

        super().visit(node.value)

    def visit_circuit(self, node: Circuit):
        # ignore input and output identifier for replacements!
        replacement_index = None
        for idx, s in enumerate(node.statements):
            if s == self.__origin:
                replacement_index = idx
                break
            super().visit(s)
            if self.__replaced:
                return  # abort

        if replacement_index is not None and isinstance(self.__replacement, Statement):
            node.statements[replacement_index] = self.__replacement
            self.__replaced = True


# -----------------------------------------------------------------------------------
