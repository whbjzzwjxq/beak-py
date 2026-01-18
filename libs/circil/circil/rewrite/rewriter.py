from dataclasses import dataclass
from random import Random
from typing import cast

from circil.ir.node import (
    Assertion,
    Assignment,
    BinaryExpression,
    Boolean,
    CallExpression,
    Circuit,
    Identifier,
    Integer,
    IRNode,
    TernaryExpression,
    UnaryExpression,
)
from circil.ir.operator import Operator
from circil.ir.visitor import NodeReplacer
from circil.rewrite.rule import Rule
from circil.rewrite.utils import RNGUtil


@dataclass
class RewriteCandidate:
    """This helper class stores information on applying rewrite rules.

    It is important to note that the fields are references and might
    change if multiple rewrites are applied. It is not recommended to
    use this class for anything outside of the `rewrite` module.
    """

    rule: Rule
    target: IRNode
    parent: IRNode | None = None
    replacement: IRNode | None = None

    def has_parent(self) -> bool:
        return self.parent is not None

    def apply_rule(self, rng_util: RNGUtil) -> IRNode:
        self.replacement = self.rule.rewrite(self.target, rng_util)
        assert self.replacement, f"unable to apply {self.rule.name} to {self.target}"
        return self.replacement


class RuleBasedRewriter:
    """Rule based rewrite visitor for CircIL's IR.

    The `RuleBasedRewriter` takes a list of rewrite rules and iteratively
    applies them for a suggested amount (default is `default_amount_of_rewrites`)
    of times on randomly selected matching `IRNode`s.

    Current the implementations allow only for limited matching on `Statement`
    nodes. Also note that the rewrite amount is not guaranteed as it depends on
    available matches. Furthermore, it is not checked if iteratively applied
    rewrite rules do reverse themselves.
    """

    # list of rewrite rules, initialized by constructor
    rules: list[Rule]

    # RNG Util for the rewrite functions
    rng_util: RNGUtil

    # Random object for the rewriter to pick rules
    rng: Random

    # For some tools the power operator (**) is very delicate and
    # it is important to respect any kind of limitations. Because
    # of this, the default is to disable exponent rewrite.
    enable_rewrite_for_exponent: bool

    # Setting to control iterative rewrites for a single call
    default_amount_of_rewrites: int

    # internal state of interesting `IRNode`s for applying rules
    __rewrite_candidates: dict[str, list[RewriteCandidate]]

    def __init__(self, rules: list[Rule], rng_util: RNGUtil, rng: Random):
        self.rules = rules
        self.rng_util = rng_util
        self.rng = rng

        self.enable_rewrite_for_exponent = False
        self.default_amount_of_rewrites = 1

        self.__rewrite_candidates = {}

    def run(self, node: IRNode, amount: int | None = None) -> tuple[IRNode, list[Rule]]:
        """Applies the rewrite rules on and `IRNode` and returns the result"""

        applied_rules: list[Rule] = []  # a list of applied rules
        root = node.copy()  # copy of the original to not destroy and references
        replacer = NodeReplacer()  # replacer to perform the rewrite

        # either passed or default amount of rewrites
        amount = self.default_amount_of_rewrites if amount is None else amount

        # main loop of rewrites
        for _ in range(amount):
            self.__rewrite_candidates = {}  # reset possible rewrite locations
            self.collect_rules(root, None)  # collect all the rules for each iterative rewrite

            # check if we have at least one candidate
            if len(self.__rewrite_candidates) > 0:

                # pick a random rule and a random location for applying it
                random_rule_name = self.rng.choice(list(self.__rewrite_candidates.keys()))
                random_candidate = self.rng.choice(self.__rewrite_candidates[random_rule_name])

                applied_rules.append(random_candidate.rule)

                # check if the root node is targeted for rewrite
                if random_candidate.target == root:
                    assert (
                        random_candidate.has_parent() is False
                    ), "unexpected parent for starting node"
                    root = random_candidate.apply_rule(self.rng_util)
                    continue  # early abort, nothing todo after root is replaced

                # else, we are targeting a sub-node that has a parent
                assert random_candidate.has_parent(), "unexpected orphan rewrite candidate"
                replacement = random_candidate.apply_rule(self.rng_util)
                is_replaced = replacer.replace(
                    cast(IRNode, random_candidate.parent), random_candidate.target, replacement
                )
                assert is_replaced, "unable to find origin node"

            # we did not found any match
            else:
                break  # unable to find another rule to apply so we can stop

        return root, applied_rules

    def collect_rules(self, node: IRNode, parent: IRNode | None):
        if node.disable_rewrite:
            return  # if the node is disable we do not look further

        for rule in self.rules:
            if rule.is_applicable(node):
                if rule.name not in self.__rewrite_candidates:
                    self.__rewrite_candidates[rule.name] = []
                self.__rewrite_candidates[rule.name].append(RewriteCandidate(rule, node, parent))

        match node:
            case Identifier():
                return self.visit_variable(node)
            case Boolean():
                return self.visit_boolean(node)
            case Integer():
                return self.visit_integer(node)
            case UnaryExpression():
                return self.visit_unary_expression(node)
            case BinaryExpression():
                return self.visit_binary_expression(node)
            case TernaryExpression():
                return self.visit_ternary_expression(node)
            case CallExpression():
                return self.visit_call_expression(node)
            case Assignment():
                return self.visit_assignment(node)
            case Assertion():
                return self.visit_assertion(node)
            case Circuit():
                return self.visit_circuit(node)
            case _:
                raise NotImplementedError(f"unexpected node with class '{node.__class__}'")

    def visit_variable(self, node: Identifier):
        pass

    def visit_boolean(self, node: Boolean):
        pass

    def visit_integer(self, node: Integer):
        pass

    def visit_binary_expression(self, node: BinaryExpression):
        self.collect_rules(node.lhs, node)
        if node.op == Operator.POW:
            # check if RHS of power operator is allowed
            if self.enable_rewrite_for_exponent:
                self.collect_rules(node.rhs, node)
        else:
            self.collect_rules(node.rhs, node)

    def visit_unary_expression(self, node: UnaryExpression):
        self.collect_rules(node.value, node)

    def visit_ternary_expression(self, node: TernaryExpression):
        self.collect_rules(node.cond, node)
        self.collect_rules(node.if_expr, node)
        self.collect_rules(node.else_expr, node)

    def visit_call_expression(self, node: CallExpression):
        for e in node.arguments:
            self.collect_rules(e, node)

    def visit_assignment(self, node: Assignment):
        # only allow the expressions part of an assignment for now
        # self.collect_rules(node.lhs, node)

        self.collect_rules(node.rhs, node)

    def visit_assertion(self, node: Assertion):
        self.collect_rules(node.value, node)

    def visit_circuit(self, node: Circuit):
        for e in node.statements:
            self.collect_rules(e, node)
