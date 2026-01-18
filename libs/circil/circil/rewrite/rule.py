from circil.ir.node import IRNode
from circil.rewrite.parser import (
    MatchFunctionType,
    MatchParser,
    RewriteFunctionType,
    RewriteParser,
)
from circil.rewrite.utils import RNGUtil


class Rule:
    """Rewrite rule for a single rewrite pattern

    This class is used to encapsulate the rewrite logic of
    of a defined pattern. It internally generates functions
    for matching and rewriting out of the provided patterns.
    """

    name: str
    pattern_match: str
    pattern_rewrite: str

    __func_match: MatchFunctionType
    __func_rewrite: RewriteFunctionType

    def __init__(self, name: str, pattern_match: str, pattern_rewrite: str):

        self.name = name
        self.pattern_match = pattern_match
        self.pattern_rewrite = pattern_rewrite

        self.__func_match = MatchParser().parse(pattern_match)
        self.__func_rewrite = RewriteParser().parse(pattern_rewrite)

    def is_applicable(self, node: IRNode) -> bool:
        """Returns `True` if the rule can be applied to the `IRNode`"""
        lookup = dict()
        return self.__func_match(lookup, node)

    def rewrite(self, node: IRNode, rng_util: RNGUtil) -> IRNode | None:
        """Creates a copy of the provided `IRNode` and applies the rule.

        Returns`None` if the rule is not applicable, i.e. if `is_applicable` returns `False`.
        """
        lookup = dict()
        if self.__func_match(lookup, node):
            rewrite_node = self.__func_rewrite(lookup, rng_util)
            return rewrite_node
        return None

    def __eq__(self, value: object) -> bool:
        if value is None or not isinstance(value, Rule):
            return False
        return (
            value.name == self.name
            and value.pattern_match == self.pattern_match
            and value.pattern_rewrite == self.pattern_rewrite
        )

    def __hash__(self) -> int:
        return (self.name, self.pattern_match, self.pattern_rewrite).__hash__()
