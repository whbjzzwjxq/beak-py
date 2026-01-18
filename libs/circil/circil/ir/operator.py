from enum import StrEnum


class Operator(StrEnum):
    """String enum containing all of CircIL's operators"""

    # arithmetic operators
    MUL = "*"
    SUB = "-"
    ADD = "+"
    POW = "**"
    DIV = "/"
    REM = "%"

    # comparators
    EQU = "=="
    NEQ = "!="
    LTH = "<"
    LEQ = "<="
    GTH = ">"
    GEQ = ">="

    # logic operators
    LAND = "&&"
    LOR = "||"
    LXOR = "^^"
    NOT = "!"

    # bitwise operators
    AND = "&"
    OR = "|"
    XOR = "^"
    COMP = "~"

    @classmethod
    def unary_arithmetic_operators(cls) -> list["Operator"]:
        """Returns a list of all arithmetic operators"""
        return [cls.SUB]

    @classmethod
    def binary_arithmetic_operators(cls) -> list["Operator"]:
        """Returns a list of all arithmetic operators"""
        return [cls.MUL, cls.SUB, cls.ADD, cls.POW, cls.DIV, cls.REM]

    @classmethod
    def comparators(cls) -> list["Operator"]:
        """Returns a list of all comparators"""
        return [cls.EQU, cls.NEQ, cls.LTH, cls.LEQ, cls.GTH, cls.GEQ]

    @classmethod
    def logic_operators(cls) -> list["Operator"]:
        """Returns a list of all logic operators"""
        return [cls.LAND, cls.LOR, cls.LXOR, cls.NOT]

    @classmethod
    def unary_logic_operators(cls) -> list["Operator"]:
        """Returns a list of all unary logic operators"""
        return [cls.NOT]

    @classmethod
    def binary_logic_operators(cls) -> list["Operator"]:
        """Returns a list of all binary logic operators"""
        return [cls.LAND, cls.LOR, cls.LXOR]

    @classmethod
    def unary_bitwise_operators(cls) -> list["Operator"]:
        """Returns a list of all unary bitwise operators"""
        return [cls.COMP]

    @classmethod
    def binary_bitwise_operators(cls) -> list["Operator"]:
        """Returns a list of all unary bitwise operators"""
        return [cls.AND, cls.OR, cls.XOR]

    @classmethod
    def unary_operations(cls) -> list["Operator"]:
        return [cls.COMP, cls.NOT, cls.SUB]

    @classmethod
    def binary_operations(cls) -> list["Operator"]:
        return [
            cls.MUL,
            cls.SUB,
            cls.ADD,
            cls.POW,
            cls.DIV,
            cls.REM,
            cls.EQU,
            cls.NEQ,
            cls.LTH,
            cls.LEQ,
            cls.GTH,
            cls.GEQ,
            cls.LAND,
            cls.LOR,
            cls.LXOR,
            cls.AND,
            cls.OR,
            cls.XOR,
        ]
