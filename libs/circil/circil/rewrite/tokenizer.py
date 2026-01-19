from dataclasses import dataclass
try:
    from enum import StrEnum  # py>=3.11
except ImportError:  # pragma: no cover
    from enum import Enum

    class StrEnum(str, Enum):
        pass

from circil.ir.operator import Operator

# -----------------------------------------------------------------------------------


class TokenizerException(Exception):
    """Exception thrown by the rewrite pattern tokenizer"""

    def __init__(self, position: int, text: str, message: str):
        super().__init__(message)
        self.position = position
        self.text = text
        self.message = message


# -----------------------------------------------------------------------------------


class TokenKind(StrEnum):
    OPERATOR = "operator"
    IDENTIFIER = "identifier"
    NUMBER = "number"
    BOOLEAN = "boolean"
    PARENTHESIS_LEFT = "'('"
    PARENTHESIS_RIGHT = "')'"
    CURLY_PARENTHESIS_LEFT = "'{'"
    CURLY_PARENTHESIS_RIGHT = "'}'"
    SEMICOLON = "';'"
    COLON = "':'"
    QUESTION_MARK = "'?'"
    DOLLAR = "'$'"


# -----------------------------------------------------------------------------------


@dataclass
class Token:
    kind: TokenKind
    value: str | int | bool | Operator | None
    pos_start: int
    pos_end: int

    def __str__(self):
        return f"<{self.kind.value}>({self.value}, {self.pos_start}:{self.pos_end})"


# -----------------------------------------------------------------------------------


class Tokenizer:
    _BOOLS = "TF"
    _CHARACTERS = "abcdefghijklmnopqrstuvwABCDEFGHIJKLMNOPQRSTUVW_"
    _DIGITS = "1234567890"
    _CHARACTERS_AND_DIGITS = "abcdefghijklmnopqrstuvwABCDEFGHIJKLMNOPQRSTUVW_1234567890"
    _MISCELLANEOUS_SYMBOLS = ")(}{?;$:"
    _OPERATOR_SYMBOLS = "*-+=!<>&|/%^~"
    _WHITESPACE = " \n\r\t"

    _text: str

    def tokenize(self, text: str) -> list[Token]:
        self._text = text
        return self._tokenize(0)

    def _tokenize(self, ptr: int) -> list[Token]:
        result = []

        # main loop of tokenization
        while len(self._text) > ptr:

            # skip over all whitespaces
            while len(self._text) > ptr and self._text[ptr] in self._WHITESPACE:
                ptr = ptr + 1

            # check again if stream ended (because whitespace removal)
            if len(self._text) == ptr:
                break

            # start parsing a specific token
            if self._text[ptr] in self._MISCELLANEOUS_SYMBOLS:
                token = self._tokenize_miscellaneous(ptr)
            elif self._text[ptr] in self._BOOLS:
                token = self._tokenize_boolean(ptr)
            elif self._text[ptr] in self._CHARACTERS:
                token = self._tokenize_identifier(ptr)
            elif self._text[ptr] in self._DIGITS:
                token = self._tokenize_number(ptr)
            elif self._text[ptr] in self._OPERATOR_SYMBOLS:
                token = self._tokenize_operator(ptr)
            else:
                msg = f"Unexpected character '{self._text[ptr]}' at position '{ptr}'!"
                raise TokenizerException(ptr, self._text, msg)

            # update state
            result.append(token)
            ptr = token.pos_end + 1

        return result

    def _tokenize_miscellaneous(self, ptr: int) -> Token:
        token_kind = {
            "(": TokenKind.PARENTHESIS_LEFT,
            ")": TokenKind.PARENTHESIS_RIGHT,
            "{": TokenKind.CURLY_PARENTHESIS_LEFT,
            "}": TokenKind.CURLY_PARENTHESIS_RIGHT,
            "?": TokenKind.QUESTION_MARK,
            ";": TokenKind.SEMICOLON,
            "$": TokenKind.DOLLAR,
            ":": TokenKind.COLON,
        }.get(self._text[ptr], None)

        if token_kind is None:
            msg = (
                f"Expects '(', ')', '{{', '}}', '?', ';', '$' or ':' at "
                f"position {ptr}, but found {self._text[ptr]}!"
            )
            raise TokenizerException(ptr, self._text, msg)

        return Token(token_kind, None, ptr, ptr)

    def _tokenize_boolean(self, ptr: int) -> Token:
        return Token(TokenKind.BOOLEAN, self._text[ptr] == "T", ptr, ptr)

    def _tokenize_identifier(self, ptr: int) -> Token:
        name = ""
        pos_start = ptr
        while len(self._text) > ptr and self._text[ptr] in self._CHARACTERS_AND_DIGITS:
            name += self._text[ptr]
            ptr += 1
        return Token(TokenKind.IDENTIFIER, name, pos_start, ptr - 1)

    def _tokenize_number(self, ptr: int) -> Token:
        number_str = ""
        pos_start = ptr
        while len(self._text) > ptr and self._text[ptr] in self._DIGITS:
            number_str += self._text[ptr]
            ptr += 1
        number = int(number_str)
        return Token(TokenKind.NUMBER, number, pos_start, ptr - 1)

    def _tokenize_operator(self, ptr: int) -> Token:
        match self._text[ptr]:
            case "*":
                if self._text[ptr + 1] == "*":
                    return Token(TokenKind.OPERATOR, Operator.POW, ptr, ptr + 1)
                else:
                    return Token(TokenKind.OPERATOR, Operator.MUL, ptr, ptr)
            case "-":
                return Token(TokenKind.OPERATOR, Operator.SUB, ptr, ptr)
            case "+":
                return Token(TokenKind.OPERATOR, Operator.ADD, ptr, ptr)
            case "/":
                return Token(TokenKind.OPERATOR, Operator.DIV, ptr, ptr)
            case "%":
                return Token(TokenKind.OPERATOR, Operator.REM, ptr, ptr)
            case "=":
                if self._text[ptr + 1] == "=":
                    return Token(TokenKind.OPERATOR, Operator.EQU, ptr, ptr + 1)
                msg = f"Expects '=' at position {ptr}, but found {self._text[ptr]}!"
                raise TokenizerException(ptr, self._text, msg)
            case "!":
                if self._text[ptr + 1] == "=":
                    return Token(TokenKind.OPERATOR, Operator.NEQ, ptr, ptr + 1)
                else:
                    return Token(TokenKind.OPERATOR, Operator.NOT, ptr, ptr)
            case "<":
                if self._text[ptr + 1] == "=":
                    return Token(TokenKind.OPERATOR, Operator.LEQ, ptr, ptr + 1)
                else:
                    return Token(TokenKind.OPERATOR, Operator.LTH, ptr, ptr)
            case ">":
                if self._text[ptr + 1] == "=":
                    return Token(TokenKind.OPERATOR, Operator.GEQ, ptr, ptr + 1)
                else:
                    return Token(TokenKind.OPERATOR, Operator.GTH, ptr, ptr)
            case "&":
                if self._text[ptr + 1] == "&":
                    return Token(TokenKind.OPERATOR, Operator.LAND, ptr, ptr + 1)
                else:
                    return Token(TokenKind.OPERATOR, Operator.AND, ptr, ptr)
            case "|":
                if self._text[ptr + 1] == "|":
                    return Token(TokenKind.OPERATOR, Operator.LOR, ptr, ptr + 1)
                else:
                    return Token(TokenKind.OPERATOR, Operator.OR, ptr, ptr)
            case "^":
                if self._text[ptr + 1] == "^":
                    return Token(TokenKind.OPERATOR, Operator.LXOR, ptr, ptr + 1)
                else:
                    return Token(TokenKind.OPERATOR, Operator.XOR, ptr, ptr)
            case "~":
                return Token(TokenKind.OPERATOR, Operator.COMP, ptr, ptr)
            case _:
                msg = (
                    f"Expects '*', '-', '+', '=', '!', '<', '>', '~', '&', '|' or "
                    f"'^' at position {ptr}, but found {self._text[ptr]}!"
                )
                raise TokenizerException(ptr, self._text, msg)


# -----------------------------------------------------------------------------------
