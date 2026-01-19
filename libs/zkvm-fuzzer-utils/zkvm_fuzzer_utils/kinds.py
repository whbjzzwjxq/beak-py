try:
    from enum import StrEnum  # py>=3.11
except ImportError:  # pragma: no cover
    from enum import Enum

    class StrEnum(str, Enum):
        pass
from typing import TypeVar

# ---------------------------------------------------------------------------- #
#                              Generic Bound Types                             #
# ---------------------------------------------------------------------------- #


InstrKind = TypeVar("InstrKind", bound=StrEnum)
InjectionKind = TypeVar("InjectionKind", bound=StrEnum)


# ---------------------------------------------------------------------------- #
