from abc import ABC, abstractmethod
from random import Random


class RNGUtil(ABC):
    """Base class of an RNG util for the rewrite mechanic.

    This helper is used abstract away the randomness from
    resulting rewrite functions.
    """

    @abstractmethod
    def random_integer(self) -> int:
        pass

    @abstractmethod
    def random_boolean(self) -> bool:
        pass


class SimpleRNGUtil(RNGUtil):
    """Simple implementation of the `RNGUtil`"""

    def __init__(self, min_integer: int, max_integer: int, rng: Random):
        self.__max_integer = max_integer
        self.__min_integer = min_integer
        self.__rng = rng

    def random_integer(self) -> int:
        return self.__rng.randint(self.__min_integer, self.__max_integer)

    def random_boolean(self) -> bool:
        return self.__rng.choice([True, False])
