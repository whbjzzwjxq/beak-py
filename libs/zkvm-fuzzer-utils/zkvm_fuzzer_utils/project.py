from abc import ABC, abstractmethod
from pathlib import Path

from circil.ir.node import Circuit
from zkvm_fuzzer_utils.common import validate_circuits_arguments

# ---------------------------------------------------------------------------- #
#                               Project Generators                             #
# ---------------------------------------------------------------------------- #


class AbstractProjectGenerator(ABC):
    __root: Path
    __zkvm_path: Path

    def __init__(self, root: Path, zkvm_path: Path):
        self.__root = root
        self.__zkvm_path = zkvm_path

    @abstractmethod
    def create(self):
        raise NotImplementedError()

    @property
    def zkvm_path(self) -> Path:
        return self.__zkvm_path

    @property
    def root(self) -> Path:
        return self.__root


# ---------------------------------------------------------------------------- #


class AbstractCircuitProjectGenerator(AbstractProjectGenerator):
    __circuits: list[Circuit]
    __fault_injection: bool
    __trace_collection: bool

    def __init__(
        self,
        root: Path,
        zkvm_path: Path,
        circuits: list[Circuit],
        fault_injection: bool,
        trace_collection: bool,
    ):
        super().__init__(root, zkvm_path)
        validate_circuits_arguments(circuits)
        self.__circuits = circuits
        self.__fault_injection = fault_injection
        self.__trace_collection = trace_collection

    @property
    def circuits(self) -> list[Circuit]:
        return self.__circuits

    @property
    def circuit_candidate(self) -> Circuit:
        return self.circuits[0]

    @property
    def is_fault_injection(self) -> bool:
        return self.__fault_injection

    @property
    def is_trace_collection(self) -> bool:
        return self.__trace_collection

    @property
    def requires_fuzzer_utils(self) -> bool:
        return self.is_fault_injection or self.is_trace_collection


# ---------------------------------------------------------------------------- #
