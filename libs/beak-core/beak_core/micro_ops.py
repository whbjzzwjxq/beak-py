from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Union

from enum import Enum

from beak_core.rv32im import Instruction, RV32Mnemonic, RV32Trap


FieldElement = int

PossibleBooleanElement = FieldElement

PossibleFieldElement = FieldElement | str


class Subdomain(str, Enum):
    CPU = "cpu"
    SYSCALL = "syscall"
    PADDING = "padding"
    MEMORY = "memory"
    INTERACTION = "interaction"


class InteractionType(str, Enum):
    SEND = "send"
    RECV = "recv"


class MemorySpace(str, Enum):
    RAM = "ram"
    REG = "reg"
    VOLATILE = "volatile"
    IO = "io"


class MemorySize(str, Enum):
    BYTE = "byte"
    HALF_WORD = "half_word"
    WORD = "word"


@dataclass
class ZKVMMeta:

    # In ZKVMMeta, Optional means this field is not available in the original ZKVM.
    # is_real means whether this micro-op is padded or not.
    is_real: Optional[PossibleBooleanElement] = None

    # is_valid means whether this micro-op is valid or not.
    is_valid: Optional[PossibleBooleanElement] = None

    # subdomain: cpu/syscall/padding/memory/...
    subdomain: Optional[Subdomain] = None

    # extensible selectors: send_to_table, is_memory, mem_space, kind, mult, ...
    selectors: Dict[str, PossibleFieldElement] = field(default_factory=dict)

    # the bucket of this micro-op.
    bucket: Optional[str] = None


@dataclass(kw_only=True)
class MicroOpBase:
    # the idx of step in the program this micro-op belongs to.
    # dynamic execution index (clk), monotonically increasing.
    # it is cross-segment monotonic.
    step_idx: int

    # the idx of this micro-op in the step.
    # For the step itself, it is 0.
    uop_idx: int

    # the timestamp of this micro-op.
    timestamp: Optional[int] = None

    # the segment_idx of this micro-op belongs to.
    segment_idx: Optional[int] = None

    # the idx of this micro-op in the segment.
    segment_step_idx: Optional[int] = None

    # the meta of this micro-op.
    meta: ZKVMMeta = field(default_factory=ZKVMMeta)


@dataclass
class Step(MicroOpBase):

    # the opcode of this step, refer to rv32im.py.
    opcode: RV32Mnemonic

    # the pc of this step.
    pc: int

    # the next pc of this step.
    next_pc: Optional[int] = None

    # the instruction of this step.
    instruction: Optional[Instruction] = None

    # the reason why this step entered a trap.
    trap: Optional[RV32Trap] = None

    # whether this step is halted.
    halted: Optional[bool] = None


@dataclass
class RegisterRead(MicroOpBase):
    reg: int
    value: int

    def __post_init__(self):
        if not (0 <= self.reg <= 31):
            raise ValueError(f"RegisterRead reg {self.reg} out of range [0, 31]")


@dataclass
class RegisterWrite(MicroOpBase):
    reg: int
    value: int
    wen: Optional[PossibleBooleanElement] = None

    def __post_init__(self):
        if not (0 <= self.reg <= 31):
            raise ValueError(f"RegisterWrite reg {self.reg} out of range [0, 31]")


@dataclass
class MemoryRead(MicroOpBase):
    space: MemorySpace
    addr: int
    size: MemorySize
    value: FieldElement

    def __post_init__(self):
        if not isinstance(self.space, MemorySpace):
            raise ValueError(f"MemoryRead space {self.space} invalid")
        if not isinstance(self.size, MemorySize):
            raise ValueError(f"MemoryRead size {self.size} invalid")


@dataclass
class MemoryWrite(MicroOpBase):
    space: MemorySpace
    addr: int
    size: MemorySize
    value: FieldElement
    wen: Optional[PossibleBooleanElement] = None

    def __post_init__(self):
        if not isinstance(self.space, MemorySpace):
            raise ValueError(f"MemoryWrite space {self.space} invalid")
        if not isinstance(self.size, MemorySize):
            raise ValueError(f"MemoryWrite size {self.size} invalid")


@dataclass
class Interaction(MicroOpBase):
    table_id: str
    io: InteractionType
    event_idx: Optional[int] = None
    payload: List[FieldElement] = field(default_factory=list)
    type_tag: Optional[str] = None
    multiplicity: Optional[int] = None

    def __post_init__(self):
        if not isinstance(self.io, InteractionType):
            raise ValueError(f"Interaction io {self.io} invalid")


MicroOp = Union[Step, RegisterRead, RegisterWrite, MemoryRead, MemoryWrite, Interaction]


class ZKVMTrace:
    def __init__(self, micro_ops: List[MicroOp]):
        sorted_ops = sorted(micro_ops, key=lambda x: x.step_idx)

        self.steps: OrderedDict[int, Step] = OrderedDict()
        self.regr_by_step: OrderedDict[int, List[RegisterRead]] = OrderedDict()
        self.regw_by_step: OrderedDict[int, List[RegisterWrite]] = OrderedDict()
        self.memr_by_step: OrderedDict[int, List[MemoryRead]] = OrderedDict()
        self.memw_by_step: OrderedDict[int, List[MemoryWrite]] = OrderedDict()
        self.inter_by_step: OrderedDict[int, List[Interaction]] = OrderedDict()
        self.micro_ops_by_step: OrderedDict[int, List[MicroOp]] = OrderedDict()

        for uop in sorted_ops:
            s_idx = uop.step_idx
            self.micro_ops_by_step.setdefault(s_idx, []).append(uop)

            if isinstance(uop, Step):
                self.steps[s_idx] = uop
            elif isinstance(uop, RegisterRead):
                self.regr_by_step.setdefault(s_idx, []).append(uop)
            elif isinstance(uop, RegisterWrite):
                self.regw_by_step.setdefault(s_idx, []).append(uop)
            elif isinstance(uop, MemoryRead):
                self.memr_by_step.setdefault(s_idx, []).append(uop)
            elif isinstance(uop, MemoryWrite):
                self.memw_by_step.setdefault(s_idx, []).append(uop)
            elif isinstance(uop, Interaction):
                self.inter_by_step.setdefault(s_idx, []).append(uop)

    def get_step(self, step_idx: int) -> Optional[Step]:
        return self.steps.get(step_idx)

    def get_steps(self) -> List[Step]:
        return list(self.steps.values())

    @property
    def step_count(self) -> int:
        return len(self.steps)

    def get_micro_ops_in_step(self, step_idx: int) -> List[MicroOp]:
        return self.micro_ops_by_step.get(step_idx, [])

    def validate(self) -> List[str]:
        errors = []
        if not self.steps:
            return ["Trace is empty"]

        indices = list(self.steps.keys())
        min_idx, max_idx = indices[0], indices[-1]

        expected_count = max_idx - min_idx + 1
        if len(self.steps) != expected_count:
            errors.append(
                f"Trace step indices not continuous: [{min_idx}, {max_idx}] expects {expected_count} steps, found {len(self.steps)}"
            )

        for s_idx in range(min_idx, max_idx + 1):
            if s_idx not in self.steps:
                errors.append(f"Step {s_idx}: Missing main Step object")
                continue

            for uop in self.micro_ops_by_step.get(s_idx, []):
                if uop.step_idx != s_idx:
                    errors.append(f"Step {s_idx}: Contains mismatched step_idx {uop.step_idx}")

        return errors
