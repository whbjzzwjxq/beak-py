from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

from beak_core.micro_ops import ZKVMTrace, RegisterWrite, Step
from beak_core.rv32im import FuzzingInstance, Instruction


class BucketType(str, Enum):
    # RISC-V register relevant buckets
    REG_INTEGRITY = "reg_integrity"  # Topology: x0, alias, triple
    REG_DEPENDENCY = "reg_dependency"  # Timing: RAW, WAW
    REG_LIFECYCLE = "reg_lifecycle"  # Context: Segment handover
    REG_WRITE_PERMISSION = "reg_write_permission"  # Gating: Write intent vs action


class EvolveActionType(str, Enum):
    SWAP_OPERAND = "swap_operand"  # rs1 <-> rs2
    SWAP_REGISTER = "swap_register"  # change rd/rs/rt
    SWAP_IMMEDIATE = "swap_immediate"  # change imm value
    SWAP_INST = "swap_inst"  # change opcode
    ADD_INST = "add_inst"  # insert new instruction (e.g., reveal or nop)


@dataclass(frozen=True)
class BucketKey:
    bucket_type: BucketType
    labels: Tuple[str, ...]

    def __str__(self) -> str:
        return f"{self.bucket_type.value}: {','.join(self.labels)}"


@dataclass(frozen=True)
class BucketHit:
    key: BucketKey
    step_idxs: List[int]
    instruction_idxs: List[int]
    details: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        object.__setattr__(self, "details", dict(self.details))


@dataclass(frozen=True)
class EvolveAction:
    action_type: EvolveActionType
    instruction_idx: int
    params: Dict[str, Any] = field(default_factory=dict)

    def apply(self, instance: FuzzingInstance) -> FuzzingInstance:
        # TODO: Implement
        return instance


class Bucket(ABC):
    @abstractmethod
    def get_type(self) -> BucketType:
        raise NotImplementedError

    @abstractmethod
    def boundary_cases(self) -> Iterable[BucketKey]:
        raise NotImplementedError

    @abstractmethod
    def match_hits(self, trace: ZKVMTrace) -> List[BucketHit]:
        raise NotImplementedError

    @abstractmethod
    def evolve(self, hit: BucketHit) -> Optional[EvolveAction]:
        raise NotImplementedError

    @abstractmethod
    def initial_seeds(self) -> Iterable[FuzzingInstance]:
        raise NotImplementedError

class RegIntegrityBoundary(str, Enum):

    X0_WRITE = "x0_write"
    X0_AS_SOURCE = "x0_as_source"
    X0_PROXY_BYPASS = "x0_proxy_bypass"

    ALIAS_RD_RS1 = "alias_rd_rs1"
    ALIAS_RS1_RS2 = "alias_rs1_rs2"
    ALIAS_RD_RS2 = "alias_rd_rs2"
    ALIAS_RD_RS1_RS2 = "alias_rd_rs1_rs2"


class RegisterIntegrityBucket(Bucket):
    def get_type(self) -> BucketType:
        return BucketType.REG_INTEGRITY

    def boundary_cases(self) -> Iterable[BucketKey]:
        for b in RegIntegrityBoundary:
            yield BucketKey(self.get_type(), (b.value,))

    def match_hits(self, trace: ZKVMTrace) -> List[BucketHit]:
        # TODO: Implement
        return []

    def evolve(self, hit: BucketHit) -> Optional[EvolveAction]:
        # TODO: Implement
        return None

    def initial_seeds(self) -> Iterable[FuzzingInstance]:
        # TODO: Implement
        return []
