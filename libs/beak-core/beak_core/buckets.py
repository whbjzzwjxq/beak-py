from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Iterable, List, Optional, Tuple

from beak_core.micro_ops import ZKVMTrace
from beak_core.rv32im import FuzzingInstance, Instruction


class RV32BucketType(str, Enum):
    # RISC-V register relevant buckets
    REG_INTEGRITY_X0_WRITE = "reg_integrity_x0_write"  # Topology: x0
    REG_INTEGRITY_X0_READ = "reg_integrity_x0_read"  # Topology: x0
    REG_INTEGRITY_X0_PROXY_BYPASS = "reg_integrity_x0_proxy_bypass"  # Topology: x0

    REG_INTEGRITY_ALIAS_RD_RS1 = "reg_integrity_alias_rd_rs1"  # Topology: alias
    REG_INTEGRITY_ALIAS_RD_RS2 = "reg_integrity_alias_rd_rs2"  # Topology: alias
    REG_INTEGRITY_ALIAS_RD_RS1_RS2 = "reg_integrity_alias_rd_rs1_rs2"  # Topology: alias
    REG_INTEGRITY_ALIAS_RS1_RS2 = "reg_integrity_alias_rs1_rs2"  # Topology: alias

    REG_DEPENDENCY_RAW = "reg_dependency_raw"  # Timing: RAW
    REG_DEPENDENCY_WAW = "reg_dependency_waw"  # Timing: WAW

    # TODO: Add more buckets


@dataclass(frozen=True)
class RV32BucketHit:
    bucket_type: RV32BucketType
    core_instruction_idxs: List[int]
    details: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        object.__setattr__(self, "details", dict(self.details))


class RV32Bucket(ABC):
    @abstractmethod
    def get_type(self) -> RV32BucketType:
        raise NotImplementedError

    @abstractmethod
    def match_hits(
        self, context: FuzzingInstance, inst_idx: int, inst: Instruction
    ) -> Optional[RV32BucketHit]:
        raise NotImplementedError

    @abstractmethod
    def initial_seeds(self) -> Iterable[FuzzingInstance]:
        raise NotImplementedError


class RV32BucketRegIntegrityX0Write(RV32Bucket):
    def get_type(self) -> RV32BucketType:
        return RV32BucketType.REG_INTEGRITY_X0_WRITE

    def match_hits(
        self, context: FuzzingInstance, inst_idx: int, inst: Instruction
    ) -> Optional[RV32BucketHit]:
        rd = inst.rd
        if rd == 0:
            return RV32BucketHit(
                bucket_type=self.get_type(),
                core_instruction_idxs=[context.core_instruction_idxs[inst_idx]],
            )
        return None


class RV32BucketRegIntegrityX0Read(RV32Bucket):
    def get_type(self) -> RV32BucketType:
        return RV32BucketType.REG_INTEGRITY_X0_READ

    def match_hits(
        self, context: FuzzingInstance, inst_idx: int, inst: Instruction
    ) -> Optional[RV32BucketHit]:
        rd = inst.rd
        if rd == 0:
            return RV32BucketHit(
                bucket_type=self.get_type(),
                core_instruction_idxs=[context.core_instruction_idxs[inst_idx]],
            )
        return None