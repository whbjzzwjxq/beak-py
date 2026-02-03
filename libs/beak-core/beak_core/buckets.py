from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from beak_core.micro_ops import MicroOp, ZKVMTrace


class BucketType(str, Enum):
    pass


@dataclass(frozen=True)
class BucketHit:
    bucket_type: BucketType
    core_instruction_idxs: List[int]
    details: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        object.__setattr__(self, "details", dict(self.details))


class Bucket(ABC):
    @abstractmethod
    def get_type(self) -> BucketType:
        raise NotImplementedError

    @abstractmethod
    def match_hits(
        self, context: ZKVMTrace, micro_op_idx: int, micro_op: MicroOp
    ) -> Optional[BucketHit]:
        raise NotImplementedError
