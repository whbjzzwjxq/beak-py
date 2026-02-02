from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from beak_core.micro_ops import InteractionBase, MicroOp, ZKVMTrace


class BucketType(str, Enum):
    MULTIPLICITY_BOOL_DOMAIN = "multiplicity_bool_domain"


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
    def match_hits(self, context: ZKVMTrace, micro_op_idx: int, micro_op: MicroOp) -> Optional[BucketHit]:
        raise NotImplementedError


class MultiplicityBoolDomainBucket(Bucket):
    """
    Bool-domain bucket for interaction multiplicity.

    For each micro-op that has a multiplicity, emits a BucketHit that indicates
    whether multiplicity is constrained to {0,1}.
    """

    def get_type(self) -> BucketType:
        return BucketType.MULTIPLICITY_BOOL_DOMAIN

    @staticmethod
    def _is_bool_like(value: Any) -> bool | None:
        if value is None:
            return None
        if isinstance(value, bool):
            return True
        if isinstance(value, int):
            return value in (0, 1)
        if isinstance(value, str):
            return value.strip() in ("0", "1")
        return False

    def match_hits(self, context: ZKVMTrace, micro_op_idx: int, micro_op: MicroOp) -> Optional[BucketHit]:
        if not isinstance(micro_op, InteractionBase):
            return None
        raw = getattr(micro_op, "multiplicity", None)
        is_bool = self._is_bool_like(raw)
        if is_bool is None:
            return None

        status = "boolean" if is_bool else "non_boolean"
        return BucketHit(
            bucket_type=self.get_type(),
            core_instruction_idxs=[micro_op_idx],
            details={
                "signal": "multiplicity",
                "status": status,
                "value": raw,
                "table_id": getattr(micro_op, "table_id", None),
                "kind": getattr(micro_op, "kind", None),
            },
        )
