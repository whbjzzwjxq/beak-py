from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

from beak_core.micro_ops import ZKVMTrace


class BucketType(str, Enum):
    BOOL_DOMAIN = "bool_domain"
    INERT_WHEN_NOT_REAL = "inert_when_not_real"
    NEXT_PC_ALIGN = "next_pc_align"
    NEXT_PC_EQ_EXPECTED = "next_pc_eq_expected"
    REG0_WRITE = "reg0_write"
    MEM_ALIGN = "mem_align"
    MULT_NEIGHBORHOOD = "mult_neighborhood"
    INTERACTION_GATED = "interaction_gated"


# Convert int to str for label.
Label = Tuple[str, ...]


@dataclass(frozen=True)
class BucketKey:
    bucket_type: BucketType
    label: Label


@dataclass(frozen=True)
class BucketHit:
    key: BucketKey
    step_idx: Optional[int] = None
    details: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        # freeze semantic: copy a new dict, avoid external continue to modify the dict
        object.__setattr__(self, "details", dict(self.details))


class Bucket(ABC):
    @abstractmethod
    def get_type(self) -> BucketType:
        raise NotImplementedError

    @abstractmethod
    def universe(self) -> Iterable[BucketKey]:
        raise NotImplementedError

    @abstractmethod
    def features(self, trace: ZKVMTrace) -> List[BucketHit]:
        raise NotImplementedError

    @abstractmethod
    def explain(self, hit: BucketHit) -> str:
        raise NotImplementedError

    @abstractmethod
    def repair(self, key: BucketKey) -> Optional[Dict[str, Any]]:
        raise NotImplementedError

    @abstractmethod
    def fallback(self, key: BucketKey) -> Optional[Dict[str, Any]]:
        raise NotImplementedError


class RepairAction(str, Enum):
    SWAP_OPERAND = "swap_operand"
    SWAP_REGISTER = "swap_register"
    SWAP_IMMEDIATE = "swap_immediate"
    SWAP_INST = "swap_inst"
    ADD_INST = "add_inst"


class InertWhenNotRealBoundary(str, Enum):
    # always use ok to represent a bucket hit is valid
    OK = "ok"
    REGW = "regw"
    MEMW = "memw"
    INTERACTION = "interaction"
    MULTI = "multi"

    @property
    def is_valid(self) -> bool:
        return self == InertWhenNotRealBoundary.OK


class InertWhenNotRealBucket(Bucket):

    def __init__(self):
        self.repair_action = RepairAction.ADD_INST

    def get_type(self) -> BucketType:
        return BucketType.INERT_WHEN_NOT_REAL

    def universe(self) -> Iterable[BucketKey]:
        for label in InertWhenNotRealBoundary:
            yield BucketKey(self.get_type(), (label.value,))

    def features(self, trace: ZKVMTrace) -> List[BucketHit]:
        hits = []
        for s_idx, step in trace.steps.items():
            if step.meta.is_real == 0:
                violations = []
                if trace.regw_by_step.get(s_idx):
                    violations.append(InertWhenNotRealBoundary.REGW)
                if trace.memw_by_step.get(s_idx):
                    violations.append(InertWhenNotRealBoundary.MEMW)
                if trace.inter_by_step.get(s_idx):
                    violations.append(InertWhenNotRealBoundary.INTERACTION)

                if not violations:
                    hits.append(
                        BucketHit(
                            key=BucketKey(self.get_type(), (InertWhenNotRealBoundary.OK.value,)),
                            step_idx=s_idx,
                        )
                    )
                elif len(violations) > 1:
                    hits.append(
                        BucketHit(
                            key=BucketKey(self.get_type(), (InertWhenNotRealBoundary.MULTI.value,)),
                            step_idx=s_idx,
                            details={"types": violations},
                        )
                    )
                else:
                    hits.append(
                        BucketHit(
                            key=BucketKey(self.get_type(), (violations[0].value,)),
                            step_idx=s_idx,
                            details={"type": violations[0].value},
                        )
                    )
        return hits

    def explain(self, hit: BucketHit) -> str:
        label = hit.key.label[0]
        if label == InertWhenNotRealBoundary.OK.value:
            return f"Step {hit.step_idx}: Padding step is inert (ok)"
        return f"Step {hit.step_idx}: Padding step violation - found {label}"

    def repair(self, key: BucketKey) -> Optional[Dict[str, Any]]:
        label = key.label[0]
        # 如果目标是触发 violation，我们就构造冲突
        if label == InertWhenNotRealBoundary.REGW:
            return {
                "action": "inject_uop",
                "uop_type": "RegisterWrite",
                "constraint": {"is_real": 0},  # 在 is_real=0 的行注入
            }
        if label == InertWhenNotRealBoundary.MEMW:
            return {"action": "inject_uop", "uop_type": "MemoryWrite", "constraint": {"is_real": 0}}
        if label == InertWhenNotRealBoundary.OK:
            return {"action": "clear_side_effects", "constraint": {"is_real": 0}}
        return None

    def fallback(self, key: BucketKey) -> Optional[Dict[str, Any]]:
        # 如果不知道怎么修，就随机翻转 is_real 信号
        return {"action": "random_flip", "field": "meta.is_real"}
