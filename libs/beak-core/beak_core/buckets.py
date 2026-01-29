from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

from beak_core.micro_ops import PossibleFieldElement, ZKVMTrace


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
        # If the target is a violation, construct a conflicting side effect.
        if label == InertWhenNotRealBoundary.REGW:
            return {
                "action": "inject_uop",
                "uop_type": "RegisterWrite",
                "constraint": {"is_real": 0},  # inject into rows with is_real=0
            }
        if label == InertWhenNotRealBoundary.MEMW:
            return {"action": "inject_uop", "uop_type": "MemoryWrite", "constraint": {"is_real": 0}}
        if label == InertWhenNotRealBoundary.OK:
            return {"action": "clear_side_effects", "constraint": {"is_real": 0}}
        return None

    def fallback(self, key: BucketKey) -> Optional[Dict[str, Any]]:
        # If we don't know how to fix it, try randomly flipping the is_real signal.
        return {"action": "random_flip", "field": "meta.is_real"}


class BoolDomainSignal(str, Enum):
    IS_REAL = "meta.is_real"
    IS_VALID = "meta.is_valid"


class BoolDomainStatus(str, Enum):
    BOOLEAN = "boolean"
    NON_BOOLEAN = "non_boolean"


def _is_bool_like(value: PossibleFieldElement | None) -> bool | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return True
    if isinstance(value, int):
        return value in (0, 1)
    if isinstance(value, str):
        # Allow simple serialization forms.
        if value.strip() in ("0", "1"):
            return True
        return False
    return False


class BoolDomainBucket(Bucket):
    """
    Detects whether boolean-like meta signals (e.g. `is_real`) are constrained to {0,1}.

    This is a high-level, cross-zkVM bucket: backends can map "meta.is_real" to their
    concrete columns/flags (e.g. Pico's MemoryLocalChip.is_real multiplicity).
    """

    def get_type(self) -> BucketType:
        return BucketType.BOOL_DOMAIN

    def universe(self) -> Iterable[BucketKey]:
        for signal in BoolDomainSignal:
            for status in BoolDomainStatus:
                yield BucketKey(self.get_type(), (signal.value, status.value))

    def features(self, trace: ZKVMTrace) -> List[BucketHit]:
        """
        Scan boolean-like meta signals across *all* micro-ops in each step.

        Rationale: different backends attach `is_real`/`is_valid` to different uops
        (instruction step, memory access row, interaction row, ...). For the closed-loop pipeline we want
        this bucket to be backend-agnostic, so we don't assume the signal only lives
        on the main `Step` object.
        """

        hits: List[BucketHit] = []
        for s_idx in trace.micro_ops_by_step.keys():
            for uop in trace.get_micro_ops_in_step(s_idx):
                for signal in (BoolDomainSignal.IS_REAL, BoolDomainSignal.IS_VALID):
                    raw = None
                    if signal == BoolDomainSignal.IS_REAL:
                        raw = uop.meta.is_real
                    elif signal == BoolDomainSignal.IS_VALID:
                        raw = uop.meta.is_valid

                    is_bool = _is_bool_like(raw)
                    if is_bool is None:
                        continue  # signal not available

                    status = BoolDomainStatus.BOOLEAN if is_bool else BoolDomainStatus.NON_BOOLEAN
                    hits.append(
                        BucketHit(
                            key=BucketKey(self.get_type(), (signal.value, status.value)),
                            step_idx=s_idx,
                            details={
                                "value": raw,
                                "uop_type": type(uop).__name__,
                                "uop_idx": getattr(uop, "uop_idx", None),
                            },
                        )
                    )
        return hits

    def explain(self, hit: BucketHit) -> str:
        signal, status = hit.key.label
        if status == BoolDomainStatus.BOOLEAN.value:
            return f"Step {hit.step_idx}: {signal} is boolean"
        return f"Step {hit.step_idx}: {signal} is non-boolean (value={hit.details.get('value')})"

    def repair(self, key: BucketKey) -> Optional[Dict[str, Any]]:
        signal, status = key.label
        if status != BoolDomainStatus.NON_BOOLEAN.value:
            return None
        if signal == BoolDomainSignal.IS_REAL.value:
            # Minimal payload used by backends: make `is_real` non-boolean (e.g. 2).
            return {
                "action": "set_non_bool",
                "field": "is_real",
                "value": 2,
            }
        if signal == BoolDomainSignal.IS_VALID.value:
            return {
                "action": "set_non_bool",
                "field": "is_valid",
                "value": 2,
            }
        return None

    def fallback(self, key: BucketKey) -> Optional[Dict[str, Any]]:
        signal, _ = key.label
        if signal == BoolDomainSignal.IS_REAL.value:
            return {"action": "random_flip", "field": "meta.is_real"}
        if signal == BoolDomainSignal.IS_VALID.value:
            return {"action": "random_flip", "field": "meta.is_valid"}
        return None
