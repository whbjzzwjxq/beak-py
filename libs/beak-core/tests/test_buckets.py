from beak_core.buckets import BoolDomainBucket, BoolDomainSignal, BoolDomainStatus
from beak_core.micro_ops import Step, ZKVMMeta, ZKVMTrace
from beak_core.rv32im import ADD


def test_bool_domain_bucket_detects_non_bool_is_real():
    trace = ZKVMTrace(
        [
            Step(step_idx=0, uop_idx=0, opcode=ADD, pc=0, meta=ZKVMMeta(is_real=2)),
            Step(step_idx=1, uop_idx=0, opcode=ADD, pc=4, meta=ZKVMMeta(is_real=1)),
        ]
    )

    hits = BoolDomainBucket().features(trace)
    labels = {(h.key.label, h.step_idx) for h in hits}

    assert ((BoolDomainSignal.IS_REAL.value, BoolDomainStatus.NON_BOOLEAN.value), 0) in labels
    assert ((BoolDomainSignal.IS_REAL.value, BoolDomainStatus.BOOLEAN.value), 1) in labels


def test_bool_domain_bucket_scans_non_step_uops_too():
    # is_real lives on a non-Step uop (e.g. a memory row) in some backends.
    from beak_core.micro_ops import MemoryWrite, MemorySpace, MemorySize

    trace = ZKVMTrace(
        [
            Step(step_idx=0, uop_idx=0, opcode=ADD, pc=0, meta=ZKVMMeta(is_real=1)),
            MemoryWrite(
                step_idx=0,
                uop_idx=1,
                space=MemorySpace.RAM,
                addr=0x20000,
                size=MemorySize.WORD,
                value=0x1234,
                meta=ZKVMMeta(is_real=2),
            ),
        ]
    )

    hits = BoolDomainBucket().features(trace)
    labels = {(h.key.label, h.step_idx) for h in hits}
    assert ((BoolDomainSignal.IS_REAL.value, BoolDomainStatus.NON_BOOLEAN.value), 0) in labels
