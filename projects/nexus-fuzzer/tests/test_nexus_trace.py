from nexus_fuzzer.kinds import InjectionKind, InstrKind
from zkvm_fuzzer_utils.trace import trace_from_str

DEFAULT_TEST_TRACE = """
// ------
some other stuff
// ------

<trace>{"step":0, "pc":136, "instruction":"auipc", "assembly":"auipc gp, 0x4", "emulator":"LinearEmulator"}</trace>
<trace>{"step":1, "pc":140, "instruction":"addi", "assembly":"addi gp, gp, -1768", "emulator":"LinearEmulator"}</trace>
<trace>{"step":2, "pc":144, "instruction":"auipc", "assembly":"auipc sp, 0x80400", "emulator":"LinearEmulator"}</trace>
<trace>{"step":3, "pc":148, "instruction":"addi", "assembly":"addi sp, sp, -144", "emulator":"LinearEmulator"}</trace>
<trace>{"step":4, "pc":152, "instruction":"addi", "assembly":"li a7, 1026", "emulator":"LinearEmulator"}</trace>
<trace>{"step":5, "pc":156, "instruction":"ecall", "assembly":"ecall", "emulator":"LinearEmulator"}</trace>
<trace>{"step":6, "pc":160, "instruction":"addi", "assembly":"mv s0, sp", "emulator":"LinearEmulator"}</trace>
<trace>{"step":7, "pc":164, "instruction":"jal", "assembly":"jal ra, 0x0", "emulator":"LinearEmulator"}</trace>
<trace>{"step":8, "pc":168, "instruction":"addi", "assembly":"addi sp, sp, -16", "emulator":"LinearEmulator"}</trace>
<trace>{"step":9, "pc":172, "instruction":"sw", "assembly":"sw ra, 12(sp)", "emulator":"LinearEmulator"}</trace>
<trace>{"step":10, "pc":176, "instruction":"auipc", "assembly":"auipc ra, 0x0", "emulator":"LinearEmulator"}</trace>

// ------
some other stuff
// ------
"""  # noqa: E501


def test_trace_collection():
    trace = trace_from_str(DEFAULT_TEST_TRACE, InstrKind, InjectionKind)

    assert len(trace.steps) == 11, "unexpected amount of steps fro linear emulator"

    for idx, trace_step in enumerate(trace.steps):
        assert idx == trace_step.step, "linear emulator step not ordered"
