from risc0_fuzzer.kinds import InjectionKind, InstrKind
from zkvm_fuzzer_utils.trace import trace_from_str

DEFAULT_TEST_TRACE = """
<trace>{"step":0, "pc":2109628, "instruction":"Eany", "assembly":"ecall"}</trace>
<trace>{"step":1, "pc":3221225584, "instruction":"Lw", "assembly":"lw a0, 20(tp)"}</trace>
<trace>{"step":2, "pc":3221225588, "instruction":"Bge", "assembly":"bge a0, s2, 16"}</trace>
<trace>{"step":3, "pc":3221225592, "instruction":"SllI", "assembly":"slli a0, a0, 2"}</trace>
<trace>{"step":4, "pc":3221225596, "instruction":"Add", "assembly":"add a1, s1, a0"}</trace>
<trace>{"step":5, "pc":3221225600, "instruction":"JalR", "assembly":"jalr zero, a1, 0"}</trace>
<trace>{"step":6, "pc":3221225564, "instruction":"Jal", "assembly":"jal zero, 276"}</trace>
<trace>{"step":7, "pc":3221225840, "instruction":"Lw", "assembly":"lw a0, 40(tp)"}</trace>
<trace>{"step":8, "pc":3221225844, "instruction":"Lw", "assembly":"lw a1, 44(tp)"}</trace>
<trace>{"step":9, "pc":3221225848, "instruction":"Lw", "assembly":"lw a2, 48(tp)"}</trace>
<trace>{"step":10, "pc":3221225852, "instruction":"Lw", "assembly":"lw a3, 52(tp)"}</trace>
<trace>{"step":11, "pc":3221225856, "instruction":"Lw", "assembly":"lw a4, 56(tp)"}</trace>
<fault>{"step":12, "pc":3221225856, "kind":"PRE_EXEC_PC_MOD", "info":"pc:3221225856 => pc:3221225800"}</fault>
<trace>{"step":12, "pc":3221225860, "instruction":"Auipc", "assembly":"auipc ra, 0x00000000"}</trace>
<trace>{"step":13, "pc":3221225864, "instruction":"JalR", "assembly":"jalr ra, ra, 780"}</trace>
<trace>{"step":14, "pc":3221226640, "instruction":"AddI", "assembly":"addi a7, a2, 32"}</trace>
<trace>{"step":15, "pc":3221226644, "instruction":"AddI", "assembly":"addi a5, a4, 0"}</trace>
<hotfix>{"step":15, "pc":3221226644, "kind":"ALIGN_PC", "info":"pc:3221225856 => pc:3221225800"}</hotfix>
<trace>{"step":16, "pc":3221226648, "instruction":"AddI", "assembly":"addi a6, a1, 0"}</trace>

// ------
some other stuff
// ------

<trace>{"step":0, "pc":2109628, "instruction":"Eany", "assembly":"ecall"}</trace>
<trace>{"step":1, "pc":3221225584, "instruction":"Lw", "assembly":"lw a0, 20(tp)"}</trace>
<trace>{"step":2, "pc":3221225588, "instruction":"Bge", "assembly":"bge a0, s2, 16"}</trace>
<trace>{"step":3, "pc":3221225592, "instruction":"SllI", "assembly":"slli a0, a0, 2"}</trace>
<trace>{"step":4, "pc":3221225596, "instruction":"Add", "assembly":"add a1, s1, a0"}</trace>
<trace>{"step":5, "pc":3221225600, "instruction":"JalR", "assembly":"jalr zero, a1, 0"}</trace>
<trace>{"step":6, "pc":3221225564, "instruction":"Jal", "assembly":"jal zero, 276"}</trace>
<trace>{"step":7, "pc":3221225840, "instruction":"Lw", "assembly":"lw a0, 40(tp)"}</trace>
<trace>{"step":8, "pc":3221225844, "instruction":"Lw", "assembly":"lw a1, 44(tp)"}</trace>
<trace>{"step":9, "pc":3221225848, "instruction":"Lw", "assembly":"lw a2, 48(tp)"}</trace>
<trace>{"step":10, "pc":3221225852, "instruction":"Lw", "assembly":"lw a3, 52(tp)"}</trace>
<trace>{"step":11, "pc":3221225856, "instruction":"Lw", "assembly":"lw a4, 56(tp)"}</trace>
<fault>{"step":12, "pc":3221225856, "kind":"PRE_EXEC_PC_MOD", "info":"pc:3221225856 => pc:3221225800"}</fault>
<trace>{"step":12, "pc":3221225860, "instruction":"Auipc", "assembly":"auipc ra, 0x00000000"}</trace>
<trace>{"step":13, "pc":3221225864, "instruction":"JalR", "assembly":"jalr ra, ra, 780"}</trace>
<trace>{"step":14, "pc":3221226640, "instruction":"AddI", "assembly":"addi a7, a2, 32"}</trace>
<trace>{"step":15, "pc":3221226644, "instruction":"AddI", "assembly":"addi a5, a4, 0"}</trace>
<hotfix>{"step":15, "pc":3221226644, "kind":"ALIGN_PC", "info":"pc:3221225856 => pc:3221225800"}</hotfix>
<trace>{"step":16, "pc":3221226648, "instruction":"AddI", "assembly":"addi a6, a1, 0"}</trace>
"""  # noqa: E501


def test_trace_collection():
    trace = trace_from_str(DEFAULT_TEST_TRACE, InstrKind, InjectionKind)

    assert len(trace.steps) == 17, "unexpected amount of steps"
    for idx, trace_step in enumerate(trace.steps):
        assert idx == trace_step.step

    assert len(trace.faults) == 1, "unexpected amount of faults"
    assert trace.faults[0].step == 12
