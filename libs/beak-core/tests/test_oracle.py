import pytest
import time
from beak_core.oracle import RISCVOracle
from beak_core.rv32im import FuzzingInstance, Instruction
from beak_core.generator import RISCVGenerator


@pytest.fixture
def oracle():
    return RISCVOracle()


def test_oracle_basic_functionality_add(oracle):
    """
    Verify that the oracle correctly computes expected results for simple instructions.
    """
    instance = FuzzingInstance(
        instructions=[Instruction.from_asm("add x10, x11, x12")], initial_regs={11: 5, 12: 7, 10: 0}
    )
    oracle.compute_expected_results(instance)
    assert instance.expected_results[10] == 12


def test_oracle_basic_functionality_addi(oracle):
    """
    Verify that the oracle correctly computes expected results for simple instructions.
    """
    instance = FuzzingInstance(
        instructions=[Instruction.from_asm("addi x10, x11, -1")], initial_regs={11: 1, 10: 0}
    )
    oracle.compute_expected_results(instance)
    assert instance.expected_results[10] == 0


def test_oracle_basic_functionality_sub(oracle):
    """
    Verify that the oracle correctly computes expected results for simple instructions.
    """
    instance = FuzzingInstance(
        instructions=[Instruction.from_asm("sub x10, x11, x12")], initial_regs={11: 5, 12: 7, 10: 0}
    )
    oracle.compute_expected_results(instance)
    assert instance.expected_results[10] == -2


def test_oracle_basic_functionality_xor(oracle):
    """
    Verify that the oracle correctly computes expected results for simple instructions.
    """
    instance = FuzzingInstance(
        instructions=[Instruction.from_asm("xor x10, x11, x12")], initial_regs={11: 5, 12: 7, 10: 0}
    )
    oracle.compute_expected_results(instance)
    assert instance.expected_results[10] == 2


def test_oracle_basic_functionality_or(oracle):
    """
    Verify that the oracle correctly computes expected results for simple instructions.
    """
    instance = FuzzingInstance(
        instructions=[Instruction.from_asm("or x10, x11, x12")], initial_regs={11: 5, 12: 7, 10: 0}
    )
    oracle.compute_expected_results(instance)
    assert instance.expected_results[10] == 7


def test_oracle_r_type_alu(oracle):
    # sll
    instance = FuzzingInstance(
        instructions=[Instruction.from_asm("sll x10, x11, x12")], initial_regs={11: 1, 12: 2, 10: 0}
    )
    oracle.compute_expected_results(instance)
    assert instance.expected_results[10] == 4

    # slt
    instance = FuzzingInstance(
        instructions=[Instruction.from_asm("slt x10, x11, x12")], initial_regs={11: -1, 12: 1, 10: 0}
    )
    oracle.compute_expected_results(instance)
    assert instance.expected_results[10] == 1

    # sltu
    instance = FuzzingInstance(
        instructions=[Instruction.from_asm("sltu x10, x11, x12")],
        initial_regs={11: 0xFFFFFFFF, 12: 1, 10: 0},
    )
    oracle.compute_expected_results(instance)
    assert instance.expected_results[10] == 0

    # srl
    instance = FuzzingInstance(
        instructions=[Instruction.from_asm("srl x10, x11, x12")], initial_regs={11: 8, 12: 1, 10: 0}
    )
    oracle.compute_expected_results(instance)
    assert instance.expected_results[10] == 4

    # sra
    instance = FuzzingInstance(
        instructions=[Instruction.from_asm("sra x10, x11, x12")], initial_regs={11: -8, 12: 1, 10: 0}
    )
    oracle.compute_expected_results(instance)
    assert instance.expected_results[10] == -4

    # and
    instance = FuzzingInstance(
        instructions=[Instruction.from_asm("and x10, x11, x12")], initial_regs={11: 3, 12: 1, 10: 0}
    )
    oracle.compute_expected_results(instance)
    assert instance.expected_results[10] == 1


def test_oracle_r_type_m_extension(oracle):
    # mul
    instance = FuzzingInstance(
        instructions=[Instruction.from_asm("mul x10, x11, x12")], initial_regs={11: 3, 12: 4, 10: 0}
    )
    oracle.compute_expected_results(instance)
    assert instance.expected_results[10] == 12

    # mulh
    instance = FuzzingInstance(
        instructions=[Instruction.from_asm("mulh x10, x11, x12")],
        initial_regs={11: 0x7FFFFFFF, 12: 2, 10: 0},
    )
    oracle.compute_expected_results(instance)
    # 0x7FFFFFFF * 2 = 0xFFFFFFFE. High 32 bits of signed 64-bit result is 0.
    assert instance.expected_results[10] == 0

    # div
    instance = FuzzingInstance(
        instructions=[Instruction.from_asm("div x10, x11, x12")], initial_regs={11: 10, 12: 3, 10: 0}
    )
    oracle.compute_expected_results(instance)
    assert instance.expected_results[10] == 3

    # divu
    instance = FuzzingInstance(
        instructions=[Instruction.from_asm("divu x10, x11, x12")],
        initial_regs={11: 0xFFFFFFFF, 12: 1, 10: 0},
    )
    oracle.compute_expected_results(instance)
    # 0xFFFFFFFF unsigned is 4294967295, which is -1 in signed 32-bit
    assert instance.expected_results[10] == -1

    # rem
    instance = FuzzingInstance(
        instructions=[Instruction.from_asm("rem x10, x11, x12")], initial_regs={11: 10, 12: 3, 10: 0}
    )
    oracle.compute_expected_results(instance)
    assert instance.expected_results[10] == 1

    # remu
    instance = FuzzingInstance(
        instructions=[Instruction.from_asm("remu x10, x11, x12")],
        initial_regs={11: 11, 12: 3, 10: 0},
    )
    oracle.compute_expected_results(instance)
    assert instance.expected_results[10] == 2

    # mulhsu
    instance = FuzzingInstance(
        instructions=[Instruction.from_asm("mulhsu x10, x11, x12")],
        initial_regs={11: -1, 12: 2, 10: 0},
    )
    oracle.compute_expected_results(instance)
    # -1 * 2 = -2. High 32 bits of signed 64-bit result for -2 is -1.
    assert instance.expected_results[10] == -1

    # mulhu
    instance = FuzzingInstance(
        instructions=[Instruction.from_asm("mulhu x10, x11, x12")],
        initial_regs={11: 0xFFFFFFFF, 12: 0xFFFFFFFF, 10: 0},
    )
    oracle.compute_expected_results(instance)
    # (2^32-1) * (2^32-1) = 2^64 - 2*2^32 + 1. High 32 bits is 2^32 - 2 = 0xFFFFFFFE (-2 signed).
    assert instance.expected_results[10] == -2


def test_oracle_i_type_alu_immediate(oracle):
    # slti
    instance = FuzzingInstance(
        instructions=[Instruction.from_asm("slti x10, x11, 0")], initial_regs={11: -1, 10: 0}
    )
    oracle.compute_expected_results(instance)
    assert instance.expected_results[10] == 1

    # sltiu
    instance = FuzzingInstance(
        instructions=[Instruction.from_asm("sltiu x10, x11, 1")], initial_regs={11: 0, 10: 0}
    )
    oracle.compute_expected_results(instance)
    assert instance.expected_results[10] == 1

    # xori
    instance = FuzzingInstance(
        instructions=[Instruction.from_asm("xori x10, x11, 1")], initial_regs={11: 0, 10: 0}
    )
    oracle.compute_expected_results(instance)
    assert instance.expected_results[10] == 1

    # ori
    instance = FuzzingInstance(
        instructions=[Instruction.from_asm("ori x10, x11, 1")], initial_regs={11: 0, 10: 0}
    )
    oracle.compute_expected_results(instance)
    assert instance.expected_results[10] == 1

    # andi
    instance = FuzzingInstance(
        instructions=[Instruction.from_asm("andi x10, x11, 1")], initial_regs={11: 3, 10: 0}
    )
    oracle.compute_expected_results(instance)
    assert instance.expected_results[10] == 1

    # slli
    instance = FuzzingInstance(
        instructions=[Instruction.from_asm("slli x10, x11, 2")], initial_regs={11: 1, 10: 0}
    )
    oracle.compute_expected_results(instance)
    assert instance.expected_results[10] == 4

    # srli
    instance = FuzzingInstance(
        instructions=[Instruction.from_asm("srli x10, x11, 2")], initial_regs={11: 8, 10: 0}
    )
    oracle.compute_expected_results(instance)
    assert instance.expected_results[10] == 2

    # srai
    instance = FuzzingInstance(
        instructions=[Instruction.from_asm("srai x10, x11, 2")], initial_regs={11: -8, 10: 0}
    )
    oracle.compute_expected_results(instance)
    assert instance.expected_results[10] == -2


def test_oracle_u_type(oracle):
    # lui
    instance = FuzzingInstance(
        instructions=[Instruction.from_asm("lui x10, 0x12345")], initial_regs={10: 0}
    )
    oracle.compute_expected_results(instance)
    assert instance.expected_results[10] == 0x12345000

    # auipc
    instance = FuzzingInstance(
        instructions=[Instruction.from_asm("auipc x10, 0")], initial_regs={10: 0}
    )
    oracle.compute_expected_results(instance)
    # DEFAULT_CODE_BASE = 0x1000
    assert instance.expected_results[10] == 0x1000


def test_oracle_load_store(oracle):
    # sw and lw
    # Use x11 as base address for memory operations. DEFAULT_DATA_BASE = 0x20000
    instance = FuzzingInstance(
        instructions=[
            Instruction.from_asm("sw x12, 0(x11)"),
            Instruction.from_asm("lw x10, 0(x11)"),
        ],
        initial_regs={11: 0x20000, 12: 0xDEADBEEF, 10: 0},
    )
    oracle.compute_expected_results(instance)
    # Unicorn/RISC-V might return signed 32-bit values. 0xDEADBEEF is negative in 32-bit signed.
    assert instance.expected_results[10] == -559038737

    # sb and lb
    instance = FuzzingInstance(
        instructions=[
            Instruction.from_asm("sb x12, 0(x11)"),
            Instruction.from_asm("lb x10, 0(x11)"),
        ],
        initial_regs={11: 0x20004, 12: 0xFF, 10: 0},
    )
    oracle.compute_expected_results(instance)
    assert instance.expected_results[10] == -1

    # sb and lbu
    instance = FuzzingInstance(
        instructions=[
            Instruction.from_asm("sb x12, 0(x11)"),
            Instruction.from_asm("lbu x10, 0(x11)"),
        ],
        initial_regs={11: 0x20008, 12: 0xFF, 10: 0},
    )
    oracle.compute_expected_results(instance)
    assert instance.expected_results[10] == 0xFF

    # sh and lh
    instance = FuzzingInstance(
        instructions=[
            Instruction.from_asm("sh x12, 0(x11)"),
            Instruction.from_asm("lh x10, 0(x11)"),
        ],
        initial_regs={11: 0x2000C, 12: 0xFFFF, 10: 0},
    )
    oracle.compute_expected_results(instance)
    assert instance.expected_results[10] == -1

    # sh and lhu
    instance = FuzzingInstance(
        instructions=[
            Instruction.from_asm("sh x12, 0(x11)"),
            Instruction.from_asm("lhu x10, 0(x11)"),
        ],
        initial_regs={11: 0x20010, 12: 0xFFFF, 10: 0},
    )
    oracle.compute_expected_results(instance)
    assert instance.expected_results[10] == 0xFFFF


def test_oracle_branch_jump(oracle):
    # beq (taken)
    instance = FuzzingInstance(
        instructions=[
            Instruction.from_asm("beq x11, x12, .+8"),
            Instruction.from_asm("addi x10, x10, 1"),
            Instruction.from_asm("addi x10, x10, 2"),
        ],
        initial_regs={10: 0, 11: 1, 12: 1},
    )
    oracle.compute_expected_results(instance)
    assert instance.expected_results[10] == 2

    # bne
    instance = FuzzingInstance(
        instructions=[
            Instruction.from_asm("bne x11, x12, .+8"),
            Instruction.from_asm("addi x10, x10, 1"),
            Instruction.from_asm("addi x10, x10, 2"),
        ],
        initial_regs={10: 0, 11: 1, 12: 2},
    )
    oracle.compute_expected_results(instance)
    assert instance.expected_results[10] == 2

    # blt
    instance = FuzzingInstance(
        instructions=[
            Instruction.from_asm("blt x11, x12, .+8"),
            Instruction.from_asm("addi x10, x10, 1"),
            Instruction.from_asm("addi x10, x10, 2"),
        ],
        initial_regs={10: 0, 11: -1, 12: 1},
    )
    oracle.compute_expected_results(instance)
    assert instance.expected_results[10] == 2

    # bge
    instance = FuzzingInstance(
        instructions=[
            Instruction.from_asm("bge x11, x12, .+8"),
            Instruction.from_asm("addi x10, x10, 1"),
            Instruction.from_asm("addi x10, x10, 2"),
        ],
        initial_regs={10: 0, 11: 1, 12: -1},
    )
    oracle.compute_expected_results(instance)
    assert instance.expected_results[10] == 2

    # bltu
    instance = FuzzingInstance(
        instructions=[
            Instruction.from_asm("bltu x11, x12, .+8"),
            Instruction.from_asm("addi x10, x10, 1"),
            Instruction.from_asm("addi x10, x10, 2"),
        ],
        initial_regs={10: 0, 11: 1, 12: 0xFFFFFFFF},
    )
    oracle.compute_expected_results(instance)
    assert instance.expected_results[10] == 2

    # bgeu
    instance = FuzzingInstance(
        instructions=[
            Instruction.from_asm("bgeu x11, x12, .+8"),
            Instruction.from_asm("addi x10, x10, 1"),
            Instruction.from_asm("addi x10, x10, 2"),
        ],
        initial_regs={10: 0, 11: 0xFFFFFFFF, 12: 1},
    )
    oracle.compute_expected_results(instance)
    assert instance.expected_results[10] == 2

    # jal
    instance = FuzzingInstance(
        instructions=[
            Instruction.from_asm("jal x1, .+8"),
            Instruction.from_asm("addi x10, x10, 1"),
            Instruction.from_asm("addi x10, x10, 2"),
        ],
        initial_regs={10: 0, 1: 0},
    )
    oracle.compute_expected_results(instance)
    assert instance.expected_results[10] == 2
    assert instance.expected_results[1] == 0x1004

    # jalr
    instance = FuzzingInstance(
        instructions=[
            Instruction.from_asm("jalr x1, 4(x11)"),
            Instruction.from_asm("addi x10, x10, 1"),
            Instruction.from_asm("addi x10, x10, 2"),
        ],
        initial_regs={11: 0x1000, 10: 0, 1: 0},
    )
    oracle.compute_expected_results(instance)
    # jumps to 0x1000 + 4 = 0x1004, which is the second instruction
    assert instance.expected_results[10] == 3
    assert instance.expected_results[1] == 0x1004


@pytest.fixture
def generator():
    return RISCVGenerator(seed=42)


def test_oracle_stress_performance_n_calls(oracle, generator, n: int = 10000):
    """
    Stress test: Run 10,000 oracle computations and measure total time.
    This demonstrates the speed of the pure Python MiniAssembler.
    """
    iterations = n
    success_count = 0
    num_insts_per_iter = 10

    print(f"\n[BENCHMARK] Starting {iterations} oracle calls...")

    start_time = time.time()
    for _ in range(iterations):
        # Generate a random instance
        instance = generator.generate_instance(num_insts=num_insts_per_iter)
        # Compute results via fast MiniAssembler + Unicorn
        oracle.compute_expected_results(instance)
        if len(instance.expected_results) == len(instance.initial_regs):
            success_count += 1
    end_time = time.time()

    total_duration = end_time - start_time
    avg_duration_ms = (total_duration / iterations) * 1000

    print(f"[BENCHMARK] Total duration for {iterations} calls: {total_duration:.2f} s")
    print(f"[BENCHMARK] Average duration per call: {avg_duration_ms:.4f} ms")

    # Check one last instance to ensure correctness during stress test
    assert success_count == iterations
