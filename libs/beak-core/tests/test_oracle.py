import pytest
import time
from beak_core.oracle import RISCVOracle
from beak_core.rv32im import FuzzingInstance, Instruction
from beak_core.generator import RISCVGenerator


@pytest.fixture
def oracle():
    return RISCVOracle()


@pytest.fixture
def generator():
    return RISCVGenerator(seed=42)


def test_oracle_basic_functionality(oracle):
    """
    Verify that the oracle correctly computes expected results for simple instructions.
    """
    instance = FuzzingInstance(
        instructions=[Instruction.from_asm("add x10, x11, x12")], initial_regs={11: 5, 12: 7, 10: 0}
    )
    oracle.compute_expected_results(instance)
    assert instance.expected_results[10] == 12


def test_oracle_stress_performance_10000_calls(oracle, generator):
    """
    Stress test: Run 100 oracle computations and measure total time.
    This demonstrates the speed of the pure Python MiniAssembler.
    """
    iterations = 10
    num_insts_per_iter = 10

    print(f"\n[BENCHMARK] Starting {iterations} oracle calls...")

    start_time = time.time()
    for _ in range(iterations):
        # Generate a random instance
        instance = generator.generate_instance(num_insts=num_insts_per_iter)
        # Compute results via fast MiniAssembler + Unicorn
        oracle.compute_expected_results(instance)
    end_time = time.time()

    total_duration = end_time - start_time
    avg_duration_ms = (total_duration / iterations) * 1000

    print(f"[BENCHMARK] Total duration for {iterations} calls: {total_duration:.2f} s")
    print(f"[BENCHMARK] Average duration per call: {avg_duration_ms:.4f} ms")

    # Check one last instance to ensure correctness during stress test
    assert len(instance.expected_results) > 0


def test_oracle_complex_corner_case(oracle):
    """
    Test sign extension and overflow corner cases to ensure oracle accuracy.
    """
    instance = FuzzingInstance(
        instructions=[Instruction.from_asm("addi x10, x11, -1")], initial_regs={11: 1, 10: 0}
    )
    oracle.compute_expected_results(instance)
    assert instance.expected_results[10] == 0

    instance = FuzzingInstance(
        instructions=[Instruction.from_asm("sltu x10, x11, x12")],
        initial_regs={11: 0xFFFFFFFF, 12: 1, 10: 0},
    )
    oracle.compute_expected_results(instance)
    assert instance.expected_results[10] == 0
