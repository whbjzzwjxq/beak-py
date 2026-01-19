import pytest
import time
from beak_core.oracle import RISCVOracle
from beak_core.types import FuzzingInstSeqInstance

@pytest.fixture
def oracle():
    return RISCVOracle()

def test_oracle_basic_functionality(oracle):
    """
    Verify that the oracle correctly computes expected results for simple instructions.
    """
    # Simple addition: x10 = x11 + x12 (5 + 7 = 12)
    instance = FuzzingInstSeqInstance(
        instructions=["add x10, x11, x12"],
        initial_regs={11: 5, 12: 7, 10: 0}
    )
    
    oracle.compute_expected_results(instance)
    
    assert instance.expected_results[10] == 12
    assert instance.expected_results[11] == 5
    assert instance.expected_results[12] == 7

def test_oracle_performance_single_call(oracle):
    """
    Benchmark a single call to compute_expected_results.
    This includes assembly (rustc), loading, and emulation (Unicorn).
    """
    # A slightly more complex sequence to represent a typical fuzzing instance
    instance = FuzzingInstSeqInstance(
        instructions=[
            "addi x10, x0, 100",
            "addi x11, x0, 200",
            "add x12, x10, x11",
            "sub x13, x12, x10",
            "mul x14, x10, x11",
        ],
        initial_regs={10: 0, 11: 0, 12: 0, 13: 0, 14: 0}
    )

    start_time = time.time()
    oracle.compute_expected_results(instance)
    end_time = time.time()
    
    duration_ms = (end_time - start_time) * 1000
    
    # Check results first to ensure the timing is for a successful run
    assert instance.expected_results[12] == 300
    assert instance.expected_results[13] == 200
    assert instance.expected_results[14] == 20000
    
    print(f"\n[BENCHMARK] Oracle single call duration: {duration_ms:.2f} ms")
    
    # Typical expected performance with rustc-based assembly is >100ms
    # We don't assert a hard limit here yet, but just print it for review.

def test_oracle_complex_corner_case(oracle):
    """
    Test sign extension and overflow corner cases to ensure oracle accuracy.
    """
    # testing addi with negative immediate (-1)
    instance = FuzzingInstSeqInstance(
        instructions=["addi x10, x11, -1"],
        initial_regs={11: 1, 10: 0}
    )
    oracle.compute_expected_results(instance)
    assert instance.expected_results[10] == 0
    
    # testing unsigned comparison with large numbers
    instance = FuzzingInstSeqInstance(
        instructions=["sltu x10, x11, x12"],
        initial_regs={11: 0xFFFFFFFF, 12: 1, 10: 0}
    )
    oracle.compute_expected_results(instance)
    assert instance.expected_results[10] == 0 # 0xFFFFFFFF is NOT less than 1 (unsigned)

