from pathlib import Path

from beak_core.fuzzing_seeds import parse_riscv_tests


def test_parse_riscv_tests_extracts_test_blocks_only():
    # In this repo, the objdump artifacts live under `riscv-tests-artifacts/`.
    dump = Path("riscv-tests-artifacts/rv32ui-p-add.dump")
    seeds = parse_riscv_tests(dump)

    assert len(seeds) > 0
    assert all(s.metadata.get("label", "").startswith("test") for s in seeds)
    assert all(len(s.instructions) > 0 for s in seeds)


def test_parse_riscv_tests_folds_initial_regs_and_strips_fail_harness():
    dump = Path("riscv-tests-artifacts/rv32ui-p-sll.dump")
    seeds = parse_riscv_tests(dump)
    s = next(x for x in seeds if x.metadata.get("label") == "test_5")

    # `li gp,5; li a1,1; li a2,14` should be folded into initial_regs.
    assert s.initial_regs.get(3) == 5
    assert s.initial_regs.get(11) == 1
    assert s.initial_regs.get(12) == 14

    # Tail `lui expected; bne ..., <fail>` harness is stripped, leaving just the core instruction.
    assert [i.mnemonic.literal for i in s.instructions] == ["sll"]
