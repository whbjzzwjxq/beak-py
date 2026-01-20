import pytest
from beak_core.generator import RISCVGenerator
from beak_core.rv32im import RV32Type

@pytest.fixture
def generator():
    return RISCVGenerator(seed=42)

def test_generator_output_structure(generator):
    """Ensure the generator returns a valid container with Instruction objects."""
    instance = generator.generate_instance(num_insts=8)
    assert len(instance.instructions) == 8
    for inst in instance.instructions:
        assert hasattr(inst, 'mnemonic')
        assert hasattr(inst, 'format')
    assert isinstance(instance.initial_regs, dict)
    assert 0 in instance.initial_regs
    assert instance.initial_regs[0] == 0

def test_instruction_legality_and_constraints(generator):
    """
    Stress test 10000 iterations to ensure all generated Instruction objects
    adhere to RISC-V architectural constraints.
    """
    for _ in range(10000):
        instance = generator.generate_instance(num_insts=10)
        for inst in instance.instructions:
            # 1. Register Index Integrity
            for reg in [inst.rd, inst.rs1, inst.rs2]:
                if reg is not None:
                    assert 0 <= reg <= 31

            # 2. Immediate Range Validation by Format
            fmt = inst.format
            if fmt == RV32Type.I:
                if inst.mnemonic in ["slli", "srli", "srai"]:
                    assert 0 <= inst.imm <= 31, f"Shift amount out of range: {inst}"
                else:
                    assert -2048 <= inst.imm <= 2047, f"I-type immediate overflow: {inst}"
            
            elif fmt == RV32Type.S:
                assert -2048 <= inst.imm <= 2047, f"S-type immediate overflow: {inst}"
            
            elif fmt == RV32Type.B:
                assert inst.imm % 2 == 0, f"Branch target not aligned: {inst}"
            
            elif fmt == RV32Type.U:
                assert 0 <= inst.imm <= 0xFFFFF, f"U-type immediate overflow: {inst}"
            
            elif fmt == RV32Type.J:
                assert inst.imm % 2 == 0, f"Jump target not aligned: {inst}"

def test_initial_regs_completeness(generator):
    """Ensure every register used in the objects has an initial value in the container."""
    for _ in range(100):
        instance = generator.generate_instance(num_insts=10)
        used_regs = set()
        for inst in instance.instructions:
            if inst.rd is not None: used_regs.add(inst.rd)
            if inst.rs1 is not None: used_regs.add(inst.rs1)
            if inst.rs2 is not None: used_regs.add(inst.rs2)
        
        for reg in used_regs:
            if reg == 0: continue
            assert reg in instance.initial_regs, f"Register x{reg} used but missing in initial_regs"
