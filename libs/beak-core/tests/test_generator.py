import pytest
import re
from beak_core.generator import RISCVGenerator

@pytest.fixture
def generator():
    return RISCVGenerator(seed=42)

def test_generator_output_structure(generator):
    """Ensure the generator returns a valid container with non-empty instructions."""
    instance = generator.generate_instance(num_insts=8)
    assert len(instance.instructions) == 8
    assert isinstance(instance.initial_regs, dict)
    assert 0 in instance.initial_regs
    assert instance.initial_regs[0] == 0

def test_instruction_legality_and_constraints(generator):
    """
    Stress test 1000 iterations to ensure all generated instructions 
    adhere to RISC-V syntax and bit-width constraints.
    """
    # R-Type: op rd, rs1, rs2
    r_pattern = re.compile(r"^\w+ x(\d+), x(\d+), x(\d+)$")
    # I-Type: op rd, rs1, imm
    i_pattern = re.compile(r"^\w+ x(\d+), x(\d+), (-?\d+)$")
    # U-Type: op rd, imm
    u_pattern = re.compile(r"^\w+ x(\d+), (0x[0-9a-fA-F]+|\d+)$")
    # Load/Store: op rd, offset(rs1)
    ls_pattern = re.compile(r"^\w+ x(\d+), (\d+)\(x(\d+)\)$")
    # Branch: op rs1, rs2, label
    br_pattern = re.compile(r"^\w+ x(\d+), x(\d+), \.\+(\d+)$")
    # JAL: jal rd, label
    jal_pattern = re.compile(r"^jal x(\d+), \.\+(\d+)$")
    # JALR (indented in our generator's multi-line output)
    jalr_inner_pattern = re.compile(r"^\s*jalr x(\d+), (\d+)\(x(\d+)\)$")

    for _ in range(10000):
        instance = generator.generate_instance(num_insts=10)
        for asm_raw in instance.instructions:
            # Handle multi-line instructions (like our jalr rule)
            lines = [line.strip() for line in asm_raw.split('\n') if line.strip()]
            
            for asm in lines:
                mnemonic = asm.split()[0]
                
                if mnemonic in generator.groups["LOAD"] or mnemonic in generator.groups["STORE"]:
                    match = ls_pattern.match(asm)
                    assert match, f"Invalid Load/Store format: {asm}"
                    rd_rs, offset, base = map(int, match.groups())
                    assert 0 <= rd_rs <= 31
                    assert 0 <= base <= 31
                    assert 0 <= offset <= 2047

                elif mnemonic in generator.groups["BRANCH"]:
                    match = br_pattern.match(asm)
                    assert match, f"Invalid Branch format: {asm}"
                    rs1, rs2, offset = map(int, match.groups())
                    assert 0 <= rs1 <= 31
                    assert 0 <= rs2 <= 31
                    assert offset % 4 == 0

                elif mnemonic == "jal":
                    match = jal_pattern.match(asm)
                    assert match, f"Invalid JAL format: {asm}"
                    rd, offset = map(int, match.groups())
                    assert 0 <= rd <= 31
                    assert offset == 8 # Current generator uses fixed +8 for JAL

                elif mnemonic == "jalr":
                    match = jalr_inner_pattern.match(asm)
                    assert match, f"Invalid JALR format: {asm}"
                    rd, offset, base = map(int, match.groups())
                    assert 0 <= rd <= 31
                    assert 0 <= base <= 31

                elif mnemonic in generator.groups["U_TYPE"]:
                    match = u_pattern.match(asm)
                    assert match, f"Invalid U-Type format: {asm}"
                    rd, imm = match.groups()
                    imm_val = int(imm, 16) if "0x" in imm else int(imm)
                    assert 0 <= int(rd) <= 31
                    assert 0 <= imm_val <= 0xFFFFF

                elif mnemonic in generator.groups["I_TYPE"] or mnemonic in generator.groups["SHIFT_I"]:
                    match = i_pattern.match(asm)
                    assert match, f"Invalid I-Type format: {asm}"
                    rd, rs1, imm = map(int, match.groups())
                    assert 0 <= rd <= 31
                    assert 0 <= rs1 <= 31
                    if mnemonic in generator.groups["SHIFT_I"]:
                        assert 0 <= imm <= 31
                    else:
                        assert -2048 <= imm <= 2047

                elif mnemonic in generator.groups["SYSTEM"]:
                    assert mnemonic in ["ecall", "ebreak"], f"Unknown system instruction: {mnemonic}"
                    # ecall and ebreak have no operands in our assembly format

                else: # R-Type (ALU or MUL)
                    match = r_pattern.match(asm)
                    assert match, f"Invalid R-Type format: {asm} (mnemonic: {mnemonic})"
                    rd, rs1, rs2 = map(int, match.groups())
                    assert 0 <= rd <= 31
                    assert 0 <= rs1 <= 31
                    assert 0 <= rs2 <= 31

def test_initial_regs_completeness(generator):
    """Ensure every register mentioned in instructions has an initial value provided."""
    for _ in range(100):
        instance = generator.generate_instance(num_insts=10)
        mentioned_regs = set()
        for asm in instance.instructions:
            # Matches 'x' followed by digits only if it's a word boundary
            matches = re.findall(r"\bx(\d+)\b", asm)
            mentioned_regs.update(map(int, matches))
        
        for reg in mentioned_regs:
            # We skip checking initial value for x0 since it's hardwired to 0
            if reg == 0: continue
            assert reg in instance.initial_regs, f"Register x{reg} used in ASM but missing in initial_regs. ASM: {instance.instructions}"
