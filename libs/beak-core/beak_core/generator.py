import random
from beak_core.types import FuzzingInstSeqInstance

class RISCVGenerator:
    def __init__(self, seed: int = None):
        self.rng = random.Random(seed)
        # Other registers are used and not safe for Rust assembly generation.
        # Thus, we only use the following registers for the generator.
        self.safe_regs = (
            [0, 1, 5, 6, 7] + list(range(10, 18)) + list(range(18, 28)) + list(range(28, 32))
        )

        self.groups = {
            "R_TYPE": ["add", "sub", "xor", "or", "and", "sll", "srl", "sra", "slt", "sltu", "mul", "mulh", "mulhsu", "mulhu", "div", "divu", "rem", "remu"],
            "I_TYPE": ["addi", "xori", "ori", "andi", "slti", "sltiu"],
            "SHIFT_I": ["slli", "srli", "srai"],
            "U_TYPE": ["lui", "auipc"],
            "LOAD": ["lb", "lh", "lw", "lbu", "lhu"],
            "STORE": ["sb", "sh", "sw"],
            "BRANCH": ["beq", "bne", "blt", "bge", "bltu", "bgeu"],
            "JUMP": ["jal", "jalr"],
            "SYSTEM": ["ecall", "ebreak"]
        }
        # Standard 32-bit register value corners
        self.word_corners = [0, 1, -1, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF, 0x55555555, 0xAAAAAAAA]
        # 12-bit signed immediate corners (I-type, S-type, B-type)
        self.imm12_corners = [-2048, -2047, -1, 0, 1, 2046, 2047]
        # Shift amount corners (5-bit for RV32)
        self.shift_corners = [0, 1, 30, 31]
        # 20-bit unsigned immediate corners (U-type, J-type)
        self.imm20_corners = [0, 1, 0x7FFFF, 0x80000, 0xFFFFE, 0xFFFFF]

    def generate_instance(self, num_insts: int = 8) -> FuzzingInstSeqInstance:
        insts = []
        used_regs = set()
        initial_regs = {}

        pattern_func = self.rng.choice([
            self.rule_x0_write_invariant,
            self.rule_sign_extension_trap,
            self.rule_shift_amount_masking,
            self.rule_signed_unsigned_edge,
            self.rule_numeric_corner_stress,
            self.rule_load_store_misalignment,
            self.rule_branch_forward_only,
            self.rule_jump_control_flow,
            self.rule_system_basic_trap,
            self.rule_pure_random
        ])

        for i in range(num_insts):
            asm, regs, vals = pattern_func(i, num_insts)
            insts.append(asm)
            used_regs.update(regs)
            initial_regs.update(vals)

        for reg in used_regs:
            if reg not in initial_regs:
                initial_regs[reg] = self.rng.randint(0, 0xFFFFFFFF)
        
        initial_regs[0] = 0
        return FuzzingInstSeqInstance(instructions=insts, initial_regs=initial_regs)

    # =========================================================================
    # ATOMIC PATTERN RULES
    # =========================================================================

    def rule_jump_control_flow(self, idx, total):
        """Pattern: JAL/JALR controlled skipping."""
        op = self.rng.choice(self.groups["JUMP"])
        rd = self.rng.choice(self.safe_regs)
        
        # We target a 2-instruction skip (8 bytes) to test PC jump logic safely
        if op == "jal":
            return f"jal x{rd}, .+8", [rd], {}
        else: # jalr
            # To make jalr safe, we must use a base register. 
            # We skip 8 bytes from current PC using auipc as a relay.
            # 1. auipc x{rd}, 0 -> puts current PC into rd
            # 2. jalr x0, 8(x{rd}) -> jumps to PC + 8
            # Note: For simplicity, we return a multi-line string for this atomic rule
            return f"auipc x{rd}, 0\n    jalr x0, 8(x{rd})", [rd], {}

    def rule_system_basic_trap(self, _idx, _total):
        """Pattern: Basic ECALL/EBREAK to test trap constraints."""
        op = self.rng.choice(self.groups["SYSTEM"])
        if op == "ecall":
            # Set a7 (x17) to a random value to test syscall ID handling
            return "ecall", [17], {17: self.rng.randint(0, 100)}
        else: # ebreak
            return "ebreak", [], {}

    def rule_load_store_misalignment(self, _idx, _total):
        """Pattern: Load/Store with misalignment offsets."""
        op = self.rng.choice(self.groups["LOAD"] + self.groups["STORE"])
        rd_rs = self.rng.choice(self.safe_regs)
        base_reg = 1
        safe_base_addr = 0x20000 
        offset = self.rng.choice([0, 1, 2, 3, 4, 7])
        return f"{op} x{rd_rs}, {offset}(x{base_reg})", [rd_rs, base_reg], {base_reg: safe_base_addr}

    def rule_branch_forward_only(self, idx, total):
        """Pattern: Forward branches using corner case values."""
        op = self.rng.choice(self.groups["BRANCH"])
        rs1, rs2 = self.rng.choice(self.safe_regs), self.rng.choice(self.safe_regs)
        remaining = (total - idx) * 4
        val1 = self.rng.choice(self.word_corners)
        val2 = val1 if self.rng.random() < 0.5 else self.rng.choice(self.word_corners)
        return f"{op} x{rs1}, x{rs2}, .+{remaining}", [rs1, rs2], {rs1: val1, rs2: val2}

    def rule_x0_write_invariant(self, _idx, _total):
        """Pattern: Writing to x0 to verify it remains zero."""
        op = self.rng.choice(self.groups["R_TYPE"] + self.groups["I_TYPE"] + self.groups["U_TYPE"])
        rs1, rs2 = self.rng.choice(self.safe_regs), self.rng.choice(self.safe_regs)
        if op in self.groups["U_TYPE"]:
            return f"{op} x0, 0x12345", [0], {}
        elif op in self.groups["I_TYPE"]:
            return f"{op} x0, x{rs1}, -1", [0, rs1], {rs1: self.rng.randint(0, 0xFFFFFFFF)}
        else:
            return f"{op} x0, x{rs1}, x{rs2}", [0, rs1, rs2], {rs1: self.rng.randint(0, 0xFFFFFFFF), rs2: self.rng.randint(0, 0xFFFFFFFF)}

    def rule_sign_extension_trap(self, _idx, _total):
        """Pattern: I-type instructions with 12-bit corner case immediates."""
        op = self.rng.choice(self.groups["I_TYPE"])
        rs1, rd = self.rng.choice(self.safe_regs), self.rng.choice(self.safe_regs)
        imm = self.rng.choice(self.imm12_corners)
        return f"{op} x{rd}, x{rs1}, {imm}", [rd, rs1], {rs1: self.rng.randint(0, 0xFFFFFFFF)}

    def rule_shift_amount_masking(self, _idx, _total):
        """Pattern: Shift instructions testing bit masking (low 5 bits)."""
        op = self.rng.choice(self.groups["SHIFT_I"] + ["sll", "srl", "sra"])
        rd, rs1 = self.rng.choice(self.safe_regs), self.rng.choice(self.safe_regs)
        if "i" in op:
            shamt = self.rng.choice(self.shift_corners)
            return f"{op} x{rd}, x{rs1}, {shamt}", [rd, rs1], {rs1: self.rng.randint(0, 0xFFFFFFFF)}
        else:
            rs2 = self.rng.choice(self.safe_regs)
            # Mix standard shift corners with large values to test masking
            shamt_val = self.rng.choice(self.shift_corners + [32, 64, 0xFFFFFFFF, 33])
            return f"{op} x{rd}, x{rs1}, x{rs2}", [rd, rs1, rs2], {rs1: self.rng.randint(0, 0xFFFFFFFF), rs2: shamt_val}

    def rule_signed_unsigned_edge(self, _idx, _total):
        """Pattern: Comparisons using register and immediate corners."""
        op = self.rng.choice(["slt", "sltu", "slti", "sltiu"])
        rd, rs1 = self.rng.choice(self.safe_regs), self.rng.choice(self.safe_regs)
        val1 = self.rng.choice(self.word_corners)
        if "i" in op:
            imm = self.rng.choice(self.imm12_corners)
            return f"{op} x{rd}, x{rs1}, {imm}", [rd, rs1], {rs1: val1}
        else:
            rs2 = self.rng.choice(self.safe_regs)
            val2 = self.rng.choice(self.word_corners)
            return f"{op} x{rd}, x{rs1}, x{rs2}", [rd, rs1, rs2], {rs1: val1, rs2: val2}

    def rule_numeric_corner_stress(self, _idx, _total):
        """Pattern: General stress test using targeted corner cases for each instruction type."""
        op_cat = self.rng.choice(["R_TYPE", "I_TYPE", "U_TYPE"])
        op = self.rng.choice(self.groups[op_cat])
        rd, rs1 = self.rng.choice(self.safe_regs), self.rng.choice(self.safe_regs)
        v1 = self.rng.choice(self.word_corners)
        if op_cat == "U_TYPE":
            imm = self.rng.choice(self.imm20_corners)
            return f"{op} x{rd}, {imm}", [rd], {}
        elif op_cat == "I_TYPE":
            imm = self.rng.choice(self.imm12_corners)
            return f"{op} x{rd}, x{rs1}, {imm}", [rd, rs1], {rs1: v1}
        else:
            rs2 = self.rng.choice(self.safe_regs)
            v2 = self.rng.choice(self.word_corners)
            return f"{op} x{rd}, x{rs1}, x{rs2}", [rd, rs1, rs2], {rs1: v1, rs2: v2}

    def rule_pure_random(self, _idx, _total):
        """Pattern: Purely random operations and values."""
        op_cat = self.rng.choice(["R_TYPE", "I_TYPE", "U_TYPE", "SHIFT_I"])
        op = self.rng.choice(self.groups[op_cat])
        rd, rs1 = self.rng.choice(self.safe_regs), self.rng.choice(self.safe_regs)
        if op_cat == "U_TYPE":
            return f"{op} x{rd}, {self.rng.randint(0, 0xFFFFF)}", [rd], {}
        elif op_cat == "I_TYPE":
            return f"{op} x{rd}, x{rs1}, {self.rng.randint(-2048, 2047)}", [rd, rs1], {rs1: self.rng.randint(0, 0xFFFFFFFF)}
        elif op_cat == "SHIFT_I":
            return f"{op} x{rd}, x{rs1}, {self.rng.randint(0, 31)}", [rd, rs1], {rs1: self.rng.randint(0, 0xFFFFFFFF)}
        else:
            rs2 = self.rng.choice(self.safe_regs)
            return f"{op} x{rd}, x{rs1}, x{rs2}", [rd, rs1, rs2], {rs1: self.rng.randint(0, 0xFFFFFFFF), rs2: self.rng.randint(0, 0xFFFFFFFF)}
