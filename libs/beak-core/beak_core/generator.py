import random
from typing import Tuple
from beak_core.rv32im import (
    AUIPC,
    BRANCH_INSTRUCTIONS,
    DEFAULT_DATA_BASE,
    EBREAK,
    ECALL,
    I_TYPE_INSTRUCTIONS,
    JAL,
    JALR,
    JUMP_INSTRUCTIONS,
    LOAD_INSTRUCTIONS,
    R_TYPE_INSTRUCTIONS,
    SHIFT_INSTRUCTIONS,
    SIGNED_OPERAND_INSTRUCTIONS,
    STORE_INSTRUCTIONS,
    SYSTEM_INSTRUCTIONS,
    U_TYPE_INSTRUCTIONS,
    FuzzingInstance,
    Instruction,
    RV32Type,
)


class RISCVGenerator:
    def __init__(self, seed: int = None):
        self.rng = random.Random(seed)
        # Safe registers for assembly generation
        self.safe_regs = (
            [0, 1, 5, 6, 7] + list(range(10, 18)) + list(range(18, 28)) + list(range(28, 32))
        )

        # Standardized Corner Values
        self.u32_corners = [0, 1, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF, 0x55555555, 0xAAAAAAAA]
        self.i32_corners = [0, 1, -1, -2147483648, 2147483647]
        self.u20_corners = [0, 1, 0x7FFFF, 0x80000, 0xFFFFF]
        self.i12_corners = [-2048, -2047, -1, 0, 1, 2046, 2047]
        self.u5_corners = [0, 1, 15, 16, 30, 31]

    def _weighted_random(self, corners: list, full_range: Tuple[int, int]) -> int:
        # 70% probability to select corner values
        if self.rng.random() < 0.7:
            return self.rng.choice(corners)
        return self.rng.randint(*full_range)

    def _random_u32(self) -> int:
        return self._weighted_random(self.u32_corners, (0, 0xFFFFFFFF))

    def _random_i32(self) -> int:
        return self._weighted_random(self.i32_corners, (-2147483648, 2147483647))

    def _random_u20(self) -> int:
        return self._weighted_random(self.u20_corners, (0, 0xFFFFF))

    def _random_i12(self) -> int:
        return self._weighted_random(self.i12_corners, (-2048, 2047))

    def _random_u5(self) -> int:
        return self._weighted_random(self.u5_corners, (0, 31))

    def generate_instance(self, num_insts: int = 8) -> FuzzingInstance:
        insts = []
        used_regs = set()
        initial_regs = {}

        pattern_func = self.rng.choice(
            [
                self.rule_x0_write_invariant,
                self.rule_sign_extension_trap,
                self.rule_shift_amount_masking,
                self.rule_signed_unsigned_edge,
                self.rule_numeric_corner_stress,
                self.rule_load_store_misalignment,
                self.rule_branch_forward_only,
                self.rule_jump_control_flow,
                self.rule_system_basic_trap,
                self.rule_pure_random,
            ]
        )

        for i in range(num_insts):
            res_inst, regs, vals = pattern_func(i, num_insts)
            if isinstance(res_inst, list):
                insts.extend(res_inst)
            else:
                insts.append(res_inst)
            used_regs.update(regs)
            initial_regs.update(vals)

        for reg in used_regs:
            if reg not in initial_regs:
                initial_regs[reg] = self._random_u32()

        initial_regs[0] = 0
        return FuzzingInstance(instructions=insts, initial_regs=initial_regs)

    # =========================================================================
    # ATOMIC PATTERN RULES
    # =========================================================================

    def rule_jump_control_flow(self, _idx, _total):
        # Controlled skipping test
        op = self.rng.choice(JUMP_INSTRUCTIONS)
        rd = self.rng.choice(self.safe_regs)
        rd1 = self.rng.choice(self.safe_regs)

        if op is JAL:
            offset = self.rng.choice([-16, -12, -8, -4, 4, 8, 12, 16])
            return Instruction(mnemonic=JAL, rd=rd, imm=offset), [rd], {}
        else:
            return (
                [
                    Instruction(mnemonic=AUIPC, rd=rd, imm=self._random_u20()),
                    Instruction(mnemonic=JALR, rd=rd1, rs1=rd, imm=self._random_i12()),
                ],
                [rd, rd1],
                {},
            )

    def rule_system_basic_trap(self, _idx, _total):
        # Trap constraints test: ECALL/EBREAK
        op = self.rng.choice(SYSTEM_INSTRUCTIONS)
        if op is ECALL:
            return Instruction(mnemonic=op), [17], {17: self.rng.randint(0, 100)}
        return Instruction(mnemonic=op), [], {}

    def rule_load_store_misalignment(self, _idx, _total):
        # Misalignment offsets test
        op = self.rng.choice(LOAD_INSTRUCTIONS + STORE_INSTRUCTIONS)
        rd_rs = self.rng.choice(self.safe_regs)
        base_reg = self.rng.choice([r for r in self.safe_regs if r != rd_rs])
        safe_base_addr = DEFAULT_DATA_BASE
        offset = self._random_i12()
        if op.format == RV32Type.I:
            return (
                Instruction(mnemonic=op, rd=rd_rs, rs1=base_reg, imm=offset),
                [rd_rs, base_reg],
                {base_reg: safe_base_addr},
            )
        else:
            return (
                Instruction(mnemonic=op, rs2=rd_rs, rs1=base_reg, imm=offset),
                [rd_rs, base_reg],
                {base_reg: safe_base_addr},
            )

    def rule_branch_forward_only(self, idx, total):
        # Forward branches with corner values
        op = self.rng.choice(BRANCH_INSTRUCTIONS)
        rs1, rs2 = self.rng.choice(self.safe_regs), self.rng.choice(self.safe_regs)
        remaining = (total - idx) * 4
        val1 = self._random_i32()
        val2 = val1 if self.rng.random() < 0.5 else self._random_i32()
        return (
            Instruction(mnemonic=op, rs1=rs1, rs2=rs2, imm=remaining),
            [rs1, rs2],
            {rs1: val1, rs2: val2},
        )

    def rule_x0_write_invariant(self, _idx, _total):
        # Verify x0 remains zero
        op = self.rng.choice(R_TYPE_INSTRUCTIONS + I_TYPE_INSTRUCTIONS + U_TYPE_INSTRUCTIONS)
        rs1, rs2 = self.rng.choice(self.safe_regs), self.rng.choice(self.safe_regs)
        val1, val2 = self._random_u32(), self._random_u32()
        if op.format == RV32Type.U:
            return Instruction(mnemonic=op, rd=0, imm=self._random_u20()), [0], {}
        elif op.format == RV32Type.I:
            return (
                Instruction(mnemonic=op, rd=0, rs1=rs1, imm=self._random_i12()),
                [0, rs1],
                {rs1: val1},
            )
        else:
            return (
                Instruction(mnemonic=op, rd=0, rs1=rs1, rs2=rs2),
                [0, rs1, rs2],
                {rs1: val1, rs2: val2},
            )

    def rule_sign_extension_trap(self, _idx, _total):
        # I-type with 12-bit corner case immediates
        op = self.rng.choice(I_TYPE_INSTRUCTIONS)
        rs1, rd = self.rng.choice(self.safe_regs), self.rng.choice(self.safe_regs)
        val1 = self._random_i32()
        imm = self._random_i12()
        return (
            Instruction(mnemonic=op, rd=rd, rs1=rs1, imm=imm),
            [rd, rs1],
            {rs1: val1},
        )

    def rule_shift_amount_masking(self, _idx, _total):
        # Shift bit masking (low 5 bits)
        op = self.rng.choice(SHIFT_INSTRUCTIONS)
        rd, rs1 = self.rng.choice(self.safe_regs), self.rng.choice(self.safe_regs)
        val1 = self._random_u32()
        if op.format == RV32Type.I:
            return (
                Instruction(mnemonic=op, rd=rd, rs1=rs1, imm=self._random_u5()),
                [rd, rs1],
                {rs1: val1},
            )
        else:
            rs2 = self.rng.choice(self.safe_regs)
            val2 = self._random_u32()
            bad_shamt = self.rng.choice([32, 64, 0xFFFFFFFF])
            return (
                Instruction(mnemonic=op, rd=rd, rs1=rs1, rs2=rs2),
                [rd, rs1, rs2],
                {rs1: val1, rs2: bad_shamt},
            )

    def rule_signed_unsigned_edge(self, _idx, _total):
        # Comparison logic with corners
        op = self.rng.choice(SIGNED_OPERAND_INSTRUCTIONS)
        rd, rs1 = self.rng.choice(self.safe_regs), self.rng.choice(self.safe_regs)
        val1 = self._random_i32()
        if op.format == RV32Type.I:
            imm = self._random_i12()
            return Instruction(mnemonic=op, rd=rd, rs1=rs1, imm=imm), [rd, rs1], {rs1: val1}
        else:
            rs2 = self.rng.choice(self.safe_regs)
            val2 = self._random_i32()
            return (
                Instruction(mnemonic=op, rd=rd, rs1=rs1, rs2=rs2),
                [rd, rs1, rs2],
                {rs1: val1, rs2: val2},
            )

    def rule_numeric_corner_stress(self, _idx, _total):
        # Comprehensive corner stress test
        op = self.rng.choice(R_TYPE_INSTRUCTIONS + I_TYPE_INSTRUCTIONS + U_TYPE_INSTRUCTIONS)
        rd, rs1 = self.rng.choice(self.safe_regs), self.rng.choice(self.safe_regs)
        v1 = self._random_i32()
        if op.format == RV32Type.U:
            return Instruction(mnemonic=op, rd=rd, imm=self._random_u20()), [rd], {}
        elif op.format == RV32Type.I:
            return (
                Instruction(mnemonic=op, rd=rd, rs1=rs1, imm=self._random_i12()),
                [rd, rs1],
                {rs1: v1},
            )
        else:
            rs2 = self.rng.choice(self.safe_regs)
            v2 = self._random_i32()
            return (
                Instruction(mnemonic=op, rd=rd, rs1=rs1, rs2=rs2),
                [rd, rs1, rs2],
                {rs1: v1, rs2: v2},
            )

    def rule_pure_random(self, _idx, _total):
        # Legal but meaningless random instructions
        op = self.rng.choice(
            R_TYPE_INSTRUCTIONS + I_TYPE_INSTRUCTIONS + U_TYPE_INSTRUCTIONS + SHIFT_INSTRUCTIONS
        )
        rd, rs1 = self.rng.choice(self.safe_regs), self.rng.choice(self.safe_regs)
        if op.format == RV32Type.U:
            return Instruction(mnemonic=op, rd=rd, imm=self.rng.randint(0, 0xFFFFF)), [rd], {}
        elif op.format == RV32Type.I:
            imm = self._random_u5() if op in SHIFT_INSTRUCTIONS else self._random_i12()
            return (
                Instruction(mnemonic=op, rd=rd, rs1=rs1, imm=imm),
                [rd, rs1],
                {rs1: self._random_u32()},
            )
        else:
            rs2 = self.rng.choice(self.safe_regs)
            return (
                Instruction(mnemonic=op, rd=rd, rs1=rs1, rs2=rs2),
                [rd, rs1, rs2],
                {rs1: self._random_u32(), rs2: self._random_u32()},
            )
