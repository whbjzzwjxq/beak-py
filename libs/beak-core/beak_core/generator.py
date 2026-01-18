import random
from beak_core.types import FuzzingInstSeqInstance

class RISCVGenerator:
    def __init__(self, seed: int = None):
        self.rng = random.Random(seed)
        
        # RV32I ALU Operations (Register-Register)
        self.alu_ops = [
            "add", "sub", "xor", "or", "and", "sll", "srl", "sra",
            "slt", "sltu"
        ]
        
        # RV32I ALU Operations (Register-Immediate)
        self.alu_imm_ops = [
            "addi", "xori", "ori", "andi", "slti", "sltiu"
        ]
        
        # RV32I Shift Operations (Register-Immediate)
        self.shift_imm_ops = [
            "slli", "srli", "srai"
        ]
        
        # RV32M Extension Instructions
        self.mul_ops = [
            "mul", "mulh", "mulhsu", "mulhu", "div", "divu", "rem", "remu"
        ]

        # SAFE REGISTERS: Avoid sp(x2), gp(x3), tp(x4), fp(x8), s1(x9)
        # Use: t0-t2 (x5-x7), a0-a7 (x10-x17), t3-t6 (x28-x31)
        self.safe_regs = [5, 6, 7, 10, 11, 12, 13, 14, 15, 16, 17, 28, 29, 30, 31]

    def generate_instance(self, num_insts: int = 10) -> FuzzingInstSeqInstance:
        insts = []
        used_regs = set()
        
        for _ in range(num_insts):
            op_type = self.rng.choice(["alu", "alu_imm", "shift_imm", "mul"])
            
            # Select from safe register list
            rd = self.rng.choice(self.safe_regs)
            rs1 = self.rng.choice(self.safe_regs)
            used_regs.add(rs1)
            used_regs.add(rd)
            
            if op_type == "alu_imm":
                op = self.rng.choice(self.alu_imm_ops)
                imm = self.rng.randint(-2048, 2047)
                insts.append(f"{op} x{rd}, x{rs1}, {imm}")
                
            elif op_type == "shift_imm":
                op = self.rng.choice(self.shift_imm_ops)
                shamt = self.rng.randint(0, 31)
                insts.append(f"{op} x{rd}, x{rs1}, {shamt}")
                
            else: # alu or mul
                rs2 = self.rng.choice(self.safe_regs)
                used_regs.add(rs2)
                op = self.rng.choice(self.alu_ops if op_type == "alu" else self.mul_ops)
                insts.append(f"{op} x{rd}, x{rs1}, x{rs2}")

        initial_regs = {reg: self.rng.randint(0, 0xFFFFFFFF) for reg in sorted(list(used_regs))}
        
        return FuzzingInstSeqInstance(
            instructions=insts,
            initial_regs=initial_regs
        )
