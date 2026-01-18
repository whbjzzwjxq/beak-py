import random
from beak_core.types import FuzzingInstSeqInstance

class RISCVGenerator:
    def __init__(self, seed: int = None):
        self.rng = random.Random(seed)
        
        # RV32I Instructions
        self.alu_ops = ["add", "sub", "xor", "or", "and", "sll", "srl", "sra", "slt", "sltu"]
        self.alu_imm_ops = ["addi", "xori", "ori", "andi", "slti", "sltiu"]
        self.shift_imm_ops = ["slli", "srli", "srai"]
        
        # U-Type Instructions (20-bit immediate)
        self.u_ops = ["lui", "auipc"]
        
        # RV32M Extension Instructions
        self.mul_ops = ["mul", "mulh", "mulhsu", "mulhu", "div", "divu", "rem", "remu"]

        # SAFE REGISTERS
        self.safe_regs = [0, 1, 5, 6, 7] + list(range(10, 18)) + list(range(18, 28)) + list(range(28, 32))

    def generate_instance(self, num_insts: int = 10) -> FuzzingInstSeqInstance:
        insts = []
        used_regs = set()
        
        for _ in range(num_insts):
            op_type = self.rng.choice(["alu", "alu_imm", "shift_imm", "u_type", "mul"])
            
            rd = self.rng.choice(self.safe_regs)
            used_regs.add(rd)
            
            if op_type == "u_type":
                op = self.rng.choice(self.u_ops)
                # 20-bit immediate for U-type: [0, 0xFFFFF]
                # In assembly, usually expressed as a 20-bit hex or decimal
                imm = self.rng.randint(0, 0xFFFFF)
                insts.append(f"{op} x{rd}, {imm}")
                
            elif op_type == "alu_imm":
                rs1 = self.rng.choice(self.safe_regs)
                used_regs.add(rs1)
                op = self.rng.choice(self.alu_imm_ops)
                imm = self.rng.randint(-2048, 2047)
                insts.append(f"{op} x{rd}, x{rs1}, {imm}")
                
            elif op_type == "shift_imm":
                rs1 = self.rng.choice(self.safe_regs)
                used_regs.add(rs1)
                op = self.rng.choice(self.shift_imm_ops)
                shamt = self.rng.randint(0, 31)
                insts.append(f"{op} x{rd}, x{rs1}, {shamt}")
                
            else: # alu or mul
                rs1 = self.rng.choice(self.safe_regs)
                rs2 = self.rng.choice(self.safe_regs)
                used_regs.add(rs1)
                used_regs.add(rs2)
                op = self.rng.choice(self.alu_ops if op_type == "alu" else self.mul_ops)
                insts.append(f"{op} x{rd}, x{rs1}, x{rs2}")

        initial_regs = {reg: self.rng.randint(0, 0xFFFFFFFF) for reg in sorted(list(used_regs)) if reg != 0}
        if 0 in used_regs:
            initial_regs[0] = 0
        
        return FuzzingInstSeqInstance(instructions=insts, initial_regs=initial_regs)
