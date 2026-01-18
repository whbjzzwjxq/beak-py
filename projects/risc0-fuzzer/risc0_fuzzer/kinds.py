from enum import StrEnum


class InstrKind(StrEnum):
    ADD = "add"
    SUB = "sub"
    XOR = "xor"
    OR = "or"
    AND = "and"
    SLT = "slt"
    SLTU = "sltu"
    ADDI = "addi"
    XORI = "xori"
    ORI = "ori"
    ANDI = "andi"
    SLTI = "slti"
    SLTIU = "sltiu"
    BEQ = "beq"
    BNE = "bne"
    BLT = "blt"
    BGE = "bge"
    BLTU = "bltu"
    BGEU = "bgeu"
    JAL = "jal"
    JALR = "jalr"
    LUI = "lui"
    AUIPC = "auipc"
    SLL = "sll"
    SLLI = "slli"
    MUL = "mul"
    MULH = "mulh"
    MULHSU = "mulhsu"
    MULHU = "mulhu"
    SRL = "srl"
    SRA = "sra"
    SRLI = "srli"
    SRAI = "srai"
    DIV = "div"
    DIVU = "divu"
    REM = "rem"
    REMU = "remu"
    LB = "lb"
    LH = "lh"
    LW = "lw"
    LBU = "lbu"
    LHU = "lhu"
    SB = "sb"
    SH = "sh"
    SW = "sw"
    EANY = "eany"
    MRET = "mret"
    INVALID = "invalid"

    def is_branch(self) -> bool:
        return self in InstrKind.branches()

    def is_load(self) -> bool:
        return self in InstrKind.loads()

    def is_store(self) -> bool:
        return self in InstrKind.stores()

    def is_computation(self) -> bool:
        return self in InstrKind.computations()

    @classmethod
    def computations(cls) -> list["InstrKind"]:
        return [
            cls.ADD,
            cls.SUB,
            cls.XOR,
            cls.OR,
            cls.AND,
            cls.SLT,
            cls.SLTU,
            cls.ADDI,
            cls.XORI,
            cls.ORI,
            cls.ANDI,
            cls.SLTI,
            cls.SLTIU,
            cls.LUI,
            cls.AUIPC,
            cls.SLL,
            cls.SLLI,
            cls.MUL,
            cls.MULH,
            cls.MULHSU,
            cls.MULHU,
            cls.SRL,
            cls.SRA,
            cls.SRLI,
            cls.SRAI,
            cls.DIV,
            cls.DIVU,
            cls.REM,
            cls.REMU,
        ]

    @classmethod
    def loads(cls) -> list["InstrKind"]:
        return [cls.LB, cls.LH, cls.LW, cls.LBU, cls.LHU]

    @classmethod
    def stores(cls) -> list["InstrKind"]:
        return [cls.SB, cls.SH, cls.SW]

    @classmethod
    def branches(cls) -> list["InstrKind"]:
        return [cls.BEQ, cls.BNE, cls.BLT, cls.BGE, cls.BLTU, cls.BGEU]


class InjectionKind(StrEnum):
    # Modifies the PC at the beginning of the step function. Results in skipping
    # or going back one or multiple instructions.
    PRE_EXEC_PC_MOD = "PRE_EXEC_PC_MOD"

    # Modifies the PC at the end of the step function. Results in skipping
    # or going back one or multiple instructions.
    POST_EXEC_PC_MOD = "POST_EXEC_PC_MOD"

    # Modifies the loaded word from the program memory.
    INSTR_WORD_MOD = "INSTR_WORD_MOD"

    # Branch specific injection that negates the condition of a branch instruction.
    BR_NEG_COND = "BR_NEG_COND"

    # Modifies the computed output of a side effect free instruction.
    COMP_OUT_MOD = "COMP_OUT_MOD"

    # Modifies the value of a load instruction.
    LOAD_VAL_MOD = "LOAD_VAL_MOD"

    # Modifies the value of a store instruction.
    STORE_OUT_MOD = "STORE_OUT_MOD"

    # Modifies the value of a random memory address before the execution
    PRE_EXEC_MEM_MOD = "PRE_EXEC_MEM_MOD"

    # Modifies the value of a random memory address after the execution
    POST_EXEC_MEM_MOD = "POST_EXEC_MEM_MOD"

    # Modifies the value of a random register address before the execution
    PRE_EXEC_REG_MOD = "PRE_EXEC_REG_MOD"

    # Modifies the value of a random register address after the execution
    POST_EXEC_REG_MOD = "POST_EXEC_REG_MOD"

    @classmethod
    def retrieve_injection_types(
        cls, kind: InstrKind, enabled: list["InjectionKind"]
    ) -> list["InjectionKind"]:
        # following types are always valid
        result = {
            cls.PRE_EXEC_PC_MOD,
            cls.POST_EXEC_PC_MOD,
            cls.INSTR_WORD_MOD,
            cls.PRE_EXEC_MEM_MOD,
            cls.POST_EXEC_MEM_MOD,
            cls.PRE_EXEC_REG_MOD,
            cls.POST_EXEC_REG_MOD,
        }

        # branch specific types
        if kind.is_branch():
            result.add(cls.BR_NEG_COND)

        # instruction with a simple output and no side effects
        if kind.is_computation():
            result.add(cls.COMP_OUT_MOD)

        # memory load instructions
        if kind.is_load():
            result.add(cls.LOAD_VAL_MOD)

        # memory store instructions
        if kind.is_store():
            result.add(cls.STORE_OUT_MOD)

        return sorted(list(result.intersection(enabled)))
