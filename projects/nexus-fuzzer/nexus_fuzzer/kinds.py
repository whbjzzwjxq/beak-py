from enum import StrEnum


class EmulatorKind(StrEnum):
    HARVARD_EMULATOR = "HarvardEmulator"
    LINEAR_EMULATOR = "LinearEmulator"


class HotfixKind(StrEnum):
    ALIGN_PC = "ALIGN_PC"


class InstrKind(StrEnum):
    ADD = "add"
    SUB = "sub"
    SLL = "sll"
    SLT = "slt"
    SLTU = "sltu"
    XOR = "xor"
    SRL = "srl"
    SRA = "sra"
    OR = "or"
    AND = "and"
    MUL = "mul"
    MULH = "mulh"
    MULHSU = "mulhsu"
    MULHU = "mulhu"
    DIV = "div"
    DIVU = "divu"
    REM = "rem"
    REMU = "remu"
    ADDI = "addi"
    SLLI = "slli"
    SLTI = "slti"
    SLTIU = "sltiu"
    XORI = "xori"
    SRLI = "srli"
    SRAI = "srai"
    ORI = "ori"
    ANDI = "andi"
    LB = "lb"
    LH = "lh"
    LW = "lw"
    LBU = "lbu"
    LHU = "lhu"
    JALR = "jalr"
    ECALL = "ecall"
    EBREAK = "ebreak"
    FENCE = "fence"
    SB = "sb"
    SH = "sh"
    SW = "sw"
    BEQ = "beq"
    BNE = "bne"
    BLT = "blt"
    BGE = "bge"
    BLTU = "bltu"
    BGEU = "bgeu"
    LUI = "lui"
    AUIPC = "auipc"
    JAL = "jal"
    DYNAMIC = "dynamic"
    UNIMPL = "unimpl"

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
    def is_load(cls, kind: "InstrKind") -> bool:
        return kind in cls.loads()

    @classmethod
    def stores(cls) -> list["InstrKind"]:
        return [cls.SB, cls.SH, cls.SW]

    @classmethod
    def is_store(cls, kind: "InstrKind") -> bool:
        return kind in cls.stores()

    @classmethod
    def is_computation(cls, kind: "InstrKind") -> bool:
        return kind in cls.computations()

    @classmethod
    def branches(cls) -> list["InstrKind"]:
        return [cls.BEQ, cls.BNE, cls.BLT, cls.BGE, cls.BLTU, cls.BGEU]

    @classmethod
    def is_branch(cls, kind: "InstrKind") -> bool:
        return kind in cls.branches()


class InjectionKind(StrEnum):
    # Modifies the PC at the end of the step function. Results in skipping
    # or going back one or multiple instructions.
    POST_EXEC_PC_MOD = "POST_EXEC_PC_MOD"

    # Modifies the loaded word from the program memory.
    INSTR_WORD_MOD = "INSTR_WORD_MOD"

    @classmethod
    def retrieve_injection_types(
        cls, kind: InstrKind, enabled: list["InjectionKind"]
    ) -> list["InjectionKind"]:
        # following types are always valid
        result = {
            cls.POST_EXEC_PC_MOD,
            cls.INSTR_WORD_MOD,
        }

        return sorted(list(result.intersection(enabled)))
