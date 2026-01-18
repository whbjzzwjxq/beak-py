from enum import StrEnum


class InstrKind(StrEnum):
    ADD = "add"
    SUB = "sub"
    XOR = "xor"
    OR = "or"
    AND = "and"
    SLL = "sll"
    SRL = "srl"
    SRA = "sra"
    SLT = "slt"
    SLTU = "sltu"
    LB = "lb"
    LH = "lh"
    LW = "lw"
    LBU = "lbu"
    LHU = "lhu"
    SB = "sb"
    SH = "sh"
    SW = "sw"
    BEQ = "beq"
    BNE = "bne"
    BLT = "blt"
    BGE = "bge"
    BLTU = "bltu"
    BGEU = "bgeu"
    JAL = "jal"
    JALR = "jalr"
    AUIPC = "auipc"
    ECALL = "ecall"
    EBREAK = "ebreak"
    MUL = "mul"
    MULH = "mulh"
    MULHU = "mulhu"
    MULHSU = "mulhsu"
    DIV = "div"
    DIVU = "divu"
    REM = "rem"
    REMU = "remu"
    UNIMP = "unimp"

    def has_modifiable_output(self):
        return self in {
            InstrKind.ADD,
            InstrKind.SUB,
            InstrKind.XOR,
            InstrKind.OR,
            InstrKind.AND,
            InstrKind.SLL,
            InstrKind.SRL,
            InstrKind.SRA,
            InstrKind.SLT,
            InstrKind.SLTU,
            InstrKind.LB,
            InstrKind.LH,
            InstrKind.LW,
            InstrKind.LBU,
            InstrKind.LHU,
            InstrKind.SB,
            InstrKind.SH,
            InstrKind.SW,
            InstrKind.MUL,
            InstrKind.MULH,
            InstrKind.MULHU,
            InstrKind.MULHSU,
            InstrKind.DIV,
            InstrKind.DIVU,
            InstrKind.REM,
            InstrKind.REMU,
        }


class InjectionKind(StrEnum):
    # Modifies the loaded word from the program memory.
    INSTR_WORD_MOD = "INSTR_WORD_MOD"

    # Emulates a random instruction on the same pc
    EMULATE_RANDOM_INSTRUCTION = "EMULATE_RANDOM_INSTRUCTION"

    # Modifies the output value for every instruction
    MODIFY_OUTPUT_VALUE = "MODIFY_OUTPUT_VALUE"

    @classmethod
    def retrieve_injection_types(
        cls, kind: InstrKind, enabled: list["InjectionKind"]
    ) -> list["InjectionKind"]:
        # following types are always valid
        result = {
            cls.INSTR_WORD_MOD,
            cls.EMULATE_RANDOM_INSTRUCTION,
        }

        if kind.has_modifiable_output():
            result.add(cls.MODIFY_OUTPUT_VALUE)

        return sorted(list(result.intersection(enabled)))
