from enum import StrEnum


class HotfixKind(StrEnum):
    ALIGN_PC = "ALIGN_PC"


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

    @classmethod
    def loads(cls) -> list["InstrKind"]:
        return [cls.LB, cls.LH, cls.LW, cls.LBU, cls.LHU]

    @classmethod
    def stores(cls) -> list["InstrKind"]:
        return [cls.SB, cls.SH, cls.SW]

    @classmethod
    def alus(cls) -> list["InstrKind"]:
        return [
            cls.ADD,
            cls.SUB,
            cls.XOR,
            cls.OR,
            cls.AND,
            cls.SLL,
            cls.SRL,
            cls.SRA,
            cls.SLT,
            cls.SLTU,
            cls.MUL,
            cls.MULH,
            cls.MULHU,
            cls.MULHSU,
            cls.DIV,
            cls.DIVU,
            cls.REM,
            cls.REMU,
        ]

    @classmethod
    def branches(cls) -> list["InstrKind"]:
        return [cls.BEQ, cls.BNE, cls.BLT, cls.BGE, cls.BLTU, cls.BGEU]

    def is_load(self) -> bool:
        return self in InstrKind.loads()

    def is_store(self) -> bool:
        return self in InstrKind.stores()

    def is_alu(self) -> bool:
        return self in InstrKind.alus()

    def is_branch(self) -> bool:
        return self in InstrKind.branches()

    def is_ecall(self) -> bool:
        return self == InstrKind.ECALL


class InjectionKind(StrEnum):
    # Modifies the PC at the end of the step function but before the next pc is committed.
    # Results in skipping or going back one or multiple instructions.
    POST_EXEC_PRE_COMMIT_PC_MOD = "POST_EXEC_PRE_COMMIT_PC_MOD"

    # Modifies the PC at the end of the step function but before the next pc is committed.
    # Results in skipping or going back one or multiple instructions.
    POST_EXEC_POST_COMMIT_PC_MOD = "POST_EXEC_POST_COMMIT_PC_MOD"

    # Modifies the loaded word from the program memory.
    INSTR_WORD_MOD = "INSTR_WORD_MOD"

    # Modifies the computed result of an ALU instruction.
    ALU_RESULT_MOD = "ALU_RESULT_MOD"

    # Modifies the operands BEFORE the alu instruction is executed, but after
    # the instruction is read and returns the modified operands.
    ALU_PARSED_OPERAND_MOD = "ALU_PARSED_OPERAND_MOD"

    # Modifies the operand parsing of an alu instruction.
    ALU_LOAD_OPERAND_MOD = "ALU_LOAD_OPERAND_MOD"

    # Modifies the output location / register of an alu instruction.
    ALU_RESULT_LOC_MOD = "ALU_RESULT_LOC_MOD"

    # Executes the same instruction again
    EXECUTE_INSTRUCTION_AGAIN = "EXECUTE_INSTRUCTION_AGAIN"

    # Changes the ecall id of a system call
    SYS_CALL_MOD_ECALL_ID = "SYS_CALL_MOD_ECALL_ID"

    @classmethod
    def retrieve_injection_types(
        cls, kind: InstrKind, enabled_injection_kinds: list["InjectionKind"] | None
    ) -> list["InjectionKind"]:

        # following types are always valid
        result = {
            cls.POST_EXEC_PRE_COMMIT_PC_MOD,
            cls.POST_EXEC_POST_COMMIT_PC_MOD,
            cls.INSTR_WORD_MOD,
            cls.EXECUTE_INSTRUCTION_AGAIN,
        }

        # instruction with a simple output and no side effects
        if kind.is_alu():
            result.add(cls.ALU_RESULT_MOD)
            result.add(cls.ALU_PARSED_OPERAND_MOD)
            result.add(cls.ALU_RESULT_LOC_MOD)
            result.add(cls.ALU_LOAD_OPERAND_MOD)

        # ecall instruction
        if kind.is_ecall():
            result.add(cls.SYS_CALL_MOD_ECALL_ID)

        if enabled_injection_kinds:
            return sorted(list(result.intersection(enabled_injection_kinds)))
        else:
            return sorted(result)
