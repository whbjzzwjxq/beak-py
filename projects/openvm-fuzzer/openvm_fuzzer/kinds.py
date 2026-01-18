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
    LOADW = "loadw"
    LOADBU = "loadbu"
    LOADHU = "loadhu"
    STOREW = "storew"
    STOREH = "storeh"
    STOREB = "storeb"
    LOADB = "loadb"
    LOADH = "loadh"
    BEQ = "beq"
    BNE = "bne"
    BLT = "blt"
    BLTU = "bltu"
    BGE = "bge"
    BGEU = "bgeu"
    JAL = "jal"
    LUI = "lui"
    JALR = "jalr"
    AUIPC = "auipc"
    MUL = "mul"
    MULH = "mulh"
    MULHSU = "mulhsu"
    MULHU = "mulhu"
    DIV = "div"
    DIVU = "divu"
    REM = "rem"
    REMU = "remu"
    HINT_STOREW = "hintstorew"
    HINT_BUFFER = "hintbuffer"
    HintInput = "hintinput"
    PrintStr = "printstr"
    HintRandom = "hintrandom"
    HintLoadByKey = "hintloadbykey"
    PHANTOM = "phantom"
    TERMINATE = "terminate"
    PUBLISH = "publish"
    UNKNOWN = "unknow"

    def is_base_alu(self) -> bool:
        return self in {
            InstrKind.ADD,
            InstrKind.SUB,
            InstrKind.XOR,
            InstrKind.OR,
            InstrKind.AND,
        }

    def is_loadstore(self) -> bool:
        return self in {
            InstrKind.LOADW,
            InstrKind.LOADBU,
            InstrKind.LOADHU,
            InstrKind.STOREW,
            InstrKind.STOREH,
            InstrKind.STOREB,
            # InstrKind.LOADB,  # these are under sign extend
            # InstrKind.LOADH,  # these are under sign extend
        }

    def is_store(self) -> bool:
        return self in {
            InstrKind.STOREW,
            InstrKind.STOREH,
            InstrKind.STOREB,
        }

    def is_load_sign_extend(self) -> bool:
        return self in {
            InstrKind.LOADB,
            InstrKind.LOADH,
        }

    def is_divrem(self) -> bool:
        return self in {
            InstrKind.DIV,
            InstrKind.DIVU,
            InstrKind.REM,
            InstrKind.REMU,
        }


class InjectionKind(StrEnum):
    # Modifies the loaded word from the program memory.
    INSTR_WORD_MOD = "INSTR_WORD_MOD"

    # Generates a random output of the computation
    BASE_ALU_RANDOM_OUTPUT = "BASE_ALU_RANDOM_OUTPUT"

    # Modifies the shift value which determines the position of the load or store
    LOADSTORE_SHIFT_MOD = "LOADSTORE_SHIFT_MOD"

    # Modifies the opcode of the load or store before output is generated
    LOADSTORE_OPCODE_MOD = "LOADSTORE_OPCODE_MOD"

    # Uses the previous or the read data as write data before output is generated
    LOADSTORE_SKIP_WRITE = "LOADSTORE_SKIP_WRITE"

    # Sets the pc in the adapter context output (skips next instruction with pc+8)
    LOADSTORE_PC_MOD = "LOADSTORE_PC_MOD"

    # Modifies the shift value which determines the position of the sign extend load
    LOAD_SIGN_EXTEND_SHIFT_MOD = "LOAD_SIGN_EXTEND_SHIFT_MOD"

    # Modifies flips the most significant bit for the sign extend load check
    LOAD_SIGN_EXTEND_MSB_FLIPPED = "LOAD_SIGN_EXTEND_MSB_FLIPPED"

    # Modifies flips the most significant bit in the most significant limb for the
    # sign extend load check
    LOAD_SIGN_EXTEND_MSL_FLIPPED = "LOAD_SIGN_EXTEND_MSL_FLIPPED"

    # flip the is signed operation flag for the div/rem chip
    DIVREM_FLIP_IS_SIGNED = "DIVREM_FLIP_IS_SIGNED"

    # flip the is div operation flag for the div/rem chip
    DIVREM_FLIP_IS_DIV = "DIVREM_FLIP_IS_DIV"

    # randomly manipulates the pc limbs
    AUIPC_PC_LIMBS_MODIFICATION = "AUIPC_PC_LIMBS_MODIFICATION"

    # randomly manipulates the imm limbs
    AUIPC_IMM_LIMBS_MODIFICATION = "AUIPC_IMM_LIMBS_MODIFICATION"

    @classmethod
    def retrieve_injection_types(
        cls, kind: InstrKind, enabled: list["InjectionKind"]
    ) -> list["InjectionKind"]:
        # following types are always valid
        result = {
            cls.INSTR_WORD_MOD,
        }

        if kind.is_base_alu():
            result.add(cls.BASE_ALU_RANDOM_OUTPUT)

        if kind.is_loadstore():
            result.add(cls.LOADSTORE_SHIFT_MOD)
            result.add(cls.LOADSTORE_OPCODE_MOD)
            result.add(cls.LOADSTORE_PC_MOD)

        if kind.is_store():
            result.add(cls.LOADSTORE_SKIP_WRITE)

        if kind.is_load_sign_extend():
            result.add(cls.LOAD_SIGN_EXTEND_SHIFT_MOD)
            result.add(cls.LOAD_SIGN_EXTEND_MSB_FLIPPED)
            result.add(cls.LOAD_SIGN_EXTEND_MSL_FLIPPED)

        if kind.is_divrem():
            result.add(cls.DIVREM_FLIP_IS_SIGNED)
            result.add(cls.DIVREM_FLIP_IS_DIV)

        if kind == InstrKind.AUIPC:
            result.add(cls.AUIPC_PC_LIMBS_MODIFICATION)
            result.add(cls.AUIPC_IMM_LIMBS_MODIFICATION)

        return sorted(list(result.intersection(enabled)))
