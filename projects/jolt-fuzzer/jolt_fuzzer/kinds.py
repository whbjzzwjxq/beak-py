from enum import StrEnum


class InstrKind(StrEnum):
    ADD = "add"
    ADDI = "addi"
    ADDIW = "addiw"
    ADDW = "addw"
    AMOADD_D = "amoaddd"
    AMOADD_W = "amoaddw"
    AMOAND_D = "amoandd"
    AMOAND_W = "amoandw"
    AMOMAX_D = "amomaxd"
    AMOMAXU_D = "amomaxud"
    AMOMAXU_W = "amomaxuw"
    AMOMAX_W = "amomaxw"
    AMOMIN_D = "amomind"
    AMOMIN_UD = "amominud"
    AMOMIN_UW = "amominuw"
    AMOMIN_W = "amominw"
    AMOOR_D = "amoord"
    AMOOR_W = "amoorw"
    AMOSWAP_D = "amoswapd"
    AMOSWAP_W = "amoswapw"
    AMOXOR_D = "amoxord"
    AMOXOR_W = "amoxorw"
    AND = "and"
    ANDI = "andi"
    AUIPC = "auipc"
    BEQ = "beq"
    BGE = "bge"
    BGEU = "bgeu"
    BLT = "blt"
    BLTU = "bltu"
    BNE = "bne"
    CSRRC = "csrrc"
    CSRRCI = "csrrci"
    CSRRS = "csrrs"
    CSRRSI = "csrrsi"
    CSRRW = "csrrw"
    CSRRWI = "csrrwi"
    DIV = "div"
    DIVU = "divu"
    DIVUW = "divuw"
    DIVW = "divw"
    EBREAK = "ebreak"
    ECALL = "ecall"
    FADD_D = "faddd"
    FCVT_D_L = "fcvtdl"
    FCVT_D_S = "fcvtds"
    FCVT_D_W = "fcvtdw"
    FCVT_D_WU = "fcvtdwu"
    FCVT_S_D = "fcvtsd"
    FCVT_W_D = "fcvtwd"
    FDIV_D = "fdivd"
    FENCE = "fence"
    FENCE_I = "fencei"
    FEQ_D = "feqd"
    FLD = "fld"
    FLE_D = "fled"
    FLT_D = "fltd"
    FLW = "flw"
    FMADD_D = "fmaddd"
    FMUL_D = "fmuld"
    FMV_D_X = "fmvdx"
    FMV_X_D = "fmvxd"
    FMV_X_W = "fmvxw"
    FMV_W_X = "fmvwx"
    FNMSUB_D = "fnmsubd"
    FSD = "fsd"
    FSGNJ_D = "fsgnjd"
    FSGNJX_D = "fsgnjxd"
    FSUB_D = "fsubd"
    FSW = "fsw"
    JAL = "jal"
    JALR = "jalr"
    LB = "lb"
    LBU = "lbu"
    LD = "ld"
    LH = "lh"
    LHU = "lhu"
    LR_D = "lrd"
    LR_W = "lrw"
    LUI = "lui"
    LW = "lw"
    LWU = "lwu"
    MUL = "mul"
    MULH = "mulh"
    MULHU = "mulhu"
    MULHSU = "mulhsu"
    MULW = "mulw"
    MRET = "mret"
    OR = "or"
    ORI = "ori"
    REM = "rem"
    REMU = "remu"
    REMUW = "remuw"
    REMW = "remw"
    SB = "sb"
    SC_D = "scd"
    SC_W = "scw"
    SD = "sd"
    SFENCE_VMA = "sfencevma"
    SH = "sh"
    SLL = "sll"
    SLLI = "slli"
    SLLIW = "slliw"
    SLLW = "sllw"
    SLT = "slt"
    SLTI = "slti"
    SLTIU = "sltiu"
    SLTU = "sltu"
    SRA = "sra"
    SRAI = "srai"
    SRAIW = "sraiw"
    SRAW = "sraw"
    SRET = "sret"
    SRL = "srl"
    SRLI = "srli"
    SRLIW = "srliw"
    SRLW = "srlw"
    SUB = "sub"
    SUBW = "subw"
    SW = "sw"
    URET = "uret"
    WFI = "wfi"
    XOR = "xor"
    XORI = "xori"
    SHA256 = "sha256"
    SHA256INIT = "sha256init"
    INLINE = "inline"  # NOTE: unclear what this is and hwo to treat it

    @classmethod
    def computations(cls) -> list["InstrKind"]:
        return [
            cls.ADD,
            cls.ADDI,
            cls.ADDIW,
            cls.ADDW,
            cls.AMOADD_D,
            cls.AMOADD_W,
            cls.AMOAND_D,
            cls.AMOAND_W,
            cls.AMOMAX_D,
            cls.AMOMAXU_D,
            cls.AMOMAXU_W,
            cls.AMOMAX_W,
            cls.AMOMIN_D,
            cls.AMOMIN_UD,
            cls.AMOMIN_UW,
            cls.AMOMIN_W,
            cls.AMOOR_D,
            cls.AMOOR_W,
            cls.AMOSWAP_D,
            cls.AMOSWAP_W,
            cls.AMOXOR_D,
            cls.AMOXOR_W,
            cls.AND,
            cls.ANDI,
            cls.AUIPC,
            cls.BEQ,
            cls.BGE,
            cls.BGEU,
            cls.BLT,
            cls.BLTU,
            cls.BNE,
            cls.CSRRC,
            cls.CSRRCI,
            cls.CSRRS,
            cls.CSRRSI,
            cls.CSRRW,
            cls.CSRRWI,
            cls.DIV,
            cls.DIVU,
            cls.DIVUW,
            cls.DIVW,
            cls.EBREAK,
            cls.ECALL,
            cls.FADD_D,
            cls.FCVT_D_L,
            cls.FCVT_D_S,
            cls.FCVT_D_W,
            cls.FCVT_D_WU,
            cls.FCVT_S_D,
            cls.FCVT_W_D,
            cls.FDIV_D,
            cls.FENCE,
            cls.FENCE_I,
            cls.FEQ_D,
            cls.FLD,
            cls.FLE_D,
            cls.FLT_D,
            cls.FLW,
            cls.FMADD_D,
            cls.FMUL_D,
            cls.FMV_D_X,
            cls.FMV_X_D,
            cls.FMV_X_W,
            cls.FMV_W_X,
            cls.FNMSUB_D,
            cls.FSD,
            cls.FSGNJ_D,
            cls.FSGNJX_D,
            cls.FSUB_D,
            cls.FSW,
            cls.JAL,
            cls.JALR,
            cls.LB,
            cls.LBU,
            cls.LD,
            cls.LH,
            cls.LHU,
            cls.LR_D,
            cls.LR_W,
            cls.LUI,
            cls.LW,
            cls.LWU,
            cls.MUL,
            cls.MULH,
            cls.MULHU,
            cls.MULHSU,
            cls.MULW,
            cls.MRET,
            cls.OR,
            cls.ORI,
            cls.REM,
            cls.REMU,
            cls.REMUW,
            cls.REMW,
            cls.SB,
            cls.SC_D,
            cls.SC_W,
            cls.SD,
            cls.SFENCE_VMA,
            cls.SH,
            cls.SLL,
            cls.SLLI,
            cls.SLLIW,
            cls.SLLW,
            cls.SLT,
            cls.SLTI,
            cls.SLTIU,
            cls.SLTU,
            cls.SRA,
            cls.SRAI,
            cls.SRAIW,
            cls.SRAW,
            cls.SRET,
            cls.SRL,
            cls.SRLI,
            cls.SRLIW,
            cls.SRLW,
            cls.SUB,
            cls.SUBW,
            cls.SW,
            cls.URET,
            cls.WFI,
            cls.XOR,
            cls.XORI,
            cls.SHA256,
            cls.SHA256INIT,
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
    # Modifies the loaded word from the program memory.
    INSTR_WORD_MOD = "INSTR_WORD_MOD"

    @classmethod
    def retrieve_injection_types(
        cls, kind: InstrKind, enabled: list["InjectionKind"]
    ) -> list["InjectionKind"]:
        # following types are always valid
        result = {
            cls.INSTR_WORD_MOD,
        }

        return sorted(list(result.intersection(enabled)))
