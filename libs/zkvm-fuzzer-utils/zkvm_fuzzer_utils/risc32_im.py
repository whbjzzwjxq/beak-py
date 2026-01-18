from random import Random

from circil.ir.node import FunctionDefinition, Identifier

# ---------------------------------------------------------------------------- #
#                           Global List Of Extensions                          #
# ---------------------------------------------------------------------------- #


# NOTE:
#   - This is without system assembler calls
#   - stores and loads are always performed together to get a result
#   - immediate values have to be provided as constant macro value so they are removed here
#   - jal (calls) returns a constant and jumps over an instruction
#       - TODO: it would be cool to also test the return address here
#   - TODO: enable jalr
#   - All immediate instructions are generated WITHOUT the constant immediate parameter
#     and argument. They are required to be added and are currently handled in `common.py`
#     by using the `Risc32IMImmediateRepair` class.
#       - TODO: find a better implementation for this as this is pretty hacky

RISCV_I_EXTENSION = [
    FunctionDefinition("add", [Identifier("rs1"), Identifier("rs2")], [Identifier("rd")]),
    FunctionDefinition("addi", [Identifier("rs1")], [Identifier("rd")]),
    FunctionDefinition("sub", [Identifier("rs1"), Identifier("rs2")], [Identifier("rd")]),
    FunctionDefinition("lui", [], [Identifier("rd")]),
    # FunctionDefinition("auipc", [], [Identifier("rd")]),
    FunctionDefinition("xor", [Identifier("rs1"), Identifier("rs2")], [Identifier("rd")]),
    FunctionDefinition("xori", [Identifier("rs1")], [Identifier("rd")]),
    FunctionDefinition("or", [Identifier("rs1"), Identifier("rs2")], [Identifier("rd")]),
    FunctionDefinition("ori", [Identifier("rs1")], [Identifier("rd")]),
    FunctionDefinition("and", [Identifier("rs1"), Identifier("rs2")], [Identifier("rd")]),
    FunctionDefinition("andi", [Identifier("rs1")], [Identifier("rd")]),
    FunctionDefinition("sll", [Identifier("rs1"), Identifier("rs2")], [Identifier("rd")]),
    FunctionDefinition("slli", [Identifier("rs1")], [Identifier("rd")]),
    FunctionDefinition("srl", [Identifier("rs1"), Identifier("rs2")], [Identifier("rd")]),
    FunctionDefinition("srli", [Identifier("rs1")], [Identifier("rd")]),
    FunctionDefinition("sra", [Identifier("rs1"), Identifier("rs2")], [Identifier("rd")]),
    FunctionDefinition("srai", [Identifier("rs1")], [Identifier("rd")]),
    FunctionDefinition("slt", [Identifier("rs1"), Identifier("rs2")], [Identifier("rd")]),
    FunctionDefinition("slti", [Identifier("rs1")], [Identifier("rd")]),
    FunctionDefinition("sltu", [Identifier("rs1"), Identifier("rs2")], [Identifier("rd")]),
    FunctionDefinition("sltiu", [Identifier("rs1")], [Identifier("rd")]),
    FunctionDefinition("beq", [Identifier("rs1"), Identifier("rs2")], [Identifier("rd")]),
    FunctionDefinition("bne", [Identifier("rs1"), Identifier("rs2")], [Identifier("rd")]),
    FunctionDefinition("blt", [Identifier("rs1"), Identifier("rs2")], [Identifier("rd")]),
    FunctionDefinition("bge", [Identifier("rs1"), Identifier("rs2")], [Identifier("rd")]),
    FunctionDefinition("bltu", [Identifier("rs1"), Identifier("rs2")], [Identifier("rd")]),
    FunctionDefinition("bgeu", [Identifier("rs1"), Identifier("rs2")], [Identifier("rd")]),
    FunctionDefinition("jal", [], [Identifier("rd")]),
    # FunctionDefinition("jalr", [Identifier("base")], [Identifier("rd")]),
    FunctionDefinition("sb_lb", [Identifier("rs1")], [Identifier("rd")]),
    FunctionDefinition("sh_lh", [Identifier("rs1")], [Identifier("rd")]),
    FunctionDefinition("sw_lw", [Identifier("rs1")], [Identifier("rd")]),
    FunctionDefinition("sb_lbu", [Identifier("rs1")], [Identifier("rd")]),
    FunctionDefinition("sh_lhu", [Identifier("rs1")], [Identifier("rd")]),
]

# ---------------------------------------------------------------------------- #


RISCV_M_EXTENSION = [
    FunctionDefinition("mul", [Identifier("rs1"), Identifier("rs2")], [Identifier("rd")]),
    FunctionDefinition("mulh", [Identifier("rs1"), Identifier("rs2")], [Identifier("rd")]),
    FunctionDefinition("mulhsu", [Identifier("rs1"), Identifier("rs2")], [Identifier("rd")]),
    FunctionDefinition("mulhu", [Identifier("rs1"), Identifier("rs2")], [Identifier("rd")]),
    FunctionDefinition("div", [Identifier("rs1"), Identifier("rs2")], [Identifier("rd")]),
    FunctionDefinition("divu", [Identifier("rs1"), Identifier("rs2")], [Identifier("rd")]),
    FunctionDefinition("rem", [Identifier("rs1"), Identifier("rs2")], [Identifier("rd")]),
    FunctionDefinition("remu", [Identifier("rs1"), Identifier("rs2")], [Identifier("rd")]),
]


# ---------------------------------------------------------------------------- #

RISCV_IM_EXTENSION = RISCV_I_EXTENSION + RISCV_M_EXTENSION


# ---------------------------------------------------------------------------- #
#                            Risc32 Helper Functions                           #
# ---------------------------------------------------------------------------- #


def risc32_function_definition_random_immediate(builtin: FunctionDefinition, rng: Random) -> int:
    match builtin.name:
        case "addi":
            return rng.randint(-2048, 2047)
        case "lui":
            return rng.randint(0, 1048575)
        case "auipc":
            return rng.randint(0, 1048575)
        case "xori":
            return rng.randint(-2048, 2047)
        case "ori":
            return rng.randint(-2048, 2047)
        case "andi":
            return rng.randint(-2048, 2047)
        case "slli":
            return rng.randint(0, 31)
        case "srli":
            return rng.randint(0, 31)
        case "srai":
            return rng.randint(0, 31)
        case "slti":
            return rng.randint(-2048, 2047)
        case "sltiu":
            return rng.randint(-2048, 2047)
        case _:
            raise ValueError(f"asm function / macro {builtin.name} has no immediate")


# ---------------------------------------------------------------------------- #


def risc32_function_definition_requires_immediate(builtin: FunctionDefinition) -> bool:
    return builtin.name in {
        "addi",
        "lui",
        "auipc",
        "xori",
        "ori",
        "andi",
        "slli",
        "srli",
        "srai",
        "slti",
        "sltiu",
    }


# ---------------------------------------------------------------------------- #


def risc32_function_definition_requires_memory(builtin: FunctionDefinition) -> bool:
    return builtin.name in {
        "sb_lb",
        "sh_lh",
        "sw_lw",
        "sb_lbu",
        "sh_lhu",
    }


# ---------------------------------------------------------------------------- #


def risc32_function_definition_to_rust_macros(builtin: FunctionDefinition) -> str:
    """Returns a string containing a rust function or macro that uses inline assembly to call
    a specific riscv instruction.
    """

    def instr_reg_reg_reg_format(instr: str) -> str:
        return f"""
macro_rules! {instr} {{
    ($a:expr, $b:expr) => {{{{
        let result: u32;
        unsafe {{
            core::arch::asm!(
                "{instr} {{result}}, {{a}}, {{b}}",
                result = out(reg) result,
                a = in(reg) $a,
                b = in(reg) $b,
            );
        }}
        result
    }}}}
}}
"""

    def instr_reg_reg_imm12_format(instr: str) -> str:
        return f"""
macro_rules! {instr} {{
    ($a:expr, $imm:literal) => {{{{
        let result: u32;
        unsafe {{
            core::arch::asm!(
                "{instr} {{result}}, {{a}}, {{imm}}",
                result = out(reg) result,
                a = in(reg) $a,
                imm = const $imm,
            );
        }}
        result
    }}}};
}}
"""  # noqa: E501

    def instr_reg_reg_shamt_format(instr: str) -> str:
        return f"""
macro_rules! {instr} {{
    ($a:expr, $shamt:literal) => {{{{
        let result: u32;
        unsafe {{
            core::arch::asm!(
                "{instr} {{result}}, {{a}}, {{imm}}",
                result = out(reg) result,
                a = in(reg) $a,
                imm = const $shamt,
            );
        }}
        result
    }}}};
}}
"""

    def instr_br_format(instr: str) -> str:
        return f"""
macro_rules! {instr} {{
    ($a:expr, $b:expr) => {{{{
        let result: u32;
        unsafe {{
            core::arch::asm!(
                "{instr} {{a}}, {{b}}, 2f",
                "li {{result}}, 0",
                "j 3f",
                "2: li {{result}}, 1",
                "3:",
                a = in(reg) $a,
                b = in(reg) $b,
                result = out(reg) result,
            );
        }}
        result
    }}}}
}}
"""

    def instr_store_load_format(s_instr: str, l_instr) -> str:
        return f"""
macro_rules! {s_instr}_{l_instr} {{
    ($addr:expr, $val:expr) => {{{{
        let result: u32;
        unsafe {{
            core::arch::asm!(
                "{s_instr} {{val}}, 0({{addr}})",
                "{l_instr} {{result}}, 0({{addr}})",
                val = in(reg) $val,
                addr = in(reg) $addr,
                result = out(reg) result,
            );
        }}
        result
    }}}}
}}
"""

    match builtin.name:
        case "add":
            return instr_reg_reg_reg_format("add")
        case "addi":
            return instr_reg_reg_imm12_format("addi")
        case "sub":
            return instr_reg_reg_reg_format("sub")
        case "lui":
            return """
macro_rules! lui {
    ($imm:literal) => {{
        let result: u32;
        unsafe {
            core::arch::asm!(
                "lui {result}, {imm}",
                result = out(reg) result,
                imm = const $imm,
            );
        }
        result
    }};
}
"""  # noqa: E501
        case "auipc":
            return """
macro_rules! auipc {
    ($imm:literal) => {{
        let result: u32;
        unsafe {
            core::arch::asm!(
                "auipc {result}, {imm}",
                result = out(reg) result,
                imm = const $imm,
            );
        }
        result
    }};
}
"""  # noqa: E501
        case "xor":
            return instr_reg_reg_reg_format("xor")
        case "xori":
            return instr_reg_reg_imm12_format("xori")
        case "or":
            return instr_reg_reg_reg_format("or")
        case "ori":
            return instr_reg_reg_imm12_format("ori")
        case "and":
            return instr_reg_reg_reg_format("and")
        case "andi":
            return instr_reg_reg_imm12_format("andi")
        case "sll":
            return instr_reg_reg_reg_format("sll")
        case "slli":
            return instr_reg_reg_shamt_format("slli")
        case "srl":
            return instr_reg_reg_reg_format("srl")
        case "srli":
            return instr_reg_reg_shamt_format("srli")
        case "sra":
            return instr_reg_reg_reg_format("sra")
        case "srai":
            return instr_reg_reg_shamt_format("srai")
        case "slt":
            return instr_reg_reg_reg_format("slt")
        case "slti":
            return instr_reg_reg_imm12_format("slti")
        case "sltu":
            return instr_reg_reg_reg_format("sltu")
        case "sltiu":
            return instr_reg_reg_imm12_format("sltiu")
        case "beq":
            return instr_br_format("beq")
        case "bne":
            return instr_br_format("bne")
        case "blt":
            return instr_br_format("blt")
        case "bge":
            return instr_br_format("bge")
        case "bltu":
            return instr_br_format("bltu")
        case "bgeu":
            return instr_br_format("bgeu")
        case "jal":
            return """
macro_rules! jal {
    () => {{
        let result: u32;
        unsafe {
            core::arch::asm!(
                "jal x0, 3f",
                "2: addi {result}, x0, 0",
                "3: addi {result}, x0, 1",
                result = out(reg) result,
            );
        }
        result
    }}
}
"""
        case "sb_lbu":
            return instr_store_load_format("sb", "lbu")
        case "sh_lhu":
            return instr_store_load_format("sh", "lhu")
        case "sb_lb":
            return instr_store_load_format("sb", "lb")
        case "sh_lh":
            return instr_store_load_format("sh", "lh")
        case "sw_lw":
            return instr_store_load_format("sw", "lw")
        case "mul":
            return instr_reg_reg_reg_format("mul")
        case "mulh":
            return instr_reg_reg_reg_format("mulh")
        case "mulhsu":
            return instr_reg_reg_reg_format("mulhsu")
        case "mulhu":
            return instr_reg_reg_reg_format("mulhu")
        case "div":
            return instr_reg_reg_reg_format("div")
        case "divu":
            return instr_reg_reg_reg_format("divu")
        case "rem":
            return instr_reg_reg_reg_format("rem")
        case "remu":
            return instr_reg_reg_reg_format("remu")
        case _:
            raise ValueError(f"unable to get rust asm function / macro for {builtin.name}")


# ---------------------------------------------------------------------------- #
