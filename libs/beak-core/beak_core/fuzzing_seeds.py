from dataclasses import dataclass, field
from pathlib import Path
import re
import struct
from typing import List
from beak_core.rv32im import Instruction


@dataclass
class FuzzingSeed:
    instructions: list[Instruction]
    initial_regs: dict[int, int] = field(default_factory=dict)
    metadata: dict = field(default_factory=dict)

    def to_dict(self):
        return {
            "instructions": [
                f"0x{struct.unpack('<I', inst.binary)[0]:08x}" for inst in self.instructions
            ],
            "initial_regs": {str(k): v for k, v in self.initial_regs.items()},
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data):
        return cls(
            instructions=[
                Instruction.from_binary(int(inst_hex, 16).to_bytes(4, "little"))
                for inst_hex in data["instructions"]
            ],
            initial_regs={int(k): v for k, v in data.get("initial_regs", {}).items()},
            metadata=data.get("metadata", {}),
        )


def parse_riscv_tests(
    dump_file: Path,
    *,
    verbose: bool = False,
    infer_initial_regs: bool = True,
    drop_initializer_insts: bool = True,
    strip_expected_branch_to_fail: bool = True,
) -> List[FuzzingSeed]:
    """
    Parse a standard `riscv64-unknown-elf-objdump -d` style `.dump` file and
    extract ONLY the instruction streams inside labels that start with `test`
    (e.g. `test_2`, `test_3`, ...). Returns one FuzzingSeed per test block.
    """

    text = dump_file.read_text(encoding="utf-8", errors="replace").splitlines()

    # Example label line:
    #   8000018c <test_2>:
    label_re = re.compile(r"^\s*([0-9a-fA-F]+)\s+<([^>]+)>:\s*$")

    # Example instruction line:
    #   80000198:    00c58733           add a4,a1,a2
    inst_re = re.compile(r"^\s*[0-9a-fA-F]+:\s*([0-9a-fA-F]{8})\b")

    seeds: list[FuzzingSeed] = []

    current_label: str | None = None
    current_label_addr: int | None = None
    current_insts: list[Instruction] = []

    def _to_i32(x: int) -> int:
        x &= 0xFFFFFFFF
        if x & 0x80000000:
            x -= 0x100000000
        return x

    def _infer_initial_regs(insts: list[Instruction]) -> tuple[dict[int, int], list[Instruction]]:
        """
        Infer initial register values from a simple prologue at the start of a test block.

        Supported patterns (at the beginning of the block):
        - addi rd, x0, imm           (i.e., objdump might show this as `li rd, imm`)
        - lui rd, imm20              (upper 20 bits)
        - lui rd, imm20; addi rd, rd, imm12  (common `li rd, imm32` expansion)
        """
        regs: dict[int, int] = {}
        i = 0
        while i < len(insts):
            inst = insts[i]
            lit = inst.mnemonic.literal

            # addi rd, x0, imm  => rd = imm
            if lit == "addi" and inst.rd is not None and inst.rs1 == 0 and inst.imm is not None:
                regs[inst.rd] = _to_i32(inst.imm)
                i += 1
                continue

            # lui rd, imm20  => rd = imm20 << 12
            if lit == "lui" and inst.rd is not None and inst.imm is not None:
                val = (inst.imm & 0xFFFFF) << 12
                consumed = 1
                # Optional fold: lui rd, imm20; addi rd, rd, imm12
                if i + 1 < len(insts):
                    nxt = insts[i + 1]
                    if (
                        nxt.mnemonic.literal == "addi"
                        and nxt.rd == inst.rd
                        and nxt.rs1 == inst.rd
                        and nxt.imm is not None
                    ):
                        val = (val + nxt.imm) & 0xFFFFFFFF
                        consumed = 2
                regs[inst.rd] = _to_i32(val)
                i += consumed
                continue

            break

        if drop_initializer_insts and regs:
            return regs, insts[i:]
        return regs, insts

    def _strip_expected_branch_to_fail(insts: list[Instruction]) -> list[Instruction]:
        """
        Heuristically strip the common riscv-tests harness tail:
          <expected-construction>; <conditional-branch to fail>

        We only strip if:
        - the last instruction is a branch (B-type), AND
        - immediately before it we see a constant initializer that writes to one of the branch operands.

        This avoids removing loop branches or control-flow-only tests.
        """
        if len(insts) < 2:
            return insts

        br = insts[-1]
        from beak_core.rv32im import RV32Type  # local import to avoid cycles in type-checkers

        if br.mnemonic.format != RV32Type.B:
            return insts

        prev = insts[-2]

        def writes_reg(i: Instruction) -> int | None:
            lit = i.mnemonic.literal
            if lit in ("addi", "lui"):
                return i.rd
            return None

        def is_const_init(i: Instruction) -> bool:
            lit = i.mnemonic.literal
            if lit == "addi" and i.rd is not None and i.rs1 == 0 and i.imm is not None:
                return True
            if lit == "lui" and i.rd is not None and i.imm is not None:
                return True
            return False

        dst = writes_reg(prev)
        if dst is None or not is_const_init(prev):
            return insts

        # Branch operands are rs1/rs2; if the previous instruction sets one of them, assume harness.
        if dst not in (br.rs1, br.rs2):
            return insts

        # Strip branch and the immediate constant initializer (and optionally a preceding lui for lui+addi).
        stripped = insts[:-2]
        # Handle lui+addi right before branch: [..., lui rd, imm20, addi rd, rd, imm12, bne ...]
        if (
            len(insts) >= 3
            and prev.mnemonic.literal == "addi"
            and prev.rd is not None
            and prev.rs1 == prev.rd
            and insts[-3].mnemonic.literal == "lui"
            and insts[-3].rd == prev.rd
        ):
            stripped = insts[:-3]

        return stripped

    def flush():
        nonlocal current_label, current_label_addr, current_insts
        if current_label is not None and current_label.startswith("test") and current_insts:
            inferred_regs: dict[int, int] = {}
            insts = current_insts
            if infer_initial_regs:
                inferred_regs, insts = _infer_initial_regs(insts)
            if strip_expected_branch_to_fail:
                insts = _strip_expected_branch_to_fail(insts)

            seed = FuzzingSeed(
                instructions=insts,
                initial_regs=inferred_regs,
                metadata={
                    "source": str(dump_file),
                    "label": current_label,
                    "label_addr": current_label_addr,
                },
            )
            if verbose:
                inst_asms = [i.asm for i in seed.instructions[:8]]
                preview = " | ".join(inst_asms)
                if len(seed.instructions) > 8:
                    preview += " | ..."
                print(
                    f"[parse_riscv_tests] matched {seed.metadata['label']} "
                    f"@0x{seed.metadata['label_addr']:x}: {len(seed.instructions)} insts "
                    f"(init_regs={len(seed.initial_regs)}) "
                    f"[{preview}]"
                )
            seeds.append(seed)
        current_label = None
        current_label_addr = None
        current_insts = []

    for line in text:
        m_label = label_re.match(line)
        if m_label:
            # New label begins; close previous block.
            flush()
            current_label_addr = int(m_label.group(1), 16)
            current_label = m_label.group(2)
            continue

        if current_label is None or not current_label.startswith("test"):
            continue

        m_inst = inst_re.match(line)
        if not m_inst:
            continue

        word_hex = m_inst.group(1)
        word = int(word_hex, 16)
        inst = Instruction.from_binary(word.to_bytes(4, "little"))
        current_insts.append(inst)

    flush()
    if verbose:
        print(f"[parse_riscv_tests] {dump_file}: total matched seeds = {len(seeds)}\n")
    return seeds
