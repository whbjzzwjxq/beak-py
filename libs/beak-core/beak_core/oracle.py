import os
import subprocess
import tempfile
import shutil
import logging
import struct
from pathlib import Path
from unicorn import *
from unicorn.riscv_const import *
from beak_core.rv32im import FuzzingInstance, Instruction, RV32Type

logger = logging.getLogger("fuzzer")

class RISCVOracle:
    def __init__(self):
        self._objcopy_path = None

    def compute_expected_results(self, instance: FuzzingInstance):
        """Compute ground truth using Unicorn with timeout protection."""
        mu = Uc(UC_ARCH_RISCV, UC_MODE_RISCV32)
        mu.mem_map(0, 4 * 1024 * 1024) 

        try:
            code = self._assemble_fast(instance.instructions)
        except Exception as e:
            logger.debug(f"Fast assembly failed, falling back: {e}")
            code = self._assemble_via_rustc(instance)
        
        # Load code at 0x1000
        mu.mem_write(0x1000, code)
        
        # Ensure we have a trap at the end to stop Unicorn safely if it runs off
        # We can append an ecall or a self-loop that we break manually
        
        for reg_idx, val in instance.initial_regs.items():
            mu.reg_write(UC_RISCV_REG_X0 + reg_idx, val)

        try:
            # Add timeout (timeout parameter is in microseconds)
            # Or add instruction count limit (timeout=0, count=1000)
            # We set a limit of 1000 instructions to prevent infinite loops
            mu.emu_start(0x1000, 0x1000 + len(code), timeout=10000, count=1000)
        except UcError as e:
            # Normal completion often throws an error if it hits the end address
            pass

        expected_results = {}
        for reg_idx in instance.initial_regs.keys():
            expected_results[reg_idx] = mu.reg_read(UC_RISCV_REG_X0 + reg_idx)
        instance.expected_results = expected_results
        
        # Explicit cleanup (though Python GC handles most, this is safer for stress tests)
        del mu

    def _assemble_fast(self, instructions: list[Instruction]) -> bytes:
        bin_code = bytearray()
        for inst in instructions:
            bin_code.extend(self._encode_instruction(inst))
        return bytes(bin_code)

    def _encode_instruction(self, inst: Instruction) -> bytes:
        spec = inst.get_spec()
        if not spec: raise ValueError(f"No spec for {inst.mnemonic}")
        
        fmt, opcode = spec[0], spec[1]
        res = 0
        
        if fmt == RV32Type.SYSTEM:
            res = 0x00000073 if inst.mnemonic == "ecall" else 0x00100073
        elif fmt == RV32Type.R:
            _, op, f3, f7 = spec
            res = (f7 << 25) | (inst.rs2 << 20) | (inst.rs1 << 15) | (f3 << 12) | (inst.rd << 7) | op
        elif fmt == RV32Type.I:
            if len(spec) == 4: # Shift I-type
                _, op, f3, f7 = spec
                res = (f7 << 25) | (inst.imm << 20) | (inst.rs1 << 15) | (f3 << 12) | (inst.rd << 7) | op
            else: # Standard I-type
                _, op, f3 = spec
                res = ((inst.imm & 0xFFF) << 20) | (inst.rs1 << 15) | (f3 << 12) | (inst.rd << 7) | op
        elif fmt == RV32Type.U:
            res = ((inst.imm & 0xFFFFF) << 12) | (inst.rd << 7) | opcode
        elif fmt == RV32Type.S:
            _, op, f3 = spec
            res = (((inst.imm >> 5) & 0x7F) << 25) | (inst.rs2 << 20) | (inst.rs1 << 15) | (f3 << 12) | ((inst.imm & 0x1F) << 7) | op
        elif fmt == RV32Type.B:
            _, op, f3 = spec
            imm = inst.imm
            res = (((imm >> 12) & 0x1) << 31) | (((imm >> 5) & 0x3F) << 25) | (inst.rs2 << 20) | (inst.rs1 << 15) | (f3 << 12) | (((imm >> 1) & 0xF) << 8) | (((imm >> 11) & 0x1) << 7) | op
        elif fmt == RV32Type.J:
            imm = inst.imm
            res = (((imm >> 20) & 0x1) << 31) | (((imm >> 1) & 0x3FF) << 21) | (((imm >> 11) & 0x1) << 20) | (((imm >> 12) & 0xFF) << 12) | (inst.rd << 7) | opcode
        
        return struct.pack("<I", res)

    def _assemble_via_rustc(self, instance: FuzzingInstance) -> bytes:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            rs_file = tmpdir_path / "lib.rs"
            rs_content = f"#![no_std]\n#![no_main]\nuse core::arch::global_asm;\nglobal_asm!(r#\"\n.section .text\n.global _start\n_start:\n{instance.asm_block()}\n\"#);\n#[panic_handler]\nfn panic(_info: &core::panic::PanicInfo) -> ! {{ loop {{}} }}\n"
            rs_file.write_text(rs_content)
            obj_file, bin_file = tmpdir_path / "out.o", tmpdir_path / "out.bin"
            subprocess.run(["rustc", "--target", "riscv32im-unknown-none-elf", "--emit=obj", "-C", "opt-level=3", str(rs_file), "-o", str(obj_file)], check=True, capture_output=True)
            objcopy = self._find_objcopy()
            subprocess.run([objcopy, "-O", "binary", "--only-section=.text", str(obj_file), str(bin_file)], check=True, capture_output=True)
            return bin_file.read_bytes()

    def _find_objcopy(self) -> str:
        if self._objcopy_path: return self._objcopy_path
        for name in ["rust-objcopy", "llvm-objcopy", "objcopy"]:
            path = shutil.which(name)
            if path: self._objcopy_path = path; return path
        try:
            sysroot = subprocess.check_output(["rustc", "--print", "sysroot"]).decode().strip()
            for p in Path(sysroot).rglob("bin/*objcopy*"):
                if os.access(p, os.X_OK) and not p.is_dir(): self._objcopy_path = str(p); return str(p)
        except: pass
        raise RuntimeError("Objcopy not found")
