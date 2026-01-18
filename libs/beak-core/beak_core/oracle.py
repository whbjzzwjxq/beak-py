import os
import subprocess
import tempfile
import shutil
import logging
from pathlib import Path
from unicorn import *
from unicorn.riscv_const import *
from beak_core.types import FuzzingInstSeqInstance

logger = logging.getLogger("fuzzer")

class RISCVOracle:
    def __init__(self):
        self._objcopy_path = None

    def compute_expected_results(self, instance: FuzzingInstSeqInstance):
        """
        Compute ground truth using Unicorn by executing binary compiled via rustc.
        """
        mu = Uc(UC_ARCH_RISCV, UC_MODE_RISCV32)
        mu.mem_map(0, 4 * 1024 * 1024) # 4MB

        code = self._assemble_via_rustc(instance)
        
        mu.mem_write(0x1000, code)

        for reg_idx, val in instance.initial_regs.items():
            mu.reg_write(UC_RISCV_REG_X0 + reg_idx, val)

        try:
            mu.emu_start(0x1000, 0x1000 + len(code))
        except UcError:
            pass

        expected_results = {}
        for reg_idx in instance.initial_regs.keys():
            expected_results[reg_idx] = mu.reg_read(UC_RISCV_REG_X0 + reg_idx)
        
        instance.expected_results = expected_results

    def _find_objcopy(self) -> str:
        """
        Hardcore discovery of llvm-objcopy in the Rust sysroot.
        """
        if self._objcopy_path and os.path.exists(self._objcopy_path):
            return self._objcopy_path

        # 1. Try PATH
        for name in ["rust-objcopy", "llvm-objcopy"]:
            path = shutil.which(name)
            if path:
                self._objcopy_path = path
                return path

        # 2. Search in Rust Sysroot (The most reliable way in Docker)
        try:
            sysroot = subprocess.check_output(["rustc", "--print", "sysroot"]).decode().strip()
            sysroot_path = Path(sysroot)
            
            # Look for any executable containing 'objcopy' in the sysroot
            # Usually in lib/rustlib/<host-triple>/bin/llvm-objcopy
            for p in sysroot_path.rglob("bin/*objcopy*"):
                if os.access(p, os.X_OK) and not p.is_dir():
                    self._objcopy_path = str(p)
                    return self._objcopy_path
        except Exception as e:
            logger.debug(f"Sysroot search failed: {e}")

        raise RuntimeError(
            "Could not find rust-objcopy or llvm-objcopy. "
            "Please ensure 'llvm-tools-preview' is installed via rustup."
        )

    def _assemble_via_rustc(self, instance: FuzzingInstSeqInstance) -> bytes:
        """
        Use rustc with global_asm! to assemble RISC-V instructions robustly.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            rs_file = tmpdir_path / "lib.rs"
            asm_payload = "\n".join([f"    {inst}" for inst in instance.instructions])
            
            rs_content = f"""
#![no_std]
#![no_main]
use core::arch::global_asm;
global_asm!(r#"
.section .text
.global _start
_start:
{asm_payload}
"#);
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {{ loop {{}} }}
"""
            rs_file.write_text(rs_content)

            obj_file = tmpdir_path / "out.o"
            bin_file = tmpdir_path / "out.bin"
            target = "riscv32im-unknown-none-elf"
            
            try:
                # Compile to object
                subprocess.run([
                    "rustc", "--target", target, "--emit=obj", "-C", "opt-level=3",
                    str(rs_file), "-o", str(obj_file)
                ], check=True, capture_output=True)

                # Extract binary using the discovered tool
                objcopy = self._find_objcopy()
                subprocess.run([
                    objcopy, "-O", "binary", "--only-section=.text",
                    str(obj_file), str(bin_file)
                ], check=True, capture_output=True)

                return bin_file.read_bytes()
            
            except subprocess.CalledProcessError as e:
                error_msg = e.stderr.decode()
                raise RuntimeError(f"Assembly/Objcopy failed: {error_msg}")
