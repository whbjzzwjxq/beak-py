import os
import subprocess
import tempfile
import shutil
from pathlib import Path
from unicorn import *
from unicorn.riscv_const import *
from beak_core.types import FuzzingInstSeqInstance

class RISCVOracle:
    def __init__(self):
        pass

    def compute_expected_results(self, instance: FuzzingInstSeqInstance):
        """
        Compute ground truth using Unicorn by executing binary compiled via Cargo/rustc.
        """
        mu = Uc(UC_ARCH_RISCV, UC_MODE_RISCV32)
        mu.mem_map(0, 4 * 1024 * 1024) # 4MB

        code = self._assemble_via_rustc(instance)
        
        # Load code at 0x1000
        mu.mem_write(0x1000, code)

        # Set initial registers
        for reg_idx, val in instance.initial_regs.items():
            mu.reg_write(UC_RISCV_REG_X0 + reg_idx, val)

        # Emulate
        try:
            # Execute the generated code block
            mu.emu_start(0x1000, 0x1000 + len(code))
        except UcError:
            # It's common to hit an error at the exact end of the block, we can ignore it
            pass

        # Collect final results
        expected_results = {}
        for reg_idx in instance.initial_regs.keys():
            expected_results[reg_idx] = mu.reg_read(UC_RISCV_REG_X0 + reg_idx)
        
        instance.expected_results = expected_results

    def _assemble_via_rustc(self, instance: FuzzingInstSeqInstance) -> bytes:
        """
        Use rustc with global_asm! to assemble RISC-V instructions robustly.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            
            # 1. Wrap assembly in a Rust file using global_asm!
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
fn panic(_info: &core::panic::PanicInfo) -> ! {{
    loop {{}}
}}
"""
            rs_file.write_text(rs_content)

            obj_file = tmpdir_path / "out.o"
            bin_file = tmpdir_path / "out.bin"
            target = "riscv32im-unknown-none-elf"
            
            try:
                # 2. Compile to object file
                subprocess.run([
                    "rustc", 
                    "--target", target,
                    "--emit=obj",
                    "-C", "opt-level=3",
                    str(rs_file),
                    "-o", str(obj_file)
                ], check=True, capture_output=True)

                # 3. Extract .text section to raw binary
                # Search for objcopy in rust-binutils first
                objcopy_tool = None
                if shutil.which("rust-objcopy"):
                    objcopy_tool = "rust-objcopy"
                elif shutil.which("objcopy"):
                    objcopy_tool = "objcopy"
                else:
                    # Fallback: check if we can find it in ~/.rustup
                    # This is common on Mac with llvm-tools-preview
                    home = Path.home()
                    rust_objcopy = home / ".rustup" / "toolchains" / "stable-aarch64-apple-darwin" / "lib" / "rustlib" / "aarch64-apple-darwin" / "bin" / "rust-objcopy"
                    if rust_objcopy.exists():
                        objcopy_tool = str(rust_objcopy)

                if not objcopy_tool:
                    raise RuntimeError("Could not find rust-objcopy or objcopy. Please run 'rustup component add llvm-tools-preview'")

                subprocess.run([
                    objcopy_tool,
                    "-O", "binary",
                    "--only-section=.text",
                    str(obj_file),
                    str(bin_file)
                ], check=True, capture_output=True)

                return bin_file.read_bytes()
            
            except subprocess.CalledProcessError as e:
                error_msg = e.stderr.decode()
                raise RuntimeError(f"Rustc/Objcopy assembly failed: {error_msg}")
