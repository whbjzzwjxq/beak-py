from __future__ import annotations

from typing import List, Optional

from beak_core.micro_ops import (
    MemoryRead,
    MemorySize,
    MemorySpace,
    MemoryWrite,
    Step,
    Subdomain,
    ZKVMMeta,
    ZKVMTrace,
)
from beak_core.rv32im import DEFAULT_CODE_BASE, FuzzingInstance, Instruction

# Convert RV32IM execution into a ZKVMTrace (micro-op stream).
#
# The current "generic" path is Unicorn-based: execute the RV32 code and hook
# instruction + memory events to emit Step/MemoryRead/MemoryWrite uops.
#
# This is intended as a backend-agnostic bridge for bucket feature extraction and
# repair mapping demos. It deliberately does not attempt to model backend-specific
# interaction/permutation/logup traces here.


class RV32ToMicroOpsConverter:
    """Convert a RV32IM program execution into a ZKVMTrace (micro-op sequence).

    The intended "generic" path is Unicorn-based: it records instruction PCs and
    memory reads/writes during execution, and emits Step + Memory{Read,Write} uops.

    This does *not* depend on a specific backend (Pico/SP1/...), and it does not
    require decoding every instruction opcode yet.
    """

    def __init__(
        self,
        *,
        code_base: int = DEFAULT_CODE_BASE,
        mem_map_size: int = 4 * 1024 * 1024,
        max_instructions: int = 1000,
        timeout_us: int = 10_000,
    ):
        self.code_base = code_base
        self.mem_map_size = mem_map_size
        self.max_instructions = max_instructions
        self.timeout_us = timeout_us

    def from_instance(self, instance: FuzzingInstance) -> ZKVMTrace:
        # Import lazily so beak-core can still be imported in environments without unicorn.
        from unicorn import Uc  # type: ignore
        from unicorn import UC_ARCH_RISCV, UC_HOOK_CODE, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE  # type: ignore
        from unicorn import UC_MODE_RISCV32  # type: ignore
        from unicorn.riscv_const import UC_RISCV_REG_X0  # type: ignore

        mu = Uc(UC_ARCH_RISCV, UC_MODE_RISCV32)
        mu.mem_map(0, self.mem_map_size)

        # Write program bytes.
        bin_code = bytearray()
        for inst in instance.instructions:
            bin_code.extend(inst.binary)
        mu.mem_write(self.code_base, bytes(bin_code))

        # Initialize registers.
        for reg_idx, val in instance.initial_regs.items():
            mu.reg_write(UC_RISCV_REG_X0 + reg_idx, val)

        uops: List[object] = []
        step_idx = -1
        uop_idx_in_step = 0

        def _pc_to_instruction(pc: int) -> Optional[Instruction]:
            # Best-effort mapping for straight-line programs.
            if pc < self.code_base:
                return None
            off = pc - self.code_base
            if off % 4 != 0:
                return None
            idx = off // 4
            if 0 <= idx < len(instance.instructions):
                return instance.instructions[idx]
            return None

        def _on_code(_uc, address, size, _user_data):
            nonlocal step_idx, uop_idx_in_step
            step_idx += 1
            uop_idx_in_step = 0

            inst = _pc_to_instruction(int(address))
            mnemonic = inst.mnemonic if inst is not None else instance.instructions[0].mnemonic
            next_pc = int(address) + int(size)
            uops.append(
                Step(
                    step_idx=step_idx,
                    uop_idx=uop_idx_in_step,
                    opcode=mnemonic,
                    pc=int(address),
                    next_pc=next_pc,
                    instruction=inst,
                    meta=ZKVMMeta(is_real=1, is_valid=1, subdomain=Subdomain.CPU),
                )
            )
            uop_idx_in_step += 1

        def _on_mem(_uc, _access, address, size, value, _user_data):
            nonlocal uop_idx_in_step
            if step_idx < 0:
                # Should not happen for normal execution (mem ops happen within an instruction),
                # but keep the converter robust.
                return

            addr = int(address) & 0xFFFFFFFF
            sz = int(size)
            # Map to our coarse MemorySize. Unicorn reports the access width in bytes.
            msize = MemorySize.WORD if sz == 4 else MemorySize.BYTE if sz == 1 else MemorySize.HALF_WORD
            val = int(value) & 0xFFFFFFFF

            # Unicorn uses the same callback signature for read/write hooks but they are installed separately.
            # We record uops in the order Unicorn reports them.
            if _user_data == "read":
                uops.append(
                    MemoryRead(
                        step_idx=step_idx,
                        uop_idx=uop_idx_in_step,
                        space=MemorySpace.RAM,
                        addr=addr,
                        size=msize,
                        value=val,
                        meta=ZKVMMeta(is_real=1, is_valid=1, subdomain=Subdomain.MEMORY),
                    )
                )
            else:
                uops.append(
                    MemoryWrite(
                        step_idx=step_idx,
                        uop_idx=uop_idx_in_step,
                        space=MemorySpace.RAM,
                        addr=addr,
                        size=msize,
                        value=val,
                        meta=ZKVMMeta(is_real=1, is_valid=1, subdomain=Subdomain.MEMORY),
                    )
                )
            uop_idx_in_step += 1

        # Hooks.
        mu.hook_add(UC_HOOK_CODE, _on_code)
        mu.hook_add(UC_HOOK_MEM_READ, _on_mem, user_data="read")
        mu.hook_add(UC_HOOK_MEM_WRITE, _on_mem, user_data="write")

        # Execute.
        try:
            mu.emu_start(
                self.code_base,
                self.code_base + len(bin_code),
                timeout=self.timeout_us,
                count=self.max_instructions,
            )
        except Exception:
            # For our current use cases (straight-line snippets), it's fine if Unicorn stops early.
            pass

        # ZKVMTrace expects Step indices to be continuous; code hook provides that.
        return ZKVMTrace(uops)  # type: ignore[arg-type]


def micro_ops_from_unicorn_execution(instance: FuzzingInstance) -> ZKVMTrace:
    """Convenience wrapper used by demos/tests.

    This relies on dynamic execution tracing (Unicorn hooks) rather than any
    instruction-specific modeling in beak-core.
    """

    return RV32ToMicroOpsConverter().from_instance(instance)
