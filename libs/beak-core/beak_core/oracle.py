import logging
from unicorn import *
from unicorn.riscv_const import *
from beak_core.rv32im import DEFAULT_CODE_BASE, FuzzingInstance

logger = logging.getLogger(__name__)


class RISCVOracle:
    def compute_expected_results(self, instance: FuzzingInstance):
        base_addr = DEFAULT_CODE_BASE
        mu = Uc(UC_ARCH_RISCV, UC_MODE_RISCV32)
        mu.mem_map(0, 4 * 1024 * 1024)

        # 1. Direct binary encoding (Fast Assemble)
        bin_code = bytearray()
        for inst in instance.instructions:
            bin_code.extend(inst.binary)

        # 2. Write to memory and initialize registers
        mu.mem_write(base_addr, bytes(bin_code))
        for reg_idx, val in instance.initial_regs.items():
            mu.reg_write(UC_RISCV_REG_X0 + reg_idx, val)

        # 3. Execute simulation (limit 1000 instructions to prevent infinite loop)
        try:
            mu.emu_start(base_addr, base_addr + len(bin_code), timeout=10000, count=1000)
        except UcError:
            pass

        # 4. Read back results
        instance.expected_results = {}
        for idx in instance.initial_regs.keys():
            val = mu.reg_read(UC_RISCV_REG_X0 + idx)
            # Convert to signed 32-bit integer for easier assertions
            if val & 0x80000000:
                val -= 0x100000000
            instance.expected_results[idx] = val
