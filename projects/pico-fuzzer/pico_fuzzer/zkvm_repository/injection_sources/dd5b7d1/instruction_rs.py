def instruction_rs() -> str:
    return """use super::{align, EmulationError, RiscvEmulator};
use crate::{
    chips::chips::riscv_memory::event::MemoryAccessPosition,
    compiler::riscv::{instruction::Instruction, opcode::Opcode, register::Register},
    emulator::riscv::syscalls::{syscall_context::SyscallContext, SyscallCode},
};
use tracing::debug;

// <----------------------- START OF FAULT INJECTION ----------------------->

use fuzzer_utils;

pub fn modify_output_helper(a: u32) -> u32 {
    if fuzzer_utils::is_injection_at_step("MODIFY_OUTPUT_VALUE") {
        let new_a = fuzzer_utils::random_mod_of_u32(a);
        fuzzer_utils::print_injection_info(
            "MODIFY_OUTPUT_VALUE",
            &format!("{:?} => {:?}", a, new_a),
        );
        new_a
    } else {
        a
    }
}

pub fn random_opcode(old_opcode: Opcode) -> Opcode {
    fuzzer_utils::random_from_choices(
        vec![
            Opcode::ADD,
            Opcode::SUB,
            Opcode::XOR,
            Opcode::OR,
            Opcode::AND,
            Opcode::SLL,
            Opcode::SRL,
            Opcode::SRA,
            Opcode::SLT,
            Opcode::SLTU,
            Opcode::LB,
            Opcode::LH,
            Opcode::LW,
            Opcode::LBU,
            Opcode::LHU,
            Opcode::SB,
            Opcode::SH,
            Opcode::SW,
            Opcode::BEQ,
            Opcode::BNE,
            Opcode::BLT,
            Opcode::BGE,
            Opcode::BLTU,
            Opcode::BGEU,
            Opcode::JAL,
            Opcode::JALR,
            Opcode::AUIPC,
            Opcode::ECALL,
            Opcode::EBREAK,
            Opcode::MUL,
            Opcode::MULH,
            Opcode::MULHU,
            Opcode::MULHSU,
            Opcode::DIV,
            Opcode::DIVU,
            Opcode::REM,
            Opcode::REMU,
        ].into_iter().filter(|&x| x != old_opcode).collect()
    )
}

pub fn random_register(old_value: u32) -> u32 {
    fuzzer_utils::random_from_choices(
        (0..=31).filter(|&x| x != old_value).collect()
    )
}

pub fn random_mutate_instruction(old_instruction: &Instruction) -> Instruction {
    let mut selected = fuzzer_utils::random_multiple_from_choices(
        vec![0, 1, 2, 3]
    );
    selected.sort();

    let mut new_instruction = old_instruction.clone();

    for i in selected {
        match i {
            0 => {
                new_instruction.opcode = random_opcode(new_instruction.opcode);
            },
            1 => {
                new_instruction.op_a = random_register(new_instruction.op_a);
            }
            2 => {
                if fuzzer_utils::random_bool() {
                    new_instruction.imm_b = false;
                    new_instruction.op_b = random_register(new_instruction.op_b);
                } else {
                    new_instruction.imm_b = true;
                    new_instruction.op_b = fuzzer_utils::random_mod_of_u32(
                        new_instruction.op_b
                    );
                }
            }
            3 => {
                if fuzzer_utils::random_bool() && !new_instruction.imm_b {
                    new_instruction.imm_c = false;
                    new_instruction.op_c = random_register(new_instruction.op_c);
                } else {
                    new_instruction.imm_c = true;
                    new_instruction.op_c = fuzzer_utils::random_mod_of_u32(
                        new_instruction.op_c
                    );
                }
            }
            _ => unreachable!(),
        }
    }
    new_instruction
}

// <------------------------ END OF FAULT INJECTION ------------------------>

impl RiscvEmulator {
    /// Emulate the given instruction over the current state.
    #[allow(clippy::too_many_lines)]
    pub(crate) fn emulate_instruction(
        &mut self,
        instruction: &Instruction,
    ) -> Result<(), EmulationError> {
        let mut exit_code = 0u32;
        let mut clk = self.state.clk;
        let mut next_pc = self.state.pc.wrapping_add(4);

        let rd: Register;
        let (a, b, c): (u32, u32, u32);
        let (addr, memory_read_value): (u32, u32);
        let mut memory_store_value: Option<u32> = None;

        self.mode.init_memory_access(&mut self.memory_accesses);

        // <----------------------- START OF FAULT INJECTION ----------------------->

        let mut instruction = instruction;
        let _old_instruction = instruction.clone();
        let new_instruction;

        // update global state
        let instruction_debug = format!("{:?}", instruction.opcode);
        let assembly_debug = format!("{:?}", instruction);
        fuzzer_utils::update_hints(self.state.pc, &instruction_debug, &assembly_debug);

        if fuzzer_utils::is_injection_at_step("INSTR_WORD_MOD") {
            new_instruction = random_mutate_instruction(instruction);
            fuzzer_utils::print_injection_info(
                "INSTR_WORD_MOD",
                &format!("{:?} => {:?}", instruction, new_instruction),
            );
            instruction = &new_instruction;

            fuzzer_utils::update_hints(
                self.state.pc,
                &format!("{:?}", instruction.opcode),
                &format!("{:?}", instruction)
            );
        }

        // <------------------------ END OF FAULT INJECTION ------------------------>

        match instruction.opcode {
            // Arithmetic instructions.
            Opcode::ADD => {
                (rd, b, c) = self.alu_rr(instruction);
                a = b.wrapping_add(c);

                // <----------------------- START OF FAULT INJECTION ----------------------->
                let a = modify_output_helper(a);
                // <------------------------ END OF FAULT INJECTION ------------------------>

                self.alu_rw(rd, a);
                self.mode.emit_alu(
                    self.state.clk,
                    a,
                    b,
                    c,
                    instruction.opcode,
                    &mut self.record.add_events,
                );
            }
            Opcode::SUB => {
                (rd, b, c) = self.alu_rr(instruction);
                a = b.wrapping_sub(c);

                // <----------------------- START OF FAULT INJECTION ----------------------->
                let a = modify_output_helper(a);
                // <------------------------ END OF FAULT INJECTION ------------------------>

                self.alu_rw(rd, a);
                self.mode.emit_alu(
                    self.state.clk,
                    a,
                    b,
                    c,
                    instruction.opcode,
                    &mut self.record.sub_events,
                );
            }
            Opcode::XOR => {
                (rd, b, c) = self.alu_rr(instruction);
                a = b ^ c;

                // <----------------------- START OF FAULT INJECTION ----------------------->
                let a = modify_output_helper(a);
                // <------------------------ END OF FAULT INJECTION ------------------------>

                self.alu_rw(rd, a);
                self.mode.emit_alu(
                    self.state.clk,
                    a,
                    b,
                    c,
                    instruction.opcode,
                    &mut self.record.bitwise_events,
                );
            }
            Opcode::OR => {
                (rd, b, c) = self.alu_rr(instruction);
                a = b | c;

                // <----------------------- START OF FAULT INJECTION ----------------------->
                let a = modify_output_helper(a);
                // <------------------------ END OF FAULT INJECTION ------------------------>

                self.alu_rw(rd, a);
                self.mode.emit_alu(
                    self.state.clk,
                    a,
                    b,
                    c,
                    instruction.opcode,
                    &mut self.record.bitwise_events,
                );
            }
            Opcode::AND => {
                (rd, b, c) = self.alu_rr(instruction);
                a = b & c;

                // <----------------------- START OF FAULT INJECTION ----------------------->
                let a = modify_output_helper(a);
                // <------------------------ END OF FAULT INJECTION ------------------------>

                self.alu_rw(rd, a);
                self.mode.emit_alu(
                    self.state.clk,
                    a,
                    b,
                    c,
                    instruction.opcode,
                    &mut self.record.bitwise_events,
                );
            }
            Opcode::SLL => {
                (rd, b, c) = self.alu_rr(instruction);
                a = b.wrapping_shl(c);

                // <----------------------- START OF FAULT INJECTION ----------------------->
                let a = modify_output_helper(a);
                // <------------------------ END OF FAULT INJECTION ------------------------>

                self.alu_rw(rd, a);
                self.mode.emit_alu(
                    self.state.clk,
                    a,
                    b,
                    c,
                    instruction.opcode,
                    &mut self.record.shift_left_events,
                );
            }
            Opcode::SRL => {
                (rd, b, c) = self.alu_rr(instruction);
                a = b.wrapping_shr(c);

                // <----------------------- START OF FAULT INJECTION ----------------------->
                let a = modify_output_helper(a);
                // <------------------------ END OF FAULT INJECTION ------------------------>

                self.alu_rw(rd, a);
                self.mode.emit_alu(
                    self.state.clk,
                    a,
                    b,
                    c,
                    instruction.opcode,
                    &mut self.record.shift_right_events,
                );
            }
            Opcode::SRA => {
                (rd, b, c) = self.alu_rr(instruction);
                a = (b as i32).wrapping_shr(c) as u32;

                // <----------------------- START OF FAULT INJECTION ----------------------->
                let a = modify_output_helper(a);
                // <------------------------ END OF FAULT INJECTION ------------------------>

                self.alu_rw(rd, a);
                self.mode.emit_alu(
                    self.state.clk,
                    a,
                    b,
                    c,
                    instruction.opcode,
                    &mut self.record.shift_right_events,
                );
            }
            Opcode::SLT => {
                (rd, b, c) = self.alu_rr(instruction);
                a = if (b as i32) < (c as i32) { 1 } else { 0 };

                // <----------------------- START OF FAULT INJECTION ----------------------->
                let a = modify_output_helper(a);
                // <------------------------ END OF FAULT INJECTION ------------------------>

                self.alu_rw(rd, a);
                self.mode.emit_alu(
                    self.state.clk,
                    a,
                    b,
                    c,
                    instruction.opcode,
                    &mut self.record.lt_events,
                );
            }
            Opcode::SLTU => {
                (rd, b, c) = self.alu_rr(instruction);
                a = if b < c { 1 } else { 0 };

                // <----------------------- START OF FAULT INJECTION ----------------------->
                let a = modify_output_helper(a);
                // <------------------------ END OF FAULT INJECTION ------------------------>

                self.alu_rw(rd, a);
                self.mode.emit_alu(
                    self.state.clk,
                    a,
                    b,
                    c,
                    instruction.opcode,
                    &mut self.record.lt_events,
                );
            }

            // Load instructions.
            Opcode::LB => {
                (rd, b, c, addr, memory_read_value) = self.load_rr(instruction);
                let value = (memory_read_value).to_le_bytes()[(addr % 4) as usize];
                a = ((value as i8) as i32) as u32;

                // <----------------------- START OF FAULT INJECTION ----------------------->
                let a = modify_output_helper(a);
                // <------------------------ END OF FAULT INJECTION ------------------------>

                memory_store_value = Some(memory_read_value);
                self.rw(rd, a);
            }
            Opcode::LH => {
                (rd, b, c, addr, memory_read_value) = self.load_rr(instruction);
                if !fuzzer_utils::is_injection() && addr % 2 != 0 {
                    return Err(EmulationError::InvalidMemoryAccess(Opcode::LH, addr));
                }
                let value = match (addr >> 1) % 2 {
                    0 => memory_read_value & 0x0000_FFFF,
                    1 => (memory_read_value & 0xFFFF_0000) >> 16,
                    _ => unreachable!(),
                };
                a = ((value as i16) as i32) as u32;

                // <----------------------- START OF FAULT INJECTION ----------------------->
                let a = modify_output_helper(a);
                // <------------------------ END OF FAULT INJECTION ------------------------>

                memory_store_value = Some(memory_read_value);
                self.rw(rd, a);
            }
            Opcode::LW => {
                (rd, b, c, addr, memory_read_value) = self.load_rr(instruction);
                if !fuzzer_utils::is_injection() && addr % 4 != 0 {
                    return Err(EmulationError::InvalidMemoryAccess(Opcode::LW, addr));
                }
                a = memory_read_value;

                // <----------------------- START OF FAULT INJECTION ----------------------->
                let a = modify_output_helper(a);
                // <------------------------ END OF FAULT INJECTION ------------------------>

                memory_store_value = Some(memory_read_value);
                self.rw(rd, a);
            }
            Opcode::LBU => {
                (rd, b, c, addr, memory_read_value) = self.load_rr(instruction);
                let value = (memory_read_value).to_le_bytes()[(addr % 4) as usize];
                a = value as u32;

                // <----------------------- START OF FAULT INJECTION ----------------------->
                let a = modify_output_helper(a);
                // <------------------------ END OF FAULT INJECTION ------------------------>

                memory_store_value = Some(memory_read_value);
                self.rw(rd, a);
            }
            Opcode::LHU => {
                (rd, b, c, addr, memory_read_value) = self.load_rr(instruction);
                if !fuzzer_utils::is_injection() && addr % 2 != 0 {
                    return Err(EmulationError::InvalidMemoryAccess(Opcode::LHU, addr));
                }
                let value = match (addr >> 1) % 2 {
                    0 => memory_read_value & 0x0000_FFFF,
                    1 => (memory_read_value & 0xFFFF_0000) >> 16,
                    _ => unreachable!(),
                };
                a = (value as u16) as u32;

                // <----------------------- START OF FAULT INJECTION ----------------------->
                let a = modify_output_helper(a);
                // <------------------------ END OF FAULT INJECTION ------------------------>

                memory_store_value = Some(memory_read_value);
                self.rw(rd, a);
            }

            // Store instructions.
            Opcode::SB => {
                (a, b, c, addr, memory_read_value) = self.store_rr(instruction);
                let value = match addr % 4 {
                    0 => (a & 0x0000_00FF) + (memory_read_value & 0xFFFF_FF00),
                    1 => ((a & 0x0000_00FF) << 8) + (memory_read_value & 0xFFFF_00FF),
                    2 => ((a & 0x0000_00FF) << 16) + (memory_read_value & 0xFF00_FFFF),
                    3 => ((a & 0x0000_00FF) << 24) + (memory_read_value & 0x00FF_FFFF),
                    _ => unreachable!(),
                };

                // <----------------------- START OF FAULT INJECTION ----------------------->
                let value = modify_output_helper(value);
                // <------------------------ END OF FAULT INJECTION ------------------------>

                memory_store_value = Some(value);
                self.mw_cpu(align(addr), value, MemoryAccessPosition::Memory);
            }
            Opcode::SH => {
                (a, b, c, addr, memory_read_value) = self.store_rr(instruction);
                if !fuzzer_utils::is_injection() && addr % 2 != 0 {
                    return Err(EmulationError::InvalidMemoryAccess(Opcode::SH, addr));
                }
                let value = match (addr >> 1) % 2 {
                    0 => (a & 0x0000_FFFF) + (memory_read_value & 0xFFFF_0000),
                    1 => ((a & 0x0000_FFFF) << 16) + (memory_read_value & 0x0000_FFFF),
                    _ => unreachable!(),
                };

                // <----------------------- START OF FAULT INJECTION ----------------------->
                let value = modify_output_helper(value);
                // <------------------------ END OF FAULT INJECTION ------------------------>

                memory_store_value = Some(value);
                self.mw_cpu(align(addr), value, MemoryAccessPosition::Memory);
            }
            Opcode::SW => {
                (a, b, c, addr, _) = self.store_rr(instruction);
                if !fuzzer_utils::is_injection() && addr % 4 != 0 {
                    return Err(EmulationError::InvalidMemoryAccess(Opcode::SW, addr));
                }

                // <----------------------- START OF FAULT INJECTION ----------------------->
                let value = modify_output_helper(a);
                // <------------------------ END OF FAULT INJECTION ------------------------>

                memory_store_value = Some(value);
                self.mw_cpu(align(addr), value, MemoryAccessPosition::Memory);
            }

            // B-type instructions.
            Opcode::BEQ => {
                (a, b, c) = self.branch_rr(instruction);
                if a == b {
                    next_pc = self.state.pc.wrapping_add(c);
                }
            }
            Opcode::BNE => {
                (a, b, c) = self.branch_rr(instruction);
                if a != b {
                    next_pc = self.state.pc.wrapping_add(c);
                }
            }
            Opcode::BLT => {
                (a, b, c) = self.branch_rr(instruction);
                if (a as i32) < (b as i32) {
                    next_pc = self.state.pc.wrapping_add(c);
                }
            }
            Opcode::BGE => {
                (a, b, c) = self.branch_rr(instruction);
                if (a as i32) >= (b as i32) {
                    next_pc = self.state.pc.wrapping_add(c);
                }
            }
            Opcode::BLTU => {
                (a, b, c) = self.branch_rr(instruction);
                if a < b {
                    next_pc = self.state.pc.wrapping_add(c);
                }
            }
            Opcode::BGEU => {
                (a, b, c) = self.branch_rr(instruction);
                if a >= b {
                    next_pc = self.state.pc.wrapping_add(c);
                }
            }

            // Jump instructions.
            Opcode::JAL => {
                let (rd, imm) = instruction.j_type();
                (b, c) = (imm, 0);
                a = self.state.pc + 4;
                self.rw(rd, a);
                next_pc = self.state.pc.wrapping_add(imm);
            }
            Opcode::JALR => {
                let (rd, rs1, imm) = instruction.i_type();
                (b, c) = (self.rr(rs1, MemoryAccessPosition::B), imm);
                a = self.state.pc + 4;
                self.rw(rd, a);
                next_pc = b.wrapping_add(c);
            }

            // Upper immediate instructions.
            Opcode::AUIPC => {
                let (rd, imm) = instruction.u_type();
                (b, c) = (imm, imm);
                a = self.state.pc.wrapping_add(b);
                self.rw(rd, a);
            }

            // System instructions.
            Opcode::ECALL => {
                // We peek at register x5 to get the syscall id. The reason we don't `self.rr` this
                // register is that we write to it later.
                let t0 = Register::X5;
                let syscall_id = self.register(t0);
                c = self.rr(Register::X11, MemoryAccessPosition::C);
                b = self.rr(Register::X10, MemoryAccessPosition::B);
                let syscall = SyscallCode::from_u32(syscall_id);

                self.mode.check_unconstrained_syscall(syscall)?;

                // Update the syscall counts.
                let syscall_for_count = syscall.count_map();
                let syscall_count = self
                    .state
                    .syscall_counts
                    .entry(syscall_for_count)
                    .or_insert(0);
                if self.log_syscalls {
                    debug!(">>syscall_id: {syscall_id:?}, syscall_count: {syscall_count:?}");
                }
                *syscall_count += 1;

                let syscall_impl = self.get_syscall(syscall).cloned();
                if syscall.should_send() != 0 {
                    self.emit_syscall(clk, syscall.syscall_id(), b, c);
                }
                let mut precompile_rt = SyscallContext::new(self);
                let (precompile_next_pc, precompile_cycles, returned_exit_code) =
                    if let Some(syscall_impl) = syscall_impl {
                        // Executing a syscall optionally returns a value to write to the t0
                        // register. If it returns None, we just keep the
                        // syscall_id in t0.
                        let res = syscall_impl.emulate(&mut precompile_rt, syscall, b, c);
                        if let Some(val) = res {
                            a = val;
                        } else {
                            a = syscall_id;
                        }

                        // <----------------------- START OF FAULT INJECTION ----------------------->

                        let mut exit_code = precompile_rt.exit_code;

                        if fuzzer_utils::is_injection() {
                            println!("WARNING: ERR: HaltWithNonZeroExitCode({})", precompile_rt.exit_code);
                            exit_code = 0;
                        } else {
                            // If the syscall is `HALT` and the exit code is non-zero, return an error.
                            if syscall == SyscallCode::HALT && precompile_rt.exit_code != 0 {
                                return Err(EmulationError::HaltWithNonZeroExitCode(
                                    precompile_rt.exit_code,
                                ));
                            }
                        }

                        // <------------------------ END OF FAULT INJECTION ------------------------>

                        (
                            precompile_rt.next_pc,
                            syscall_impl.num_extra_cycles(),
                            exit_code,
                        )
                    } else {
                        return Err(EmulationError::UnsupportedSyscall(syscall_id));
                    };

                // Allow the syscall impl to modify state.clk/pc (exit unconstrained does this)
                // we must save the clk here because it is modified by precompile_cycles later which
                // means emit_cpu cannot read the correct clk and it must be passed as a value
                clk = self.state.clk;

                self.rw(t0, a);
                next_pc = precompile_next_pc;
                self.state.clk += precompile_cycles;
                exit_code = returned_exit_code;
            }
            Opcode::EBREAK => {
                return Err(EmulationError::Breakpoint());
            }

            // Multiply instructions.
            Opcode::MUL => {
                (rd, b, c) = self.alu_rr(instruction);
                a = b.wrapping_mul(c);

                // <----------------------- START OF FAULT INJECTION ----------------------->
                let a = modify_output_helper(a);
                // <------------------------ END OF FAULT INJECTION ------------------------>

                self.alu_rw(rd, a);
                self.mode.emit_alu(
                    self.state.clk,
                    a,
                    b,
                    c,
                    instruction.opcode,
                    &mut self.record.mul_events,
                );
            }
            Opcode::MULH => {
                (rd, b, c) = self.alu_rr(instruction);
                a = (((b as i32) as i64).wrapping_mul((c as i32) as i64) >> 32) as u32;

                // <----------------------- START OF FAULT INJECTION ----------------------->
                let a = modify_output_helper(a);
                // <------------------------ END OF FAULT INJECTION ------------------------>

                self.alu_rw(rd, a);
                self.mode.emit_alu(
                    self.state.clk,
                    a,
                    b,
                    c,
                    instruction.opcode,
                    &mut self.record.mul_events,
                );
            }
            Opcode::MULHU => {
                (rd, b, c) = self.alu_rr(instruction);
                a = ((b as u64).wrapping_mul(c as u64) >> 32) as u32;

                // <----------------------- START OF FAULT INJECTION ----------------------->
                let a = modify_output_helper(a);
                // <------------------------ END OF FAULT INJECTION ------------------------>

                self.alu_rw(rd, a);
                self.mode.emit_alu(
                    self.state.clk,
                    a,
                    b,
                    c,
                    instruction.opcode,
                    &mut self.record.mul_events,
                );
            }
            Opcode::MULHSU => {
                (rd, b, c) = self.alu_rr(instruction);
                a = (((b as i32) as i64).wrapping_mul(c as i64) >> 32) as u32;

                // <----------------------- START OF FAULT INJECTION ----------------------->
                let a = modify_output_helper(a);
                // <------------------------ END OF FAULT INJECTION ------------------------>

                self.alu_rw(rd, a);
                self.mode.emit_alu(
                    self.state.clk,
                    a,
                    b,
                    c,
                    instruction.opcode,
                    &mut self.record.mul_events,
                );
            }
            Opcode::DIV => {
                (rd, b, c) = self.alu_rr(instruction);
                if c == 0 {
                    a = u32::MAX;
                } else {
                    a = (b as i32).wrapping_div(c as i32) as u32;
                }

                // <----------------------- START OF FAULT INJECTION ----------------------->
                let a = modify_output_helper(a);
                // <------------------------ END OF FAULT INJECTION ------------------------>

                self.alu_rw(rd, a);
                self.mode.emit_alu(
                    self.state.clk,
                    a,
                    b,
                    c,
                    instruction.opcode,
                    &mut self.record.divrem_events,
                );
            }
            Opcode::DIVU => {
                (rd, b, c) = self.alu_rr(instruction);
                if c == 0 {
                    a = u32::MAX;
                } else {
                    a = b.wrapping_div(c);
                }

                // <----------------------- START OF FAULT INJECTION ----------------------->
                let a = modify_output_helper(a);
                // <------------------------ END OF FAULT INJECTION ------------------------>

                self.alu_rw(rd, a);
                self.mode.emit_alu(
                    self.state.clk,
                    a,
                    b,
                    c,
                    instruction.opcode,
                    &mut self.record.divrem_events,
                );
            }
            Opcode::REM => {
                (rd, b, c) = self.alu_rr(instruction);
                if c == 0 {
                    a = b;
                } else {
                    a = (b as i32).wrapping_rem(c as i32) as u32;
                }

                // <----------------------- START OF FAULT INJECTION ----------------------->
                let a = modify_output_helper(a);
                // <------------------------ END OF FAULT INJECTION ------------------------>

                self.alu_rw(rd, a);
                self.mode.emit_alu(
                    self.state.clk,
                    a,
                    b,
                    c,
                    instruction.opcode,
                    &mut self.record.divrem_events,
                );
            }
            Opcode::REMU => {
                (rd, b, c) = self.alu_rr(instruction);
                if c == 0 {
                    a = b;
                } else {
                    a = b.wrapping_rem(c);
                }

                // <----------------------- START OF FAULT INJECTION ----------------------->
                let a = modify_output_helper(a);
                // <------------------------ END OF FAULT INJECTION ------------------------>

                self.alu_rw(rd, a);
                self.mode.emit_alu(
                    self.state.clk,
                    a,
                    b,
                    c,
                    instruction.opcode,
                    &mut self.record.divrem_events,
                );
            }

            // See https://github.com/riscv-non-isa/riscv-asm-manual/blob/main/src/asm-manual.adoc#instruction-aliases
            Opcode::UNIMP => {
                return Err(EmulationError::Unimplemented());
            }
        }

        // <----------------------- START OF FAULT INJECTION ----------------------->

        // TODO:
        //  - double emit things by calling self.mode.emit_cpu( ... ) again
        //  - fix emit by passing the correct values into the record
        //  - call a new function inbetween by calling self.emulate_instruction( ... )
        //

        // <------------------------ END OF FAULT INJECTION ------------------------>

        // Emit the CPU event for this cycle.
        self.mode.emit_cpu(
            self.chunk(),
            clk,
            self.state.pc,
            next_pc,
            exit_code,
            a,
            b,
            c,
            *instruction,
            self.memory_accesses,
            memory_store_value,
            &mut self.record.cpu_events,
        );

        // <----------------------- START OF FAULT INJECTION ----------------------->

        fuzzer_utils::print_trace_info();

        if fuzzer_utils::is_injection_at_step("EMULATE_RANDOM_INSTRUCTION") {

            let new_instruction = random_mutate_instruction(instruction);
            fuzzer_utils::print_injection_info(
                "EMULATE_RANDOM_INSTRUCTION",
                &format!("{:?} => {:?}", instruction, new_instruction),
            );

            // update has to be done inside of "if" such that it is not executed twice and
            // does not manipulate if queried. Also the injection info is emitted before such
            // that the correct step is used.
            fuzzer_utils::inc_step();

            if fuzzer_utils::random_bool() { // optional update
                self.state.pc = next_pc;
            }

            if fuzzer_utils::random_bool() { // optional update
                self.state.clk += 4;
            }

            let _ = self.emulate_instruction(&new_instruction);
        } else {

            // end of call update for a normal non-(emulate)-injection execution
            fuzzer_utils::inc_step();

        }

        // <------------------------ END OF FAULT INJECTION ------------------------>

        // Update the program counter.
        self.state.pc = next_pc;

        // Update the clk to the next cycle.
        self.state.clk += 4;

        Ok(())
    }
}
"""  # noqa: E501
