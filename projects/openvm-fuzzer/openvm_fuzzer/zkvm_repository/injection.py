import logging
import re
from pathlib import Path

from openvm_fuzzer.settings import (
    OPENVM_AUDIT_336_COMMIT,
    OPENVM_AUDIT_F038_COMMIT,
    OPENVM_REGZERO_COMMIT,
    resolve_openvm_commit,
)
from openvm_fuzzer.zkvm_repository.fuzzer_utils_crate import create_fuzzer_utils_crate
from openvm_fuzzer.zkvm_repository.injection_sources import (
    openvm_crates_vm_src_arch_segment_rs,
    openvm_extensions_rv32im_circuit_src_auipc_core_rs,
    openvm_extensions_rv32im_circuit_src_base_alu_core_rs,
    openvm_extensions_rv32im_circuit_src_divrem_core_rs,
    openvm_extensions_rv32im_circuit_src_load_sign_extend_core_rs,
    openvm_extensions_rv32im_circuit_src_loadstore_core_rs,
)
from zkvm_fuzzer_utils.file import overwrite_file, prepend_file, replace_in_file

logger = logging.getLogger("fuzzer")

_OPENVM_SNAPSHOT_COMMITS = {OPENVM_REGZERO_COMMIT, OPENVM_AUDIT_336_COMMIT, OPENVM_AUDIT_F038_COMMIT}


def _insert_after(contents: str, *, anchor: str, insert: str, guard: str) -> str:
    if guard in contents:
        return contents
    idx = contents.find(anchor)
    if idx < 0:
        raise RuntimeError(f"anchor not found for injection: {anchor!r}")
    pos = idx + len(anchor)
    return contents[:pos] + insert + contents[pos:]


def _insert_before(contents: str, *, anchor: str, insert: str, guard: str) -> str:
    if guard in contents:
        return contents
    idx = contents.find(anchor)
    if idx < 0:
        raise RuntimeError(f"anchor not found for injection: {anchor!r}")
    return contents[:idx] + insert + contents[idx:]


def _patch_audit_segment_rs_for_microops(openvm_install_path: Path) -> None:
    """
    Audit snapshots (336/f038) predate our template overwrite approach.
    Patch `crates/vm/src/arch/segment.rs` in-place to emit ChipRow + Interaction micro-ops.
    """
    segment_rs = openvm_install_path / "crates" / "vm" / "src" / "arch" / "segment.rs"
    if not segment_rs.exists():
        logger.info("segment.rs not found; skipping audit segment patch: %s", segment_rs)
        return

    contents = segment_rs.read_text()

    # Repair a prior bad patch that inserted `inc_step()` *after* the `(opcode, dsl_instr)` tuple,
    # breaking the block's return type.
    bad_block = (
        "(opcode, dsl_instr.cloned())\n\n"
        "                // Advance \"op index\" for micro-op grouping.\n"
        "                fuzzer_utils::print_trace_info();\n"
        "                fuzzer_utils::inc_step();\n\n"
    )
    if bad_block in contents:
        good_block = (
            "\n                // Advance \"op index\" for micro-op grouping.\n"
            "                fuzzer_utils::print_trace_info();\n"
            "                fuzzer_utils::inc_step();\n\n"
            "                (opcode, dsl_instr.cloned())\n"
        )
        contents = contents.replace(bad_block, good_block)

    # Ensure imports used by the injected blocks.
    if "use serde_json::json;" not in contents:
        # Prefer inserting after the top-level `use crate::{ ... };` block.
        m = re.search(r"\nuse crate::\{[\s\S]*?\};\n", contents, flags=re.MULTILINE)
        if m:
            pos = m.end()
            contents = contents[:pos] + "use serde_json::json;\n" + contents[pos:]
        else:
            # Best-effort: insert after the last `use` line in the header.
            header_end = contents.find("\n\n")
            if header_end > 0:
                header = contents[:header_end]
                if "use serde_json::json;" not in header:
                    contents = (
                        contents[:header_end]
                        + "\nuse serde_json::json;\n"
                        + contents[header_end:]
                    )

    if "use crate::system::memory::online::MemoryLogEntry;" not in contents:
        # Insert after existing `use crate::{ ... system::memory::MemoryImage, ... };` block if present.
        m = re.search(r"use crate::\{[\s\S]*?system::memory::MemoryImage,[\s\S]*?\};", contents)
        if m:
            insert_pos = m.end()
            contents = (
                contents[:insert_pos]
                + "\nuse crate::system::memory::online::MemoryLogEntry;\n"
                + contents[insert_pos:]
            )

    # Ensure `use fuzzer_utils;` is present somewhere (assert-rewrite usually adds it, but be robust).
    if "use fuzzer_utils;" not in contents:
        header_end = contents.find("\n\n")
        if header_end > 0:
            contents = contents[:header_end] + "\nuse fuzzer_utils;\n" + contents[header_end:]

    # ProgramChip + ProgramBus emission (pc -> opcode/operands).
    contents = _insert_after(
        contents,
        anchor="let (instruction, debug_info) = program_chip.get_instruction(pc)?;",
        guard="\"ProgramBus\"",
        insert=r"""

                // Program-table semantics: the program bus constrains that (pc -> opcode/operands).
                // Emit a ChipRow so op-level analyses can include this "system" chip alongside
                // the instruction's adapter/core chips.
                if fuzzer_utils::is_trace_logging() {
                    let gates = json!({"is_real": 1}).to_string();
                    let locals = json!({
                        "pc": pc,
                        "opcode": instruction.opcode.as_usize(),
                        "operands": [
                            instruction.a.as_canonical_u32(),
                            instruction.b.as_canonical_u32(),
                            instruction.c.as_canonical_u32(),
                            instruction.d.as_canonical_u32(),
                            instruction.e.as_canonical_u32(),
                            instruction.f.as_canonical_u32(),
                            instruction.g.as_canonical_u32(),
                        ],
                    })
                    .to_string();
                    let chip = "ProgramChip".to_string();
                    fuzzer_utils::print_chip_row_json("openvm", &chip, &gates, &locals);

                    // Program-table interaction: lookup (pc -> opcode/operands).
                    let anchor_row_id = fuzzer_utils::get_last_row_id();
                    let payload = json!({
                        "pc": pc,
                        "opcode": instruction.opcode.as_usize(),
                        "operands": [
                            instruction.a.as_canonical_u32(),
                            instruction.b.as_canonical_u32(),
                            instruction.c.as_canonical_u32(),
                            instruction.d.as_canonical_u32(),
                            instruction.e.as_canonical_u32(),
                            instruction.f.as_canonical_u32(),
                            instruction.g.as_canonical_u32(),
                        ],
                    })
                    .to_string();
                    fuzzer_utils::print_interaction_json(
                        "ProgramBus",
                        "recv",
                        "program",
                        &anchor_row_id,
                        &payload,
                        1,
                        "gates.is_real",
                    );
                }
""",
    )

    # Memory log snapshot + prev state before execute.
    contents = _insert_after(
        contents,
        anchor="if let Some(executor) = chip_complex.inventory.get_mut_executor(&opcode) {",
        guard="let mem_log_start =",
        insert=r"""

                        // Snapshot memory logs to attribute memory chips per instruction.
                        let mem_log_start = memory_controller.get_memory_logs().len();

                        let prev_pc = pc;
                        let prev_timestamp = timestamp;
""",
    )

    # Post-exec memory chips + boundary + execution-bus + per-step increment.
    contents = _insert_after(
        contents,
        anchor="timestamp = next_state.timestamp;",
        guard="ExecutionBus",
        insert=r"""

                        // Emit memory-related chips as ChipRow markers.
                        //
                        // NOTE: During execution, OpenVM accumulates *memory logs* in online memory.
                        // Those logs are later replayed in `finalize()` to populate memory trace
                        // chips (Boundary, AccessAdapter<N>, ...). We attribute per-instruction
                        // "memory chips involved" based on the newly-added memory-log entries here.
                        if fuzzer_utils::is_trace_logging() {
                            let gates = json!({"is_real": 1}).to_string();
                            let logs = memory_controller.get_memory_logs();
                            let new_logs = logs.iter().skip(mem_log_start);

                            let mut boundary_spaces: Vec<u32> = Vec::new();
                            let mut access_count: u32 = 0;

                            for (i, entry) in new_logs.enumerate() {
                                let record_id = (mem_log_start + i) as u32;
                                match entry {
                                    MemoryLogEntry::Read { address_space, pointer, len } => {
                                        access_count += 1;
                                        if *address_space != 0
                                            && !boundary_spaces.contains(address_space)
                                        {
                                            boundary_spaces.push(*address_space);
                                        }
                                        let chip = format!("AccessAdapter<{}>", len);
                                        let locals = json!({
                                            "record_id": record_id,
                                            "op": "read",
                                            "address_space": address_space,
                                            "pointer": pointer,
                                            "len": len,
                                        })
                                        .to_string();
                                        fuzzer_utils::print_chip_row_json(
                                            "openvm",
                                            &chip,
                                            &gates,
                                            &locals,
                                        );

                                        let anchor_row_id = fuzzer_utils::get_last_row_id();
                                        let payload = json!({
                                            "record_id": record_id,
                                            "op": "read",
                                            "address_space": address_space,
                                            "pointer": pointer,
                                            "len": len,
                                        })
                                        .to_string();
                                        fuzzer_utils::print_interaction_json(
                                            "MemoryBus",
                                            "send",
                                            "memory",
                                            &anchor_row_id,
                                            &payload,
                                            1,
                                            "gates.is_real",
                                        );
                                    }
                                    MemoryLogEntry::Write { address_space, pointer, data } => {
                                        access_count += 1;
                                        if *address_space != 0
                                            && !boundary_spaces.contains(address_space)
                                        {
                                            boundary_spaces.push(*address_space);
                                        }
                                        let len = data.len() as u32;
                                        let chip = format!("AccessAdapter<{}>", len);
                                        let locals = json!({
                                            "record_id": record_id,
                                            "op": "write",
                                            "address_space": address_space,
                                            "pointer": pointer,
                                            "len": len,
                                        })
                                        .to_string();
                                        fuzzer_utils::print_chip_row_json(
                                            "openvm",
                                            &chip,
                                            &gates,
                                            &locals,
                                        );

                                        let anchor_row_id = fuzzer_utils::get_last_row_id();
                                        let payload = json!({
                                            "record_id": record_id,
                                            "op": "write",
                                            "address_space": address_space,
                                            "pointer": pointer,
                                            "len": len,
                                        })
                                        .to_string();
                                        fuzzer_utils::print_interaction_json(
                                            "MemoryBus",
                                            "send",
                                            "memory",
                                            &anchor_row_id,
                                            &payload,
                                            1,
                                            "gates.is_real",
                                        );
                                    }
                                    MemoryLogEntry::IncrementTimestampBy(_) => {}
                                }
                            }

                            // Boundary: constrain which address spaces are accessed.
                            if access_count > 0 {
                                let chip = "Boundary".to_string();
                                let locals = json!({
                                    "access_count": access_count,
                                    "address_spaces": boundary_spaces,
                                })
                                .to_string();
                                fuzzer_utils::print_chip_row_json("openvm", &chip, &gates, &locals);
                                let anchor_row_id = fuzzer_utils::get_last_row_id();
                                let payload = json!({
                                    "access_count": access_count,
                                    "address_spaces": boundary_spaces,
                                })
                                .to_string();
                                fuzzer_utils::print_interaction_json(
                                    "Boundary",
                                    "send",
                                    "memory",
                                    &anchor_row_id,
                                    &payload,
                                    1,
                                    "gates.is_real",
                                );
                            }
                        }

                        // Execution-bus semantics: (pc,timestamp) transitions are constrained via
                        // the execution bus (checked by the connector air). We record the edge as
                        // a ChipRow so buckets can reason about next_pc / timestamp changes.
                        if fuzzer_utils::is_trace_logging() {
                            let gates = json!({"is_real": 1}).to_string();
                            let locals = json!({
                                "from_pc": prev_pc,
                                "to_pc": pc,
                                "from_timestamp": prev_timestamp,
                                "to_timestamp": timestamp,
                                "opcode": opcode.as_usize(),
                            })
                            .to_string();
                            let chip = "VmConnectorAir".to_string();
                            fuzzer_utils::print_chip_row_json("openvm", &chip, &gates, &locals);

                            let anchor_row_id = fuzzer_utils::get_last_row_id();
                            let recv_payload = json!({
                                "pc": prev_pc,
                                "timestamp": prev_timestamp,
                            })
                            .to_string();
                            fuzzer_utils::print_interaction_json(
                                "ExecutionBus",
                                "recv",
                                "global",
                                &anchor_row_id,
                                &recv_payload,
                                1,
                                "gates.is_real",
                            );
                            let send_payload = json!({
                                "pc": pc,
                                "timestamp": timestamp,
                            })
                            .to_string();
                            fuzzer_utils::print_interaction_json(
                                "ExecutionBus",
                                "send",
                                "global",
                                &anchor_row_id,
                                &send_payload,
                                1,
                                "gates.is_real",
                            );
                        }
""",
    )

    # Per-op step increment (needed so bucket code gets `op_spans`).
    contents = _insert_before(
        contents,
        anchor="(opcode, dsl_instr.cloned())",
        guard="fuzzer_utils::inc_step()",
        insert=r"""

                // Advance "op index" for micro-op grouping.
                fuzzer_utils::print_trace_info();
                fuzzer_utils::inc_step();
""",
    )

    segment_rs.write_text(contents)


def _patch_audit_integration_api_for_microops(openvm_install_path: Path) -> None:
    """
    Audit snapshots (336/f038) have a slightly different `integration_api.rs` layout (multi-line
    `postprocess` assignment). Patch it in-place to emit adapter/core ChipRow micro-ops.
    """
    integration_api = openvm_install_path / "crates" / "vm" / "src" / "arch" / "integration_api.rs"
    if not integration_api.exists():
        return

    contents = integration_api.read_text()
    if "fuzzer_utils::print_chip_row_json(\"openvm\"" in contents:
        # Already injected.
        return

    # Ensure serde_json::json is available.
    if "use serde_json::json;" not in contents:
        # Accept both `use serde::{Deserialize, Serialize};` and
        # `use serde::{de::DeserializeOwned, Deserialize, Serialize};` variants.
        contents, n = re.subn(
            r"^use serde::\{[^}]*\};\s*$",
            lambda m: m.group(0) + "\nuse serde_json::json;",
            contents,
            count=1,
            flags=re.MULTILINE,
        )
        if n == 0:
            raise RuntimeError("unable to locate serde import to append serde_json::json")

    # Insert after the multi-line postprocess assignment (ending at `?;`).
    m = re.search(
        r"(let\s+\(to_state,\s*write_record\)\s*=\s*\n\s*self\.adapter\s*\n\s*\.postprocess\([\s\S]*?\)\?\s*;)",
        contents,
        flags=re.MULTILINE,
    )
    if not m:
        raise RuntimeError("unable to locate adapter postprocess assignment in integration_api.rs")

    insert = r"""

        if fuzzer_utils::is_trace_logging() {
            // NOTE: We emit ChipRow-style micro-ops, i.e. per-chip payloads. This matches
            // the beak-core interface (MicroOp = ChipRow | InteractionBase).
            let gates = json!({"is_real": 1}).to_string();

            let adapter_chip = get_air_name(self.adapter.air());
            let adapter_locals = json!({
                "from_pc": from_state.pc,
                "to_pc": to_state.pc,
                "from_timestamp": from_state.timestamp,
                "to_timestamp": to_state.timestamp,
                "payload_json": json!({
                    "adapter_read": &read_record,
                    "adapter_write": &write_record,
                })
                .to_string(),
            })
            .to_string();
            fuzzer_utils::print_chip_row_json("openvm", &adapter_chip, &gates, &adapter_locals);

            let core_chip = get_air_name(self.core.air());
            let core_locals = json!({
                "from_pc": from_state.pc,
                "payload_json": json!({ "core": &core_record }).to_string(),
            })
            .to_string();
            fuzzer_utils::print_chip_row_json("openvm", &core_chip, &gates, &core_locals);
        }
"""
    pos = m.end()
    contents = contents[:pos] + insert + contents[pos:]
    integration_api.write_text(contents)


def _patch_regzero_interpreter_preflight_for_microops(openvm_install_path: Path) -> None:
    """
    regzero snapshot uses the preflight interpreter loop for trace-generation. Patch it to emit
    ProgramChip + ProgramBus and a lightweight ExecutionBus edge per instruction.
    """
    path = (
        openvm_install_path
        / "crates"
        / "vm"
        / "src"
        / "arch"
        / "interpreter_preflight.rs"
    )
    if not path.exists():
        return

    contents = path.read_text()
    # Idempotence: allow incremental additions (e.g. later adding Exec(...) chip markers).
    if (
        "ProgramChip" in contents
        and "ProgramBus" in contents
        and "ExecutionBus" in contents
        and "fuzzer_utils::inc_step();" in contents
        and "Exec(" in contents
    ):
        return

    # Ensure serde_json::json import.
    if "use serde_json::json;" not in contents:
        header_end = contents.find("\n\n")
        if header_end > 0:
            contents = contents[:header_end] + "\nuse serde_json::json;\n" + contents[header_end:]

    # Ensure we can call fuzzer_utils even if assert-rewrite didn't touch this file.
    if "use fuzzer_utils;" not in contents:
        header_end = contents.find("\n\n")
        if header_end > 0:
            contents = contents[:header_end] + "\nuse fuzzer_utils;\n" + contents[header_end:]

    # Pre-exec: ProgramChip + ProgramBus.
    contents = _insert_after(
        contents,
        anchor='tracing::trace!("pc: {pc:#x} | {:?}", pc_entry.insn);',
        guard="ProgramChip",
        insert=r"""

        let beak_from_timestamp = state.memory.timestamp();
        if fuzzer_utils::is_trace_logging() {
            let gates = json!({"is_real": 1}).to_string();
            let locals = json!({
                "pc": pc,
                "opcode": pc_entry.insn.opcode.as_usize(),
                "operands": [
                    pc_entry.insn.a.as_canonical_u32(),
                    pc_entry.insn.b.as_canonical_u32(),
                    pc_entry.insn.c.as_canonical_u32(),
                    pc_entry.insn.d.as_canonical_u32(),
                    pc_entry.insn.e.as_canonical_u32(),
                    pc_entry.insn.f.as_canonical_u32(),
                    pc_entry.insn.g.as_canonical_u32(),
                ],
            })
            .to_string();
            let chip = "ProgramChip".to_string();
            fuzzer_utils::print_chip_row_json("openvm", &chip, &gates, &locals);

            let anchor_row_id = fuzzer_utils::get_last_row_id();
            let payload = json!({
                "pc": pc,
                "opcode": pc_entry.insn.opcode.as_usize(),
                "operands": [
                    pc_entry.insn.a.as_canonical_u32(),
                    pc_entry.insn.b.as_canonical_u32(),
                    pc_entry.insn.c.as_canonical_u32(),
                    pc_entry.insn.d.as_canonical_u32(),
                    pc_entry.insn.e.as_canonical_u32(),
                    pc_entry.insn.f.as_canonical_u32(),
                    pc_entry.insn.g.as_canonical_u32(),
                ],
            })
            .to_string();
            fuzzer_utils::print_interaction_json(
                "ProgramBus",
                "recv",
                "program",
                &anchor_row_id,
                &payload,
                1,
                "gates.is_real",
            );
        }
""",
    )

    # Per-instruction executor chip marker (may be added later than ProgramChip patch).
    contents = _insert_after(
        contents,
        anchor="if fuzzer_utils::is_trace_logging() {",
        guard="Exec(",
        insert=r"""
            // Per-instruction "main chip" marker at the executor granularity.
            // regzero-era preflight execution does not expose adapter/core splits here.
            // TODO(beak-fuzz): If we want ChipRow outputs for concrete AIRs like
            // `Rv32JalrAdapterAir` / `Rv32BranchAdapterAir` (with their real column/locals
            // payloads), we must instrument the trace build/filler stage that materializes those
            // AIR rows (e.g. the rv32im adapter fillers / tracegen). The preflight interpreter
            // only sees decoded `Instruction` and executor dispatch, so it cannot access the
            // per-AIR row objects needed to print accurate ChipRow locals.
            let opcode_name = executor.get_opcode_name(pc_entry.insn.opcode.as_usize());
            let gates = json!({"is_real": 1}).to_string();
            let locals = json!({
                "pc": pc,
                "opcode": pc_entry.insn.opcode.as_usize(),
                "opcode_name": opcode_name,
                "operands": [
                    pc_entry.insn.a.as_canonical_u32(),
                    pc_entry.insn.b.as_canonical_u32(),
                    pc_entry.insn.c.as_canonical_u32(),
                    pc_entry.insn.d.as_canonical_u32(),
                    pc_entry.insn.e.as_canonical_u32(),
                    pc_entry.insn.f.as_canonical_u32(),
                    pc_entry.insn.g.as_canonical_u32(),
                ],
            })
            .to_string();
            let chip = format!("Exec({})", opcode_name);
            fuzzer_utils::print_chip_row_json("openvm", &chip, &gates, &locals);

""",
    )

    # Post-exec: ExecutionBus edge + per-op increment.
    contents = _insert_after(
        contents,
        anchor="executor.execute(vm_state_mut, &pc_entry.insn)?;",
        guard="ExecutionBus",
        insert=r"""

        if fuzzer_utils::is_trace_logging() {
            let to_pc = state.pc();
            let to_timestamp = state.memory.timestamp();
            let from_timestamp = beak_from_timestamp;
            let gates = json!({"is_real": 1}).to_string();
            let locals = json!({
                "from_pc": pc,
                "to_pc": to_pc,
                "from_timestamp": from_timestamp,
                "to_timestamp": to_timestamp,
                "opcode": pc_entry.insn.opcode.as_usize(),
            })
            .to_string();
            let chip = "VmConnectorAir".to_string();
            fuzzer_utils::print_chip_row_json("openvm", &chip, &gates, &locals);

            let anchor_row_id = fuzzer_utils::get_last_row_id();
            let recv_payload = json!({
                "pc": pc,
                "timestamp": from_timestamp,
            })
            .to_string();
            fuzzer_utils::print_interaction_json(
                "ExecutionBus",
                "recv",
                "global",
                &anchor_row_id,
                &recv_payload,
                1,
                "gates.is_real",
            );
            let send_payload = json!({
                "pc": to_pc,
                "timestamp": to_timestamp,
            })
            .to_string();
            fuzzer_utils::print_interaction_json(
                "ExecutionBus",
                "send",
                "global",
                &anchor_row_id,
                &send_payload,
                1,
                "gates.is_real",
            );
        }

        fuzzer_utils::print_trace_info();
        fuzzer_utils::inc_step();
""",
    )

    path.write_text(contents)


def openvm_fault_injection(openvm_install_path: Path, commit_or_branch: str):
    resolved_commit = resolve_openvm_commit(commit_or_branch)

    # create a fuzzer_utils crate at zkvm root
    create_fuzzer_utils_crate(openvm_install_path)

    # add fuzzer utils to root Cargo.toml using RELATIVE paths
    # This allows the project to be built both on host and inside Docker
    root_cargo = openvm_install_path / "Cargo.toml"
    if root_cargo.exists():
        root_contents = root_cargo.read_text()
        if '"crates/fuzzer_utils"' not in root_contents:
            replace_in_file(
                root_cargo,
                [(r"members = \[", 'members = [\n    "crates/fuzzer_utils",')],
            )
        root_contents = root_cargo.read_text()
        if "fuzzer_utils = { path = \"crates/fuzzer_utils\" }" not in root_contents:
            replace_in_file(
                root_cargo,
                [
                    (
                        r"\[workspace\.dependencies\]",
                        "[workspace.dependencies]\nfuzzer_utils = { path = \"crates/fuzzer_utils\" }",
                    )
                ],
            )

    # recursively remove asserts in the whole vm folder
    working_dirs = [openvm_install_path / "crates" / "vm"]
    while len(working_dirs) > 0:
        working_dir = working_dirs.pop()
        for elem in working_dir.iterdir():
            if elem.is_dir():
                working_dirs.append(elem)
            if elem.is_file() and elem.name == "Cargo.toml":
                contents = elem.read_text()
                if "fuzzer_utils.workspace = true" not in contents:
                    replace_in_file(
                        elem,
                        [(r"\[dependencies\]", "[dependencies]\nfuzzer_utils.workspace = true")],
                    )
            if elem.is_file() and elem.suffix == ".rs":
                # NOTE: the order matters here because the replacement is done iteratively
                is_updated = replace_in_file(
                    elem,
                    [
                        (r"\bassert!", "fuzzer_utils::fuzzer_assert!"),
                        (r"\bassert_eq!", "fuzzer_utils::fuzzer_assert_eq!"),
                        (r"\bassert_ne!", "fuzzer_utils::fuzzer_assert_ne!"),
                        (r"\bdebug_assert!", "fuzzer_utils::fuzzer_assert!"),
                        (r"\bdebug_assert_eq!", "fuzzer_utils::fuzzer_assert_eq!"),
                    ],
                )
                if is_updated:
                    prefix = "#[allow(unused_imports)]\nuse fuzzer_utils;\n"
                    if not elem.read_text().startswith(prefix):
                        prepend_file(elem, prefix)

    # Ensure OpenVM circuit crate can serialize per-instruction records.
    # (serde_json is provided in the OpenVM workspace dependencies.)
    vm_cargo_toml = openvm_install_path / "crates" / "vm" / "Cargo.toml"
    if vm_cargo_toml.exists():
        vm_contents = vm_cargo_toml.read_text()
        if "serde_json.workspace = true" not in vm_contents:
            replace_in_file(
                vm_cargo_toml,
                [
                    (
                        r"\[dependencies\]",
                        "[dependencies]\nserde_json.workspace = true",
                    )
                ],
            )

    # Emit per-op micro-op records from the Integration API (VmChipWrapper::execute).
    integration_api = openvm_install_path / "crates" / "vm" / "src" / "arch" / "integration_api.rs"
    if integration_api.exists():
        if resolved_commit in {OPENVM_AUDIT_336_COMMIT, OPENVM_AUDIT_F038_COMMIT}:
            _patch_audit_integration_api_for_microops(openvm_install_path)
        else:
            # Ensure serde_json::json is available.
            contents = integration_api.read_text()
            if "use serde_json::json;" not in contents:
                replace_in_file(
                    integration_api,
                    [
                        (
                            r"use serde::\{de::DeserializeOwned, Deserialize, Serialize\};",
                            "use serde::{de::DeserializeOwned, Deserialize, Serialize};\nuse serde_json::json;",
                        )
                    ],
                )
            # Inject per-instruction micro-ops in beak-core format (ChipRow records).
            contents = integration_api.read_text()
            # Repair a prior bad injection that left a literal `\1` line in the file.
            if "\n\\1\n" in contents:
                integration_api.write_text(contents.replace("\n\\1\n", "\n"))
                contents = integration_api.read_text()
            if "fuzzer_utils::print_chip_row_json(\"openvm\"" not in contents:
                replace_in_file(
                    integration_api,
                    [
                        (
                            r"^(\s*self\.adapter\s*\.postprocess\(\s*memory,\s*instruction,\s*from_state,\s*output,\s*&read_record\s*\)\?\s*;)\s*$",
                            r"""\1

        if fuzzer_utils::is_trace_logging() {
            // NOTE: We emit ChipRow-style micro-ops, i.e. per-chip payloads. This matches
            // the beak-core interface (MicroOp = ChipRow | InteractionBase).
            let gates = json!({"is_real": 1}).to_string();

            let adapter_chip = get_air_name(self.adapter.air());
            let adapter_locals = json!({
                "from_pc": from_state.pc,
                "to_pc": to_state.pc,
                "from_timestamp": from_state.timestamp,
                "to_timestamp": to_state.timestamp,
                "payload_json": json!({
                    "adapter_read": &read_record,
                    "adapter_write": &write_record,
                })
                .to_string(),
            })
            .to_string();
            fuzzer_utils::print_chip_row_json("openvm", &adapter_chip, &gates, &adapter_locals);

            let core_chip = get_air_name(self.core.air());
            let core_locals = json!({
                "from_pc": from_state.pc,
                "payload_json": json!({ "core": &core_record }).to_string(),
            })
            .to_string();
            fuzzer_utils::print_chip_row_json("openvm", &core_chip, &gates, &core_locals);
        }""",
                        ),
                    ],
                    flags=re.MULTILINE,
                )

    # Fault-inject `segment.rs`:
    # - For ca36de/main we overwrite from a known template.
    # - For older audit snapshots we patch in-place (file layout differs).
    if resolved_commit in {OPENVM_AUDIT_336_COMMIT, OPENVM_AUDIT_F038_COMMIT}:
        _patch_audit_segment_rs_for_microops(openvm_install_path)
    elif resolved_commit in _OPENVM_SNAPSHOT_COMMITS:
        logger.info("snapshot commit without segment template; skipping segment overwrite: %s", resolved_commit)
        if resolved_commit == OPENVM_REGZERO_COMMIT:
            _patch_regzero_interpreter_preflight_for_microops(openvm_install_path)
    else:
        overwrite_file(
            openvm_install_path / "crates" / "vm" / "src" / "arch" / "segment.rs",
            openvm_crates_vm_src_arch_segment_rs(resolved_commit),
        )

    # add fuzzer utils to extensions/rv32im/circuit/Cargo.toml
    rv32im_cargo = openvm_install_path / "extensions" / "rv32im" / "circuit" / "Cargo.toml"
    if rv32im_cargo.exists():
        rv32im_contents = rv32im_cargo.read_text()
        if "fuzzer_utils.workspace = true" not in rv32im_contents:
            replace_in_file(
                rv32im_cargo,
                [(r"\[dependencies\]", "[dependencies]\nfuzzer_utils.workspace = true")],
            )

    # overwrite base_alu/core.rs
    # NOTE: this is done before all assertions are replaced! This is intentional!
    if resolved_commit not in _OPENVM_SNAPSHOT_COMMITS:
        overwrite_file(
            openvm_install_path
            / "extensions"
            / "rv32im"
            / "circuit"
            / "src"
            / "base_alu"
            / "core.rs",
            openvm_extensions_rv32im_circuit_src_base_alu_core_rs(resolved_commit),
        )

    # overwrite auipc/core.rs
    # NOTE: this is done before all assertions are replaced! This is intentional!
    if resolved_commit not in _OPENVM_SNAPSHOT_COMMITS:
        overwrite_file(
            openvm_install_path
            / "extensions"
            / "rv32im"
            / "circuit"
            / "src"
            / "auipc"
            / "core.rs",
            openvm_extensions_rv32im_circuit_src_auipc_core_rs(resolved_commit),
        )

    # overwrite loadstore/core.rs
    # NOTE: this is done before all assertions are replaced! This is intentional!
    if resolved_commit not in _OPENVM_SNAPSHOT_COMMITS:
        overwrite_file(
            openvm_install_path
            / "extensions"
            / "rv32im"
            / "circuit"
            / "src"
            / "loadstore"
            / "core.rs",
            openvm_extensions_rv32im_circuit_src_loadstore_core_rs(resolved_commit),
        )

    # overwrite divrem/core.rs
    # NOTE: this is done before all assertions are replaced! This is intentional!
    if resolved_commit not in _OPENVM_SNAPSHOT_COMMITS:
        overwrite_file(
            openvm_install_path
            / "extensions"
            / "rv32im"
            / "circuit"
            / "src"
            / "divrem"
            / "core.rs",
            openvm_extensions_rv32im_circuit_src_divrem_core_rs(resolved_commit),
        )

    # overwrite load_sign_extend/core.rs
    # NOTE: this is done before all assertions are replaced! This is intentional!
    if resolved_commit not in _OPENVM_SNAPSHOT_COMMITS:
        overwrite_file(
            openvm_install_path
            / "extensions"
            / "rv32im"
            / "circuit"
            / "src"
            / "load_sign_extend"
            / "core.rs",
            openvm_extensions_rv32im_circuit_src_load_sign_extend_core_rs(resolved_commit),
        )

    # recursively remove asserts in the whole rv32im circuit folder
    working_dirs = [openvm_install_path / "extensions" / "rv32im" / "circuit" / "src"]
    while len(working_dirs) > 0:
        working_dir = working_dirs.pop()
        for elem in working_dir.iterdir():
            if elem.is_dir():
                working_dirs.append(elem)
            if elem.is_file() and elem.suffix == ".rs":
                # NOTE: the order matters here because the replacement is done iteratively
                is_updated = replace_in_file(
                    elem,
                    [
                        (r"\bassert!", "fuzzer_utils::fuzzer_assert!"),
                        (r"\bassert_eq!", "fuzzer_utils::fuzzer_assert_eq!"),
                        (r"\bdebug_assert!", "fuzzer_utils::fuzzer_assert!"),
                        (r"\bdebug_assert_eq!", "fuzzer_utils::fuzzer_assert_eq!"),
                    ],
                )
                if is_updated:
                    prefix = "#[allow(unused_imports)]\nuse fuzzer_utils;\n"
                    if not elem.read_text().startswith(prefix):
                        prepend_file(elem, prefix)
