import io
import logging
import shutil
from pathlib import Path

from circil.ir.node import Circuit
from circil.ir.type import IRType
from jolt_fuzzer.settings import (
    RUST_GUEST_CORRECT_VALUE,
    RUST_GUEST_RETURN_TYPE,
    get_rust_toolchain_version,
)
from zkvm_fuzzer_utils.file import create_file
from zkvm_fuzzer_utils.project import AbstractCircuitProjectGenerator
from zkvm_fuzzer_utils.rust.common import (
    ir_type_to_str,
    stream_circuit_output_and_compare_routine,
)
from zkvm_fuzzer_utils.rust.ir2rust import CircIL2UnsafeRustEmitter

logger = logging.getLogger("fuzzer")


# ---------------------------------------------------------------------------- #
#                                Circuit Project                               #
# ---------------------------------------------------------------------------- #


class CircuitProjectGenerator(AbstractCircuitProjectGenerator):
    commit_or_branch: str
    cached_patch_crates_io: str | None

    def __init__(
        self,
        root: Path,
        zkvm_path: Path,
        circuits: list[Circuit],
        fault_injection: bool,
        trace_collection: bool,
        commit_or_branch: str,
    ):
        super().__init__(root, zkvm_path, circuits, fault_injection, trace_collection)
        self.cached_patch_crates_io = None
        self.commit_or_branch = commit_or_branch

    @property
    def patch_crates_io_section(self) -> str:
        if self.cached_patch_crates_io is None:
            cargo_toml_lines = (self.zkvm_path / "Cargo.toml").read_text().split("\n")
            patch_section_lines = []
            is_record = False
            for line in cargo_toml_lines:
                if line == "[patch.crates-io]":
                    is_record = True
                if line == "":
                    is_record = False
                if is_record:
                    patch_section_lines.append(line)
            self.cached_patch_crates_io = "\n".join(patch_section_lines)

        assert self.cached_patch_crates_io, "singleton was not set!"
        return self.cached_patch_crates_io

    def create(self):

        if self.commit_or_branch in [
            "0582b2aa4a33944506d75ce891db7cf090814ff6",
            "57ea518d6d9872fb221bf6ac97df1456a5494cf2",
            "20ac6eb526af383e7b597273990b5e4b783cc2a6",
            "70c77337426615b67191b301e9175e2bb093830d",
        ]:
            shutil.copy2(self.zkvm_path / "Cargo.lock", self.root / "Cargo.lock")

        self.create_root_cargo_toml()
        self.create_root_rust_toolchain()
        self.create_host_main_rs()
        self.create_guest_cargo_toml()
        self.create_guest_main_rs()
        self.create_guest_lib_rs()

    def create_root_cargo_toml(self):
        buffer = io.StringIO()
        buffer.write(
            """[package]
name = "jolt-host"
version = "0.1.0"
edition = "2021"

[workspace]
members = [ "guest" ]

[profile.release]
debug = 0
codegen-units = 1
lto = "fat"

[dependencies]
clap = { version = "4.0", features = ["derive", "env"] }
"""
        )

        if self.requires_fuzzer_utils:
            buffer.write(f'fuzzer_utils = {{ path = "{self.zkvm_path}/fuzzer_utils" }}\n')

        buffer.write(
            f"""jolt-sdk = {{ path = "{self.zkvm_path}/jolt-sdk", features = ["host"] }}
guest = {{ package = "jolt-guest", path = "./guest" }}
"""  # noqa: E501
        )

        if self.commit_or_branch in [
            "55b9830a3944dde55d33a55c42522b81dd49f87a",
            "42de0ca1f581dd212dda7ff44feee806556531d2",
            "85bf51da10efa9c679c35ffc1a8d45cc6cb1c788",
            "e9caa23565dbb13019afe61a2c95f51d1999e286",
        ]:
            buffer.write('ark-serialize = "0.5.0"\n')

        if self.commit_or_branch in [
            "20ac6eb526af383e7b597273990b5e4b783cc2a6",
            "70c77337426615b67191b301e9175e2bb093830d",
            "55b9830a3944dde55d33a55c42522b81dd49f87a",
            "42de0ca1f581dd212dda7ff44feee806556531d2",
            "85bf51da10efa9c679c35ffc1a8d45cc6cb1c788",
            "e9caa23565dbb13019afe61a2c95f51d1999e286",
        ]:
            buffer.write(
                """
[features]
icicle = ["jolt-sdk/icicle"]
"""
            )

        buffer.write("\n")
        buffer.write(f"{self.patch_crates_io_section}")

        create_file(self.root / "Cargo.toml", buffer.getvalue())

    def create_root_rust_toolchain(self):
        create_file(
            self.root / "rust-toolchain.toml",
            f"""[toolchain]
channel = "{get_rust_toolchain_version(self.commit_or_branch)}"
targets = ["riscv32im-unknown-none-elf"]
profile    = "minimal"
components = ["cargo", "rustc", "clippy", "rustfmt"]
""",
        )

    def create_host_main_rs(self):
        buffer = io.StringIO()

        if self.requires_fuzzer_utils:
            buffer.write("use fuzzer_utils;\n")

        buffer.write(
            """use clap::Parser;
use std::time::Instant;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
        """
        )

        if self.is_trace_collection:
            buffer.write("    #[clap(long)]\n")
            buffer.write("    trace: bool,\n")
            buffer.write("\n")

        if self.is_fault_injection:
            buffer.write('    #[arg(long, requires_all=["inject_step", "inject_kind", "seed"])]\n')
            buffer.write("    #[clap(long)]\n")
            buffer.write("    inject: bool,\n\n")

            buffer.write("    #[clap(long)]\n")
            buffer.write("    seed: Option<u64>,\n\n")

            buffer.write("    #[clap(long)]\n")
            buffer.write("    inject_step: Option<u64>,\n\n")

            buffer.write("    #[clap(long)]\n")
            buffer.write("    inject_kind: Option<String>,\n\n")

        for e in self.circuit_candidate.inputs:
            buffer.write("\n")
            buffer.write("    #[clap(long)]\n")
            buffer.write(f"    {e.name}: {ir_type_to_str(e.ty_hint)},\n")

        buffer.write(
            """}

pub fn main() {

    let args = Args::parse();
"""
        )

        if self.is_trace_collection:
            buffer.write("    fuzzer_utils::set_trace_logging(args.trace);\n")

        if self.is_fault_injection:
            buffer.write("    fuzzer_utils::set_injection(args.inject);\n")
            buffer.write("    if args.inject {\n")
            buffer.write("        fuzzer_utils::set_seed(args.seed.unwrap());\n")
            buffer.write("        fuzzer_utils::set_injection_step(args.inject_step.unwrap());\n")
            buffer.write("        fuzzer_utils::set_injection_kind(args.inject_kind.unwrap());\n")
            buffer.write("        fuzzer_utils::disable_assertions();\n")
            buffer.write("    } else {\n")
            buffer.write("        fuzzer_utils::enable_assertions();\n")
            buffer.write("    }\n\n")

        buffer.write(f"    let circuit_inputs: [u32; {len(self.circuit_candidate.inputs)}] = [\n")
        for e in self.circuit_candidate.inputs:
            buffer.write(f"        args.{e.name} as u32,\n")
        buffer.write("    ];\n")

        buffer.write(
            """
    println!(
        "<record>{{\\
            \\"context\\":\\"Compiler\\", \\
            \\"status\\":\\"start\\"\\
        }}</record>"
    );
    let timer = Instant::now();

    let target_dir = "/tmp/jolt-guest-targets";
    let mut program = guest::compile_circuits(target_dir);

    println!(
        "<record>{{\\
            \\"context\\":\\"Compiler\\", \\
            \\"status\\":\\"success\\", \\
            \\"time\\":\\"{:.2?}\\"\\
        }}</record>",
        timer.elapsed()
    );

    println!(
        "<record>{{\\
            \\"context\\":\\"Preprocessing\\", \\
            \\"status\\":\\"start\\"\\
        }}</record>"
    );
    let timer = Instant::now();
"""
        )

        if self.commit_or_branch in [
            "55b9830a3944dde55d33a55c42522b81dd49f87a",
            "42de0ca1f581dd212dda7ff44feee806556531d2",
            "85bf51da10efa9c679c35ffc1a8d45cc6cb1c788",
            "e9caa23565dbb13019afe61a2c95f51d1999e286",
        ]:
            buffer.write(
                "    let prover_preprocessing = "
                "guest::preprocess_prover_circuits(&program);\n"
                "    let verifier_preprocessing = "
                "guest::preprocess_verifier_circuits(&program);\n"
            )
        else:
            buffer.write(
                "    let prover_preprocessing = "
                "guest::preprocess_prover_circuits(&mut program);\n"
                "    let verifier_preprocessing = "
                "guest::verifier_preprocessing_from_prover_circuits(&prover_preprocessing);\n"
            )

        buffer.write(
            """
    let prove_circuits = guest::build_prover_circuits(program, prover_preprocessing);
    let verify_circuits = guest::build_verifier_circuits(verifier_preprocessing);

    println!(
        "<record>{{\\
            \\"context\\":\\"Preprocessing\\", \\
            \\"status\\":\\"success\\", \\
            \\"time\\":\\"{:.2?}\\"\\
        }}</record>",
        timer.elapsed()
    );

    println!(
        "<record>{{\\
            \\"context\\":\\"Prover\\", \\
            \\"status\\":\\"start\\"\\
        }}</record>"
    );
    let timer = Instant::now();

"""
        )

        if self.commit_or_branch in [
            "55b9830a3944dde55d33a55c42522b81dd49f87a",
            "42de0ca1f581dd212dda7ff44feee806556531d2",
            "20ac6eb526af383e7b597273990b5e4b783cc2a6",
            "70c77337426615b67191b301e9175e2bb093830d",
            "85bf51da10efa9c679c35ffc1a8d45cc6cb1c788",
            "e9caa23565dbb13019afe61a2c95f51d1999e286",
        ]:
            buffer.write("    let (output, proof) = prove_circuits(\n")
        else:
            buffer.write("    let (output, proof, program_io) = prove_circuits(\n")

        for _ in self.circuits:
            buffer.write("        circuit_inputs.clone(),\n")
        buffer.write("    );\n")

        buffer.write(
            """
    println!(
        "<record>{{\\
            \\"context\\":\\"Prover\\", \\
            \\"status\\":\\"success\\", \\
            \\"output\\":\\"{output}\\", \\
            \\"time\\":\\"{:.2?}\\"\\
        }}</record>",
        timer.elapsed()
    );
"""
        )

        if self.is_fault_injection:
            buffer.write("    if args.inject { fuzzer_utils::enable_assertions(); }\n")

        buffer.write(
            """
    println!(
        "<record>{{\\
            \\"context\\":\\"Verifier\\", \\
            \\"status\\":\\"start\\"\\
        }}</record>"
    );
    let timer = Instant::now();

"""
        )

        buffer.write("    if !verify_circuits(\n")
        for _ in self.circuits:
            buffer.write("        circuit_inputs.clone(),\n")
        buffer.write("        output,\n")

        if self.commit_or_branch in [
            "57ea518d6d9872fb221bf6ac97df1456a5494cf2",
            "20ac6eb526af383e7b597273990b5e4b783cc2a6",
            "70c77337426615b67191b301e9175e2bb093830d",
            "55b9830a3944dde55d33a55c42522b81dd49f87a",
            "42de0ca1f581dd212dda7ff44feee806556531d2",
            "85bf51da10efa9c679c35ffc1a8d45cc6cb1c788",
            "e9caa23565dbb13019afe61a2c95f51d1999e286",
        ]:
            pass  # no io device for these commits
        else:
            buffer.write("        program_io.panic,\n")

        buffer.write("        proof,\n")
        buffer.write("    ) {\n")
        buffer.write('        panic!("verifier failed!");\n')
        buffer.write("    }\n")

        buffer.write(
            """
    println!(
        "<record>{{\\
            \\"context\\":\\"Verifier\\", \\
            \\"status\\":\\"success\\", \\
            \\"time\\":\\"{:.2?}\\"\\
        }}</record>",
        timer.elapsed()
    );
}
"""
        )

        create_file(self.root / "src" / "main.rs", buffer.getvalue())

    def create_guest_cargo_toml(self):
        create_file(
            self.root / "guest" / "Cargo.toml",
            f"""[package]
name = "jolt-guest"
version = "0.1.0"
edition = "2021"

[features]
guest = []

[dependencies]
jolt = {{ package = "jolt-sdk", path = "{self.zkvm_path}/jolt-sdk" }}
""",
        )

    def create_guest_main_rs(self):
        create_file(
            self.root / "guest" / "src" / "main.rs",
            """#![cfg_attr(feature = "guest", no_std)]
#![no_main]

#[allow(unused_imports)]
use jolt_guest::*;

""",
        )

    def create_guest_lib_rs(self):

        buffer = io.StringIO()

        buffer.write('#![cfg_attr(feature = "guest", no_std)]\n')
        buffer.write("#![allow(unconditional_panic)]\n")
        buffer.write("#![allow(arithmetic_overflow)]\n")

        # NOTE: it is unclear to me why we need this as the program
        #       is compiled to riscv and not x86, but the warning says
        #       stuff about sub registers for x86.
        buffer.write("#![allow(asm_sub_register)]\n\n")

        for circuit in self.circuits:
            buffer.write(CircIL2UnsafeRustEmitter().run(circuit))
            buffer.write("\n")
        buffer.write("\n")

        buffer.write("#[jolt::provable(guest_only)]\n")
        buffer.write("fn circuits(\n")
        input_arr_type = f"[u32; {len(self.circuit_candidate.inputs)}]"
        for circuit in self.circuits:
            buffer.write(f"    {circuit.name}_args: {input_arr_type},\n")
        buffer.write(f") -> {RUST_GUEST_RETURN_TYPE} {{\n")

        buffer.write("\n")
        buffer.write("    //\n")
        buffer.write("    // Parse Inputs and call Circuits\n")
        buffer.write("    //\n\n")

        for circuit in self.circuits:
            buffer.write(f"    // -- {circuit.name} --\n")
            for idx, circuit_input in enumerate(circuit.inputs):
                in_var = f"{circuit.name}_{circuit_input.name}"
                ir_type = ir_type_to_str(circuit_input.ty_hint)
                arg_access = f"{circuit.name}_args[{idx}]"
                if circuit_input.ty_hint == IRType.Bool:
                    buffer.write(f"    let {in_var}: {ir_type} = {arg_access} == 0_u32;\n")
                else:
                    buffer.write(f"    let {in_var}: {ir_type} = {arg_access};\n")
            buffer.write("\n")

        def helper_commit_and_exit(value: int, is_end: bool) -> list[str]:
            if is_end:
                return [f"{value}_u32"]
            else:
                return [f"return {value}_u32;"]

        stream_circuit_output_and_compare_routine(
            buffer,
            self.circuits,
            RUST_GUEST_CORRECT_VALUE,
            helper_commit_and_exit,
        )

        buffer.write("}\n")

        create_file(self.root / "guest" / "src" / "lib.rs", buffer.getvalue())


# ---------------------------------------------------------------------------- #
