import io
from pathlib import Path

from circil.ir.node import Circuit
from pico_fuzzer.settings import (
    RUST_GUEST_CORRECT_VALUE,
)
from zkvm_fuzzer_utils.file import create_file
from zkvm_fuzzer_utils.project import AbstractCircuitProjectGenerator
from zkvm_fuzzer_utils.rust.common import (
    ir_type_to_str,
    stream_circuit_output_and_compare_routine,
)
from zkvm_fuzzer_utils.rust.ir2rust import CircIL2UnsafeRustEmitter


class CircuitProjectGenerator(AbstractCircuitProjectGenerator):
    def __init__(
        self,
        root: Path,
        zkvm_path: Path,
        circuits: list[Circuit],
        fault_injection: bool,
        trace_collection: bool,
    ):
        super().__init__(root, zkvm_path, circuits, fault_injection, trace_collection)

    def create(self):
        self.create_app_cargo_toml()
        self.create_app_main_rs()
        self.create_prover_cargo_toml()
        self.create_prover_main_rs()
        self.create_lib_cargo_toml()
        self.create_lib_lib_rs()

    def create_lib_cargo_toml(self):
        create_file(
            self.root / "lib" / "Cargo.toml",
            """[package]
name = "lib"
version = "1.0.0"
edition = "2024"
""",
        )

    def create_lib_lib_rs(self):
        create_file(
            self.root / "lib" / "src" / "lib.rs",
            """use std::fs;
pub fn load_elf(path: &str) -> Vec<u8> {
    fs::read(path).unwrap_or_else(|err| {
        panic!("Failed to load ELF file from {}: {}", path, err);
    })
}
""",
        )

    def create_app_cargo_toml(self):
        create_file(
            self.root / "app" / "Cargo.toml",
            f"""[package]
name = "pico-circuit"
version = "1.0.0"
edition = "2024"

[dependencies]
pico-sdk = {{ path = "{self.zkvm_path}/sdk/sdk" }}
getrandom = {{ version = "0.2.15", features = ["custom"] }}
""",
        )

    def create_app_main_rs(self):
        buffer = io.StringIO()

        buffer.write(
            """#![no_main]
#![allow(unused_unsafe)]
#![allow(unconditional_panic)]
#![allow(arithmetic_overflow)]

use pico_sdk::io::{commit_bytes, read_as};

pico_sdk::entrypoint!(main);

"""
        )

        for circuit in self.circuits:
            buffer.write(CircIL2UnsafeRustEmitter().run(circuit))
            buffer.write("\n")

        buffer.write(
            """
pub fn main() {
"""
        )

        for circuit in self.circuits:
            for parameter in circuit.inputs:
                var_name = f"{circuit.name}_{parameter.name}"
                var_type = ir_type_to_str(parameter.ty_hint)
                buffer.write(f"    let {var_name}: {var_type} = read_as();\n")
        buffer.write("\n")

        def helper_commit_and_exit(value: int, is_end: bool) -> list[str]:
            if is_end:
                return [f"commit_bytes(&({value}_u32.to_le_bytes()));"]
            else:
                return [f"commit_bytes(&({value}_u32.to_le_bytes()));", "return; // abort"]

        stream_circuit_output_and_compare_routine(
            buffer, self.circuits, RUST_GUEST_CORRECT_VALUE, helper_commit_and_exit
        )

        buffer.write("}")

        create_file(
            self.root / "app" / "src" / "main.rs",
            buffer.getvalue(),
        )

    def create_prover_cargo_toml(self):
        buffer = io.StringIO()
        buffer.write(
            f"""[package]
name = "pico-prover"
version = "1.0.0"
edition = "2024"

[dependencies]
pico-sdk = {{ path = "{self.zkvm_path}/sdk/sdk" }}
lib = {{ path = "../lib" }}
clap = {{ version = "4.0", features = ["derive", "env"] }}
"""
        )

        if self.requires_fuzzer_utils:
            buffer.write(f'fuzzer_utils = {{ path = "{self.zkvm_path}/fuzzer_utils" }}\n')

        create_file(
            self.root / "prover" / "Cargo.toml",
            buffer.getvalue(),
        )

    def create_prover_main_rs(self):
        buffer = io.StringIO()

        if self.requires_fuzzer_utils:
            buffer.write("use fuzzer_utils;\n")

        buffer.write(
            """use lib::load_elf;
use pico_sdk::{client::DefaultProverClient, init_logger};
use clap::Parser;
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
            """
}

fn main() {
    // Initialize logger
    init_logger();

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
            buffer.write("    }\n")

        buffer.write(
            """
    println!(
        "<record>{{\\
            \\"context\\":\\"Setup\\", \\
            \\"status\\":\\"start\\"\\
        }}</record>"
    );
    let timer = Instant::now();

    // Load the ELF file
    let elf = load_elf("../app/elf/riscv32im-pico-zkvm-elf");

    // Initialize the prover client
    let client = DefaultProverClient::new(&elf);
    let mut stdin_builder = client.new_stdin_builder();

    // Set up input and generate proof
"""
        )

        for circuit in self.circuits:
            buffer.write(f"    // -- {circuit.name} --\n")
            for e in self.circuit_candidate.inputs:
                buffer.write(f"    stdin_builder.write(&args.{e.name});\n")
            buffer.write("\n")

        buffer.write(
            """
    println!(
        "<record>{{\\
            \\"context\\":\\"Setup\\", \\
            \\"status\\":\\"success\\", \\
            \\"time\\":\\"{:.2?}\\"\\
        }}</record>",
        timer.elapsed()
    );

    println!(
        "<record>{{\\
            \\"context\\":\\"Prover & Verifier\\", \\
            \\"status\\":\\"start\\"\\
        }}</record>"
    );
    let timer = Instant::now();

    // Generate long proof
    // let (riscv_proof, embed_proof) = client.prove(stdin_builder).expect("prove");

    // Generate short proof and verification
    let riscv_proof = client.prove_fast(stdin_builder).expect("prove & verify");

    // decode public values
    let public_buffer = riscv_proof.pv_stream.clone().unwrap();

    println!(
        "<record>{{\\
            \\"context\\":\\"Prover & Verifier\\", \\
            \\"status\\":\\"success\\", \\
            \\"output\\":\\"{:?}\\", \\
            \\"time\\":\\"{:.2?}\\"\\
        }}</record>",
        public_buffer,
        timer.elapsed()
    );

    // Verification IF long prove is enabled
    // client.verify(&(riscv_proof, embed_proof)).expect("verify");
}
"""
        )

        create_file(
            self.root / "prover" / "src" / "main.rs",
            buffer.getvalue(),
        )
