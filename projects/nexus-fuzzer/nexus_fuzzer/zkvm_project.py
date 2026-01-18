import io
from pathlib import Path

from circil.ir.node import Circuit
from circil.ir.type import IRType
from nexus_fuzzer.settings import (
    RUST_GUEST_CORRECT_VALUE,
    RUST_GUEST_RETURN_TYPE,
    get_riscv_target,
    get_rust_toolchain_version,
)
from zkvm_fuzzer_utils.file import create_file
from zkvm_fuzzer_utils.project import AbstractCircuitProjectGenerator
from zkvm_fuzzer_utils.rust.common import (
    ir_type_to_str,
    stream_circuit_output_and_compare_routine,
)
from zkvm_fuzzer_utils.rust.ir2rust import CircIL2UnsafeRustEmitter


class CircuitProjectGenerator(AbstractCircuitProjectGenerator):
    commit_or_branch: str

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
        self.commit_or_branch = commit_or_branch

    def create(self):
        self.create_root_cargo_toml()
        self.create_root_rust_toolchain()
        self.create_guest_cargo_config_toml()
        self.create_host_cargo_toml()
        self.create_host_main_rs()
        self.create_guest_cargo_toml()
        self.create_guest_main_rs()

    def create_root_cargo_toml(self):
        create_file(
            self.root / "Cargo.toml",
            """[workspace]
members = [
    "host",
    "guest",
]
default-members = [ "host" ]

resolver = "2"
""",
        )

    def create_root_rust_toolchain(self):
        create_file(
            self.root / "rust-toolchain.toml",
            f"""[toolchain]
channel = "{get_rust_toolchain_version(self.commit_or_branch)}"
components = ["rustfmt", "rust-src"]
profile = "minimal"
""",
        )

    def create_guest_cargo_config_toml(self):
        create_file(
            self.root / "guest" / ".cargo" / "config.toml",
            f"""[build]
target = "{get_riscv_target(self.commit_or_branch)}"

[target.{get_riscv_target(self.commit_or_branch)}]
rustflags = [
  "-C", "link-arg=-Tlink.x",
]
""",
        )

    def create_host_cargo_toml(self):
        buffer = io.StringIO()
        buffer.write(
            f"""[package]
name = "nexus-host"
version = "0.1.0"
edition = "2021"
default-run = "nexus-host"

[dependencies]
nexus-sdk = {{ path = "{self.zkvm_path}/sdk" }}
clap = {{ version = "4.0", features = ["derive", "env"] }}
"""
        )

        if self.requires_fuzzer_utils:
            buffer.write(f'fuzzer_utils = {{ path = "{self.zkvm_path}/fuzzer_utils" }}\n')

        create_file(
            self.root / "host" / "Cargo.toml",
            buffer.getvalue(),
        )

    def create_host_main_rs(self):
        buffer = io.StringIO()

        if self.requires_fuzzer_utils:
            buffer.write("use fuzzer_utils;\n")

        buffer.write(
            """use nexus_sdk::{
    compile::{cargo::CargoPackager, Compile, Compiler},
    stwo::seq::Stwo,
    ByGuestCompilation, Local, Prover, Verifiable, Viewable,
};
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
            """}

const PACKAGE: &str = "nexus-guest";

fn main() {
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

        public_input = "&circuit_inputs"
        private_input = "&(" + ", ".join(["circuit_inputs" for _ in self.circuits]) + ")"
        public_input_type = f"[u32; {len(self.circuit_candidate.inputs)}]"
        private_input_type = "(" + ", ".join([public_input_type for _ in self.circuits]) + ")"

        buffer.write(
            """
    println!(
        "<record>{{\\
            \\"context\\":\\"Compiler\\", \\
            \\"status\\":\\"start\\"\\
        }}</record>"
    );
    let timer = Instant::now();

    let mut prover_compiler = Compiler::<CargoPackager>::new(PACKAGE);
    let prover : Stwo<Local> = Stwo::compile(&mut prover_compiler).expect("compile");

    let elf = prover.elf.clone(); // save elf for use with test verification

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
            \\"context\\":\\"Prover\\", \\
            \\"status\\":\\"start\\"\\
        }}</record>"
    );
    let timer = Instant::now();
"""
        )

        buffer.write(
            f"""
    let (view, proof) = prover.prove_with_input::<{private_input_type}, {public_input_type}>(
        {private_input}, {public_input}
    ).expect("prover failed");
"""
        )

        if self.is_fault_injection:
            buffer.write("    if args.inject { fuzzer_utils::enable_assertions(); }\n")

        buffer.write(
            """
    println!(
        ">>>>> Logging\n{}\n<<<<<",
        view.logs().expect("failed to retrieve debug logs").join("")
    );
"""
        )

        buffer.write(
            f"""
    let output = view
        .public_output::<{RUST_GUEST_RETURN_TYPE}>()
        .expect("output retrieval failed");
"""
        )

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

    println!(
        "<record>{{\\
            \\"context\\":\\"Exit Code Check\\", \\
            \\"status\\":\\"start\\"\\
        }}</record>"
    );
    let timer = Instant::now();

    let exit_code = view.exit_code().expect("failed to retrieve exit code");
    println!("exit_code = {:?}", exit_code);
    assert!(exit_code == nexus_sdk::KnownExitCodes::ExitSuccess as u32, "unexpected exit code");

    println!(
        "<record>{{\\
            \\"context\\":\\"Exit Code Check\\", \\
            \\"status\\":\\"success\\", \\
            \\"time\\":\\"{:.2?}\\"\\
        }}</record>",
        timer.elapsed()
    );

    println!(
        "<record>{{\\
            \\"context\\":\\"Verifier\\", \\
            \\"status\\":\\"start\\"\\
        }}</record>"
    );
    let timer = Instant::now();

"""
        )

        buffer.write("    proof.verify_expected::<\n")
        buffer.write(f"        {public_input_type},\n")
        buffer.write(f"        {RUST_GUEST_RETURN_TYPE},\n")
        buffer.write("    >(\n")
        buffer.write(f"        {public_input},\n")
        buffer.write("        nexus_sdk::KnownExitCodes::ExitSuccess as u32,\n")
        buffer.write("        &output,\n")
        buffer.write("        &elf,\n")
        buffer.write("        &[],  // no associated data\n")
        buffer.write('    ).expect("verifier failed");\n')

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
}"""
        )

        create_file(self.root / "host" / "src" / "main.rs", buffer.getvalue())

    def create_guest_cargo_toml(self):
        create_file(
            self.root / "guest" / "Cargo.toml",
            f"""[package]
name = "nexus-guest"
version = "0.1.0"
edition = "2021"

[dependencies]
nexus-rt = {{ path = "{self.zkvm_path}/runtime" }}

[features]
cycles = [] # Enable cycle counting for run command
""",
        )

    def create_guest_main_rs(self):
        buffer = io.StringIO()

        buffer.write('#![cfg_attr(target_arch = "riscv32", no_std, no_main)]\n')
        buffer.write("#![allow(unconditional_panic)]\n")
        buffer.write("#![allow(arithmetic_overflow)]\n\n")

        for circuit in self.circuits:
            buffer.write(CircIL2UnsafeRustEmitter().run(circuit))
            buffer.write("\n")

        # NOTE: first circuit input is public
        c0_var = self.circuits[0].name + "_args"

        buffer.write(
            f"""
#[nexus_rt::public_input({c0_var})]
#[nexus_rt::main]
fn main(
"""
        )

        for circuit in self.circuits:
            args_var = circuit.name + "_args"
            args_type = f"[u32; {len(self.circuit_candidate.inputs)}]"
            buffer.write(f"    {args_var}: {args_type},\n")

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

        buffer.write("}")

        create_file(self.root / "guest" / "src" / "main.rs", buffer.getvalue())
