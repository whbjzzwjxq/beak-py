import io
from pathlib import Path

from circil.ir.node import Circuit
from openvm_fuzzer.settings import (
    RUST_GUEST_CORRECT_VALUE,
)
from zkvm_fuzzer_utils.file import create_file
from zkvm_fuzzer_utils.project import AbstractCircuitProjectGenerator
from zkvm_fuzzer_utils.rust.common import (
    ir_type_to_str,
    stream_circuit_output_and_compare_routine,
)
from zkvm_fuzzer_utils.rust.ir2rust import CircIL2UnsafeRustEmitter

# ---------------------------------------------------------------------------- #
#                            Openvm stark sdk helper                           #
# ---------------------------------------------------------------------------- #

__SINGLETON_STARK_SDK_FROM_OPENVM_WORKSPACE: str | None = None


def _set_openvm_stark_sdk_from_openvm(value: str):
    """This function is used to set the singleton for testing purposes!"""
    global __SINGLETON_STARK_SDK_FROM_OPENVM_WORKSPACE
    __SINGLETON_STARK_SDK_FROM_OPENVM_WORKSPACE = value


def get_openvm_stark_sdk_from_openvm_workspace_cargo_toml(zkvm_path: Path) -> str:
    """Parses the Cargo.toml file of the openvm repository and extracts
    the openvm-stark-sdk dependency line. It is then saved into a singleton
    and never parsed again.

    NOTE: It expects the entry to be a one liner!
    """

    global __SINGLETON_STARK_SDK_FROM_OPENVM_WORKSPACE

    if __SINGLETON_STARK_SDK_FROM_OPENVM_WORKSPACE is None:
        cargo_toml = zkvm_path / "Cargo.toml"
        lines = cargo_toml.read_text().split("\n")
        for line in lines:
            if line.startswith("openvm-stark-sdk"):
                __SINGLETON_STARK_SDK_FROM_OPENVM_WORKSPACE = line
                break  # stop searching

    assert (
        __SINGLETON_STARK_SDK_FROM_OPENVM_WORKSPACE
    ), f"unable to find 'openvm-stark-sdk' entry in {zkvm_path}"

    return __SINGLETON_STARK_SDK_FROM_OPENVM_WORKSPACE


# ---------------------------------------------------------------------------- #
#                           Circuit project generator                          #
# ---------------------------------------------------------------------------- #


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

    def create_host_cargo_toml(self):
        buffer = io.StringIO()
        buffer.write(
            """[package]
name = "openvm-host"
version = "0.1.0"
edition = "2021"

[dependencies]
clap = { version = "4.0", features = ["derive", "env"] }
"""
        )

        if self.requires_fuzzer_utils:
            buffer.write(f'fuzzer_utils = {{ path = "{self.zkvm_path}/crates/fuzzer_utils" }}\n')

        buffer.write(
            f"""openvm = {{ path = "{self.zkvm_path}/crates/toolchain/openvm" }}
openvm-sdk = {{ path = "{self.zkvm_path}/crates/sdk" }}
openvm-build = {{ path = "{self.zkvm_path}/crates/toolchain/build" }}
openvm-platform = {{ path = "{self.zkvm_path}/crates/toolchain/platform" }}
openvm-transpiler = {{ path = "{self.zkvm_path}/crates/toolchain/transpiler" }}

{get_openvm_stark_sdk_from_openvm_workspace_cargo_toml(self.zkvm_path)}
"""
        )

        create_file(
            self.root / "host" / "Cargo.toml",
            buffer.getvalue(),
        )

    def create_host_main_rs(self):
        buffer = io.StringIO()

        if self.requires_fuzzer_utils:
            buffer.write("use fuzzer_utils;\n")

        buffer.write(
            """use std::sync::Arc;

use openvm_build::GuestOptions;
use openvm_sdk::{
    config::{AppConfig, SdkVmConfig},
    Sdk, StdIn,
};
use openvm_stark_sdk::config::FriParameters;

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

    // SDK VM Config
    let vm_config = SdkVmConfig::builder()
       .system(Default::default())
       .rv32i(Default::default())
       .rv32m(Default::default())
       .io(Default::default())
       .build();
"""
        )

        for e in self.circuit_candidate.inputs:
            buffer.write(f"    let {e.name} = args.{e.name};\n")

        buffer.write(
            """
    let sdk = Sdk::new();

    let guest_opts = GuestOptions::default();
    let target_path = "guest";
    let elf = sdk.build(
        guest_opts,
        &vm_config,
        target_path,
        &Default::default(),
        None // If None, "openvm-init.rs" is used
    ).expect("guest build");

    let exe = sdk.transpile(elf, vm_config.transpiler()).expect("guest transpile");

    let mut stdin = StdIn::default();
"""
        )

        for circuit in self.circuits:
            buffer.write(f"    // -- {circuit.name} --\n")
            for e in self.circuit_candidate.inputs:
                buffer.write(f"    stdin.write(&{e.name});\n")
            buffer.write("\n")

        buffer.write(
            """
    let app_log_blowup = 2;
    let app_fri_params = FriParameters::standard_with_100_bits_conjectured_security(app_log_blowup);
    let app_config = AppConfig::new(app_fri_params, vm_config);

    let app_committed_exe = sdk.commit_app_exe(app_fri_params, exe).expect("commit app exe");

    let app_pk = Arc::new(sdk.app_keygen(app_config).expect("app keygen"));

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
            \\"context\\":\\"Prover\\", \\
            \\"status\\":\\"start\\"\\
        }}</record>"
    );
    let timer = Instant::now();

    let proof = sdk.generate_app_proof(
        app_pk.clone(),
        app_committed_exe.clone(),
        stdin.clone()
    ).expect("prove");

    println!(
        "<record>{{\\
            \\"context\\":\\"Prover\\", \\
            \\"status\\":\\"success\\",\\
            \\"output\\":\\"{:?}\\", \\
            \\"time\\":\\"{:.2?}\\"\\
        }}</record>",
        proof.user_public_values.public_values,
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

    let app_vk = app_pk.get_app_vk();
    sdk.verify_app_proof(&app_vk, &proof).expect("verify");

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
name = "openvm-guest"
version = "0.1.0"
edition = "2021"

[dependencies]
openvm = {{ path = "{self.zkvm_path}/crates/toolchain/openvm", features = ["std"] }}
""",
        )

    def create_guest_main_rs(self):
        buffer = io.StringIO()

        buffer.write("#![allow(unused_unsafe)]\n")
        buffer.write("#![allow(unconditional_panic)]\n")
        buffer.write("#![allow(arithmetic_overflow)]\n\n")

        buffer.write("use openvm::io::{read, reveal_u32};\n")
        buffer.write("openvm::entry!(main);\n\n")

        for circuit in self.circuits:
            buffer.write(CircIL2UnsafeRustEmitter().run(circuit))
            buffer.write("\n")

        buffer.write(
            """
fn main() {
"""
        )

        buffer.write("\n")
        buffer.write("    //\n")
        buffer.write("    // Parse Inputs and call Circuits\n")
        buffer.write("    //\n\n")

        # parse input variables
        for circuit in self.circuits:
            buffer.write(f"    // -- {circuit.name} --\n")
            for parameter in circuit.inputs:
                var_name = f"{circuit.name}_{parameter.name}"
                var_type = ir_type_to_str(parameter.ty_hint)
                buffer.write(f"    let {var_name}: {var_type} = read();\n")
            buffer.write("\n")

        def helper_commit_and_exit(value: int, is_end: bool) -> list[str]:
            if is_end:
                return [f"reveal_u32({value}_u32, 0);"]
            else:
                return [f"reveal_u32({value}_u32, 0);", "return; // abort"]

        stream_circuit_output_and_compare_routine(
            buffer,
            self.circuits,
            RUST_GUEST_CORRECT_VALUE,
            helper_commit_and_exit,
        )

        buffer.write("}\n")

        create_file(self.root / "guest" / "src" / "main.rs", buffer.getvalue())
