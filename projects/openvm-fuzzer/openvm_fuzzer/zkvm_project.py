import io
from pathlib import Path
from jinja2 import Environment, FileSystemLoader

from beak_core.types import FuzzingInstSeqInstance
from zkvm_fuzzer_utils.file import create_file
from zkvm_fuzzer_utils.project import AbstractProjectGenerator

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


class CircuitProjectGenerator(AbstractProjectGenerator):
    commit_or_branch: str
    instance: FuzzingInstSeqInstance

    def __init__(
        self,
        root: Path,
        zkvm_path: Path,
        instance: FuzzingInstSeqInstance,
        fault_injection: bool,
        trace_collection: bool,
        commit_or_branch: str,
    ):
        super().__init__(root, zkvm_path)
        self.instance = instance
        self._fault_injection = fault_injection
        self._trace_collection = trace_collection
        self.commit_or_branch = commit_or_branch
        self.template_env = Environment(
            loader=FileSystemLoader(Path(__file__).parent / "templates"),
            trim_blocks=True,
            lstrip_blocks=True,
        )

    @property
    def is_fault_injection(self) -> bool:
        return self._fault_injection

    @property
    def is_trace_collection(self) -> bool:
        return self._trace_collection

    @property
    def requires_fuzzer_utils(self) -> bool:
        return self.is_fault_injection or self.is_trace_collection

    def render_template(self, template_name: str, **kwargs) -> str:
        template = self.template_env.get_template(template_name)
        return template.render(**kwargs)

    def create(self):
        self.create_root_cargo_toml()
        self.create_host_cargo_toml()
        self.create_host_main_rs()
        self.create_guest_cargo_toml()
        self.create_guest_main_rs()

    def create_root_cargo_toml(self):
        content = self.render_template("root_cargo.toml.j2")
        create_file(self.root / "Cargo.toml", content)

    def create_host_cargo_toml(self):
        content = self.render_template(
            "host_cargo.toml.j2",
            requires_fuzzer_utils=self.requires_fuzzer_utils,
            zkvm_path=self.zkvm_path,
            openvm_stark_sdk_dep=get_openvm_stark_sdk_from_openvm_workspace_cargo_toml(
                self.zkvm_path
            ),
        )
        create_file(self.root / "host" / "Cargo.toml", content)

    def create_host_main_rs(self):
        # Initial regs info for host to push into stdin
        content = self.render_template(
            "host_main.rs.j2",
            requires_fuzzer_utils=self.requires_fuzzer_utils,
            is_trace_collection=self.is_trace_collection,
            is_fault_injection=self.is_fault_injection,
            initial_regs=self.instance.initial_regs,
        )
        create_file(self.root / "host" / "src" / "main.rs", content)

    def create_guest_cargo_toml(self):
        content = self.render_template("guest_cargo.toml.j2", zkvm_path=self.zkvm_path)
        create_file(self.root / "guest" / "Cargo.toml", content)

    def create_guest_main_rs(self):
        content = self.render_template(
            "guest_main.rs.j2",
            instructions=self.instance.instructions,
            initial_regs=self.instance.initial_regs,
        )
        create_file(self.root / "guest" / "src" / "main.rs", content)
