import argparse
import logging
from abc import ABC, abstractmethod
from datetime import datetime
from pathlib import Path

from zkvm_fuzzer_utils.file import create_dir


class FuzzerClient(ABC):
    """Base class for a zkvm fuzzer client. Handles environment setup,
    argument parsing, and orchestration of Loop 1 (Expansion) and Loop 2 (Injection).
    """

    backend_name: str
    logger_prefix: str
    allowed_commits_and_branches: list[str]

    # Common State
    verbosity: int
    seed: float
    out_dir: Path | None
    zkvm_dir: Path | None
    commit_or_branch: str

    # Logic Switches (Defaults)
    trace_collection: bool = True
    zkvm_modification: bool = True
    fault_injection: bool = False

    argument_parser: argparse.ArgumentParser
    args: argparse.Namespace

    def __init__(
        self, backend_name: str, logger_prefix: str, allowed_commits_and_branches: list[str]
    ):
        if len(allowed_commits_and_branches) == 0:
            raise ValueError("Fuzzer client needs at least 1 commit or branch!")

        self.backend_name = backend_name
        self.logger_prefix = logger_prefix
        self.allowed_commits_and_branches = allowed_commits_and_branches
        self.commit_or_branch = self.allowed_commits_and_branches[0]

        self.verbosity = 0
        self.seed = 0
        self.out_dir = None
        self.zkvm_dir = None

        self.argument_parser = self.generate_parser()
        self.args = argparse.Namespace()

    def extract_out_dir(self) -> Path:
        out_dir = Path(self.args.out).absolute()
        if out_dir.is_file():
            self.argument_parser.error("--out requires to be a directory, found a file!")
        create_dir(out_dir)
        return out_dir

    def extract_zkvm_dir(self) -> Path:
        if self.args.zkvm:
            zkvm_dir = Path(self.args.zkvm).absolute()
            if zkvm_dir.is_file():
                self.argument_parser.error("--zkvm requires to be a directory, found a file!")
            if not zkvm_dir.is_dir():
                create_dir(zkvm_dir)
            return zkvm_dir
        self.argument_parser.error(
            f"{self.backend_name} fuzzer requires path to zkvm git repository ('--zkvm')!"
        )

    def set_logger_config(self):
        logger = logging.getLogger("fuzzer")
        logger.propagate = False
        verbosity = min(max(0, self.verbosity), 2)
        logging_level = {0: logging.ERROR, 1: logging.INFO, 2: logging.DEBUG}.get(
            verbosity, logging.ERROR
        )
        logger.setLevel(logging.DEBUG)

        console_handler = logging.StreamHandler()
        formatter = logging.Formatter(
            f"[{self.logger_prefix} %(asctime)s ~ %(levelname)s]: %(message)s"
        )
        console_handler.setFormatter(formatter)
        console_handler.setLevel(logging_level)
        logger.addHandler(console_handler)

    def add_shared_flags(self, subparser: argparse.ArgumentParser):
        """Flags shared between loop1 and loop2"""
        subparser.add_argument("-v", "--verbosity", default=1, choices=[0, 1, 2], type=int)
        subparser.add_argument(
            "-s", "--seed", metavar="SEED_NUM", type=float, help="seed for randomness"
        )
        subparser.add_argument(
            "-o",
            "--out",
            metavar="OUTPUT_DIR",
            type=str,
            default=f"out/{self.backend_name.lower()}",
            help="output directory",
        )
        subparser.add_argument(
            "-z", "--zkvm", metavar="ZKVM_DIR", type=str, help="path to the zkvm repository"
        )
        subparser.add_argument(
            "--commit-or-branch",
            type=str,
            choices=self.allowed_commits_and_branches,
            default=self.commit_or_branch,
            help="zkVM commit/branch to use",
        )

    def generate_parser(self) -> argparse.ArgumentParser:
        parser = argparse.ArgumentParser(
            prog=f"{self.backend_name} Fuzzer",
            description=f"{self.backend_name} zkVM Dual-Loop Fuzzer (Expansion & Injection)",
        )
        subparsers = parser.add_subparsers(required=True, dest="command")

        # --- Subcommand: install ---
        install_subparser = subparsers.add_parser("install", help="Install and modify zkVM source")
        install_subparser.add_argument("zkvm", help="target installation path")
        install_subparser.add_argument(
            "--no-modification",
            action="store_false",
            dest="zkvm_modification",
            help="Disable source modification (no trace/fault hooks)",
        )
        install_subparser.add_argument(
            "--commit-or-branch",
            type=str,
            choices=self.allowed_commits_and_branches,
            default=self.commit_or_branch,
        )
        install_subparser.add_argument("-v", "--verbosity", default=1, choices=[0, 1, 2], type=int)

        # --- Subcommand: loop1 (Seed Expansion) ---
        l1_parser = subparsers.add_parser(
            "loop1", help="Loop 1: Expand seeds using libAFL and Trace feedback"
        )
        self.add_shared_flags(l1_parser)
        l1_parser.add_argument(
            "--seeds", type=str, required=True, help="Path to JSONLines seeds file"
        )
        l1_parser.add_argument(
            "--iterations", type=int, default=1000000, help="Number of expansion steps"
        )

        # --- Subcommand: loop2 (Fault Injection) ---
        l2_parser = subparsers.add_parser(
            "loop2", help="Loop 2: Perform fault injection on expanded corpus"
        )
        self.add_shared_flags(l2_parser)
        l2_parser.add_argument(
            "--input-corpus", type=str, required=True, help="Path to expanded seeds from Loop 1"
        )

        return parser

    def start(self):
        self.args = self.argument_parser.parse_args()
        self.verbosity = self.args.verbosity
        self.set_logger_config()

        # Command Dispatch
        match self.args.command:
            case "install":
                self.zkvm_dir = Path(self.args.zkvm).absolute()
                self.commit_or_branch = self.args.commit_or_branch
                self.zkvm_modification = self.args.zkvm_modification
                self.install()
            case "loop1":
                self.setup_runtime_env()
                self.fault_injection = False  # Ensure no injection in Loop 1
                self.run_loop1()
            case "loop2":
                self.setup_runtime_env()
                self.fault_injection = True  # Enable injection in Loop 2
                self.run_loop2()

    def setup_runtime_env(self):
        """Common setup for loop1 and loop2"""
        self.zkvm_dir = self.extract_zkvm_dir()
        self.out_dir = self.extract_out_dir()
        self.commit_or_branch = self.args.commit_or_branch
        self.seed = self.args.seed if self.args.seed is not None else datetime.now().timestamp()

    @property
    def enable_fault_injection(self) -> bool:
        return self.fault_injection

    @property
    def enable_trace_collection(self) -> bool:
        return self.trace_collection

    @property
    def enable_zkvm_modification(self) -> bool:
        return self.zkvm_modification

    @abstractmethod
    def install(self):
        """Switch to commit and apply trace/fault patches"""
        raise NotImplementedError()

    @abstractmethod
    def run_loop1(self):
        """Execute seed expansion logic (libAFL)"""
        raise NotImplementedError()

    @abstractmethod
    def run_loop2(self):
        """Execute fault injection logic on expanded corpus"""
        raise NotImplementedError()
