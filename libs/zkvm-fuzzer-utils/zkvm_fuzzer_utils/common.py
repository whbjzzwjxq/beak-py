import logging
import re
from random import Random

from circil.fuzzer.config import FuzzerConfig
from circil.fuzzer.simple import SimpleCircuitFuzzer
from circil.ir.node import Circuit, Identifier
from circil.ir.type import IRType
from circil.rewrite.rewriter import RuleBasedRewriter
from circil.rewrite.rule import Rule
from circil.rewrite.utils import SimpleRNGUtil
from zkvm_fuzzer_utils.circil import Risc32IMImmediateRepair

logger = logging.getLogger("fuzzer")


# ---------------------------------------------------------------------------- #
#                                  Validators                                  #
# ---------------------------------------------------------------------------- #


def validate_circuits_arguments(circuits: list[Circuit]):
    """Validates the circuit arguments for the zkvm projects that use circuits.

    If one of the following requirements are not met, a `ValueError` is raised:
        - Circuit list size must be between of [2, 12] circuits
        - Circuit require [1, 12] inputs
        - Circuit require [1, 12] outputs
        - Circuits need to be type compatible
    """

    is_valid = True

    len_circuits = len(circuits)
    if len_circuits < 2 or 12 < len_circuits:
        logger.critical(
            f"Circuit list size must be in the interval [2, 12], but was {len_circuits}!"
        )
        is_valid = False

    circuit_candidate = circuits[0]

    len_inputs = len(circuit_candidate.inputs)
    if len_inputs < 1 or 12 < len_inputs:
        logger.critical(
            f"Circuits inputs size must be in the interval [1, 12], but was {len_inputs}!"
        )
        is_valid = False

    len_outputs = len(circuit_candidate.outputs)
    if len_outputs < 1 or 12 < len_outputs:
        logger.critical(
            f"Circuits outputs size must be in the interval [1, 12], but was {len_outputs}!"
        )
        is_valid = False

    for other_circuit in circuits[1:]:
        if not circuit_candidate.is_type_compatible_with(other_circuit):
            logger.critical(
                f"Circuits {circuit_candidate.name} and {other_circuit.name} are not compatible!"
            )
            is_valid = False

    if not is_valid:
        raise ValueError("provided circuits are not valid")


# ---------------------------------------------------------------------------- #
#                             Input Related Helper                             #
# ---------------------------------------------------------------------------- #


def generate_metamorphic_bundle(
    rng: Random,
    min_value: int,
    max_value: int,
    rewrites: int,
    batch_size: int,
    rules: list[Rule],
    fuzzer_config: FuzzerConfig,
    enable_iterative_rewrites: bool,
) -> list[Circuit]:
    """Generates a list of metamorphic equivalent circuits"""

    field_modulo = max_value + 1
    rng_util = SimpleRNGUtil(min_value, max_value, rng)
    fuzzer = SimpleCircuitFuzzer(field_modulo, rng, fuzzer_config)
    rewriter = RuleBasedRewriter(rules, rng_util, rng)

    # The `Risc32IMImmediateRepair` is used to add the immediate values to potential custom
    # functions that are added in the custom settings. See the `risc32_im.py` for more info.
    c_0 = Risc32IMImmediateRepair(rng).transform(fuzzer.run())
    c_0.name = "c0"

    bundle = [c_0]
    c_rewrite_basis = c_0
    for i in range(1, batch_size):

        c_i, rules = rewriter.run(c_rewrite_basis, rewrites)
        assert isinstance(c_i, Circuit), "unexpected rewrite return type"
        c_i.name = f"c{i}"

        logger.info(f"Rewrite basis {c_rewrite_basis.name} --> {c_i.name} with {len(rules)} rules")
        for rule in rules:
            logger.debug(f"  - {rule.name}")

        if enable_iterative_rewrites:
            c_rewrite_basis = c_i

        bundle.append(c_i)

    return bundle


# ---------------------------------------------------------------------------- #


def random_inputs(
    circuit: Circuit, rng: Random, allow_modulo: bool = False
) -> dict[str, bool | int]:
    inputs = {}
    for e in circuit.inputs:
        match e.ty_hint:
            case IRType.Bool:
                inputs[e.name] = rng.choice([True, False])
            case IRType.Field:
                if allow_modulo:
                    inputs[e.name] = rng.randint(0, circuit.field_modulo)
                else:
                    inputs[e.name] = rng.randint(0, circuit.field_modulo - 1)
            case _:
                raise NotImplementedError(f"unknown IRType '{e.ty_hint}'")
    return inputs


# ---------------------------------------------------------------------------- #


def convert_input_to_flags(circuit: Circuit, inputs: dict[str, bool | int]) -> list[str]:
    flags = []
    for e in circuit.inputs:
        assert e.name in inputs, f"missing input '{e.name}'"
        match e.ty_hint:
            case IRType.Bool:
                if inputs[e.name]:
                    flags += [f"--{e.name}"]
            case IRType.Field:
                flags += [f"--{e.name}", str(inputs[e.name])]
            case _:
                raise NotImplementedError(f"unknown IRType '{e.ty_hint}'")
    return flags


# ---------------------------------------------------------------------------- #


def convert_input_to_bytes(
    circuit: Circuit, inputs: dict[str, bool | int], is_little_endian: bool = True
) -> bytes:
    endian_literal = "little" if is_little_endian else "big"
    input_bytes: bytes = bytes()
    for e in circuit.inputs:
        match e.ty_hint:
            case IRType.Bool:
                value = 1 if inputs[e.name] else 0
                input_bytes += value.to_bytes(1, endian_literal)
            case IRType.Field:
                max_val = circuit.field_modulo - 1  # USE rust u32 to be (2**32 - 1)
                assert max_val.bit_length() <= 32, "unexpected bit length for maximal input value!"
                value = inputs[e.name]
                input_bytes += value.to_bytes(4, endian_literal)
            case _:
                raise NotImplementedError(f"unknown IRType '{e.ty_hint}'")
    return input_bytes


# ---------------------------------------------------------------------------- #


def convert_hex_str_to_param_str(parameter: Identifier, hex_str: str) -> str:
    """Converts a u32 hex string to a fitting string representation respecting the
    parameter type.
    """
    match parameter.ty_hint:
        case IRType.Bool:
            return "true" if int(hex_str, 16) > 0 else "false"
        case IRType.Field:
            return str(int(hex_str, 16))
        case _:
            raise NotImplementedError(f"unknown IRType '{parameter.ty_hint}'")


# ---------------------------------------------------------------------------- #
#                                  CSV Helper                                  #
# ---------------------------------------------------------------------------- #


def to_clean_quoted_entry(value: str, *, max_msg_len: int | None = None) -> str:
    """
    Helper function to clean up a string to use inside of a CSV file.
        * removes unwanted bytes
        * replaces new lines
        * replaces "|" with <PIPE>
        * can be length restricted using `max_msg_len`
    """
    value = re.sub(r"[^\x20-\x7E\r\n\t]", "?", value)
    value = value.replace("\n", "\\n").replace("\r", "").replace("|", "<PIPE>")
    if max_msg_len is not None and len(value) > max_msg_len:
        value = value[:max_msg_len] + " (...)"
    return f"|{value}|"


# ---------------------------------------------------------------------------- #
#                             General Parser Helper                            #
# ---------------------------------------------------------------------------- #


def parse_hms_as_seconds(hms: str) -> int | None:
    """Given a time amount given in `hms` format, e.g. `2h10m`, `55m1s`, `1h1m1s`,
    it returns the amount in seconds. If the format is malformed, the return value
    is `None`.
    """

    pattern = re.compile(r"^(h(?P<h>[0-9]+))?(m(?P<m>[0-9]+))?(s(?P<s>[0-9]+))?$")
    matched = re.match(pattern, hms)

    if matched:
        accumulator = 0
        hours = matched.group("h")
        minutes = matched.group("m")
        seconds = matched.group("s")

        if hours is None and minutes is None and seconds is None:
            return None

        accumulator += int(hours) * 3600 if hours else 0
        accumulator += int(minutes) * 60 if minutes else 0
        accumulator += int(seconds) if seconds else 0

        return accumulator

    return None


# ---------------------------------------------------------------------------- #
