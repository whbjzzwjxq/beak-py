from nexus_fuzzer.fuzzer import guest_division_or_modulo_by_zero
from zkvm_fuzzer_utils.cmd import ExecStatus


def mock_exec_status(
    stdout: str = "", stderr: str = "", returncode: int = 1, is_timeout=False
) -> ExecStatus:
    return ExecStatus(
        "<mock>", stdout, stderr, bytes(), bytes(), returncode, 0, is_timeout, None, None
    )


def test_predicate_guest_division_or_modulo_by_zero():

    positive_test_cases = [
        """>>>>> Logging
Emulated program panic in file 'guest/src/main.rs' at line 64: attempt to calculate the remainder with a divisor of zero
<<<<<
""",  # noqa: E501
        """>>>>> Logging
Emulated program panic in file 'guest/src/main.rs' at line 583: attempt to divide by zero
<<<<<
""",
    ]

    negative_test_cases = [
        """>>>>> Logging
Hello World!
<<<<<
""",
        """>>>>> Logging
Emulated program panic in file 'guest/src/lib.rs' at line 1: division-by-zero (id: 1)
<<<<<
""",
    ]

    for positive_test_case in positive_test_cases:
        assert guest_division_or_modulo_by_zero(
            mock_exec_status(stdout=positive_test_case)
        ), f"'{positive_test_case}' should be ignored"

    for negative_test_case in negative_test_cases:
        assert not guest_division_or_modulo_by_zero(
            mock_exec_status(stdout=negative_test_case)
        ), f"'{negative_test_case}' should not be ignored"
