from zkvm_fuzzer_utils.cmd import ExecStatus
from zkvm_fuzzer_utils.record import (
    Record,
    record_from_exec_status,
)

MOCK_STDOUT = """
...
<record>{"context": "abc", "status": "start"}</record>
<record>{"context": "abc", "status": "ok", "time": "100s", "output": "ok"}</record>
<record>{"context": "xyz", "status": "start"}</record>
<record>{"context": "xyz", "status": "error", "time": "123"}</record>
...
"""

MOCK_STDERR = """
...
thread 'main' panicked at src/main.rs:3:5:
pan
ic
stack backtrace:
   0: __rustc::rust_begin_unwind
...

thread 'main' panicked at src/main.rs:3:5:
pan
ic-2
stack backtrace:
   0: __rustc::rust_begin_unwind
...
"""


def test_empty_record():
    # check robustness

    mock_exec = ExecStatus("no-command", "", "", None, None, -1, -1)
    empty_record = Record([], [], mock_exec)

    assert empty_record.get_entry_by_context("abc") is None
    assert empty_record.get_last_entry() is None
    assert empty_record.panics == []
    assert not empty_record.has_panicked()


def test_record():

    mock_exec = ExecStatus("no-command", MOCK_STDOUT, MOCK_STDERR, None, None, -1, -1)
    record = record_from_exec_status(mock_exec)

    assert len(record.entries) == 4
    assert record.has_panicked()
    assert len(record.panics) > 0

    assert record.entries[0].entries.get("time", None) is None
    assert record.entries[0].entries.get("output", None) is None
    assert record.entries[0].context == "abc"
    assert record.entries[0].entries.get("status", None) == "start"

    assert record.entries[1].entries.get("time", None) == "100s"
    assert record.entries[1].entries.get("output", None) == "ok"
    assert record.entries[1].context == "abc"
    assert record.entries[1].entries.get("status", None) == "ok"

    assert record.entries[2].entries.get("time", None) is None
    assert record.entries[2].entries.get("output", None) is None
    assert record.entries[2].context == "xyz"
    assert record.entries[2].entries.get("status", None) == "start"

    assert record.entries[3].entries.get("time", None) == "123"
    assert record.entries[3].entries.get("output", None) is None
    assert record.entries[3].context == "xyz"
    assert record.entries[3].entries.get("status", None) == "error"

    assert record.entries[1] == record.get_entry_by_context("abc")
    assert record.entries[3] == record.get_entry_by_context("xyz")
    assert record.entries[3] == record.get_last_entry()

    assert len(record.panics) == 2
    assert record.panics[0].context == "xyz"
    assert record.panics[1].context == "xyz"

    # NOTE: panic parsing is tested in other tests
