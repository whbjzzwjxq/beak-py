import json
import re
from dataclasses import dataclass
from typing import Any

from zkvm_fuzzer_utils.cmd import ExecStatus
from zkvm_fuzzer_utils.rust.panics import RustPanicInfo, parse_panic_info


@dataclass(frozen=True)
class RecordPanic:
    context: str
    rust_panic: RustPanicInfo


@dataclass(frozen=True)
class RecordEntry:
    context: str
    entries: dict[str, Any]

    @classmethod
    def from_dict(cls, data: dict[str, str]) -> "RecordEntry":
        return RecordEntry(
            context=data.get("context", "<no context>"),
            entries=data,
        )


@dataclass
class Record:
    """
    Very simple interface to the record logs of a zkvm host execution.
    An example record could look like this:
    ```
    <record>"context": "Name", "status": "start"</record>
    ```
    If a panic occurs it is assumed that it occurred during the last context.
    """

    # ordered log entries
    entries: list[RecordEntry]
    panics: list[RecordPanic]
    exec_status: ExecStatus

    def get_entry_by_context(self, context: str) -> RecordEntry | None:
        for entry in reversed(self.entries):
            if entry.context == context:
                return entry
        return None  # context not available or no entries present

    def get_last_entry(self) -> RecordEntry | None:
        if len(self.entries) > 0:
            return self.entries[-1]
        return None  # no entries present

    def has_panicked(self) -> bool:
        return len(self.panics) > 0

    def search_by_key(self, key: str) -> None | str:
        values = [e.entries[key] for e in self.entries if key in e.entries]
        if len(values) > 1:
            raise ValueError(f"record contains multiple values for key '{key}'")
        elif len(values) == 1:
            return values[0]
        else:
            return None

    def search_by_context_and_key(self, context: str, key: str) -> None | str:
        values = [e.entries[key] for e in self.entries if e.context == context and key in e.entries]
        if len(values) > 1:
            raise ValueError(f"record contains multiple values for key '{key}'")
        elif len(values) == 1:
            return values[0]
        else:
            return None

    def is_failure(self) -> bool:
        return self.exec_status.is_failure()

    def is_success(self) -> bool:
        return not self.exec_status.is_failure()

    def is_timeout(self) -> bool:
        return self.exec_status.is_timeout


def record_from_exec_status(exec_status: ExecStatus) -> Record:
    # first step is to parse the stdout to get the last context

    entries = []
    system_pattern = re.compile(r"\<record\>(.+?)\<\/record\>")
    for entry_match in re.finditer(system_pattern, exec_status.stdout):
        json_data = entry_match.group(1)
        entry_dict = json.loads(json_data)
        entries.append(RecordEntry.from_dict(entry_dict))

    # finally we parse the stderr to see if we have a panic
    rust_panics = parse_panic_info(exec_status.stderr)

    panics = []
    context = entries[-1].context if len(entries) > 0 else "<no context>"
    for rust_panic in rust_panics:
        panics.append(RecordPanic(context, rust_panic))

    return Record(entries, panics, exec_status)
