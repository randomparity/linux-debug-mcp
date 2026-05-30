from __future__ import annotations

from linux_debug_mcp.providers.gdb_mi import MiRecord, parse_mi_records


def test_parse_result_done_record() -> None:
    [record] = parse_mi_records('^done,features=["frozen-varobjs"]')
    assert isinstance(record, MiRecord)
    assert record.type == "result"
    assert record.message == "done"
    assert record.payload == {"features": ["frozen-varobjs"]}
    assert record.token is None


def test_parse_running_and_stopped() -> None:
    records = parse_mi_records('^running\n*stopped,reason="breakpoint-hit",thread-id="1"')
    assert [r.message for r in records] == ["running", "stopped"]
    assert records[1].type == "notify"
    assert records[1].payload == {"reason": "breakpoint-hit", "thread-id": "1"}


def test_parse_console_stream_record() -> None:
    [record] = parse_mi_records('~"hello\\n"')
    assert record.type == "console"
    assert record.payload == "hello\n"


def test_parse_ignores_blank_lines_and_gdb_prompt() -> None:
    records = parse_mi_records("\n(gdb)\n^done\n")
    assert [r.message for r in records] == ["done"]


def test_first_result_record_helper() -> None:
    records = parse_mi_records('~"noise\\n"\n^done,value="0x1"')
    result = MiRecord.first_result(records)
    assert result is not None and result.message == "done" and result.payload == {"value": "0x1"}
    assert MiRecord.first_result(parse_mi_records('~"only console\\n"')) is None
