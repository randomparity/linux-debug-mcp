from __future__ import annotations

from kdive.postmortem.crash_parsers import parse_command

BT = """PID: 0      TASK: ffffffff81c1a8c0  CPU: 0   COMMAND: "swapper/0"
 #0 [ffff8881] machine_kexec at ffffffff81051d4e
 #1 [ffff8882] __crash_kexec at ffffffff811a3b2c
"""

PS = """   PID    PPID  CPU       TASK        ST  %MEM     VSZ    RSS  COMM
>     0       0   0  ffffffff81c1a8c0  RU   0.0       0      0  [swapper/0]
      1       0   1  ffff888100a40000  IN   0.1  167404  11600  systemd
"""

SYS = """      KERNEL: vmlinux
    DUMPFILE: vmcore
        CPUS: 4
     RELEASE: 6.1.0
     MACHINE: x86_64
       PANIC: "Kernel panic - not syncing: sysrq triggered crash"
"""

LOG = """[    0.000000] Linux version 6.1.0
[    1.234567] Call Trace:
"""


def test_parse_bt() -> None:
    out = parse_command("bt", BT)
    assert out["parsed"] is True
    assert out["pid"] == 0
    assert out["command"] == "swapper/0"
    assert out["frames"][0]["symbol"] == "machine_kexec"
    assert out["frames"][1]["level"] == 1


def test_parse_ps() -> None:
    out = parse_command("ps", PS)
    assert out["parsed"] is True
    assert out["processes"][1]["pid"] == 1
    assert out["processes"][1]["comm"] == "systemd"


def test_parse_sys() -> None:
    out = parse_command("sys", SYS)
    assert out["parsed"] is True
    assert out["system"]["RELEASE"] == "6.1.0"
    assert out["system"]["CPUS"] == "4"


def test_parse_log() -> None:
    out = parse_command("log", LOG)
    assert out["parsed"] is True
    assert out["lines"][0]["ts"] == 0.0
    assert "Linux version" in out["lines"][0]["text"]


def test_kmem_i_dispatch() -> None:
    out = parse_command("kmem -i", "TOTAL MEM  1000000  3.8 GB\nFREE  500000  1.9 GB\n")
    assert out["parsed"] is True
    assert "TOTAL MEM" in out["memory"]
    assert out["memory"]["TOTAL MEM"] == {"pages": "1000000", "detail": "3.8 GB"}
    assert out["memory"]["FREE"] == {"pages": "500000", "detail": "1.9 GB"}


# TD-24: parse_kmem_i ingests untrusted crash output; these lock its edge-case behavior so it
# stays crash-free and stable on malformed/degenerate input rather than raising.
def test_kmem_i_empty_input() -> None:
    out = parse_command("kmem -i", "")
    assert out == {"parsed": True, "memory": {}}


def test_kmem_i_blank_and_whitespace_lines_skipped() -> None:
    out = parse_command("kmem -i", "\n\n  \n")
    assert out == {"parsed": True, "memory": {}}


def test_kmem_i_single_field_line_skipped() -> None:
    # A row with fewer than two fields has no pages column; it is skipped, not errored.
    out = parse_command("kmem -i", "ORPHAN\n")
    assert out == {"parsed": True, "memory": {}}


def test_kmem_i_label_only_line_skipped() -> None:
    # A row with no numeric field (all tokens are label words) yields an empty `rest` and is skipped.
    out = parse_command("kmem -i", "TOTAL MEM PAGES\n")
    assert out == {"parsed": True, "memory": {}}


def test_kmem_i_comma_separated_number_is_pages() -> None:
    out = parse_command("kmem -i", "NODE  1,234,567  pages\n")
    assert out["memory"]["NODE"] == {"pages": "1,234,567", "detail": "pages"}


def test_kmem_i_unicode_digits_treated_as_pages() -> None:
    # str.isdigit() is true for non-ASCII digits (e.g. Arabic-Indic), so they are accepted as the
    # pages field. This is benign — `pages` is kept as a string and never int()-converted here — but
    # the behavior is locked so a future stricter ASCII-only change is a deliberate decision.
    out = parse_command("kmem -i", "TOTAL ٠١٢\n")
    assert out["memory"]["TOTAL"] == {"pages": "٠١٢", "detail": ""}


def test_kmem_i_leading_numeric_token_skips_row() -> None:
    # When the first token is numeric there is no label; the row is skipped rather than mislabeled.
    out = parse_command("kmem -i", "12345 TOTAL\n")
    assert out == {"parsed": True, "memory": {}}


def test_unknown_command_raw() -> None:
    out = parse_command("vtop 0xffff", "some text")
    assert out == {"parsed": False, "reason": "unknown_command", "raw": "some text"}


def test_parser_exception_falls_back_to_raw(monkeypatch) -> None:
    import kdive.postmortem.crash_parsers as mod

    def boom(_text: str) -> dict:
        raise ValueError("kaboom")

    monkeypatch.setitem(mod._PARSERS, "sys", boom)
    out = parse_command("sys", "anything")
    assert out["parsed"] is False
    assert out["reason"] == "parse_failed"
    assert out["raw"] == "anything"
