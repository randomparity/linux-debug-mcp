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
