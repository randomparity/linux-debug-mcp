import pytest

from kdive.server import _ssh_host_is_unset_or_loopback, _validated_guest_ip


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        (None, True),
        ("", True),
        ("   ", True),
        ("127.0.0.1", True),
        ("127.0.0.2", True),
        ("::1", True),
        ("localhost", True),
        ("LocalHost", True),
        ("192.168.122.45", False),
        ("10.0.0.5", False),
        ("bastion.example", False),
    ],
)
def test_ssh_host_is_unset_or_loopback(host: str | None, expected: bool) -> None:
    assert _ssh_host_is_unset_or_loopback(host) is expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("192.168.122.45", "192.168.122.45"),
        ("10.0.0.5", "10.0.0.5"),
        (None, None),
        ("", None),
        ("127.0.0.1", None),  # loopback rejected
        ("169.254.1.2", None),  # link-local rejected
        ("not-an-ip", None),  # non-IP rejected
        ("192.168.122.45; echo X", None),  # injected token rejected
        (12345, None),  # non-str rejected
    ],
)
def test_validated_guest_ip(value: object, expected: str | None) -> None:
    assert _validated_guest_ip(value) == expected
