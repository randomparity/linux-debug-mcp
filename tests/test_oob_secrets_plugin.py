from tools.detect_secrets_plugins.oob_credentials import OobCredentialDetector


def test_flags_assignment_with_value():
    det = OobCredentialDetector()
    line = 'bmc_password = "Sup3rSecret!"'  # pragma: allowlist secret
    assert det.analyze_line(filename="fixture.py", line=line, line_number=1)


def test_does_not_flag_prose_mention():
    det = OobCredentialDetector()
    line = "The bmc password is resolved via the Secrets interface."
    assert not det.analyze_line(filename="fixture.md", line=line, line_number=1)


def test_flags_ipmi_and_hmc_and_novalink():
    det = OobCredentialDetector()
    for line in (
        'ipmi_password: "abc123"',  # pragma: allowlist secret
        'hmc_token = "t0ken"',  # pragma: allowlist secret
        'novalink_pass = "p"',  # pragma: allowlist secret
    ):
        assert det.analyze_line(filename="fixture.py", line=line, line_number=1)
