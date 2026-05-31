from kdive.workflow import handlers


def test_workflow_handlers_share_build_boot_runner() -> None:
    assert hasattr(handlers, "_run_build_boot_workflow")
