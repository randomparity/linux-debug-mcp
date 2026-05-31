from __future__ import annotations

from kdive.providers.local.introspect.drgn_live_wrapper import render_wrapper as render_wrapper
from kdive.providers.local.introspect.drgn_live_wrapper import render_wrapper_skeleton as render_wrapper_skeleton
from kdive.providers.local.introspect.drgn_vmcore_wrapper import render_vmcore_wrapper as render_vmcore_wrapper
from kdive.providers.local.introspect.drgn_vmcore_wrapper import (
    render_vmcore_wrapper_skeleton as render_vmcore_wrapper_skeleton,
)
from kdive.providers.local.introspect.drgn_wrapper_common import WrapperRenderError as WrapperRenderError
from kdive.providers.local.introspect.drgn_wrapper_common import user_script_sha256 as user_script_sha256

SCRIPT_BYTE_CAP = 256 * 1024
TARGET_PYTHON_ARGV = ["python3", "-"]
