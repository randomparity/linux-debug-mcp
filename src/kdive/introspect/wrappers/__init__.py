from __future__ import annotations

from kdive.introspect.wrappers.common import WrapperRenderError as WrapperRenderError
from kdive.introspect.wrappers.common import user_script_sha256 as user_script_sha256
from kdive.introspect.wrappers.live import WRAPPER_TEMPLATE as WRAPPER_TEMPLATE
from kdive.introspect.wrappers.live import render_wrapper as render_wrapper
from kdive.introspect.wrappers.live import render_wrapper_skeleton as render_wrapper_skeleton
from kdive.introspect.wrappers.vmcore import VMCORE_WRAPPER_TEMPLATE as VMCORE_WRAPPER_TEMPLATE
from kdive.introspect.wrappers.vmcore import render_vmcore_wrapper as render_vmcore_wrapper
from kdive.introspect.wrappers.vmcore import render_vmcore_wrapper_skeleton as render_vmcore_wrapper_skeleton

SCRIPT_BYTE_CAP = 256 * 1024
TARGET_PYTHON_ARGV = ["python3", "-"]
