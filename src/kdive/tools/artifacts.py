from __future__ import annotations

from pathlib import Path
from typing import Any, Protocol

from mcp.server.fastmcp import FastMCP
from pydantic import ValidationError

from kdive.domain import ToolResponse
from kdive.model import Model
from kdive.tools.adapter_boundary import adapter_validation_failure, model_arg, optional_model_arg


class ArtifactCollectHandler(Protocol):
    def __call__(
        self,
        *,
        artifact_root: Path,
        run_id: str,
        force_recollect: bool,
    ) -> ToolResponse: ...


class ArtifactCollectContext(Model):
    run_id: str
    artifact_root: str | None = None


class ArtifactCollectOptions(Model):
    force_recollect: bool = False


def register_artifact_tools(
    app: FastMCP,
    *,
    default_artifact_root: Path,
    collect_handler: ArtifactCollectHandler,
) -> None:
    default_artifact_root_text = str(default_artifact_root)

    @app.tool(name="artifacts.collect")
    def artifacts_collect(
        context: ArtifactCollectContext | dict[str, Any],
        options: ArtifactCollectOptions | dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        try:
            context_model = model_arg(context, ArtifactCollectContext)
            options_model = optional_model_arg(options, ArtifactCollectOptions)
        except (TypeError, ValueError, ValidationError) as exc:
            return adapter_validation_failure(exc)
        return collect_handler(
            artifact_root=Path(context_model.artifact_root or default_artifact_root_text),
            run_id=context_model.run_id,
            force_recollect=options_model.force_recollect,
        ).model_dump(mode="json")
