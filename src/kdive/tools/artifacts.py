from __future__ import annotations

from pathlib import Path
from typing import Any, Protocol

from mcp.server.fastmcp import FastMCP

from kdive.domain import ToolResponse


class ArtifactCollectHandler(Protocol):
    def __call__(
        self,
        *,
        artifact_root: Path,
        run_id: str,
        force_recollect: bool,
    ) -> ToolResponse: ...


def register_artifact_tools(
    app: FastMCP,
    *,
    default_artifact_root: Path,
    collect_handler: ArtifactCollectHandler,
) -> None:
    default_artifact_root_text = str(default_artifact_root)

    @app.tool(name="artifacts.collect")
    def artifacts_collect(
        run_id: str,
        artifact_root: str = default_artifact_root_text,
        force_recollect: bool = False,
    ) -> dict[str, Any]:
        return collect_handler(
            artifact_root=Path(artifact_root),
            run_id=run_id,
            force_recollect=force_recollect,
        ).model_dump(mode="json")
