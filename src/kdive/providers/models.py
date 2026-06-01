from __future__ import annotations

from enum import StrEnum

from pydantic import Field, model_validator

from kdive.model import Model


class TargetKind(StrEnum):
    LOCAL = "local"
    REMOTE = "remote"
    VIRTUAL = "virtual"
    PHYSICAL = "physical"


class ImplementationState(StrEnum):
    IMPLEMENTED = "implemented"
    STUB = "stub"
    EXTERNAL_RESERVED = "external_reserved"


class OperationSemantics(Model):
    idempotent: bool
    retryable: bool
    destructive: bool
    cancelable: bool
    concurrent_safe: bool


class ProviderDependency(Model):
    name: str
    kind: str = "host_tool"
    required: bool = True


class ProviderOperationCapability(Model):
    operation: str
    semantics: OperationSemantics
    implementation_state: ImplementationState | None = None
    required_host_tools: list[str] = Field(default_factory=list)
    destructive_permissions: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


class ProviderCapability(Model):
    provider_name: str
    provider_version: str
    provider_family: str = "local"
    implementation_state: ImplementationState = ImplementationState.IMPLEMENTED
    architectures: list[str]
    target_kinds: list[TargetKind]
    transports: list[str] = Field(default_factory=list)
    documentation_paths: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    operations: list[str]
    required_host_tools: list[str]
    destructive_permissions: list[str]
    access_methods: list[str]
    semantics: OperationSemantics
    operation_capabilities: list[ProviderOperationCapability] = Field(default_factory=list)

    @model_validator(mode="after")
    def fill_operation_capabilities(self) -> ProviderCapability:
        if not self.operation_capabilities:
            object.__setattr__(
                self,
                "operation_capabilities",
                [
                    ProviderOperationCapability(
                        operation=operation,
                        semantics=self.semantics,
                        implementation_state=self.implementation_state,
                        required_host_tools=list(self.required_host_tools),
                        destructive_permissions=list(self.destructive_permissions),
                        limitations=list(self.limitations),
                    )
                    for operation in self.operations
                ],
            )
            return self

        operation_names = [capability.operation for capability in self.operation_capabilities]
        if operation_names != self.operations:
            raise ValueError("operations must match operation_capabilities in order")
        if all(capability.implementation_state is not None for capability in self.operation_capabilities):
            return self
        object.__setattr__(
            self,
            "operation_capabilities",
            [
                capability.model_copy(
                    update={
                        "implementation_state": capability.implementation_state or self.implementation_state,
                    }
                )
                for capability in self.operation_capabilities
            ],
        )
        return self
