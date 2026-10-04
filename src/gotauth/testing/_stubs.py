"""Stand-ins for other plugins: principal resolvers and cross-plugin endpoints."""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from dataclasses import field as dc_field
from typing import Any

from pydantic import BaseModel, ConfigDict

from gotauth.contracts.endpoints import Endpoint, EndpointContext, Plugin
from gotauth.contracts.http import AuthResponse
from gotauth.contracts.oauth import CROSS_PLUGIN_CALLS
from gotauth.contracts.principal import Principal

__all__ = ["StubCall", "StubPlugin", "StubResolver", "stub_plugin", "stub_resolver"]

# Any: a fake returns the endpoint's output as a model or a plain dict.
StubFake = Callable[..., Awaitable[Any]]


class StubResolver:
    """A ``PrincipalResolver`` returning a fixed principal for one credential prefix.

    ``calls`` counts the credentials it was asked about (not their values).
    """

    def __init__(self, prefix: str, principal: Principal) -> None:
        self.prefixes: tuple[str, ...] = (prefix,)
        self.principal = principal
        self.calls = 0

    def __repr__(self) -> str:
        return f"StubResolver({self.prefixes[0]!r})"

    async def __call__(self, ctx: EndpointContext, credential: str) -> Principal | None:
        """Return the principal for any credential with the prefix, else ``None``."""
        self.calls += 1
        return self.principal if credential.startswith(self.prefixes[0]) else None

    def as_plugin(self, id: str | None = None) -> Plugin:
        """Wrap the resolver in a plugin, for ``make_context`` or ``make_auth``."""
        name = id if id is not None else "stub_" + self.prefixes[0].rstrip("_")
        return Plugin(id=name, principal_resolvers=(self,))


def stub_resolver(prefix: str, principal: Principal) -> StubResolver:
    """Return a resolver that maps every ``prefix`` credential to ``principal``.

    Lets tests use API-key (``"gak_"``) and JWT (``"eyJ"``) principals before P1 and
    O1 exist.
    """
    return StubResolver(prefix, principal)


@dataclass(frozen=True)
class StubCall:
    """One recorded call to a stub endpoint.

    Attributes:
        endpoint_id: The endpoint called.
        body: The keys the caller sent, after validation against the 12.5 shape.
    """

    endpoint_id: str
    body: dict[str, Any]  # Any: JSON input values


@dataclass(frozen=True)
class StubPlugin(Plugin):
    """A plugin of ``server_only`` stub endpoints that records ``calls``."""

    calls: list[StubCall] = dc_field(
        default_factory=list[StubCall], compare=False, repr=False
    )

    def calls_to(self, endpoint_id: str) -> list[dict[str, Any]]:
        """Return the bodies of the calls to one endpoint, oldest first."""
        return [call.body for call in self.calls if call.endpoint_id == endpoint_id]


class _AnyInput(BaseModel):
    model_config = ConfigDict(extra="allow")


def _handler(
    endpoint_id: str,
    fake: StubFake,
    calls: list[StubCall],
    output: type[BaseModel] | None,
) -> Callable[[EndpointContext, BaseModel], Awaitable[Any]]:
    async def handler(ctx: EndpointContext, data: BaseModel) -> Any:
        if isinstance(data, _AnyInput):
            kwargs: dict[str, Any] = dict(data.model_extra or {})
        else:
            kwargs = {name: getattr(data, name) for name in data.model_fields_set}
        calls.append(StubCall(endpoint_id, data.model_dump(exclude_unset=True)))
        result = await fake(**kwargs)
        if output is None or isinstance(result, BaseModel | AuthResponse):
            return result
        return output.model_validate(result)

    return handler


def stub_plugin(id: str, endpoints: Mapping[str, StubFake]) -> StubPlugin:
    """Return a ``server_only`` fake of another plugin's endpoints.

    For a CONTRACTS 12.5 endpoint id, the input is validated against the frozen input
    model (unknown keys are rejected) and the fake's return value against the output
    model. The fake is awaited with the keys the caller sent as keyword arguments::

        async def revoke(owner_type: str, owner_id: str, key_id: str | None = None):
            return {"revoked": 1}

        keys = stub_plugin("api_key", {"revoke_api_keys": revoke})
        ctx = make_context(plugins=[keys])
        await ctx.auth.api.call("revoke_api_keys", body={...}, ctx=ctx)
        assert keys.calls_to("revoke_api_keys") == [{...}]

    Args:
        id: The faked plugin's id, e.g. ``"api_key"``; it appears in ``plugin_ids``.
        endpoints: Endpoint id -> async fake.
    """
    calls: list[StubCall] = []
    built: list[Endpoint[Any, Any]] = []
    for endpoint_id, fake in endpoints.items():
        shape = CROSS_PLUGIN_CALLS.get(endpoint_id)
        input_model = shape.input if shape is not None else _AnyInput
        output = shape.output if shape is not None else None
        built.append(
            Endpoint[Any, Any](
                id=endpoint_id,
                method="POST",
                path=f"/stub-{id.replace('_', '-')}/{endpoint_id.replace('_', '-')}",
                handler=_handler(endpoint_id, fake, calls, output),
                input=input_model,
                output=output,
                server_only=True,
            )
        )
    return StubPlugin(id=id, endpoints=tuple(built), calls=calls)
