"""``auth.api`` (CONTRACTS 13)."""

from __future__ import annotations

from collections.abc import Awaitable, Mapping
from typing import TYPE_CHECKING, Any, Generic, Literal, TypeVar, overload

from pydantic import BaseModel

from gotauth.contracts.config import ApiMethod
from gotauth.contracts.endpoints import EndpointContext
from gotauth.contracts.http import AuthResponse
from gotauth.contracts.http_models import (
    AccountListOut,
    ChallengeOut,
    RedirectOut,
    SessionListOut,
    SessionWithUserOut,
    SignInOut,
    StatusOut,
    UserOut,
)

if TYPE_CHECKING:
    from gotauth.core._auth import GotAuth

__all__ = ["Api"]

OutputT = TypeVar("OutputT")


class _ApiCaller(Generic[OutputT]):
    def __init__(self, api: Api, endpoint_id: str) -> None:
        self._api = api
        self._endpoint_id = endpoint_id

    @overload
    def __call__(
        self,
        body: BaseModel | Mapping[str, Any] | None = None,
        *,
        headers: Mapping[str, str] | None = None,
        query: Mapping[str, str] | None = None,
        path_params: Mapping[str, str] | None = None,
        as_response: Literal[False] = False,
        ctx: EndpointContext | None = None,
    ) -> Awaitable[OutputT]: ...

    @overload
    def __call__(
        self,
        body: BaseModel | Mapping[str, Any] | None = None,
        *,
        headers: Mapping[str, str] | None = None,
        query: Mapping[str, str] | None = None,
        path_params: Mapping[str, str] | None = None,
        as_response: Literal[True],
        ctx: EndpointContext | None = None,
    ) -> Awaitable[AuthResponse]: ...

    def __call__(
        self,
        body: BaseModel | Mapping[str, Any] | None = None,
        *,
        headers: Mapping[str, str] | None = None,
        query: Mapping[str, str] | None = None,
        path_params: Mapping[str, str] | None = None,
        as_response: bool = False,
        ctx: EndpointContext | None = None,
    ) -> Awaitable[Any]:
        return self._api.call(
            self._endpoint_id,
            body,
            headers=headers,
            query=query,
            path_params=path_params,
            as_response=as_response,
            ctx=ctx,
        )


class Api:
    """``auth.api``: every endpoint callable from code (CONTRACTS 13).

    Typed members cover the core endpoint table 13.1; plugin endpoints use
    :meth:`call`. Server calls skip origin checks and rate limits.
    """

    def __init__(self, auth: GotAuth) -> None:
        self._auth = auth
        self.sign_up_email: ApiMethod[SignInOut | StatusOut] = _ApiCaller(
            self, "sign_up_email"
        )
        self.sign_in_email: ApiMethod[SignInOut | ChallengeOut] = _ApiCaller(
            self, "sign_in_email"
        )
        self.sign_out: ApiMethod[StatusOut] = _ApiCaller(self, "sign_out")
        self.send_verification_email: ApiMethod[StatusOut] = _ApiCaller(
            self, "send_verification_email"
        )
        self.verify_email: ApiMethod[StatusOut | AuthResponse] = _ApiCaller(
            self, "verify_email"
        )
        self.request_password_reset: ApiMethod[StatusOut] = _ApiCaller(
            self, "request_password_reset"
        )
        self.reset_password: ApiMethod[StatusOut] = _ApiCaller(self, "reset_password")
        self.change_password: ApiMethod[StatusOut] = _ApiCaller(self, "change_password")
        self.change_email: ApiMethod[StatusOut] = _ApiCaller(self, "change_email")
        self.update_user: ApiMethod[UserOut] = _ApiCaller(self, "update_user")
        self.delete_user: ApiMethod[StatusOut] = _ApiCaller(self, "delete_user")
        self.get_session: ApiMethod[SessionWithUserOut | None] = _ApiCaller(
            self, "get_session"
        )
        self.list_sessions: ApiMethod[SessionListOut] = _ApiCaller(
            self, "list_sessions"
        )
        self.revoke_session: ApiMethod[StatusOut] = _ApiCaller(self, "revoke_session")
        self.revoke_other_sessions: ApiMethod[StatusOut] = _ApiCaller(
            self, "revoke_other_sessions"
        )
        self.sign_in_social: ApiMethod[RedirectOut] = _ApiCaller(self, "sign_in_social")
        self.social_callback: ApiMethod[AuthResponse] = _ApiCaller(
            self, "social_callback"
        )
        self.social_callback_post: ApiMethod[AuthResponse] = _ApiCaller(
            self, "social_callback_post"
        )
        self.link_social: ApiMethod[RedirectOut] = _ApiCaller(self, "link_social")
        self.list_accounts: ApiMethod[AccountListOut] = _ApiCaller(
            self, "list_accounts"
        )
        self.unlink_account: ApiMethod[StatusOut] = _ApiCaller(self, "unlink_account")

    async def call(
        self,
        endpoint_id: str,
        body: BaseModel | Mapping[str, Any] | None = None,  # Any: JSON input values
        *,
        headers: Mapping[str, str] | None = None,
        query: Mapping[str, str] | None = None,
        path_params: Mapping[str, str] | None = None,
        as_response: bool = False,
        ctx: EndpointContext | None = None,
    ) -> Any:  # Any: the output of whichever endpoint is called
        """Call any endpoint by id, ``server_only`` ones included.

        With ``ctx`` the call joins that context's transaction and principal
        (CONTRACTS 12.5). Errors are raised as ``AuthError``, not rendered.
        """
        return await self._auth.server_call(
            endpoint_id,
            body,
            headers=headers,
            query=query,
            path_params=path_params,
            as_response=as_response,
            ctx=ctx,
        )
