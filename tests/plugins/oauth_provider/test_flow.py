"""Authorization code + PKCE, consent, refresh, resources and the other grants."""

from __future__ import annotations

import json

import httpx
import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from gotauth.contracts import ConfigError
from gotauth.contracts.oauth import PLUGIN_ENDPOINTS
from gotauth.plugins.oauth_provider import oauth_provider
from gotauth.testing import make_auth

from .conftest import ISSUER, REDIRECT, RESOURCE, pkce, query_of, world


def test_endpoints_match_the_contract_table() -> None:
    specs = {s.id: s for s in PLUGIN_ENDPOINTS if s.owner == "O1"}
    plugin = oauth_provider(allow_dynamic_registration=True)
    endpoints = {e.id: e for e in (*plugin.endpoints, *plugin.well_known_endpoints)}
    assert set(endpoints) == set(specs)
    for id, spec in specs.items():
        endpoint = endpoints[id]
        assert endpoint.server_only == spec.server_only, id
        if not spec.server_only:
            assert (endpoint.method, endpoint.path, endpoint.auth) == (
                spec.method,
                spec.path,
                spec.auth,
            ), id
            assert endpoint.input_format == spec.input_format, id
            assert endpoint.error_format == spec.error_format, id
    assert "oauth_register" not in {e.id for e in oauth_provider().endpoints}


async def test_full_flow_with_consent_and_refresh() -> None:
    w = await world()
    first = await w.authorize(
        nonce="n-1", resource=RESOURCE, scope="openid profile email offline_access"
    )
    assert first.status_code == 200
    screen = first.json()
    assert screen["redirect_host"] == "app.example.com"
    assert screen["loopback_only"] is False
    location = (await w.consent(screen["consent_id"])).headers["location"]
    values = query_of(location)
    assert values["state"] == "st-1" and values["iss"] == ISSUER
    tokens = (await w.exchange(values["code"])).json()
    assert tokens["token_type"] == "Bearer" and tokens["refresh_token"].startswith(
        "gar_"
    )
    assert "id_token" in tokens
    verified = await w.auth.api.call(
        "verify_access_token",
        body={"token": tokens["access_token"], "resource": RESOURCE},
    )
    assert verified.valid and verified.principal.via == "oauth_token"
    refreshed = (
        await w.token(grant_type="refresh_token", refresh_token=tokens["refresh_token"])
    ).json()
    assert refreshed["refresh_token"] != tokens["refresh_token"]
    again = await w.auth.api.call(
        "verify_access_token",
        body={"token": refreshed["access_token"], "resource": RESOURCE},
    )
    assert again.valid  # refreshed tokens keep the original audience
    # Consent is remembered: the next authorize issues a code on the GET.
    second = await w.authorize(resource=RESOURCE, scope="openid profile")
    assert second.status_code == 302 and "code" in query_of(second.headers["location"])
    forced = await w.authorize(
        resource=RESOURCE, scope="openid profile", prompt="consent"
    )
    assert forced.status_code == 200 and "consent_id" in forced.json()


async def test_pkce_is_required_and_checked() -> None:
    w = await world()
    for params in ({"code_challenge": ""}, {"code_challenge_method": "plain"}):
        response = await w.authorize(**params)
        assert response.status_code == 302
        values = query_of(response.headers["location"])
        assert values["error"] == "invalid_request" and values["iss"] == ISSUER
    code = await w.code()
    wrong, _ = pkce()
    response = await w.exchange(code, code_verifier=wrong)
    assert response.status_code == 400 and response.json()["error"] == "invalid_grant"


@pytest.mark.parametrize(
    "redirect",
    [
        REDIRECT + "/",
        REDIRECT.upper(),
        REDIRECT + "?x=1",
        "https://evil.example.com/callback",
        REDIRECT + "#frag",
    ],
)
async def test_redirect_tricks_get_an_error_page(redirect: str) -> None:
    w = await world()
    response = await w.authorize(redirect_uri=redirect)
    assert response.status_code == 400
    assert "location" not in response.headers
    assert "text/html" in response.headers["content-type"]


async def test_loopback_redirects() -> None:
    w = await world(client={"redirect_uris": ["http://localhost:3000/cb"]})
    response = await w.authorize(redirect_uri="http://localhost:5555/cb")
    assert response.status_code == 200
    assert response.json()["loopback_only"] is True
    with pytest.raises(Exception, match="redirect"):
        await w.auth.api.call(
            "create_oauth_client",
            body={
                "name": "x",
                "type": "public",
                "redirect_uris": ["http://example.com/cb"],
            },
        )
    nip = await world(client={"redirect_uris": ["https://127.0.0.1.nip.io/cb"]})
    other_port = await nip.authorize(redirect_uri="https://127.0.0.1.nip.io:9999/cb")
    assert other_port.status_code == 400  # not loopback: ports must match exactly


async def test_iss_on_denied_consent_and_invalid_scope() -> None:
    w = await world()
    bad_scope = await w.authorize(scope="admin")
    assert query_of(bad_scope.headers["location"]) == {
        "error": "invalid_scope",
        "state": "st-1",
        "iss": ISSUER,
    }
    screen = (await w.authorize()).json()
    denied = await w.consent(screen["consent_id"], accept="false")
    values = query_of(denied.headers["location"])
    assert values["error"] == "access_denied" and values["iss"] == ISSUER


async def test_code_reuse_revokes_its_tokens() -> None:
    w = await world()
    code = await w.code()
    verifier = w.extra["verifier"]
    first = (await w.exchange(code)).json()
    replay = await w.exchange(code, code_verifier=verifier)
    assert replay.status_code == 400 and replay.json()["error"] == "invalid_grant"
    result = await w.auth.api.call(
        "verify_access_token", body={"token": first["access_token"]}
    )
    assert not result.valid


async def test_refresh_reuse_revokes_the_family() -> None:
    w = await world()
    tokens = (await w.exchange(await w.code())).json()
    rotated = (
        await w.token(grant_type="refresh_token", refresh_token=tokens["refresh_token"])
    ).json()
    reuse = await w.token(
        grant_type="refresh_token", refresh_token=tokens["refresh_token"]
    )
    assert reuse.json()["error"] == "invalid_grant"
    stale = await w.token(
        grant_type="refresh_token", refresh_token=rotated["refresh_token"]
    )
    assert stale.json()["error"] == "invalid_grant"  # the whole family was revoked


@settings(
    max_examples=15,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
@given(
    granted=st.sets(st.sampled_from(["openid", "profile", "email"]), min_size=1),
    narrowed=st.sets(st.sampled_from(["openid", "profile", "email", "admin"])),
)
async def test_issued_scopes_stay_within_granted(
    granted: set[str], narrowed: set[str]
) -> None:
    w = await world()
    tokens = (await w.exchange(await w.code(scope=" ".join(sorted(granted))))).json()
    assert set(tokens["scope"].split()) <= granted
    response = await w.token(
        grant_type="refresh_token",
        refresh_token=tokens["refresh_token"],
        scope=" ".join(sorted(narrowed)),
    )
    if narrowed and narrowed <= granted:
        assert set(response.json()["scope"].split()) == narrowed
    elif narrowed:
        assert response.json()["error"] == "invalid_scope"


async def test_resources() -> None:
    w = await world(resources=[RESOURCE, "https://other.example.com/mcp"])
    tokens = (
        await w.exchange(await w.code(resource="HTTPS://MCP.EXAMPLE.COM:443/mcp"))
    ).json()
    at_a = await w.auth.api.call(
        "verify_access_token",
        body={"token": tokens["access_token"], "resource": RESOURCE},
    )
    at_b = await w.auth.api.call(
        "verify_access_token",
        body={
            "token": tokens["access_token"],
            "resource": "https://other.example.com/mcp",
        },
    )
    assert at_a.valid and not at_b.valid
    for bad in ("https://unknown.example.com/mcp", RESOURCE + "/../admin"):
        response = await w.authorize(resource=bad)
        assert query_of(response.headers["location"])["error"] == "invalid_target"
    plain = (await w.exchange(await w.code())).json()
    issuer_bound = await w.auth.api.call(
        "verify_access_token", body={"token": plain["access_token"]}
    )
    assert issuer_bound.valid  # no resource: aud is the issuer
    code = await w.code(resource=RESOURCE)
    mismatch = await w.exchange(code, resource="https://other.example.com/mcp")
    assert mismatch.json()["error"] == "invalid_target"
    same = (await w.exchange(await w.code(resource=RESOURCE), resource=RESOURCE)).json()
    refreshed = await w.token(
        grant_type="refresh_token",
        refresh_token=same["refresh_token"],
        resource=RESOURCE,
    )
    assert refreshed.status_code == 200
    two = await w.http.get(
        "/oauth2/authorize",
        params=[
            ("response_type", "code"),
            ("client_id", w.client_id),
            ("redirect_uri", REDIRECT),
            ("code_challenge", pkce()[1]),
            ("code_challenge_method", "S256"),
            ("resource", RESOURCE),
            ("resource", "https://other.example.com/mcp"),
        ],
    )
    assert query_of(two.headers["location"])["error"] == "invalid_target"


async def test_client_credentials() -> None:
    w = await world(
        client={
            "type": "confidential",
            "grant_types": ["client_credentials"],
            "redirect_uris": [],
            "scopes": ["profile"],
        }
    )
    response = await w.token(grant_type="client_credentials", scope="profile")
    body = response.json()
    assert response.status_code == 200 and "refresh_token" not in body
    result = await w.auth.api.call(
        "verify_access_token", body={"token": body["access_token"]}
    )
    assert result.valid and result.principal.user_id is None
    public = await world()
    denied = await public.token(grant_type="client_credentials")
    assert denied.json()["error"] in ("unauthorized_client", "invalid_client")


async def test_introspection_and_revocation() -> None:
    w = await world()
    tokens = (await w.exchange(await w.code())).json()
    rs = await w.auth.api.call(
        "create_oauth_client",
        body={
            "name": "Resource server",
            "type": "confidential",
            "redirect_uris": [],
            "grant_types": ["client_credentials"],
        },
    )
    auth = httpx.BasicAuth(rs.client.client_id, rs.client_secret)
    active = (
        await w.http.post(
            "/oauth2/introspect", data={"token": tokens["access_token"]}, auth=auth
        )
    ).json()
    assert active["active"] is True and active["iss"] == ISSUER
    revoked = await w.http.post(
        "/oauth2/revoke",
        data={"token": tokens["access_token"], "client_id": w.client_id},
    )
    assert revoked.status_code == 200
    after = (
        await w.http.post(
            "/oauth2/introspect", data={"token": tokens["access_token"]}, auth=auth
        )
    ).json()
    assert after == {"active": False}
    principal = await w.auth.get_principal(
        {"authorization": f"Bearer {tokens['access_token']}"}, {}
    )
    assert principal is None  # no clock advance needed
    unknown = await w.http.post(
        "/oauth2/revoke", data={"token": "nonsense", "client_id": w.client_id}
    )
    assert unknown.status_code == 200


async def test_token_endpoint_errors_are_rfc6749() -> None:
    w = await world()
    as_json = await w.http.post(
        "/oauth2/token", json={"grant_type": "authorization_code"}
    )
    assert as_json.json()["error"] == "invalid_request"
    bad_client = await w.http.post(
        "/oauth2/token", data={"grant_type": "client_credentials", "client_id": "nope"}
    )
    assert (
        bad_client.status_code == 401 and bad_client.json()["error"] == "invalid_client"
    )
    assert "www-authenticate" in bad_client.headers
    statuses = [
        (
            await w.http.post(
                "/oauth2/token",
                data={
                    "grant_type": "refresh_token",
                    "client_id": w.client_id,
                    "refresh_token": "x",
                },
            )
        ).status_code
        for _ in range(35)
    ]
    limited = await w.http.post(
        "/oauth2/token", data={"grant_type": "refresh_token", "client_id": w.client_id}
    )
    assert 429 in statuses or limited.status_code == 429
    assert "error" in limited.json()


async def test_issuer_and_discovery() -> None:
    w = await world(allow_dynamic_registration=False)
    inside = (await w.http.get("/.well-known/openid-configuration")).json()
    transport = httpx.ASGITransport(app=w.auth.well_known())
    async with httpx.AsyncClient(
        transport=transport, base_url="http://localhost:8000"
    ) as root:
        outside = (
            await root.get("/.well-known/oauth-authorization-server/api/auth")
        ).json()
    assert inside == outside
    assert inside["issuer"] == ISSUER
    for key in (
        "issuer",
        "authorization_endpoint",
        "token_endpoint",
        "jwks_uri",
        "userinfo_endpoint",
        "introspection_endpoint",
        "revocation_endpoint",
        "scopes_supported",
        "response_types_supported",
        "grant_types_supported",
        "token_endpoint_auth_methods_supported",
        "code_challenge_methods_supported",
        "authorization_response_iss_parameter_supported",
        "client_id_metadata_document_supported",
        "subject_types_supported",
        "id_token_signing_alg_values_supported",
    ):
        assert key in inside, key
    assert "registration_endpoint" not in inside
    with_dcr = await world(allow_dynamic_registration=True)
    assert (
        "registration_endpoint"
        in (await with_dcr.http.get("/.well-known/openid-configuration")).json()
    )
    tokens = (await w.exchange(await w.code())).json()
    claims = json.loads(_payload(tokens["access_token"]))
    assert claims["iss"] == ISSUER


async def test_trailing_slash_base_url_keeps_the_issuer() -> None:
    auth = make_auth(base_url="http://localhost:8000/", plugins=[oauth_provider()])
    from gotauth.testing import make_client

    async with make_client(auth) as http:
        document = (await http.get("/.well-known/openid-configuration")).json()
    assert document["issuer"] == ISSUER


async def test_mcp_mode_needs_https() -> None:
    with pytest.raises(ConfigError, match="https"):
        make_auth(
            base_url="http://example.com",
            plugins=[oauth_provider(mcp=True, resources=[RESOURCE])],
        )
    ok = make_auth(
        base_url="http://localhost:8000",
        plugins=[oauth_provider(mcp=True, resources=[RESOURCE])],
    )
    await ok.api.call("list_oauth_clients", body={})


async def test_consent_page_and_ids() -> None:
    w = await world()
    html_response = await w.http.get(
        "/oauth2/authorize",
        params={
            "response_type": "code",
            "client_id": w.client_id,
            "redirect_uri": REDIRECT,
            "code_challenge": pkce()[1],
            "code_challenge_method": "S256",
            "scope": "openid",
        },
    )
    page = html_response.text
    assert html_response.status_code == 200 and "<script" not in page.lower()
    assert (
        "app.example.com" in page
        and "frame-ancestors 'none'" in html_response.headers["content-security-policy"]
    )
    consent_id = (await w.authorize()).json()["consent_id"]
    forged = await w.consent(consent_id[:-2] + "xx")
    assert forged.status_code == 400
    w.clock.advance("11m")
    expired = await w.consent(consent_id)
    assert expired.status_code == 400
    other = (await w.authorize()).json()["consent_id"]
    w.http.cookies = httpx.Cookies()
    await w.http.post(
        "/sign-up/email",
        json={"email": "bob@example.com", "password": "another password"},
    )
    stolen = await w.consent(other)
    assert stolen.status_code == 400


async def test_static_loopback_clients_get_codes_with_stored_consent() -> None:
    # The CIMD case (consent shown again) is in test_security.py.
    w = await world(client={"redirect_uris": ["http://localhost:3000/cb"]})
    assert await w.code(redirect_uri="http://localhost:3000/cb")
    again = await w.authorize(redirect_uri="http://localhost:3000/cb")
    assert again.status_code == 302 and "code" in query_of(again.headers["location"])


async def test_no_secrets_in_the_database() -> None:
    w = await world(client={"type": "confidential"})
    tokens = (await w.exchange(await w.code())).json()
    dump = json.dumps(
        {m: await w.auth.database.find_many(m) for m in w.auth.schema}, default=str
    )
    for secret in (tokens["refresh_token"], w.client_secret):
        assert secret and secret not in dump
    assert "gac_" not in dump and "gar_" not in dump and "gcs_" not in dump
    assert "BEGIN PRIVATE KEY" not in dump


def _payload(token: str) -> str:
    import base64

    part = token.split(".")[1]
    return base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)).decode()


async def test_userinfo() -> None:
    w = await world()
    tokens = (await w.exchange(await w.code(scope="openid email"))).json()
    info = await w.http.get(
        "/oauth2/userinfo",
        headers={"authorization": f"Bearer {tokens['access_token']}"},
    )
    assert info.json()["email"] == "ada@example.com" and "name" not in info.json()
    bad = await w.http.get("/oauth2/userinfo", headers={"authorization": "Bearer nope"})
    assert (
        bad.status_code == 401
        and 'error="invalid_token"' in bad.headers["www-authenticate"]
    )


async def test_consent_details_for_an_app_consent_page() -> None:
    # CCR 014: consent_page gets only the id; the page reads the request with it.
    w = await world()
    consent_id = (await w.authorize(resource=RESOURCE)).json()["consent_id"]
    details = await w.http.get("/oauth2/consent", params={"consent_id": consent_id})
    assert details.status_code == 200, details.text
    body = details.json()
    assert body["consent_id"] == consent_id
    assert body["client"]["client_id"] == w.client_id
    assert body["client"]["host"] is None
    assert body["redirect_host"] == "app.example.com"
    assert body["resource"] == RESOURCE
    assert body["loopback_only"] is False
    assert "openid" in body["scopes"]
    forged = await w.http.get(
        "/oauth2/consent", params={"consent_id": consent_id[:-2] + "xx"}
    )
    assert forged.status_code == 400
    w.http.cookies = httpx.Cookies()
    await w.http.post(
        "/sign-up/email",
        json={"email": "bob@example.com", "password": "another password"},
    )
    other_user = await w.http.get("/oauth2/consent", params={"consent_id": consent_id})
    assert other_user.status_code == 400
    w.http.cookies = httpx.Cookies()
    anonymous = await w.http.get("/oauth2/consent", params={"consent_id": consent_id})
    assert anonymous.status_code == 401
