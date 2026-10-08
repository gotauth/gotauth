"""OAuth 2.1 authorization server and OpenID Connect provider (work package O1).

from gotauth.plugins.oauth_provider import oauth_provider

auth = GotAuth(..., plugins=[oauth_provider(resources=["https://mcp.example.com/mcp"])])
app.mount("/", auth.well_known())  # RFC 8414 metadata at the host root
"""

from __future__ import annotations

from ._clients import ClientStore, check_document, is_cimd_url
from ._plugin import OAuthJwtResolver, oauth_provider
from ._rules import normalize_resource, redirect_matches, valid_redirect_uri

__all__ = [
    "ClientStore",
    "OAuthJwtResolver",
    "check_document",
    "is_cimd_url",
    "normalize_resource",
    "oauth_provider",
    "redirect_matches",
    "valid_redirect_uri",
]
