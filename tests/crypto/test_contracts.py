"""Conformance with the CryptoKit protocol of gotauth.contracts.crypto (F2)."""

from __future__ import annotations

import inspect
from types import ModuleType

import gotauth.contracts.crypto as contracts_crypto_module
from gotauth.contracts.crypto import CryptoKit
from gotauth.contracts.crypto import PasswordCheck as ContractPasswordCheck
from gotauth.crypto import DefaultCryptoKit, PasswordCheck, crypto_kit

# The exact members of CONTRACTS section 8.
CONTRACT_MEMBERS = {
    "random_token",
    "hash_token",
    "equal",
    "hash_password",
    "verify_password",
    "sign",
    "unsign",
    "encrypt",
    "decrypt",
    "derive_key",
    "new_totp_secret",
    "totp",
    "verify_totp",
    "new_otp",
    "pkce_s256",
    "new_ulid",
}
ASYNC_MEMBERS = {"hash_password", "verify_password"}


def contracts_crypto() -> ModuleType:
    return contracts_crypto_module


def test_kit_has_every_contract_member() -> None:
    kit = crypto_kit("contract-tests-secret-0123456789abcdef")
    for name in CONTRACT_MEMBERS:
        member = getattr(kit, name)
        assert callable(member)
        assert inspect.iscoroutinefunction(member) == (name in ASYNC_MEMBERS), name


def test_kit_matches_the_protocol_signatures() -> None:
    # The annotation makes pyright check the same thing statically.
    kit: CryptoKit = crypto_kit("contract-tests-secret-0123456789abcdef")
    assert isinstance(kit, CryptoKit)
    protocol = contracts_crypto().CryptoKit
    members = {
        name
        for name in dir(protocol)
        if not name.startswith("_") and callable(getattr(protocol, name))
    }
    assert members == CONTRACT_MEMBERS
    for name in members:
        wanted = inspect.signature(getattr(protocol, name))
        actual = inspect.signature(getattr(DefaultCryptoKit, name))
        for parameter in wanted.parameters.values():
            assert parameter.name in actual.parameters, (name, parameter.name)
            mine = actual.parameters[parameter.name]
            assert mine.kind == parameter.kind, (name, parameter.name)
            assert mine.default == parameter.default, (name, parameter.name)
        # Extra parameters are allowed only as keyword arguments with defaults.
        for parameter in actual.parameters.values():
            if parameter.name not in wanted.parameters:
                assert parameter.kind is inspect.Parameter.KEYWORD_ONLY, name
                assert parameter.default is not inspect.Parameter.empty, name
        assert inspect.iscoroutinefunction(
            getattr(DefaultCryptoKit, name)
        ) == inspect.iscoroutinefunction(getattr(protocol, name))


def test_password_check_is_the_contract_class() -> None:
    assert PasswordCheck is ContractPasswordCheck
