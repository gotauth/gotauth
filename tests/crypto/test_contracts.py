"""Conformance with the CryptoKit protocol of gotauth.contracts.crypto (F2).

Skipped until F2 merges.
"""

from __future__ import annotations

import dataclasses
import importlib
import inspect
from types import ModuleType

import pytest

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
    # importlib, not an import statement: the module does not exist before F2 merges.
    try:
        return importlib.import_module("gotauth.contracts.crypto")
    except ImportError:
        pytest.skip("gotauth.contracts.crypto does not exist yet (F2 has not merged)")


def test_kit_has_every_contract_member() -> None:
    kit = crypto_kit("contract-tests-secret-0123456789abcdef")
    for name in CONTRACT_MEMBERS:
        member = getattr(kit, name)
        assert callable(member)
        assert inspect.iscoroutinefunction(member) == (name in ASYNC_MEMBERS), name


def test_kit_matches_the_protocol_signatures() -> None:
    # TODO(F2): after merge, also annotate `kit: CryptoKit = crypto_kit(...)` so
    # pyright checks the same thing statically.
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


def test_password_check_matches_the_contract() -> None:
    # TODO(F2): replace the local PasswordCheck with the contract's after merge;
    # then this test checks that both names are the same class.
    contract = contracts_crypto().PasswordCheck
    assert [field.name for field in dataclasses.fields(contract)] == [
        field.name for field in dataclasses.fields(PasswordCheck)
    ]
