# type: ignore
# ruff: noqa
"""Raises as soon as it is imported: gotauth check must only read it."""

raise RuntimeError("gotauth check imported a file it should only have parsed")

from passlib.hash import bcrypt  # never reached, but still found by the scanner
