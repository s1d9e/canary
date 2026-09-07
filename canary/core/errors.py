"""Canary custom exceptions."""

from __future__ import annotations


class CanaryError(Exception):
    """Base exception for all Canary errors."""


class ConfigError(CanaryError):
    """Raised when configuration is invalid."""


class DatabaseError(CanaryError):
    """Raised on database failures."""


class NormalizationError(CanaryError):
    """Raised when an event cannot be normalized."""


class CorrelationError(CanaryError):
    """Raised during correlation processing."""


class IngestionError(CanaryError):
    """Raised when an event cannot be ingested."""
