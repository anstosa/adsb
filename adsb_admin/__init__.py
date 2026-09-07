"""Local administration service for the ADS-B production stack."""

from .server import AdminApplication, create_server

__all__ = ["AdminApplication", "create_server"]
