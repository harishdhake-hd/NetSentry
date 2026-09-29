"""
backend/config.py

Configuration management for NetSentry.
Loads from .env and provides typed access to all settings.
"""

import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    """Main configuration class."""

    # Network interface
    NETSENTRY_INTERFACE = os.getenv("NETSENTRY_INTERFACE", "auto")
    CAPTURE_PROMISC_MODE = os.getenv("CAPTURE_PROMISC_MODE", "true").lower() == "true"

    # Flow tracking
    FLOW_TIMEOUT_SECONDS = int(os.getenv("FLOW_TIMEOUT_SECONDS", "300"))

    # Database
    DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./data/netsentry.db")

    # API
    API_HOST = os.getenv("API_HOST", "0.0.0.0")
    API_PORT = int(os.getenv("API_PORT", "8000"))

    # Logging
    LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")

    @staticmethod
    def get_database_url():
        """Get the database URL."""
        return Config.DATABASE_URL

    @staticmethod
    def get_interface():
        """Get the network interface to use for capture."""
        return Config.NETSENTRY_INTERFACE

    @staticmethod
    def get_flow_timeout():
        """Get flow timeout in seconds."""
        return Config.FLOW_TIMEOUT_SECONDS

    @staticmethod
    def is_promisc_mode():
        """Check if promiscuous mode is enabled."""
        return Config.CAPTURE_PROMISC_MODE


config = Config()
