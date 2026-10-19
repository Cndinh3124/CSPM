"""Load project settings from .env and environment variables."""
import os
from pathlib import Path

from dotenv import load_dotenv

# This file is at python/secnet_cspm/config.py; parents[2] is the repo root.
ROOT_DIR = Path(__file__).resolve().parents[2]
load_dotenv(ROOT_DIR / ".env")


def setting(name: str, default: str = "") -> str:
    """Return one setting, using default when it is not configured."""
    return os.getenv(name, default)


def project_path(value: str) -> Path:
    """Resolve relative paths from the repository root."""
    path = Path(value)
    return path if path.is_absolute() else ROOT_DIR / path
