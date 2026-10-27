"""Optional FastAPI dashboard for browsing and running scans.

Import is deliberately lazy: the scanning engine and the CLI work without
FastAPI, uvicorn or Jinja2 installed. ``d3ta1l3r web`` reports a friendly error
if the ``[web]`` extras are missing.
"""

from __future__ import annotations

__all__ = ["AppSettings", "create_app"]


def __getattr__(name: str):  # pragma: no cover - lazy import shim
    if name in {"create_app", "AppSettings"}:
        from .app import AppSettings, create_app

        return {"create_app": create_app, "AppSettings": AppSettings}[name]
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
