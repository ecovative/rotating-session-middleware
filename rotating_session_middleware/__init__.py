"""Rotating session middleware for Starlette and FastAPI.

A drop-in replacement for Starlette's ``SessionMiddleware`` that supports
atomic secret rotation.  After a rotation the *previous* signer is kept
so in-flight sessions signed with the old secret still verify.

Usage::

    from rotating_session_middleware import RotatingSessionMiddleware

    app.add_middleware(
        RotatingSessionMiddleware,
        secret_key="initial-secret",
        max_age=86400,
    )

Runtime rotation::

    from rotating_session_middleware import get_instance
    get_instance().rotate_secret("new-secret-value")
"""

__all__ = [
    "RotatingSessionMiddleware",
    "get_instance",
]

from rotating_session_middleware.middleware import (
    RotatingSessionMiddleware,
    get_instance,
)
