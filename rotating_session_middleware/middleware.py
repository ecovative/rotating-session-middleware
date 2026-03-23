"""Rotating session middleware with hot-swappable secrets.

Drop-in replacement for Starlette's ``SessionMiddleware`` that supports
atomic secret rotation.  After a rotation the *previous* signer is kept
so in-flight sessions signed with the old secret still verify.
"""

__all__ = [
    "RotatingSessionMiddleware",
    "get_instance",
]

import base64
import json
import logging
import threading
import typing

import itsdangerous
from starlette.datastructures import MutableHeaders, Secret
from starlette.requests import HTTPConnection
from starlette.types import ASGIApp, Message, Receive, Scope, Send

logger = logging.getLogger(__name__)

_instance_lock = threading.Lock()
_instance: "RotatingSessionMiddleware | None" = None


def get_instance() -> "RotatingSessionMiddleware":
    """Return the singleton middleware instance.

    Raises:
        RuntimeError: If the middleware has not been instantiated yet.
    """
    if _instance is None:
        msg = "RotatingSessionMiddleware has not been instantiated"
        raise RuntimeError(msg)
    return _instance


class RotatingSessionMiddleware:
    """Session middleware that allows atomic secret rotation.

    Mirrors the Starlette ``SessionMiddleware`` interface but stores an
    ordered list of ``TimestampSigner`` instances behind a lock.  Signing
    always uses the *first* (newest) signer; verification tries each
    signer in order so sessions signed with the previous secret still
    validate during the transition window.
    """

    def __init__(
        self,
        app: ASGIApp,
        secret_key: str | Secret,
        session_cookie: str = "session",
        max_age: int | None = 14 * 24 * 60 * 60,  # 14 days
        path: str = "/",
        same_site: typing.Literal["lax", "strict", "none"] = "lax",
        https_only: bool = False,
        domain: str | None = None,
    ) -> None:
        global _instance

        self.app = app
        self.session_cookie = session_cookie
        self.max_age = max_age
        self.path = path
        self.same_site = same_site
        self.https_only = https_only
        self.domain = domain
        self.security_flags = "httponly; samesite=" + same_site
        if https_only:
            self.security_flags += "; secure"

        secret = str(secret_key) if isinstance(secret_key, Secret) else secret_key
        self._signers_lock = threading.Lock()
        self._signers: list[itsdangerous.TimestampSigner] = [
            itsdangerous.TimestampSigner(secret),
        ]

        with _instance_lock:
            _instance = self

    # --- Public rotation API ---

    def rotate_secret(self, new_secret: str, *, keep_previous: bool = True) -> None:
        """Atomically swap to a new signing secret.

        Args:
            new_secret: The new secret value.
            keep_previous: If ``True`` (default), the immediately-previous
                signer is retained for verification so in-flight sessions
                still validate.  Only the *one* previous signer is kept;
                older ones are dropped.
        """
        new_signer = itsdangerous.TimestampSigner(new_secret)
        with self._signers_lock:
            if keep_previous and self._signers:
                self._signers = [new_signer, self._signers[0]]
            else:
                self._signers = [new_signer]
        logger.info(
            "Session secret rotated (signers=%d)",
            len(self._signers),
        )

    # --- Internal helpers ---

    def _get_signers(self) -> list[itsdangerous.TimestampSigner]:
        """Return a snapshot of the current signers list."""
        with self._signers_lock:
            return list(self._signers)

    def _sign(self, data: str) -> str:
        """Sign *data* with the current (newest) signer.

        Base64-encodes the data first to ensure the cookie value
        contains only safe ASCII characters.
        """
        encoded = base64.b64encode(data.encode("utf-8"))
        signers = self._get_signers()
        return signers[0].sign(encoded).decode("utf-8")

    def _unsign(self, signed: str) -> str | None:
        """Verify and decode *signed*, trying each signer in order.

        Returns ``None`` when no signer can verify.
        """
        signers = self._get_signers()
        for signer in signers:
            try:
                unsigned = signer.unsign(signed, max_age=self.max_age)
                return base64.b64decode(unsigned).decode("utf-8")
            except itsdangerous.SignatureExpired:
                return None
            except itsdangerous.BadSignature:
                continue
        return None

    # --- ASGI plumbing (mirrors Starlette SessionMiddleware) ---

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return

        connection = HTTPConnection(scope)
        initial_session_was_empty = True

        if self.session_cookie in connection.cookies:
            cookie = connection.cookies[self.session_cookie]
            data = self._unsign(cookie)
            if data is not None:
                try:
                    scope["session"] = json.loads(data)
                    initial_session_was_empty = False
                except json.JSONDecodeError:
                    scope["session"] = {}
            else:
                scope["session"] = {}
        else:
            scope["session"] = {}

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                session: dict[str, typing.Any] = scope.get("session", {})
                headers = MutableHeaders(scope=message)

                if session:
                    data = self._sign(json.dumps(session))
                    header_value = (
                        "{session_cookie}={data}; path={path}; "
                        "{max_age}{domain}{security_flags}"
                    ).format(
                        session_cookie=self.session_cookie,
                        data=data,
                        path=self.path,
                        max_age="Max-Age=%d; " % self.max_age if self.max_age else "",
                        domain="domain=%s; " % self.domain if self.domain else "",
                        security_flags=self.security_flags,
                    )
                    headers.append("set-cookie", header_value)
                elif not initial_session_was_empty:
                    # Clear the cookie
                    header_value = (
                        "{session_cookie}={data}; path={path}; "
                        "{domain}{security_flags}; Max-Age=0"
                    ).format(
                        session_cookie=self.session_cookie,
                        data="null",
                        path=self.path,
                        domain="domain=%s; " % self.domain if self.domain else "",
                        security_flags=self.security_flags,
                    )
                    headers.append("set-cookie", header_value)
            await send(message)

        await self.app(scope, receive, send_wrapper)
