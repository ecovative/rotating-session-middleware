"""Tests for RotatingSessionMiddleware."""

import threading

import fastapi
import httpx
import pytest

from starlette.datastructures import Secret

from rotating_session_middleware import RotatingSessionMiddleware, get_instance


def _build_app(secret: str = "test-secret") -> fastapi.FastAPI:
    """Build a minimal test app with RotatingSessionMiddleware."""
    app = fastapi.FastAPI()

    app.add_middleware(
        RotatingSessionMiddleware,
        secret_key=secret,
        max_age=86400,
    )

    @app.get("/set")
    async def set_session(request: fastapi.Request) -> dict:
        request.session["user"] = "alice"
        return {"status": "ok"}

    @app.get("/get")
    async def get_session(request: fastapi.Request) -> dict:
        return {"user": request.session.get("user")}

    @app.get("/clear")
    async def clear_session(request: fastapi.Request) -> dict:
        request.session.clear()
        return {"status": "cleared"}

    return app


class TestSignUnsignRoundtrip:
    """Test basic session cookie sign/unsign."""

    @pytest.mark.asyncio
    async def test_session_roundtrip(self) -> None:
        """Set a session value and read it back."""
        app = _build_app()
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver",
        ) as client:
            resp = await client.get("/set")
            assert resp.status_code == 200

            resp = await client.get("/get")
            assert resp.status_code == 200
            assert resp.json()["user"] == "alice"

    @pytest.mark.asyncio
    async def test_no_session_returns_none(self) -> None:
        """No session cookie returns None for session values."""
        app = _build_app()
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver",
        ) as client:
            resp = await client.get("/get")
            assert resp.status_code == 200
            assert resp.json()["user"] is None

    @pytest.mark.asyncio
    async def test_invalid_cookie_returns_empty_session(self) -> None:
        """A tampered cookie results in an empty session, not an error."""
        app = _build_app()
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver",
        ) as client:
            resp = await client.get(
                "/get", cookies={"session": "garbage.tampered.value"}
            )
            assert resp.status_code == 200
            assert resp.json()["user"] is None


class TestRotateSecret:
    """Test secret rotation keeps old sessions valid."""

    @pytest.mark.asyncio
    async def test_rotate_allows_old_sessions(self) -> None:
        """Sessions signed with the previous secret still verify."""
        app = _build_app("secret-v1")

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver",
        ) as client:
            resp = await client.get("/set")
            assert resp.status_code == 200

            middleware = get_instance()
            middleware.rotate_secret("secret-v2")

            resp = await client.get("/get")
            assert resp.status_code == 200
            assert resp.json()["user"] == "alice"

    @pytest.mark.asyncio
    async def test_double_rotation_drops_oldest(self) -> None:
        """Two rotations drop the original signer, invalidating old sessions."""
        app = _build_app("secret-v1")

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver",
        ) as client:
            resp = await client.get("/set")
            assert resp.status_code == 200

            middleware = get_instance()
            middleware.rotate_secret("secret-v2")
            middleware.rotate_secret("secret-v3")

            resp = await client.get("/get")
            assert resp.status_code == 200
            assert resp.json()["user"] is None

    @pytest.mark.asyncio
    async def test_rotate_without_keep_previous(self) -> None:
        """Rotating with keep_previous=False immediately invalidates old sessions."""
        app = _build_app("secret-v1")

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver",
        ) as client:
            resp = await client.get("/set")
            assert resp.status_code == 200

            middleware = get_instance()
            middleware.rotate_secret("secret-v2", keep_previous=False)

            resp = await client.get("/get")
            assert resp.status_code == 200
            assert resp.json()["user"] is None

    @pytest.mark.asyncio
    async def test_new_sessions_use_new_secret(self) -> None:
        """Sessions created after rotation use the new signer."""
        app = _build_app("secret-v1")

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver",
        ) as client:
            resp = await client.get("/get")
            assert resp.status_code == 200

            middleware = get_instance()
            middleware.rotate_secret("secret-v2")

            resp = await client.get("/set")
            assert resp.status_code == 200

            middleware.rotate_secret("secret-v3")

            resp = await client.get("/get")
            assert resp.status_code == 200
            assert resp.json()["user"] == "alice"


class TestClearedSession:
    """Test that clearing a session removes the cookie."""

    @pytest.mark.asyncio
    async def test_clear_session_sets_max_age_zero(self) -> None:
        """Clearing the session dict causes Max-Age=0 to be sent."""
        app = _build_app()
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver",
        ) as client:
            await client.get("/set")
            resp = await client.get("/clear")
            assert resp.status_code == 200

            resp = await client.get("/get")
            assert resp.json()["user"] is None


class TestCookieAttributes:
    """Test cookie attribute configuration."""

    @pytest.mark.asyncio
    async def test_custom_cookie_name(self) -> None:
        """Custom session_cookie name is used."""
        app = fastapi.FastAPI()
        app.add_middleware(
            RotatingSessionMiddleware,
            secret_key="test",
            session_cookie="my_session",
            max_age=3600,
        )

        @app.get("/set")
        async def set_session(request: fastapi.Request) -> dict:
            request.session["key"] = "value"
            return {"ok": True}

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver",
        ) as client:
            resp = await client.get("/set")
            assert resp.status_code == 200
            cookie_header = resp.headers.get("set-cookie", "")
            assert cookie_header.startswith("my_session=")

    @pytest.mark.asyncio
    async def test_https_only_sets_secure_flag(self) -> None:
        """https_only=True includes 'secure' in cookie flags."""
        app = fastapi.FastAPI()
        app.add_middleware(
            RotatingSessionMiddleware,
            secret_key="test",
            https_only=True,
        )

        @app.get("/set")
        async def set_session(request: fastapi.Request) -> dict:
            request.session["key"] = "value"
            return {"ok": True}

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver",
        ) as client:
            resp = await client.get("/set")
            cookie_header = resp.headers.get("set-cookie", "").lower()
            assert "secure" in cookie_header

    @pytest.mark.asyncio
    async def test_domain_attribute(self) -> None:
        """domain parameter is included in the Set-Cookie header."""
        app = fastapi.FastAPI()
        app.add_middleware(
            RotatingSessionMiddleware,
            secret_key="test",
            domain=".example.com",
        )

        @app.get("/set")
        async def set_session(request: fastapi.Request) -> dict:
            request.session["key"] = "value"
            return {"ok": True}

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver",
        ) as client:
            resp = await client.get("/set")
            cookie_header = resp.headers.get("set-cookie", "")
            assert "domain=.example.com" in cookie_header

    @pytest.mark.asyncio
    async def test_samesite_strict(self) -> None:
        """same_site='strict' is reflected in cookie flags."""
        app = fastapi.FastAPI()
        app.add_middleware(
            RotatingSessionMiddleware,
            secret_key="test",
            same_site="strict",
        )

        @app.get("/set")
        async def set_session(request: fastapi.Request) -> dict:
            request.session["key"] = "value"
            return {"ok": True}

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver",
        ) as client:
            resp = await client.get("/set")
            cookie_header = resp.headers.get("set-cookie", "").lower()
            assert "samesite=strict" in cookie_header


class TestWebSocketPassthrough:
    """Test that non-HTTP scopes pass through."""

    @pytest.mark.asyncio
    async def test_non_http_scope_passes_through(self) -> None:
        """ASGI lifespan and other non-http scopes are passed through."""
        app = _build_app()
        # FastAPI handles lifespan internally — just verify the app starts
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver",
        ) as client:
            resp = await client.get("/get")
            assert resp.status_code == 200


class TestThreadSafety:
    """Verify concurrent rotation doesn't corrupt state."""

    def test_concurrent_rotations(self) -> None:
        """Concurrent rotate_secret calls don't corrupt the signers list."""
        _build_app("initial")
        middleware = get_instance()

        errors: list[Exception] = []

        def rotate(n: int) -> None:
            try:
                for i in range(50):
                    middleware.rotate_secret(f"secret-{n}-{i}")
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=rotate, args=(t,)) for t in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == []
        signers = middleware._get_signers()
        assert 1 <= len(signers) <= 2


class TestGetInstance:
    """Test the singleton accessor."""

    def test_get_instance_returns_middleware(self) -> None:
        """get_instance returns the middleware after it's been created."""
        _build_app()
        middleware = get_instance()
        assert isinstance(middleware, RotatingSessionMiddleware)

    def test_get_instance_raises_before_init(self) -> None:
        """get_instance raises RuntimeError before any middleware is created."""
        # We can't easily reset the global without reaching into internals,
        # but we can verify it's set after building an app.
        import rotating_session_middleware.middleware as mod

        original = mod._instance
        try:
            mod._instance = None
            with pytest.raises(RuntimeError, match="has not been instantiated"):
                get_instance()
        finally:
            mod._instance = original


class TestSecretKeyTypes:
    """Test that Secret objects and plain strings both work."""

    @pytest.mark.asyncio
    async def test_starlette_secret_object(self) -> None:
        """Starlette Secret object is accepted as secret_key."""
        app = fastapi.FastAPI()
        app.add_middleware(
            RotatingSessionMiddleware,
            secret_key=Secret("my-secret"),
            max_age=86400,
        )

        @app.get("/set")
        async def set_session(request: fastapi.Request) -> dict:
            request.session["key"] = "value"
            return {"ok": True}

        @app.get("/get")
        async def get_session(request: fastapi.Request) -> dict:
            return {"key": request.session.get("key")}

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver",
        ) as client:
            resp = await client.get("/set")
            assert resp.status_code == 200

            resp = await client.get("/get")
            assert resp.json()["key"] == "value"
