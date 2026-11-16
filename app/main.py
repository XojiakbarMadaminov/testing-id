import html
import re
import sqlite3
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from app.config import Settings
from app.security import ProtocolError, parse_parameters, require, response_url, url_origin
from app.store import Store

ENDPOINT = "/sso/oauth/Authorization.do"
ASSETS = Path(__file__).parent / "static"


async def form(request: Request):
    require(
        request.headers.get("content-type", "").split(";", 1)[0].lower()
        == "application/x-www-form-urlencoded",
        description="Expected a URL-encoded form.",
    )
    data = bytearray()
    async for part in request.stream():
        require(len(data) + len(part) <= 8192, description="Request is too large.", status=413)
        data.extend(part)
    return parse_parameters(bytes(data))


def login_page(request_id: str, csrf: str, *, error="", username="", status=200):
    template = (Path(__file__).parent / "templates/login.html").read_text()
    for name, value in {
        "REQUEST": request_id,
        "CSRF": csrf,
        "ERROR": error,
        "USERNAME": username,
    }.items():
        template = template.replace("{{" + name + "}}", html.escape(value, quote=True))
    return HTMLResponse(template, status_code=status)


def create_app(settings: Settings | None = None):
    @asynccontextmanager
    async def lifespan(app):
        app.state.settings = settings or Settings.from_env()
        app.state.store = Store(app.state.settings)
        yield

    app = FastAPI(
        title="Testing ID — OneID contract mock",
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.mount("/static", StaticFiles(directory=ASSETS), name="static")

    @app.exception_handler(ProtocolError)
    async def protocol_error(_request, exc):
        headers = {"Retry-After": "60"} if exc.status == 429 else {}
        return JSONResponse(
            {"error": exc.error, "error_description": exc.description},
            status_code=exc.status,
            headers=headers,
        )

    @app.exception_handler(sqlite3.Error)
    async def storage_error(_request, _exc):
        return JSONResponse(
            {
                "error": "temporarily_unavailable",
                "error_description": "Mock storage is unavailable.",
            },
            status_code=503,
        )

    @app.middleware("http")
    async def security_headers(request, call_next):
        response = await call_next(request)
        config = app.state.settings
        try:
            origins = sorted(set(app.state.store.callback_origins()) | set(config.frontend_origins))
        except sqlite3.Error:
            origins = []
        response.headers["Cache-Control"] = "no-store, private"
        response.headers["Pragma"] = "no-cache"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        # Keep Origin on the login POST; do not send state/code URLs cross-origin as Referer.
        response.headers["Referrer-Policy"] = "same-origin"
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; style-src 'self'; img-src 'self'; "
            "form-action 'self' " + " ".join(origins) + "; frame-ancestors 'none'; base-uri 'none'"
        )
        return response

    def cookie(response, raw):
        config = app.state.settings
        response.set_cookie(
            config.cookie_name,
            raw,
            max_age=config.browser_ttl,
            httponly=True,
            secure=config.secure,
            samesite="lax",
            path="/",
        )
        return response

    @app.get("/health")
    def health():
        with app.state.store.connect() as db:
            count = db.execute("SELECT count(*) FROM clients WHERE enabled=1").fetchone()[0]
        return {"status": "ok", "mode": "testing-id-mock", "configured_clients": count}

    @app.get("/", response_class=HTMLResponse)
    def index():
        return HTMLResponse((Path(__file__).parent / "templates/index.html").read_text())

    @app.get(ENDPOINT)
    async def authorize(request: Request):
        params = parse_parameters(request.scope.get("query_string", b""))
        require(
            set(params) == {"response_type", "client_id", "redirect_uri", "scope", "state"},
            description="Expected the five documented authorization parameters.",
        )
        config = app.state.settings
        browser = request.cookies.get(config.cookie_name, "")
        if not re.fullmatch(r"[A-Za-z0-9_-]{43}", browser):
            browser = ""
        result = app.state.store.start_authorization(params, browser)
        if "code" in result:
            response = RedirectResponse(
                response_url(params["redirect_uri"], code=result["code"], state=params["state"]),
                status_code=302,
            )
        else:
            response = login_page(result["request"], result["csrf"])
        return cookie(response, result["cookie"])

    @app.post("/login")
    async def login(request: Request):
        require(
            request.headers.get("origin") == url_origin(app.state.settings.public_url),
            description="Login Origin does not match.",
            status=403,
        )
        params = await form(request)
        require(set(params) == {"request", "csrf", "username", "password"})
        browser = request.cookies.get(app.state.settings.cookie_name, "")
        result = app.state.store.login(
            params, browser, request.client.host if request.client else "unknown"
        )
        if result is None:
            return login_page(
                params["request"],
                params["csrf"],
                username=params["username"],
                error="Login yoki parol noto‘g‘ri, yoxud test hisobi o‘chirilgan.",
                status=401,
            )
        response = RedirectResponse(
            response_url(result["redirect_uri"], code=result["code"], state=result["state"]),
            status_code=303,
        )
        return cookie(response, result["cookie"])

    @app.post(ENDPOINT)
    async def operation(request: Request):
        params = await form(request)
        require(
            not request.headers.get("authorization"),
            description="This contract authenticates the client in the POST form.",
        )
        app.state.store.authenticate_client(params)
        grant = params.get("grant_type")
        if grant == "one_authorization_code":
            require(
                set(params) == {"grant_type", "client_id", "client_secret", "redirect_uri", "code"}
            )
            return app.state.store.exchange(params)
        if grant in {"one_access_token_identify", "one_log_out"}:
            require(
                set(params) == {"grant_type", "client_id", "client_secret", "access_token", "scope"}
            )
            method = (
                app.state.store.identify
                if grant == "one_access_token_identify"
                else app.state.store.logout
            )
            return method(params)
        raise ProtocolError("unsupported_grant_type", "Grant is not defined by the supplied guide.")

    return app


app = create_app()
