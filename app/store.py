import hmac
import json
import secrets
import sqlite3
import time
import uuid
from contextlib import contextmanager

from app.config import Settings
from app.security import check_password, digest, opaque, password_hash, require, validate_url

SCHEMA = """
CREATE TABLE IF NOT EXISTS clients (
    id INTEGER PRIMARY KEY AUTOINCREMENT, client_id TEXT NOT NULL UNIQUE,
    secret_hash TEXT NOT NULL, redirects TEXT NOT NULL, scopes TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL, profile TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS browsers (
    browser_hash TEXT PRIMARY KEY, user_id INTEGER REFERENCES users(id),
    sess_id TEXT UNIQUE, expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS auth_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT, request_hash TEXT NOT NULL UNIQUE,
    csrf_hash TEXT NOT NULL, browser_hash TEXT NOT NULL REFERENCES browsers(browser_hash),
    client_id TEXT NOT NULL REFERENCES clients(client_id), redirect_uri TEXT NOT NULL,
    scope TEXT NOT NULL, state TEXT NOT NULL, expires_at INTEGER NOT NULL,
    used_at INTEGER
);
CREATE TABLE IF NOT EXISTS codes (
    id INTEGER PRIMARY KEY AUTOINCREMENT, code_hash TEXT NOT NULL UNIQUE,
    browser_hash TEXT NOT NULL REFERENCES browsers(browser_hash),
    client_id TEXT NOT NULL REFERENCES clients(client_id), user_id INTEGER NOT NULL REFERENCES users(id),
    sess_id TEXT NOT NULL, redirect_uri TEXT NOT NULL, scope TEXT NOT NULL,
    expires_at INTEGER NOT NULL, used_at INTEGER
);
CREATE TABLE IF NOT EXISTS tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT, access_hash TEXT NOT NULL UNIQUE,
    refresh_hash TEXT NOT NULL UNIQUE, browser_hash TEXT NOT NULL REFERENCES browsers(browser_hash),
    client_id TEXT NOT NULL REFERENCES clients(client_id), user_id INTEGER NOT NULL REFERENCES users(id),
    sess_id TEXT NOT NULL, scope TEXT NOT NULL, expires_at INTEGER NOT NULL,
    refresh_expires_at INTEGER NOT NULL, revoked_at INTEGER
);
CREATE TABLE IF NOT EXISTS attempts (
    bucket TEXT PRIMARY KEY, count INTEGER NOT NULL, expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS auth_requests_expiry ON auth_requests(expires_at);
CREATE INDEX IF NOT EXISTS codes_expiry ON codes(expires_at);
CREATE INDEX IF NOT EXISTS tokens_expiry ON tokens(expires_at);
"""


class Store:
    def __init__(self, settings: Settings, clock=time.time):
        self.settings, self.clock = settings, clock
        settings.data_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.path = settings.data_dir / "testing-id.sqlite3"
        with self.connect() as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.executescript(SCHEMA)
        self.path.chmod(0o600)
        self.dummy_password = password_hash(secrets.token_urlsafe(32))

    def now(self):
        return int(self.clock())

    @contextmanager
    def connect(self, *, write=False):
        db = sqlite3.connect(self.path, timeout=5)
        db.row_factory = sqlite3.Row
        try:
            db.execute("PRAGMA foreign_keys=ON")
            if write:
                db.execute("BEGIN IMMEDIATE")
            with db:
                yield db
        finally:
            db.close()

    @staticmethod
    def validate_client(client_id, secret, redirects, scopes):
        if (
            not isinstance(client_id, str)
            or not 1 <= len(client_id) <= 100
            or not isinstance(secret, str)
            or len(secret) < 24
            or not redirects
            or not scopes
        ):
            raise ValueError("Client needs an id, a random secret, callbacks and scopes.")
        for uri in redirects:
            validate_url(uri, callback=True)
        if any(not isinstance(s, str) or not s.strip() or len(s) > 512 for s in scopes):
            raise ValueError("Invalid scope.")

    def add_client(self, client_id, secret, redirects, scopes):
        self.validate_client(client_id, secret, redirects, scopes)
        with self.connect(write=True) as db:
            db.execute(
                "INSERT INTO clients(client_id,secret_hash,redirects,scopes) VALUES (?,?,?,?)",
                (client_id, digest(secret), json.dumps(redirects), json.dumps(scopes)),
            )

    def add_user(self, username, password, profile, *, enabled=True):
        if not username or len(username) > 64 or not 12 <= len(password) <= 128:
            raise ValueError("Invalid synthetic account.")
        with self.connect(write=True) as db:
            db.execute(
                "INSERT INTO users(username,password_hash,profile,enabled) VALUES (?,?,?,?)",
                (username, password_hash(password), json.dumps(profile), int(enabled)),
            )

    def client(self, client_id):
        with self.connect() as db:
            client = db.execute("SELECT * FROM clients WHERE client_id=?", (client_id,)).fetchone()
        require(client is not None and client["enabled"], "invalid_client", "Unknown client.", 401)
        return client

    def authenticate_client(self, params):
        client = self.client(params.get("client_id", ""))
        require(
            hmac.compare_digest(digest(params.get("client_secret", "")), client["secret_hash"]),
            "invalid_client",
            "Client authentication failed.",
            401,
        )
        return client

    def validate_authorization(self, params):
        client = self.client(params.get("client_id", ""))
        require(
            params.get("redirect_uri") in json.loads(client["redirects"]),
            description="Callback is not registered.",
        )
        require(
            params.get("response_type") == "one_code",
            "unsupported_response_type",
            "Expected response_type=one_code.",
        )
        require(
            params.get("scope") in json.loads(client["scopes"]), "invalid_scope", "Invalid scope."
        )
        require(
            0 < len(params.get("state", "")) <= 2048, description="A nonempty state is required."
        )

    def new_browser(self, db, user_id=None):
        raw = secrets.token_urlsafe(32)
        session_id = str(uuid.uuid4()) if user_id is not None else None
        db.execute(
            "INSERT INTO browsers VALUES (?,?,?,?)",
            (digest(raw), user_id, session_id, self.now() + self.settings.browser_ttl),
        )
        return raw, session_id

    def _browser(self, db, raw):
        return db.execute(
            "SELECT b.*, u.enabled FROM browsers b LEFT JOIN users u ON u.id=b.user_id "
            "WHERE browser_hash=? AND expires_at>?",
            (digest(raw), self.now()),
        ).fetchone()

    def start_authorization(self, params, browser_cookie):
        self.validate_authorization(params)
        with self.connect(write=True) as db:
            db.execute("DELETE FROM attempts WHERE expires_at<=?", (self.now(),))
            db.execute("DELETE FROM auth_requests WHERE expires_at<=?", (self.now(),))
            browser = self._browser(db, browser_cookie)
            if browser and browser["user_id"] and browser["enabled"]:
                code = self._code(
                    db, params, browser["browser_hash"], browser["user_id"], browser["sess_id"]
                )
                return {"code": code, "cookie": browser_cookie}
            if browser is None:
                browser_cookie, _ = self.new_browser(db)
            require(
                db.execute("SELECT count(*) FROM auth_requests").fetchone()[0] < 1000,
                "temporarily_unavailable",
                "Too many pending logins.",
                503,
            )
            request_id, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
            db.execute(
                "INSERT INTO auth_requests(request_hash,csrf_hash,browser_hash,client_id,redirect_uri,"
                "scope,state,expires_at) VALUES (?,?,?,?,?,?,?,?)",
                (
                    digest(request_id),
                    digest(csrf),
                    digest(browser_cookie),
                    params["client_id"],
                    params["redirect_uri"],
                    params["scope"],
                    params["state"],
                    self.now() + self.settings.login_ttl,
                ),
            )
            return {"request": request_id, "csrf": csrf, "cookie": browser_cookie}

    def _code(self, db, params, browser_hash, user_id, session_id):
        raw = opaque()
        db.execute(
            "INSERT INTO codes(code_hash,browser_hash,client_id,user_id,sess_id,redirect_uri,scope,"
            "expires_at) VALUES (?,?,?,?,?,?,?,?)",
            (
                digest(raw),
                browser_hash,
                params["client_id"],
                user_id,
                session_id,
                params["redirect_uri"],
                params["scope"],
                self.now() + self.settings.code_ttl,
            ),
        )
        return raw

    def check_login_request(self, params, browser_cookie):
        with self.connect() as db:
            row = db.execute(
                "SELECT * FROM auth_requests WHERE request_hash=?",
                (digest(params.get("request", "")),),
            ).fetchone()
        require(
            row and row["used_at"] is None and row["expires_at"] > self.now(),
            description="Login request expired or already used.",
        )
        require(
            hmac.compare_digest(row["browser_hash"], digest(browser_cookie))
            and hmac.compare_digest(row["csrf_hash"], digest(params.get("csrf", ""))),
            description="Login browser or CSRF token does not match.",
        )
        return row

    def rate_limit(self, ip, username):
        with self.connect(write=True) as db:
            for bucket, maximum in (
                ("ip:" + digest(ip), 25),
                ("user:" + digest(username.lower()), 8),
            ):
                row = db.execute("SELECT * FROM attempts WHERE bucket=?", (bucket,)).fetchone()
                require(
                    not row or row["expires_at"] <= self.now() or row["count"] < maximum,
                    "temporarily_unavailable",
                    "Too many login attempts.",
                    429,
                )
            for bucket in ("ip:" + digest(ip), "user:" + digest(username.lower())):
                db.execute(
                    "INSERT INTO attempts VALUES (?,1,?) ON CONFLICT(bucket) DO UPDATE SET "
                    "count=CASE WHEN expires_at<=? THEN 1 ELSE count+1 END, "
                    "expires_at=CASE WHEN expires_at<=? THEN excluded.expires_at ELSE expires_at END",
                    (bucket, self.now() + 60, self.now(), self.now()),
                )

    def login(self, params, browser_cookie, ip):
        self.check_login_request(params, browser_cookie)
        username, password = params.get("username", "").strip(), params.get("password", "")
        require(len(username) <= 64 and len(password) <= 128)
        self.rate_limit(ip, username)
        with self.connect() as db:
            user = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        valid = check_password(password, user["password_hash"] if user else self.dummy_password)
        if not valid or not user or not user["enabled"]:
            return None
        with self.connect(write=True) as db:
            # Recheck under the write lock: two submits may not consume the same request.
            row = db.execute(
                "SELECT * FROM auth_requests WHERE request_hash=?", (digest(params["request"]),)
            ).fetchone()
            require(row and row["used_at"] is None and row["expires_at"] > self.now())
            current = db.execute(
                "SELECT enabled,password_hash FROM users WHERE id=?", (user["id"],)
            ).fetchone()
            require(
                current["enabled"] and current["password_hash"] == user["password_hash"],
                "access_denied",
                "Account changed; start again.",
                401,
            )
            db.execute("UPDATE auth_requests SET used_at=? WHERE id=?", (self.now(), row["id"]))
            db.execute(
                "UPDATE browsers SET expires_at=0 WHERE browser_hash=?", (row["browser_hash"],)
            )
            raw, session_id = self.new_browser(db, user["id"])
            code = self._code(db, row, digest(raw), user["id"], session_id)
            db.execute("DELETE FROM attempts WHERE bucket=?", ("user:" + digest(username.lower()),))
            return {
                "cookie": raw,
                "code": code,
                "redirect_uri": row["redirect_uri"],
                "state": row["state"],
            }

    def exchange(self, params):
        with self.connect(write=True) as db:
            row = db.execute(
                "SELECT * FROM codes WHERE code_hash=?", (digest(params.get("code", "")),)
            ).fetchone()
            require(
                row and row["used_at"] is None and row["expires_at"] > self.now(),
                "invalid_grant",
                "Code is invalid, expired or already used.",
            )
            require(
                row["client_id"] == params["client_id"]
                and row["redirect_uri"] == params.get("redirect_uri"),
                "invalid_grant",
                "Code binding does not match.",
            )
            browser = db.execute(
                "SELECT * FROM browsers WHERE browser_hash=?", (row["browser_hash"],)
            ).fetchone()
            user = db.execute("SELECT enabled FROM users WHERE id=?", (row["user_id"],)).fetchone()
            require(
                user["enabled"] and browser["expires_at"] > self.now(),
                "invalid_grant",
                "Session is unavailable.",
            )
            db.execute("UPDATE codes SET used_at=? WHERE id=?", (self.now(), row["id"]))
            access, refresh = opaque(), opaque()
            db.execute(
                "INSERT INTO tokens(access_hash,refresh_hash,browser_hash,client_id,user_id,sess_id,scope,"
                "expires_at,refresh_expires_at) VALUES (?,?,?,?,?,?,?,?,?)",
                (
                    digest(access),
                    digest(refresh),
                    row["browser_hash"],
                    row["client_id"],
                    row["user_id"],
                    row["sess_id"],
                    row["scope"],
                    self.now() + self.settings.access_ttl,
                    self.now() + self.settings.refresh_ttl,
                ),
            )
            return {
                "access_token": access,
                "refresh_token": refresh,
                "token_type": "bearer",
                "expires_in": self.settings.access_ttl,
                "scope": row["scope"],
            }

    def _token(self, db, params, *, allow_expired=False):
        row = db.execute(
            "SELECT * FROM tokens WHERE access_hash=?", (digest(params.get("access_token", "")),)
        ).fetchone()
        require(
            row
            and row["client_id"] == params["client_id"]
            and row["scope"] == params.get("scope")
            and row["revoked_at"] is None
            and (allow_expired or row["expires_at"] > self.now()),
            "invalid_token",
            "Token is invalid, expired or revoked.",
            401,
        )
        return row

    def identify(self, params):
        with self.connect() as db:
            row = self._token(db, params)
            user = db.execute("SELECT * FROM users WHERE id=?", (row["user_id"],)).fetchone()
            require(user["enabled"], "invalid_token", "Identity is unavailable.", 401)
            return {**json.loads(user["profile"]), "sess_id": row["sess_id"]}

    def logout(self, params):
        with self.connect(write=True) as db:
            row = self._token(db, params, allow_expired=True)
            db.execute(
                "UPDATE browsers SET expires_at=0 WHERE browser_hash=?", (row["browser_hash"],)
            )
            db.execute(
                "UPDATE tokens SET revoked_at=? WHERE browser_hash=?",
                (self.now(), row["browser_hash"]),
            )
            db.execute(
                "UPDATE codes SET used_at=? WHERE browser_hash=?", (self.now(), row["browser_hash"])
            )
            db.execute(
                "UPDATE auth_requests SET used_at=? WHERE browser_hash=?",
                (self.now(), row["browser_hash"]),
            )
            # The supplied guide does not specify the logout response body. Mock convention.
            return {"ret_cd": "0"}

    def callback_origins(self):
        from app.security import url_origin

        with self.connect() as db:
            clients = db.execute("SELECT redirects FROM clients WHERE enabled=1").fetchall()
        return sorted({url_origin(uri) for row in clients for uri in json.loads(row["redirects"])})
