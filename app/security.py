import base64
import hashlib
import hmac
import ipaddress
import re
import secrets
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


class ProtocolError(Exception):
    def __init__(self, error="invalid_request", description="Invalid request.", status=400):
        self.error, self.description, self.status = error, description, status


def require(condition, error="invalid_request", description="Invalid request.", status=400):
    if not condition:
        raise ProtocolError(error, description, status)


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def opaque() -> str:
    # Exercise the +, / and = form-encoding used in OneID's opaque-token examples.
    return base64.b64encode(secrets.token_bytes(32)).decode()


def password_hash(password: str) -> str:
    salt = secrets.token_bytes(16)
    hashed = hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1, dklen=32)
    return base64.b64encode(salt + hashed).decode()


def check_password(password: str, encoded: str) -> bool:
    value = base64.b64decode(encoded, validate=True)
    actual = hashlib.scrypt(password.encode(), salt=value[:16], n=16384, r=8, p=1, dklen=32)
    return hmac.compare_digest(actual, value[16:])


def url_origin(value: str) -> str:
    parsed = urlsplit(value)
    host = parsed.hostname.lower()
    if ":" in host:
        host = f"[{host}]"
    port = parsed.port
    suffix = f":{port}" if port and port != {"http": 80, "https": 443}[parsed.scheme] else ""
    return f"{parsed.scheme}://{host}{suffix}"


def validate_url(value: str, *, callback=False, origin=False) -> str:
    if not isinstance(value, str) or re.search(r"[\x00-\x20\x7f\\]", value):
        raise ValueError("Expected an absolute HTTP(S) URL.")
    try:
        p = urlsplit(value)
        port = p.port
    except ValueError:
        raise ValueError("Invalid URL.") from None
    if (
        p.scheme not in {"http", "https"}
        or not p.hostname
        or p.username
        or p.password
        or p.fragment
        or (port is not None and not 1 <= port <= 65535)
    ):
        raise ValueError("Invalid URL.")
    host = p.hostname.lower().rstrip(".")
    try:
        loopback = (
            ipaddress.ip_address(host).is_loopback or ipaddress.ip_address(host).is_unspecified
        )
    except ValueError:
        if not re.fullmatch(r"[a-z0-9.-]+", host):
            raise ValueError("Invalid hostname.") from None
        loopback = host == "localhost" or host.endswith(".localhost")
    if callback:
        if loopback or p.scheme != "https":
            raise ValueError("Callbacks must use registered HTTPS URLs without localhost/loopback.")
        if any(k in {"code", "state", "error"} for k, _ in parse_qsl(p.query)):
            raise ValueError("Callback query cannot predefine OAuth response parameters.")
    elif p.scheme == "http" and not loopback:
        raise ValueError("HTTP is allowed only on loopback.")
    if origin and (p.path not in {"", "/"} or p.query):
        raise ValueError("Expected an origin without a path or query.")
    return value


def response_url(callback: str, **params: str) -> str:
    p = urlsplit(callback)
    query = urlencode([*parse_qsl(p.query, keep_blank_values=True), *params.items()])
    return urlunsplit((p.scheme, p.netloc, p.path, query, ""))


def parse_parameters(raw: bytes) -> dict[str, str]:
    require(len(raw) <= 8192, description="Request is too large.", status=413)
    try:
        text = raw.decode("utf-8")
        require(not re.search(r"%(?![0-9a-fA-F]{2})", text))
        pairs = parse_qsl(text, keep_blank_values=True, max_num_fields=30, errors="strict")
    except (ValueError, UnicodeDecodeError):
        raise ProtocolError(description="Malformed form parameters.") from None
    require(len({k for k, _ in pairs}) == len(pairs), description="Duplicate parameters.")
    return dict(pairs)
