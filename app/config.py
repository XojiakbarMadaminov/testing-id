import os
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from dotenv import load_dotenv

from app.security import validate_url


@dataclass(frozen=True)
class Settings:
    public_url: str = "http://localhost:8089"
    data_dir: Path = Path(".local/data")
    code_ttl: int = 60
    access_ttl: int = 300
    refresh_ttl: int = 86400
    browser_ttl: int = 3600
    login_ttl: int = 300
    frontend_origins: tuple[str, ...] = ()
    allow_https_localhost_callbacks: bool = False
    allow_http_localhost_callbacks: bool = False
    allow_http_local_domains: bool = False

    def __post_init__(self):
        validate_url(self.public_url, origin=True)
        for value in self.frontend_origins:
            validate_url(value, origin=True, allow_http_local_domains=self.allow_http_local_domains)
        if any(
            value < 1
            for value in (
                self.code_ttl,
                self.access_ttl,
                self.refresh_ttl,
                self.browser_ttl,
                self.login_ttl,
            )
        ):
            raise ValueError("All lifetimes must be positive seconds.")

    @property
    def secure(self) -> bool:
        return urlsplit(self.public_url).scheme == "https"

    @property
    def cookie_name(self) -> str:
        return "__Host-testing_id_browser" if self.secure else "testing_id_browser"

    @classmethod
    def from_env(cls):
        load_dotenv(override=False)
        return cls(
            public_url=os.getenv("MOCK_PUBLIC_BASE_URL", "http://localhost:8089").rstrip("/"),
            data_dir=Path(os.getenv("MOCK_DATA_DIR", ".local/data")),
            code_ttl=int(os.getenv("MOCK_CODE_TTL", "60")),
            access_ttl=int(os.getenv("MOCK_ACCESS_TTL", "300")),
            refresh_ttl=int(os.getenv("MOCK_REFRESH_TTL", "86400")),
            browser_ttl=int(os.getenv("MOCK_BROWSER_TTL", "3600")),
            login_ttl=int(os.getenv("MOCK_LOGIN_TTL", "300")),
            allow_https_localhost_callbacks=os.getenv(
                "MOCK_ALLOW_HTTPS_LOCALHOST_CALLBACKS", "false"
            ).lower()
            == "true",
            allow_http_localhost_callbacks=os.getenv(
                "MOCK_ALLOW_HTTP_LOCALHOST_CALLBACKS", "false"
            ).lower()
            == "true",
            allow_http_local_domains=os.getenv("MOCK_ALLOW_HTTP_LOCAL_DOMAINS", "false").lower()
            == "true",
            frontend_origins=tuple(
                filter(None, (v.strip() for v in os.getenv("MOCK_FRONTEND_ORIGINS", "").split(",")))
            ),
        )
