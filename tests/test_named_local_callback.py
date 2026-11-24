from urllib.parse import parse_qs, urlsplit

import pytest
from conftest import ORIGIN, PASSWORD, SECRET, Inputs
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import ENDPOINT, create_app
from app.profiles import fixtures
from app.security import validate_url
from app.store import Store


@pytest.mark.parametrize("host", ["petition.local", "cabinet-petition.local"])
def test_named_http_frontend_requires_flag_and_preserves_full_code_flow(tmp_path, host):
    origin = f"http://{host}"
    callback = origin + "/auth/callback"
    with pytest.raises(ValueError):
        Settings(public_url=ORIGIN, data_dir=tmp_path, frontend_origins=(origin,))
    default = Settings(public_url=ORIGIN, data_dir=tmp_path)
    with pytest.raises(ValueError):
        Store(default).add_client("local-client", SECRET, [callback], ["scope"])
    settings = Settings(
        public_url=ORIGIN,
        data_dir=tmp_path,
        frontend_origins=(origin,),
        allow_http_local_domains=True,
    )
    store = Store(settings)
    store.add_client("local-client", SECRET, [callback], ["scope"])
    store.add_user("verified", PASSWORD, fixtures()["verified"])
    params = {
        "response_type": "one_code",
        "client_id": "local-client",
        "redirect_uri": callback,
        "scope": "scope",
        "state": "synthetic-state",
    }
    with TestClient(create_app(settings), base_url=ORIGIN, follow_redirects=False) as browser:
        assert (
            browser.get(
                ENDPOINT, params={**params, "redirect_uri": callback + "/other"}
            ).status_code
            == 400
        )
        response = browser.get(ENDPOINT, params=params)
        assert response.status_code == 200
        assert origin in response.headers["Content-Security-Policy"]
        response = browser.post(
            "/login",
            data={**Inputs(response.text).values, "username": "verified", "password": PASSWORD},
            headers={"Origin": ORIGIN},
        )
        assert response.status_code == 303
        target = urlsplit(response.headers["location"])
        assert (
            target.scheme == "http" and target.hostname == host and target.path == "/auth/callback"
        )
        query = parse_qs(target.query)
        assert query["state"] == ["synthetic-state"]
        form = {
            "grant_type": "one_authorization_code",
            "client_id": "local-client",
            "client_secret": SECRET,
            "redirect_uri": callback,
            "code": query["code"][0],
        }
        assert (
            browser.post(ENDPOINT, data={**form, "redirect_uri": callback + "/other"}).status_code
            == 400
        )
        assert browser.post(ENDPOINT, data=form).status_code == 200
        assert browser.post(ENDPOINT, data=form).status_code == 400
    with TestClient(create_app(default), base_url=ORIGIN) as browser:
        assert browser.get(ENDPOINT, params=params).status_code == 400


@pytest.mark.parametrize(
    "url",
    [
        "http://evil.local/callback",
        "http://petition.local.evil.test/callback",
        "http://sub.petition.local/callback",
        "http://petition.local./callback",
        "http://127.0.0.1/callback",
        "http://localhost:5310/callback",
    ],
)
def test_named_domain_exception_does_not_allow_other_http_hosts(url):
    with pytest.raises(ValueError):
        validate_url(url, callback=True, allow_http_local_domains=True)


def test_named_domain_flag_does_not_enable_http_provider_url(tmp_path):
    with pytest.raises(ValueError):
        Settings(
            public_url="http://petition.local", data_dir=tmp_path, allow_http_local_domains=True
        )
