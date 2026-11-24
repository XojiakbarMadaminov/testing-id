from dataclasses import replace
from urllib.parse import parse_qs, urlsplit

import pytest
from conftest import ORIGIN, PASSWORD, SECRET, Inputs
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import ENDPOINT, create_app
from app.profiles import fixtures
from app.security import validate_url
from app.store import Store


@pytest.mark.parametrize("scheme,port", [("https", 5310), ("http", 5310), ("http", 5320)])
def test_local_callback_requires_opt_in_and_preserves_login_code_binding(tmp_path, scheme, port):
    settings = Settings(public_url=ORIGIN, data_dir=tmp_path)
    callback = f"{scheme}://localhost:{port}/auth/callback"
    with pytest.raises(ValueError):
        Store(settings).add_client("local-client", SECRET, [callback], ["local-scope"])
    enabled = replace(settings, **{f"allow_{scheme}_localhost_callbacks": True})
    store = Store(enabled)
    store.add_client("local-client", SECRET, [callback], ["local-scope"])
    store.add_user("local-user", PASSWORD, fixtures()["verified"])
    params = {
        "response_type": "one_code",
        "client_id": "local-client",
        "redirect_uri": callback,
        "scope": "local-scope",
        "state": "synthetic-state",
    }
    with TestClient(create_app(enabled), base_url=ORIGIN, follow_redirects=False) as browser:
        assert (
            browser.get(
                ENDPOINT, params={**params, "redirect_uri": callback + "/other"}
            ).status_code
            == 400
        )
        response = browser.get(ENDPOINT, params=params)
        assert response.status_code == 200
        assert f"{scheme}://localhost:{port}" in response.headers["content-security-policy"]
        response = browser.post(
            "/login",
            data={**Inputs(response.text).values, "username": "local-user", "password": PASSWORD},
            headers={"Origin": ORIGIN},
        )
        assert response.status_code == 303
        target = urlsplit(response.headers["location"])
        assert (target.scheme, target.netloc, target.path) == (
            scheme,
            f"localhost:{port}",
            "/auth/callback",
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
        assert browser.post(ENDPOINT, data=form).status_code == 200
        assert browser.post(ENDPOINT, data=form).status_code == 400
    # Disabling the exception also refuses previously registered local callbacks.
    with TestClient(create_app(settings), base_url=ORIGIN) as browser:
        assert browser.get(ENDPOINT, params=params).status_code == 400


@pytest.mark.parametrize(
    "url",
    [
        "http://example.test/callback",
        "http://localhost.evil.test/callback",
        "http://localhost./callback",
        "http://sub.localhost/callback",
        "http://127.0.0.1/callback",
        "http://[::1]/callback",
        "https://localhost/callback",
    ],
)
def test_http_exception_does_not_allow_other_hosts_or_enable_https(url):
    with pytest.raises(ValueError):
        validate_url(url, callback=True, allow_http_localhost=True)


def test_https_exception_does_not_enable_http():
    with pytest.raises(ValueError):
        validate_url("http://localhost:5310/callback", callback=True, allow_https_localhost=True)
