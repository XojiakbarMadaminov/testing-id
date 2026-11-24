import concurrent.futures
import json
from dataclasses import replace
from urllib.parse import urlencode, urlsplit

import pytest
from conftest import CALLBACK, ORIGIN, PASSWORD, SECRET, Harness, Inputs
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import ENDPOINT, create_app
from app.security import validate_url
from app.store import Store


def test_documented_flow_cookie_rotation_profile_and_logout(harness):
    page = harness.begin()
    old = harness.client.cookies.get(harness.settings.cookie_name)
    cookie = page.headers["set-cookie"]
    assert "Secure" in cookie and "HttpOnly" in cookie and "SameSite=lax" in cookie
    assert "Domain=" not in cookie and "Path=/" in cookie
    assert "TEST MUHITI" in page.text and "haqiqiy OneID emas" in page.text
    token = harness.tokens()
    assert harness.client.cookies.get(harness.settings.cookie_name) != old
    assert set(token) == {"access_token", "refresh_token", "token_type", "scope", "expires_in"}
    assert token["token_type"] == "bearer" and token["scope"] == "petition-dev"
    profile = harness.identify(token["access_token"])
    assert profile.status_code == 200
    profile = profile.json()
    assert profile["pin"] == "00000000000001" and profile["valid"] is True
    assert profile["validation_method"] == ["MOBILEMETHOD"] and profile["ret_cd"] == "0"
    assert {
        "first_name",
        "sur_name",
        "mid_name",
        "full_name",
        "pport_no",
        "birth_date",
        "sess_id",
        "auth_method",
        "user_type",
        "user_id",
    } <= profile.keys()
    assert "pinfl" not in profile and "id_token" not in token
    assert "access_token" not in json.dumps(profile) and "password" not in json.dumps(profile)
    logout = harness.client.post(
        ENDPOINT,
        data={
            **harness.auth,
            "grant_type": "one_log_out",
            "scope": "petition-dev",
            "access_token": token["access_token"],
        },
    )
    assert logout.status_code == 200 and logout.json() == {"ret_cd": "0"}
    assert harness.identify(token["access_token"]).status_code == 401
    assert harness.begin().status_code == 200  # Provider SSO session was invalidated too.


def test_sso_preserves_profile_session_and_echoes_each_new_state(harness):
    first = harness.tokens()
    session = harness.identify(first["access_token"]).json()["sess_id"]
    response = harness.begin(state="different-state")
    assert response.status_code == 302
    from urllib.parse import parse_qs

    query = parse_qs(urlsplit(response.headers["location"]).query)
    assert query["state"] == ["different-state"]
    response = harness.exchange(query["code"][0])
    assert response.status_code == 200
    assert harness.identify(response.json()["access_token"]).json()["sess_id"] == session


@pytest.mark.parametrize(
    "changes,error",
    [
        ({"client_id": "unknown"}, "invalid_client"),
        ({"redirect_uri": "https://evil.example.test/callback"}, "invalid_request"),
        ({"redirect_uri": CALLBACK + "&extra=1"}, "invalid_request"),
        ({"response_type": "code"}, "unsupported_response_type"),
        ({"scope": "openid profile email"}, "invalid_scope"),
        ({"state": ""}, "invalid_request"),
        ({"state": "a" * 2049}, "invalid_request"),
    ],
)
def test_authorization_rejects_invalid_inputs_without_redirecting(harness, changes, error):
    response = harness.begin(**changes)
    assert response.status_code in {400, 401}
    assert response.json()["error"] == error
    assert "location" not in response.headers and "set-cookie" not in response.headers


@pytest.mark.parametrize(
    "missing", ["response_type", "client_id", "redirect_uri", "scope", "state"]
)
def test_every_documented_authorization_parameter_is_required(harness, missing):
    params = {k: v for k, v in harness.params.items() if k != missing}
    response = harness.client.get(ENDPOINT, params=params)
    assert response.status_code == 400 and "location" not in response.headers


@pytest.mark.parametrize(
    "callback",
    [
        "http://localhost:5173/callback",
        "https://localhost:5173/callback",
        "https://127.0.0.1/callback",
        "https://[::1]/callback",
        "https://localhost./callback",
        "https://a.localhost/callback",
        "http://client.example.test/callback",
        "//client.example.test/callback",
        "https://user:password@client.example.test/callback",
        "https://client.example.test/callback#fragment",
        "https://client.example.test/callback?state=predefined",
    ],
)
def test_registration_refuses_localhost_and_unsafe_callbacks(tmp_path, callback):
    store = Store(Settings(data_dir=tmp_path))
    with pytest.raises(ValueError):
        store.add_client("bad-client", SECRET, [callback], ["test"])


def test_login_browser_origin_csrf_and_single_use_request_binding(harness):
    page = harness.begin()
    form = {**Inputs(page.text).values, "username": "verified", "password": PASSWORD}
    for origin in (None, "null", "https://evil.example.test"):
        response = harness.client.post(
            "/login", data=form, headers={} if origin is None else {"Origin": origin}
        )
        assert response.status_code == 403
    with TestClient(create_app(harness.settings), base_url=ORIGIN, follow_redirects=False) as other:
        assert other.post("/login", data=form, headers={"Origin": ORIGIN}).status_code == 400
    assert (
        harness.client.post(
            "/login", data={**form, "csrf": "wrong"}, headers={"Origin": ORIGIN}
        ).status_code
        == 400
    )
    assert harness.client.post("/login", data=form, headers={"Origin": ORIGIN}).status_code == 303
    assert harness.client.post("/login", data=form, headers={"Origin": ORIGIN}).status_code == 400


@pytest.mark.parametrize(
    "username,password", [("verified", "wrong"), ("unknown", PASSWORD), ("disabled", PASSWORD)]
)
def test_wrong_unknown_and_disabled_accounts_do_not_authenticate(harness, username, password):
    harness.account("disabled")
    page = harness.begin()
    response = harness.client.post(
        "/login",
        data={**Inputs(page.text).values, "username": username, "password": password},
        headers={"Origin": ORIGIN},
    )
    assert response.status_code == 401 and "location" not in response.headers
    assert password not in response.text


def test_login_limits_are_bounded_and_return_retry_after(harness):
    page = harness.begin()
    form = {**Inputs(page.text).values, "username": "unknown", "password": "wrong"}
    for _ in range(8):
        assert (
            harness.client.post("/login", data=form, headers={"Origin": ORIGIN}).status_code == 401
        )
    response = harness.client.post("/login", data=form, headers={"Origin": ORIGIN})
    assert response.status_code == 429 and response.headers["Retry-After"] == "60"
    original = harness.store.now()
    harness.store.clock = lambda: original + 61
    assert harness.client.post("/login", data=form, headers={"Origin": ORIGIN}).status_code == 401


def test_code_cannot_cross_clients_callbacks_or_be_used_twice(harness):
    code = harness.login()
    wrong_client = harness.exchange(code, client_id="other-client", client_secret=SECRET + "-other")
    assert wrong_client.status_code == 400
    assert (
        harness.exchange(code, redirect_uri="https://evil.example.test/callback").status_code == 400
    )
    assert harness.exchange(code, client_secret="wrong").status_code == 401
    assert harness.exchange(code).status_code == 200
    assert harness.exchange(code).status_code == 400


def test_concurrent_code_exchange_has_exactly_one_winner(harness):
    code = harness.login()
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: harness.exchange(code).status_code, range(2)))
    assert sorted(results) == [200, 400]


def test_expired_login_request_and_code_fail_closed(harness):
    page = harness.begin()
    now = harness.store.now()
    harness.store.clock = lambda: now + harness.settings.login_ttl
    form = {**Inputs(page.text).values, "username": "verified", "password": PASSWORD}
    assert harness.client.post("/login", data=form, headers={"Origin": ORIGIN}).status_code == 400
    harness.store.clock = lambda: now
    code = harness.login()
    harness.store.clock = lambda: now + harness.settings.code_ttl
    assert harness.exchange(code).status_code == 400


def test_profile_authentication_scope_token_type_and_expiry(harness):
    token = harness.tokens()
    assert harness.identify("not-issued").status_code == 401
    assert harness.identify(token["refresh_token"]).status_code == 401
    assert harness.identify(token["access_token"], scope="other-scope").status_code == 401
    assert (
        harness.identify(
            token["access_token"], client_id="other-client", client_secret=SECRET + "-other"
        ).status_code
        == 401
    )
    now = harness.store.now()
    harness.store.clock = lambda: now + harness.settings.access_ttl
    assert harness.identify(token["access_token"]).status_code == 401


def test_disabled_identity_is_rechecked_after_token_issue(harness):
    token = harness.tokens()
    with harness.store.connect(write=True) as db:
        db.execute("UPDATE users SET enabled=0 WHERE username='verified'")
    assert harness.identify(token["access_token"]).status_code == 401
    assert harness.begin().status_code == 200


@pytest.mark.parametrize(
    "name",
    [
        "unverified",
        "string-true",
        "string-false",
        "missing-pin",
        "invalid-pin",
        "no-middle",
        "legacy-date",
        "denied",
        "mobile",
        "pkcs",
        "qr",
        "legal",
    ],
)
def test_synthetic_profile_variants_are_returned_without_oidc_renaming(harness, name):
    from app.profiles import fixtures

    token = harness.tokens(name)
    profile = harness.identify(token["access_token"])
    assert profile.status_code == 200
    body = profile.json()
    assert set(body) == set(fixtures()[name]) | {"sess_id"}
    assert {k: v for k, v in body.items() if k != "sess_id"} == fixtures()[name]


def test_logout_revokes_browser_token_family_and_pending_codes_but_not_other_browser(harness):
    first = harness.tokens()
    peer = harness.tokens()
    pending = harness.login()
    with TestClient(
        create_app(harness.settings), base_url=ORIGIN, follow_redirects=False
    ) as second_client:
        second = Harness(second_client, harness.settings)
        other = second.tokens()
        logout = {
            **harness.auth,
            "grant_type": "one_log_out",
            "scope": "petition-dev",
            "access_token": first["access_token"],
        }
        response = harness.client.post(ENDPOINT, data=logout)
        assert response.status_code == 200
        assert harness.exchange(pending).status_code == 400
        assert second.identify(other["access_token"]).status_code == 200
        assert second.begin().status_code == 302

        new_login = harness.tokens()
        retry = harness.client.post(ENDPOINT, data={**logout, "access_token": peer["access_token"]})
        assert retry.status_code == 200 and retry.json() == {"ret_cd": "0"}
        assert harness.identify(peer["access_token"]).status_code == 401
        assert harness.identify(new_login["access_token"]).status_code == 200

        for changes in (
            {"access_token": "unknown-token"},
            {"scope": "other-scope"},
            {
                "client_id": "other-client",
                "client_secret": SECRET + "-other",
                "scope": "other-scope",
            },
        ):
            rejected = harness.client.post(ENDPOINT, data={**logout, **changes})
            assert rejected.status_code == 401 and rejected.json()["error"] == "invalid_token"


def test_restart_preserves_tokens_accounts_and_code_consumption(harness):
    code = harness.login()
    token = harness.exchange(code).json()
    with TestClient(
        create_app(harness.settings), base_url=ORIGIN, follow_redirects=False
    ) as restarted_client:
        restarted = Harness(restarted_client, harness.settings)
        assert restarted.identify(token["access_token"]).status_code == 200
        assert restarted.exchange(code).status_code == 400
        assert restarted.tokens()["access_token"] != token["access_token"]


def test_plain_credentials_codes_and_tokens_are_not_in_database_or_responses(harness):
    code = harness.login()
    tokens = harness.exchange(code).json()
    with harness.store.connect() as db:
        dump = "\n".join(db.iterdump())
    for value in [SECRET, PASSWORD, code, tokens["access_token"], tokens["refresh_token"]]:
        assert value not in dump
    assert harness.store.path.stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize(
    "body", [b"grant_type=x&client_id=a&client_id=b", b"bad=%GG", b"bad=%FF", b"a=" + b"x" * 8192]
)
def test_duplicate_malformed_and_oversized_forms_are_rejected(harness, body):
    response = harness.client.post(
        ENDPOINT, content=body, headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    assert response.status_code in {400, 413}
    assert "traceback" not in response.text.lower()


def test_only_documented_protocol_is_supported_and_no_secret_is_reflected(harness):
    assert harness.client.post(ENDPOINT, json=harness.auth).status_code == 400
    for grant in ["authorization_code", "refresh_token", "one_refresh_token", "client_credentials"]:
        response = harness.client.post(ENDPOINT, data={**harness.auth, "grant_type": grant})
        assert response.status_code == 400 and response.json()["error"] == "unsupported_grant_type"
        assert SECRET not in response.text
    response = harness.client.post(
        ENDPOINT,
        data={**harness.auth, "grant_type": "one_authorization_code"},
        headers={"Authorization": "Bearer something"},
    )
    assert response.status_code == 400
    for path in [
        "/.env",
        "/.local/credentials.json",
        "/internal/users",
        "/docs",
        "/openapi.json",
        "/token",
        "/userinfo",
        "/authorize",
        "/.well-known/openid-configuration",
    ]:
        assert harness.client.get(path).status_code == 404


def test_headers_health_and_static_assets(harness):
    response = harness.begin()
    assert response.headers["cache-control"] == "no-store, private"
    assert response.headers["referrer-policy"] == "same-origin"
    csp = response.headers["content-security-policy"]
    assert "'unsafe-inline'" not in csp and "*" not in csp
    assert "https://client.example.test" in csp and "https://frontend.example.test" in csp
    assert harness.client.get("/health").json() == {
        "status": "ok",
        "mode": "testing-id-mock",
        "configured_clients": 2,
    }
    assert harness.client.get("/static/app.css").status_code == 200
    assert harness.client.get("/").status_code == 200
    assert "access-control-allow-origin" not in response.headers


def test_http_loopback_uses_a_nonprefixed_cookie_without_weakening_https(tmp_path):
    settings = Settings(data_dir=tmp_path)
    store = Store(settings)
    store.add_client("petition-dev", SECRET, [CALLBACK], ["petition-dev"])
    with TestClient(
        create_app(settings), base_url=settings.public_url, follow_redirects=False
    ) as client:
        response = Harness(client, settings).begin()
        cookie = response.headers["set-cookie"]
        assert cookie.startswith("testing_id_browser=") and "HttpOnly" in cookie
        assert "Secure" not in cookie and "Domain=" not in cookie
    assert replace(settings, public_url=ORIGIN).secure
    with pytest.raises(ValueError):
        Settings(public_url="http://public.example.test", data_dir=tmp_path)


def test_code_form_encoding_is_not_json_or_bearer_auth(harness):
    code = harness.login()
    raw = urlencode(
        {
            **harness.auth,
            "grant_type": "one_authorization_code",
            "redirect_uri": CALLBACK,
            "code": code,
        }
    )
    response = harness.client.post(
        ENDPOINT,
        content=raw,
        headers={"Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"},
    )
    assert response.status_code == 200
    validate_url(CALLBACK, callback=True)
