"""Bounded HTTP contract check. Never follow the callback or print credential values."""

import argparse
import http.cookiejar
import json
from html.parser import HTMLParser
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import parse_qs, urlencode, urlsplit
from urllib.request import HTTPCookieProcessor, HTTPRedirectHandler, Request, build_opener

ENDPOINT = "/sso/oauth/Authorization.do"


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        return None


class Inputs(HTMLParser):
    def __init__(self, text):
        super().__init__()
        self.values = {}
        self.feed(text)

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        if tag == "input" and values.get("type") == "hidden":
            self.values[values["name"]] = values.get("value", "")


def check(condition, stage):
    if not condition:
        raise RuntimeError(f"Contract check failed at {stage}.")


def smoke(base, credentials, client_id="petition-dev", username="verified"):
    parsed = urlsplit(base)
    check(
        parsed.scheme in {"http", "https"}
        and parsed.netloc
        and not parsed.query
        and not parsed.fragment
        and not parsed.username
        and parsed.path in {"", "/"},
        "base URL",
    )
    check(parsed.hostname not in {"sso.egov.uz", "id.egov.uz", "id.gov.uz"}, "mock-only boundary")
    base = base.rstrip("/")
    origin = f"{parsed.scheme}://{parsed.netloc}"
    browser = build_opener(NoRedirect(), HTTPCookieProcessor(http.cookiejar.CookieJar()))

    def call(path, data=None, expected=200):
        raw = None if data is None else urlencode(data).encode()
        headers = (
            {}
            if raw is None
            else {"Content-Type": "application/x-www-form-urlencoded", "Origin": origin}
        )
        try:
            response = browser.open(Request(base + path, data=raw, headers=headers), timeout=10)
        except HTTPError as error:
            response = error
        with response:
            body = response.read(65536)
            check(response.status == expected, f"HTTP {expected} {path.split('?', 1)[0]}")
            return body, response.headers

    raw, _ = call("/health")
    check(json.loads(raw).get("mode") == "testing-id-mock", "mock health identity")
    data = json.loads(Path(credentials).read_text())
    client = next(c for c in data["clients"] if c["client_id"] == client_id)
    account = next(a for a in data["accounts"] if a["username"] == username)
    auth = {"client_id": client["client_id"], "client_secret": client["client_secret"]}
    state = "http-smoke-state+with/encoding="
    params = {
        "response_type": "one_code",
        "client_id": client["client_id"],
        "redirect_uri": client["redirect_uri"],
        "scope": client["scope"],
        "state": state,
    }
    raw, _ = call(ENDPOINT + "?" + urlencode(params))
    inputs = Inputs(raw.decode()).values
    check(set(inputs) == {"request", "csrf"}, "login form")
    login = {**inputs, "username": account["username"], "password": account["password"]}
    call("/login", {**login, "password": "not-the-test-password"}, expected=401)
    _, headers = call("/login", login, expected=303)
    target = urlsplit(headers["Location"])
    registered = urlsplit(client["redirect_uri"])
    check(
        (target.scheme, target.netloc, target.path)
        == (registered.scheme, registered.netloc, registered.path),
        "callback binding",
    )
    callback = parse_qs(target.query)
    check(callback["state"] == [state], "state echo")
    code = callback["code"][0]
    token_form = {
        **auth,
        "grant_type": "one_authorization_code",
        "redirect_uri": client["redirect_uri"],
        "code": code,
    }
    call(ENDPOINT, {**token_form, "client_secret": "invalid-synthetic-secret"}, expected=401)
    raw, _ = call(ENDPOINT, token_form)
    tokens = json.loads(raw)
    check(
        set(tokens) == {"access_token", "refresh_token", "expires_in", "token_type", "scope"},
        "token fields",
    )
    call(ENDPOINT, token_form, expected=400)
    identify = {
        **auth,
        "grant_type": "one_access_token_identify",
        "scope": client["scope"],
        "access_token": tokens["access_token"],
    }
    raw, _ = call(ENDPOINT, identify)
    profile = json.loads(raw)
    check(
        {
            "user_id",
            "first_name",
            "sur_name",
            "mid_name",
            "valid",
            "validation_method",
            "ret_cd",
            "sess_id",
        }
        <= profile.keys(),
        "profile fields",
    )
    raw, _ = call(ENDPOINT, {**identify, "grant_type": "one_log_out"})
    check(json.loads(raw) == {"ret_cd": "0"}, "mock logout convention")
    call(ENDPOINT, identify, expected=401)
    print("PASS: health, browser binding/login, state, token, code replay, profile and logout.")
    print("No callback was followed; no credentials, codes, tokens or profile values were printed.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://localhost:8089")
    parser.add_argument("--credentials-file", default=".local/docker-credentials.json")
    args = parser.parse_args()
    try:
        smoke(args.base_url, args.credentials_file)
    except Exception as exc:
        raise SystemExit(
            f"HTTP smoke failed ({type(exc).__name__}); check the mock setup without sharing private values."
        ) from None
