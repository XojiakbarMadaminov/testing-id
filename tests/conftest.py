from html.parser import HTMLParser
from urllib.parse import parse_qs, urlsplit

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import ENDPOINT, create_app
from app.profiles import fixtures
from app.store import Store

PASSWORD = "synthetic-test-password-not-a-real-account"
SECRET = "synthetic-test-client-secret-which-is-not-live"
CALLBACK = "https://client.example.test/callback?source=testing-id"
ORIGIN = "https://mock.example.test"


class Inputs(HTMLParser):
    def __init__(self, html):
        super().__init__()
        self.values = {}
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        if tag == "input" and values.get("type") == "hidden":
            self.values[values["name"]] = values.get("value", "")


class Harness:
    def __init__(self, client, settings):
        self.client, self.settings = client, settings
        self.params = {
            "response_type": "one_code",
            "client_id": "petition-dev",
            "redirect_uri": CALLBACK,
            "scope": "petition-dev",
            "state": "state+with/encoding=&",
        }
        self.auth = {"client_id": "petition-dev", "client_secret": SECRET}

    @property
    def store(self):
        return self.client.app.state.store

    def account(self, name):
        with self.store.connect() as db:
            exists = db.execute("SELECT 1 FROM users WHERE username=?", (name,)).fetchone()
        if not exists:
            self.store.add_user(name, PASSWORD, fixtures()[name], enabled=name != "disabled")

    def begin(self, **changes):
        return self.client.get(ENDPOINT, params={**self.params, **changes})

    def login(self, name="verified"):
        self.account(name)
        response = self.begin()
        if response.status_code == 302:
            return parse_qs(urlsplit(response.headers["location"]).query)["code"][0]
        assert response.status_code == 200
        response = self.client.post(
            "/login",
            data={**Inputs(response.text).values, "username": name, "password": PASSWORD},
            headers={"Origin": ORIGIN},
        )
        assert response.status_code == 303
        query = parse_qs(urlsplit(response.headers["location"]).query)
        assert query["state"] == [self.params["state"]]
        assert query["source"] == ["testing-id"]
        return query["code"][0]

    def exchange(self, code, **changes):
        return self.client.post(
            ENDPOINT,
            data={
                **self.auth,
                "grant_type": "one_authorization_code",
                "redirect_uri": CALLBACK,
                "code": code,
                **changes,
            },
        )

    def tokens(self, name="verified"):
        response = self.exchange(self.login(name))
        assert response.status_code == 200
        return response.json()

    def identify(self, access, **changes):
        return self.client.post(
            ENDPOINT,
            data={
                **self.auth,
                "grant_type": "one_access_token_identify",
                "scope": "petition-dev",
                "access_token": access,
                **changes,
            },
        )


@pytest.fixture
def harness(tmp_path):
    settings = Settings(
        public_url=ORIGIN, data_dir=tmp_path, frontend_origins=("https://frontend.example.test",)
    )
    store = Store(settings)
    store.add_client("petition-dev", SECRET, [CALLBACK], ["petition-dev"])
    store.add_client("other-client", SECRET + "-other", [CALLBACK], ["other-scope"])
    store.add_user("verified", PASSWORD, fixtures()["verified"])
    with TestClient(create_app(settings), base_url=ORIGIN, follow_redirects=False) as client:
        yield Harness(client, settings)
