import json
import sqlite3

import pytest
from conftest import CALLBACK

from app import cli
from app.config import Settings
from app.security import digest
from app.store import Store


def test_init_saves_private_credentials_without_printing_or_reseeding(tmp_path, capsys):
    settings = Settings(data_dir=tmp_path / "data")
    output = tmp_path / "credentials.json"
    cli.initialize(settings, CALLBACK, output)
    data = json.loads(output.read_text())
    assert output.stat().st_mode & 0o777 == 0o600
    assert len(data["clients"]) == 2 and len(data["accounts"]) == 14
    captured = capsys.readouterr().out
    for client in data["clients"]:
        assert client["client_secret"] not in captured
    for account in data["accounts"]:
        assert account["password"] not in captured
    before = output.read_bytes()
    with pytest.raises(ValueError):
        cli.initialize(settings, CALLBACK, output)
    assert output.read_bytes() == before
    store = Store(settings)
    with store.connect() as db:
        assert db.execute("SELECT count(*) FROM users").fetchone()[0] == 14
        assert db.execute("SELECT count(*) FROM clients").fetchone()[0] == 2


def test_failed_private_file_creation_rolls_back_all_seed_data(tmp_path, monkeypatch):
    settings = Settings(data_dir=tmp_path / "data")

    def unavailable(*_args):
        raise OSError("synthetic failure")

    monkeypatch.setattr(cli, "private_json", unavailable)
    with pytest.raises(OSError):
        cli.initialize(settings, CALLBACK, tmp_path / "credentials.json")
    with Store(settings).connect() as db:
        assert db.execute("SELECT count(*) FROM users").fetchone()[0] == 0
        assert db.execute("SELECT count(*) FROM clients").fetchone()[0] == 0


def test_add_client_does_not_overwrite_credentials_or_change_other_clients(tmp_path):
    settings = Settings(data_dir=tmp_path / "data")
    output = tmp_path / "client.json"
    cli.register(settings, "new-client", [CALLBACK], ["oneid-scope"], output)
    client = json.loads(output.read_text())
    store = Store(settings)
    assert store.client("new-client")["secret_hash"] == digest(client["client_secret"])
    assert output.stat().st_mode & 0o777 == 0o600
    with pytest.raises(ValueError):
        cli.register(settings, "other-client", [CALLBACK], ["other"], output)
    with pytest.raises(sqlite3.IntegrityError):
        cli.register(settings, "new-client", [CALLBACK], ["other"], tmp_path / "another.json")
    assert not (tmp_path / "another.json").exists()
    assert json.loads(output.read_text()) == client


def test_registration_output_failure_does_not_leave_an_unknown_secret(tmp_path, monkeypatch):
    settings = Settings(data_dir=tmp_path / "data")

    def unavailable(*_args):
        raise OSError("synthetic failure")

    monkeypatch.setattr(cli, "private_json", unavailable)
    with pytest.raises(OSError):
        cli.register(settings, "new-client", [CALLBACK], ["scope"], tmp_path / "client.json")
    with Store(settings).connect() as db:
        assert db.execute("SELECT count(*) FROM clients").fetchone()[0] == 0


def test_private_output_refuses_an_existing_file(tmp_path):
    output = tmp_path / "keep.json"
    output.write_text("preserved")
    with pytest.raises(FileExistsError):
        cli.private_json(output, {"client_secret": "synthetic-secret"})
    assert output.read_text() == "preserved"
