import argparse
import json
import os
import secrets
import sqlite3
from pathlib import Path

from app.config import Settings
from app.profiles import fixtures
from app.security import digest, password_hash, validate_url
from app.store import Store


def private_json(path: Path, data):
    serialized = json.dumps(data, indent=2, ensure_ascii=False) + "\n"
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as out:
        path.chmod(0o600)
        try:
            out.write(serialized)
        except BaseException:
            path.unlink()
            raise


def initialize(settings, callback, output):
    # Existing data is never reseeded/reset; init must run only against an empty store.
    validate_url(
        callback,
        callback=True,
        allow_https_localhost=settings.allow_https_localhost_callbacks,
        allow_http_localhost=settings.allow_http_localhost_callbacks,
        allow_http_local_domains=settings.allow_http_local_domains,
    )
    store = Store(settings)
    if output.exists():
        raise ValueError("Credentials already exist; init refuses to replace them.")
    accounts = []
    for username, profile in fixtures().items():
        password = secrets.token_urlsafe(24)
        accounts.append({"username": username, "password": password})
    clients = []
    for name in ("petition-dev", "cabinet-dev"):
        secret = secrets.token_urlsafe(48)
        clients.append(
            {"client_id": name, "client_secret": secret, "scope": name, "redirect_uri": callback}
        )
    created_output = False
    try:
        with store.connect(write=True) as db:
            if (
                db.execute("SELECT count(*) FROM clients").fetchone()[0]
                or db.execute("SELECT count(*) FROM users").fetchone()[0]
            ):
                raise ValueError("Database is not empty; init refuses to reseed it.")
            profiles = fixtures()
            for account in accounts:
                username = account["username"]
                db.execute(
                    "INSERT INTO users(username,password_hash,profile,enabled) VALUES (?,?,?,?)",
                    (
                        username,
                        password_hash(account["password"]),
                        json.dumps(profiles[username]),
                        int(username != "disabled"),
                    ),
                )
            for client in clients:
                db.execute(
                    "INSERT INTO clients(client_id,secret_hash,redirects,scopes) VALUES (?,?,?,?)",
                    (
                        client["client_id"],
                        digest(client["client_secret"]),
                        json.dumps([callback]),
                        json.dumps([client["scope"]]),
                    ),
                )
            private_json(output, {"clients": clients, "accounts": accounts})
            created_output = True
    except BaseException:
        if created_output:
            output.unlink(missing_ok=True)
        raise
    print(f"Initialized {len(clients)} clients and {len(accounts)} synthetic accounts.")
    print(f"Private credentials saved to: {output}. Values are not printed.")


def register(settings, client_id, redirects, scopes, output):
    if output.exists():
        raise ValueError("Output already exists; refusing to overwrite credentials.")
    secret = secrets.token_urlsafe(48)
    Store.validate_client(
        client_id,
        secret,
        redirects,
        scopes,
        allow_https_localhost=settings.allow_https_localhost_callbacks,
        allow_http_localhost=settings.allow_http_localhost_callbacks,
        allow_http_local_domains=settings.allow_http_local_domains,
    )
    created_output = False
    try:
        with Store(settings).connect(write=True) as db:
            db.execute(
                "INSERT INTO clients(client_id,secret_hash,redirects,scopes) VALUES (?,?,?,?)",
                (client_id, digest(secret), json.dumps(redirects), json.dumps(scopes)),
            )
            private_json(
                output,
                {
                    "client_id": client_id,
                    "client_secret": secret,
                    "redirect_uris": redirects,
                    "scopes": scopes,
                },
            )
            created_output = True
    except BaseException:
        if created_output:
            output.unlink(missing_ok=True)
        raise
    print(f"Client registered. Private credentials: {output}")


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description="Private management CLI for Testing ID")
    commands = parser.add_subparsers(dest="command", required=True)
    init = commands.add_parser("init")
    init.add_argument("--redirect-uri", default="https://client.example.test/callback")
    init.add_argument("--credentials-file", type=Path, default=Path(".local/credentials.json"))
    client = commands.add_parser("add-client")
    client.add_argument("client_id")
    client.add_argument("--redirect-uri", action="append", required=True)
    client.add_argument("--scope", action="append", required=True)
    client.add_argument("--credentials-file", type=Path, required=True)
    user = commands.add_parser("set-user-enabled")
    user.add_argument("username")
    user.add_argument("state", choices=["true", "false"])
    args = parser.parse_args()
    try:
        settings = Settings.from_env()
        if args.command == "init":
            initialize(settings, args.redirect_uri, args.credentials_file)
        elif args.command == "add-client":
            register(settings, args.client_id, args.redirect_uri, args.scope, args.credentials_file)
        else:
            with Store(settings).connect(write=True) as db:
                result = db.execute(
                    "UPDATE users SET enabled=? WHERE username=?",
                    (int(args.state == "true"), args.username),
                )
                if result.rowcount != 1:
                    raise ValueError("Unknown synthetic account.")
            print("Synthetic account state updated.")
    except (ValueError, sqlite3.Error, OSError):
        parser.exit(
            2,
            "Command failed. Check arguments, private output path and database state; no reset was performed.\n",
        )


if __name__ == "__main__":
    main()
