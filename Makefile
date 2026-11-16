.PHONY: install test check run init build up docker-init health tunnel tunnel-url down

CALLBACK ?= https://client.example.test/callback

install:
	uv sync --frozen

test:
	uv run --frozen pytest

check:
	uv run --frozen ruff check .
	uv run --frozen ruff format --check .

run:
	uv run --frozen uvicorn app.main:app --host 127.0.0.1 --port 8089 --no-access-log --no-proxy-headers

init:
	uv run --frozen python -m app.cli init --redirect-uri '$(CALLBACK)'

build:
	docker compose build app

up:
	docker compose up -d app

docker-init:
	docker compose exec -T app python -m app.cli init --redirect-uri '$(CALLBACK)' --credentials-file /data/credentials.json < /dev/null
	mkdir -p .local
	docker compose cp app:/data/credentials.json .local/docker-credentials.json
	chmod 600 .local/docker-credentials.json

health:
	docker compose exec -T app python -c 'import json, urllib.request; print(json.load(urllib.request.urlopen("http://127.0.0.1:8080/health", timeout=3)))' < /dev/null

tunnel:
	docker compose --profile https up -d tunnel

tunnel-url:
	python3 scripts/tunnel_url.py

down:
	docker compose --profile https down

