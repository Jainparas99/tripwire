.PHONY: setup test lint eval demo live-demo investigate audit-index tools gateway mcp dashboard docker-build docker-up docker-down

setup:
	uv sync

test:
	uv run pytest -q

lint:
	uv run ruff check .
	uv run ruff format --check .

eval:
	PYTHONPATH=src uv run python -m tripwire.evaluation.runner

demo:
	PYTHONPATH=src uv run python -m tripwire.demo

live-demo:
	PYTHONPATH=src uv run python -m tripwire.demo --mode live

investigate:
	PYTHONPATH=src uv run python -m tripwire.investigation.cli .tripwire/demo-*.jsonl

audit-index:
	PYTHONPATH=src uv run python -m tripwire.audit.index_cli .tripwire/demo-*.jsonl

tools:
	PYTHONPATH=src uv run python -m tripwire.tools.server --host 127.0.0.1 --port 9090

gateway:
	PYTHONPATH=src TRIPWIRE_TOOL_BASE_URL=http://127.0.0.1:9090 uv run python -m tripwire.proxy.server --host 127.0.0.1 --port 8080

mcp:
	PYTHONPATH=src TRIPWIRE_TOOL_BASE_URL=http://127.0.0.1:9090 uv run python -m tripwire.proxy.mcp_server --transport http --host 127.0.0.1 --port 8081

dashboard:
	PYTHONPATH=src uv run streamlit run dashboard/app.py

docker-build:
	docker compose -f docker/compose.yaml build

docker-up:
	docker compose -f docker/compose.yaml up

docker-down:
	docker compose -f docker/compose.yaml down
