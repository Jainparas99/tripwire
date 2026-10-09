.PHONY: setup test lint analytics analytics-down eval remediate evidence demo live-demo open-web model-gauntlet redteam investigate investigate-akash audit-index tools gateway mcp dashboard docker-build docker-up docker-down docker-check

setup:
	uv sync

test:
	uv run pytest -q

lint:
	uv run ruff check .
	uv run ruff format --check .

eval:
	PYTHONPATH=src uv run python -m tripwire.evaluation.runner

remediate:
	PYTHONPATH=src uv run python -m tripwire.remediation $(ARGS)

analytics:
	PYTHONPATH=src uv run python -m tripwire.analytics all $(ARGS)

analytics-down:
	docker rm -f tripwire-clickhouse

evidence:
	PYTHONPATH=src uv run python -m tripwire.audit.evidence .tripwire/*.jsonl --output .tripwire/evidence.json

demo:
	PYTHONPATH=src uv run python -m tripwire.demo

live-demo:
	PYTHONPATH=src uv run python -m tripwire.demo --mode live

open-web:
	PYTHONPATH=src uv run python -m tripwire.open_web

model-gauntlet:
	PYTHONPATH=src uv run python -m tripwire.model_gauntlet $(ARGS)

redteam:
	PYTHONPATH=src uv run python -m tripwire.redteam $(ARGS)

investigate:
	PYTHONPATH=src uv run python -m tripwire.investigation.cli .tripwire/demo-*.jsonl

# AkashML (OpenAI-compatible) investigator. Copy the endpoint and key from your AkashML dashboard.
investigate-akash:
	@test -n "$$AKASHML_ENDPOINT" || (echo "set AKASHML_ENDPOINT=<akashml base url>/v1/chat/completions" && exit 1)
	@test -n "$$AKASHML_API_KEY" || (echo "set AKASHML_API_KEY" && exit 1)
	PYTHONPATH=src TRIPWIRE_OPENAI_COMPAT_ENDPOINT="$$AKASHML_ENDPOINT" TRIPWIRE_OPENAI_COMPAT_API_KEY="$$AKASHML_API_KEY" \
		uv run python -m tripwire.investigation.cli --refresh \
		--provider "openai-compatible:$${AKASHML_MODEL:-meta-llama/Llama-3.3-70B-Instruct}" --provider template \
		.tripwire/demo-escape.jsonl

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

docker-check:
	@set -e; \
	trap 'docker compose -f docker/compose.yaml down' EXIT; \
	docker compose -f docker/compose.yaml up -d --wait --build gateway mcp-gateway mock-tools; \
	docker compose -f docker/compose.yaml run --rm --no-deps --entrypoint python agent check_isolation.py
