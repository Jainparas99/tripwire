.PHONY: setup test lint demo

setup:
	uv sync

test:
	uv run pytest -q

lint:
	uv run ruff check .
	uv run ruff format --check .

demo:
	PYTHONPATH=src uv run python -m tripwire.demo
