.PHONY: setup test lint eval demo

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
