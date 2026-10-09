# Trusted side: gateway and mock tool service. Never given to the agent.
FROM python:3.12-slim

COPY --from=ghcr.io/astral-sh/uv:0.8.4 /uv /bin/uv
ENV UV_PROJECT_ENVIRONMENT=/opt/venv \
    UV_LINK_MODE=copy \
    UV_COMPILE_BYTECODE=1 \
    PATH=/opt/venv/bin:$PATH

WORKDIR /app
COPY pyproject.toml uv.lock README.md LICENSE ./
RUN uv sync --locked --no-default-groups --no-install-project

COPY src ./src
COPY examples/contracts ./examples/contracts
RUN uv sync --locked --no-default-groups --no-editable

CMD ["tripwire-gateway", "--host", "0.0.0.0", "--port", "8080"]
