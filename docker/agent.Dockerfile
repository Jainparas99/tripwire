# Untrusted side: only the scripted agent and its scenarios. No Tripwire source,
# contracts, tool data or honeytokens; standard library only.
FROM python:3.12-slim

RUN useradd --create-home agent
WORKDIR /agent
COPY examples/enterprise_agent/replay_agent.py examples/enterprise_agent/scenarios.json docker/check_isolation.py ./
USER agent

ENTRYPOINT ["python", "replay_agent.py"]
