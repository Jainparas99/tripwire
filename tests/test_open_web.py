from pathlib import Path

from tripwire.contracts import ToolCall
from tripwire.open_web import ALERT_ARG, ALERT_FILE, OpenWebToolRegistry


def _publish(path: str) -> ToolCall:
    return ToolCall(tool="publish_alert", arguments={"path": path, "content": "{}"})


def test_alert_argument_is_repo_relative_and_points_at_the_alert_file() -> None:
    assert not Path(ALERT_ARG).is_absolute()
    assert str(Path.home()) not in ALERT_ARG
    assert OpenWebToolRegistry().validate(_publish(ALERT_ARG)) is None


def test_publish_still_allows_only_the_one_alert_file(tmp_path: Path) -> None:
    registry = OpenWebToolRegistry()

    assert registry.validate(_publish(str(ALERT_FILE))) is None
    for path in (
        ".tripwire/other.json",
        "../open-web-alert.json",
        ".tripwire/../../open-web-alert.json",
        str(tmp_path / "open-web-alert.json"),
        "/etc/passwd",
    ):
        assert registry.validate(_publish(path)) == "PUBLISH_PATH_NOT_ALLOWED", path
