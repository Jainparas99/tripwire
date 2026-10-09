from tripwire.contracts.destinations import destination_allowed, destination_host


def test_destination_matching_normalizes_url_case_and_default_ports() -> None:
    assert destination_allowed("HTTPS://SAFE.EXAMPLE:443/collect", ("safe.example:443",))
    assert destination_allowed("https://safe.example/collect", ("safe.example",))
    assert destination_host("https://SAFE.EXAMPLE:443/collect") == "safe.example"


def test_destination_matching_supports_email_domains_and_explicit_wildcards() -> None:
    assert destination_allowed("Lead@SAFE.EXAMPLE", ("safe.example",))
    assert destination_allowed("Lead@SAFE.EXAMPLE", ("@safe.example",))
    assert destination_allowed("lead@sub.safe.example", ("*.safe.example",))
    assert not destination_allowed("lead@safe.example", ("*.safe.example",))


def test_destination_matching_keeps_url_paths_and_ports_explicit() -> None:
    assert destination_allowed("https://safe.example/collect", ("https://safe.example/collect",))
    assert not destination_allowed("https://safe.example/other", ("https://safe.example/collect",))
    assert not destination_allowed("https://safe.example:8443/collect", ("safe.example:443",))
