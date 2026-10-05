import pytest


@pytest.fixture(autouse=True)
def isolated_home(tmp_path, monkeypatch):
    """Never touch (or depend on) the developer's real ~/.qurihunter config, DB or scan lock."""
    monkeypatch.setenv("QURIHUNTER_HOME", str(tmp_path / "qh-home"))


@pytest.fixture(autouse=True)
def no_network_page_fetch(monkeypatch):
    """classify.fetch_text would hit the real internet for fake URLs; tests that need it patch it themselves."""
    from qurihunter import classify
    monkeypatch.setattr(classify, "fetch_text", lambda url, limit=4000: "")


@pytest.fixture(autouse=True)
def no_wayback_network(monkeypatch):
    """Wayback CDX would hit the internet; by default the archive 'has no capture' (= likely new)."""
    from qurihunter import wayback
    monkeypatch.setattr(wayback, "lookup", lambda url, timeout=8: None)
    monkeypatch.setattr(wayback, "available", lambda url, timeout=10: (_ for _ in ()).throw(
        __import__("requests").ConnectionError("availability stub: down")))
    monkeypatch.setattr(wayback, "_last_call", 0.0)
    import time as _t
    from types import SimpleNamespace
    monkeypatch.setattr(wayback, "time", SimpleNamespace(sleep=lambda s: None, time=_t.time))  # module-local, not global


@pytest.fixture(autouse=True)
def no_telegram_sleep(monkeypatch):
    from qurihunter import notify
    monkeypatch.setattr(notify, "_sleep", lambda s: None)


@pytest.fixture(autouse=True)
def fast_scanner_sleeps(monkeypatch):
    """run_dorks sleeps between queries to be polite to real APIs; tests don't need that (module-local shim)."""
    import time as _t
    from types import SimpleNamespace
    from qurihunter import scanner
    monkeypatch.setattr(scanner, "time", SimpleNamespace(sleep=lambda s: None, time=_t.time))


@pytest.fixture(autouse=True)
def release_db_gate_between_tests():
    """A DB object left behind by a finished test must not keep the process-wide write gate."""
    from qurihunter import dblock
    yield
    dblock.flush()
    dblock.GATE.owner, dblock.GATE.info = None, None


@pytest.fixture(autouse=True)
def no_rate_limit_sleeps(monkeypatch):
    """Tests don't wait for real per-provider rate limits; limiter tests switch it on explicitly."""
    from qurihunter import ratelimit
    ratelimit.reset()
    monkeypatch.setattr(ratelimit, "ENABLED", False)
    yield
    ratelimit.reset()
