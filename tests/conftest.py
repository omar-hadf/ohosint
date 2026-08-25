"""Shared pytest fixtures and CI safety rails.

Two things here matter for a tool that talks to third-party OSINT APIs:

1. **No test may touch the network.** Real outbound calls make the suite slow
   and flaky, they fail on egress-restricted CI, and — worse for this project —
   they would fire live queries at third-party breach APIs from every fork's CI
   run. The ``_block_network`` fixture makes any such call fail loudly instead
   of silently succeeding on a developer's machine.
2. **No test may read the developer's real credentials.** ``get_api_keys()``
   falls back to reading a ``.env`` file from the current working directory, so
   tests are pinned to a scratch directory with no ``.env`` in it.
"""

import socket

import pytest

import osint_core.exclusions as _exclusions

_ALLOWED_HOSTS = {"127.0.0.1", "::1", "localhost"}


class NetworkCallInTest(RuntimeError):
    """Raised when a test attempts a real outbound connection."""


@pytest.fixture(autouse=True)
def _block_network(monkeypatch):
    """Fail any test that opens a non-loopback socket.

    Tests must mock at the ``osint_core``/``ohosint`` seam (``oc.gravatar``,
    ``oc.leakcheck``, ``oc.fetch_exclusions``, ``check_username_on_sites``, …)
    rather than reaching the internet.
    """
    real_connect = socket.socket.connect
    real_create = socket.create_connection

    def _host_of(address):
        if isinstance(address, tuple) and address:
            return str(address[0])
        return str(address)

    def guarded_connect(self, address, *args, **kwargs):
        host = _host_of(address)
        if host not in _ALLOWED_HOSTS:
            raise NetworkCallInTest(
                f"Blocked outbound connection to {host!r} during a test. "
                "Mock the source helper instead of hitting the real API."
            )
        return real_connect(self, address, *args, **kwargs)

    def guarded_create(address, *args, **kwargs):
        host = _host_of(address)
        if host not in _ALLOWED_HOSTS:
            raise NetworkCallInTest(
                f"Blocked outbound connection to {host!r} during a test. "
                "Mock the source helper instead of hitting the real API."
            )
        return real_create(address, *args, **kwargs)

    monkeypatch.setattr(socket.socket, "connect", guarded_connect)
    monkeypatch.setattr(socket, "create_connection", guarded_create)
    yield


@pytest.fixture(autouse=True)
def _reset_exclusions_cache():
    """Clear the process-wide exclusions cache between tests.

    ``fetch_exclusions()`` memoises into a module global, so without this a
    test that populates it leaks that state into every later test.
    """
    _exclusions._exclusions_cache = None
    yield
    _exclusions._exclusions_cache = None


@pytest.fixture(autouse=True)
def _isolate_dotenv(tmp_path, monkeypatch):
    """Run every test in a scratch cwd so no real ``.env`` is picked up."""
    monkeypatch.chdir(tmp_path)
    yield


@pytest.fixture
def no_sources(monkeypatch):
    """Stub the passive source lookups used by ``run_email_pipeline``."""
    import ohosint.pipelines as pipelines

    monkeypatch.setattr(pipelines.oc, "gravatar", lambda *a, **k: {})
    monkeypatch.setattr(pipelines.oc, "leakcheck", lambda *a, **k: {})
    monkeypatch.setattr(pipelines.oc, "hudson_rock", lambda *a, **k: {})
    monkeypatch.setattr(pipelines.oc, "fetch_exclusions", lambda *a, **k: set())
    yield
