"""Web UI: a local dashboard for ctf-harness.

Run with::

    ctfh web [--host 127.0.0.1] [--port 8787]

The dashboard is a single-page app (no build step, no CDN) served by the
standard-library HTTP server. Solving runs in an isolated subprocess so a
task can be cancelled and heavy tool calls never block the UI thread.
"""

__all__ = ["run", "create_server"]

from .server import create_server, run

__version__ = "0.1.0"