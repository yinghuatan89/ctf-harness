"""Safety guardrails: workspace jail, shell deny-list, network scope.

The guard is intentionally pragmatic - this is a CTF *workstation* tool:

* file operations are jailed to the per-challenge workspace;
* shell commands are checked against a small deny-list of clearly
  system-destructive patterns (rm -rf /, mkfs, fork bombs, raw device
  writes, power control, cloud metadata endpoints);
* HTTP requests made through the ``http`` tool must stay inside the
  declared challenge scope (challenge URL/remote/scorer hosts + loopback).

It is *not* a sandbox: run the harness in a container/VM when working with
untrusted binaries. See SECURITY.md.
"""

from .guard import Guard, GuardError

__all__ = ["Guard", "GuardError"]
