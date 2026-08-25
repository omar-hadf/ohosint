"""Shared command-line plumbing for the one-shot skill scripts.

Removes the per-script repetition of the same proxy/delay arguments, the
Fetcher construction, and the JSON report dump.
"""

import json
import os

from .net import Fetcher


def add_common_args(parser):
    """Add the --proxy / --delay-min / --delay-max options every skill accepts."""
    parser.add_argument("--proxy", default=None, help="e.g. socks5h://127.0.0.1:9050")
    parser.add_argument("--delay-min", type=float, default=1.5)
    parser.add_argument("--delay-max", type=float, default=3.5)
    return parser


def fetcher_from_args(args):
    """Build a Fetcher from the common args added by add_common_args()."""
    return Fetcher(proxy=args.proxy, delay=(args.delay_min, args.delay_max))


def save_report(path, data):
    """Write `data` as pretty JSON to `path` (0600); return the path.

    Reports carry the target's personal data, so they are created
    owner-readable only rather than inheriting the process umask.
    """
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    os.chmod(path, 0o600)
    return path
