"""Security events for a SIEM.

Every time something security-relevant happens in the network (a login
succeeds, a check fails), we write one event. Each event is one line of
JSON, which is the format Splunk and most other SIEMs read best.
"""

from __future__ import annotations

import hashlib  # SHA-256 for the pseudonyms
import hmac  # keyed hash, so pseudonyms can't be brute-forced back to the IMSI
import json  # turns a Python dictionary into a JSON line
import sys  # sys.stdout = the screen, used as the default output
from collections.abc import Callable  # type hint: something you can call, like a function
from datetime import UTC, datetime  # timestamps, always in UTC so logs line up
from typing import TextIO  # type hint: something you can write text to


def utc_now() -> datetime:
    """The real current time in UTC. The default clock for EventLog."""
    return datetime.now(UTC)


def pseudonymize(supi: str, key: bytes) -> str:
    """Turn a permanent subscriber ID into a stable pseudonym for the logs.

    The same SUPI always gives the same pseudonym, so we can still follow
    one subscriber in Splunk. But without the key, nobody reading the logs
    can work out who it is.
    """
    return hmac.new(key, supi.encode(), hashlib.sha256).hexdigest()[:16]


class EventLog:
    """Write security events as JSON lines.

    Each event is one line of JSON. By default it writes to the screen,
    but you can pass in a file instead.
    """

    def __init__(self, pseudonym_key: bytes, out: TextIO = sys.stdout,
                 clock: Callable[[], datetime] = utc_now) -> None:
        self._key = pseudonym_key
        self._out = out
        self._clock = clock

    def emit(self, event_type: str, supi: str | None = None,
             time: datetime | None = None, **fields) -> dict:
        """Write one event and return it.

        event_type : what happened, e.g. "auth_success" or "auth_failure"
        supi       : the subscriber, only ever logged as a pseudonym
        time       : when it happened (the generator sets this, normally it's now)
        **fields   : anything else worth logging, e.g. cell="cell-07"
        """
        event = {
            "time": (time or self._clock()).isoformat(timespec="milliseconds"),
            "event_type": event_type,
        }
        if supi is not None:
            event["subscriber"] = pseudonymize(supi, self._key)
        event.update(fields)

        self._out.write(json.dumps(event) + "\n")
        return event
