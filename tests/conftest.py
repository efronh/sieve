import logging
import os
import sys
from pathlib import Path

import pytest

# don't rely on the editable install (macOS can hide its .pth file)
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# BERTurk is a 440 MB download; test_cascade.py fakes it, the rest use TF-IDF only.
os.environ.setdefault("SIEVE_CASCADE", "0")


class _Capture(logging.Handler):
    def __init__(self):
        super().__init__()
        self.events = []

    def emit(self, record):
        self.events.append(record.event)


@pytest.fixture
def siem_events():
    handler = _Capture()
    logger = logging.getLogger("sieve.siem")
    saved = logger.handlers, logger.level
    logger.handlers = [handler]
    logger.setLevel(logging.INFO)
    yield handler.events
    logger.handlers, logger.level = saved
