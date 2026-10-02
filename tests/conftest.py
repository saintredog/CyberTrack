import os
import tempfile

import pytest

from cybertrack import create_app
from cybertrack.db import get_session


@pytest.fixture
def app():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    app = create_app(
        {
            "TESTING": True,
            "DATABASE_URL": f"sqlite:///{path}",
            "TODAY": "2026-10-02",
            "WTF_CSRF_ENABLED": False,
        }
    )
    yield app
    os.unlink(path)


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def session(app):
    with app.app_context():
        yield get_session()
