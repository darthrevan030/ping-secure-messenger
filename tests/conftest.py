import pytest

from ping import auth


@pytest.fixture(autouse=True)
def fast_scrypt(monkeypatch):
    monkeypatch.setitem(auth.SCRYPT, "n", 2**4)


@pytest.fixture
def tmp_home(tmp_path):
    return tmp_path / "home"


@pytest.fixture
def env(tmp_home, monkeypatch):
    from ping import messaging
    from tests.pki_fixture import Env

    e = Env(tmp_home)
    monkeypatch.setattr(messaging, "pki", e.pki, raising=False)
    return e


@pytest.fixture
def alice(env):
    return env.add_user("alice")


@pytest.fixture
def bob(env):
    return env.add_user("bobby")


@pytest.fixture
def carol(env):
    return env.add_user("carol")
