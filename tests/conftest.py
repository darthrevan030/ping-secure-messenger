import pytest

from ping import auth


@pytest.fixture(autouse=True)
def fast_scrypt(monkeypatch):
    monkeypatch.setitem(auth.SCRYPT, "n", 2**4)


@pytest.fixture
def tmp_home(tmp_path):
    return tmp_path / "home"
