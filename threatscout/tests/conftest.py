import pytest

from threatscout.config import Settings
from threatscout.db import Store
from threatscout.engine import SQLiteCache, ThreatScoutEngine


@pytest.fixture
def make_engine(tmp_path):
    # Testlerde gercek veritabani yerine gecici bir klasor kullanilir
    def _make(providers=None):
        return ThreatScoutEngine(
            settings=Settings(
                sqlite_path=str(tmp_path / "app.db"),
                sqlite_cache_path=str(tmp_path / "cache.db"),
            ),
            providers=providers or [],
            cache=SQLiteCache(str(tmp_path / "cache.db")),
            store=Store(str(tmp_path / "app.db")),
        )

    return _make
