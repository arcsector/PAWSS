import json
from ..call_api import Config, ShadowAPI
from datetime import date, timedelta
from time import sleep
import pytest

@pytest.fixture(scope="session")
def import_creds() -> Config:
    config = json.loads(open("shadowapi/tests/conf.json", 'r').read())
    c = Config(**config)
    return c

@pytest.fixture(scope="session")
def S(import_creds) -> ShadowAPI:
    S = ShadowAPI(import_creds)
    return S

@pytest.fixture(scope="session")
def date_since() -> date:
    return date.today() - timedelta(days=7)

@pytest.fixture(scope="session")
def date_today() -> date:
    return date.today()
