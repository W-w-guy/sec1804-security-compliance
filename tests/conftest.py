import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.config import Settings           # noqa: E402
from app.container import Container       # noqa: E402
from app.rbac import Principal            # noqa: E402
from app.service import CandidateService  # noqa: E402


@pytest.fixture()
def c(tmp_path):
    st = Settings()
    st.kms_secret = "test-secret"
    box = Container(st, db_path=str(tmp_path / "t.db"), kms_dir=str(tmp_path / "kms"))
    yield box
    box.close()


@pytest.fixture()
def svc(c):
    return CandidateService(c)


@pytest.fixture()
def admin():
    return Principal(actor="adm", role="admin", city="深圳", all_cities=True)


@pytest.fixture()
def recruiter():
    return Principal(actor="rec1", role="recruiter", city="深圳", stations={"S1"})


@pytest.fixture()
def manager():
    return Principal(actor="mgr1", role="station_manager", city="深圳", stations={"S1"})


@pytest.fixture()
def auditor():
    return Principal(actor="aud1", role="auditor", city="深圳", all_cities=True)


@pytest.fixture()
def ops():
    return Principal(actor="ops1", role="ops", all_cities=True)


def make_candidate(svc, p, **kw):
    data = {"name": "王小二", "phone": "13800138000", "city": "深圳", "station_id": "S1"}
    data.update(kw)
    return svc.create(p, data)
