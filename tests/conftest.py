import os
import sys
import uuid

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.config import Settings           # noqa: E402
from app.container import Container       # noqa: E402
from app.rbac import Principal            # noqa: E402
from app.service import CandidateService  # noqa: E402


@pytest.fixture()
def c(tmp_path):
    """每个用例一个独立容器。

    有 PG_DSN 时给每个用例分配独立 schema：否则整个测试套件共用 public，
    上一个用例的残留行会让"库里不该出现明文""链应为空"这类断言随机失败
    ——在容器里跑 pytest 时才暴露（Windows 上没有 PG，永远看不到）。
    """
    st = Settings()
    st.kms_secret = "test-secret"
    schema = "t_" + uuid.uuid4().hex[:10] if st.pg_dsn else None
    box = Container(st, db_path=str(tmp_path / "t.db"), kms_dir=str(tmp_path / "kms"),
                    pg_schema=schema)
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
