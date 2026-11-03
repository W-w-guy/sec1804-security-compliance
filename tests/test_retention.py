"""AC5：时间快进后清理任务生效（删除/匿名化 + 留记录）；撤回同意立即删除。"""
from tests.conftest import make_candidate

DAY = 86400.0


def test_transcript_expires_after_30_days(c, admin):
    cand = make_candidate(c and __import__("app.service", fromlist=["x"]).CandidateService(c), admin)
    c.db.insert("transcripts", {"id": "t1", "candidate_id": cand["id"], "body": "原文",
                               "is_minor": 0, "created_at": "2026-01-01T00:00:00Z", "deleted_at": None})
    c.db.insert("transcripts", {"id": "t2", "candidate_id": cand["id"], "body": "新原文",
                               "is_minor": 0, "created_at": "2026-10-01T00:00:00Z", "deleted_at": None})
    import datetime as dt
    now = dt.datetime(2026, 3, 1, tzinfo=dt.timezone.utc).timestamp()
    rep = c.retention.run(now=now)
    assert rep["transcripts_deleted"] >= 1
    left = [r["id"] for r in c.db.query("SELECT id FROM transcripts WHERE deleted_at IS NULL")]
    assert "t1" not in left and "t2" in left
    assert any(d["entity"] == "transcript" for d in c.retention.deletions())


def test_minor_deleted_within_24h(c, svc, admin):
    import datetime as dt
    cand = make_candidate(svc, admin, is_minor=True)
    now = dt.datetime.now(dt.timezone.utc).timestamp() + 25 * 3600
    rep = c.retention.run(now=now)
    assert rep["minors_deleted"] == 1
    assert c.db.one("SELECT id FROM candidates WHERE id=?", (cand["id"],)) is None


def test_not_hired_expires_90d_delete(c, svc, admin):
    import datetime as dt
    cand = make_candidate(svc, admin, status="new")
    now = dt.datetime.now(dt.timezone.utc).timestamp() + 91 * DAY
    rep = c.retention.run(now=now)
    assert rep["expired_deleted"] == 1
    assert c.db.one("SELECT id FROM candidates WHERE id=?", (cand["id"],)) is None
    log = c.retention.deletions()[0]
    assert log["rule"] == "not_hired_90d" and log["mode"] == "delete"


def test_hired_expires_180d_anonymize(c, svc, admin):
    import datetime as dt
    cand = make_candidate(svc, admin, status="hired")
    now = dt.datetime.now(dt.timezone.utc).timestamp() + 181 * DAY
    rep = c.retention.run(now=now)
    assert rep["expired_anonymized"] == 1
    row = c.db.one("SELECT * FROM candidates WHERE id=?", (cand["id"],))
    assert row is not None and row["name_token"] is None and row["anonymized_at"]


def test_consent_revoke_deletes_immediately(c, svc, admin):
    cand = make_candidate(svc, admin)
    c.consent.record(cand["id"], "v1", "qr")
    res = c.consent.revoke(cand["id"])
    assert res["deleted"] is True
    assert c.db.one("SELECT id FROM candidates WHERE id=?", (cand["id"],)) is None
    assert any(d["rule"] == "consent_revoked" for d in c.retention.deletions())


def test_retention_is_idempotent(c, svc, admin):
    cand = make_candidate(svc, admin)
    c.consent.record(cand["id"], "v1", "qr")
    c.consent.revoke(cand["id"])
    rep2 = c.retention.run()
    assert rep2["revoked_deleted"] == 0
