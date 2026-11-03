"""AC2：≥200 条合成样本随仓库提交；手机号/身份证召回 100%，姓名/地址 ≥95%，并给出误报率。"""
import csv
import json
import os
import re

import pytest

from app.masking import MaskingSession, mask_text

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(ROOT, "data")


def _norm(typ, s):
    s = s.strip()
    if typ in ("手机号", "身份证号", "银行卡号"):
        return re.sub(r"[\s\-]", "", s).upper()
    return re.sub(r"\s+", "", s)


def _eval(filename):
    rows = list(csv.DictReader(open(os.path.join(DATA, filename), encoding="utf-8")))
    stats = {t: {"exp": 0, "hit": 0, "det": 0, "fp": 0}
             for t in ("手机号", "身份证号", "银行卡号", "地址", "姓名", "邮箱")}
    for r in rows:
        exp = json.loads(r["expect"])
        spans = MaskingSession().detect(r["text"])
        for s in spans:
            stats[s["type"]]["det"] += 1
        for typ, vals in exp.items():
            for v in vals:
                stats[typ]["exp"] += 1
                nv = _norm(typ, v)
                got = [_norm(s["type"], s["text"]) for s in spans if s["type"] == typ]
                if any(nv == g or nv in g or g in nv for g in got):
                    stats[typ]["hit"] += 1
        for s in spans:
            nv = _norm(s["type"], s["text"])
            if not any(nv == _norm(s["type"], v) or nv in _norm(s["type"], v)
                       or _norm(s["type"], v) in nv for v in exp.get(s["type"], [])):
                stats[s["type"]]["fp"] += 1
    return rows, stats


def test_samples_file_has_at_least_200_rows():
    rows, _ = _eval("samples_200.csv")
    assert len(rows) >= 200


@pytest.mark.parametrize("filename,phone,rname,addr", [
    ("samples_200.csv", 1.0, 0.95, 0.95),
    ("holdout_adversarial.csv", 1.0, 0.95, 0.95),
])
def test_recall_thresholds(filename, phone, rname, addr):
    _, st = _eval(filename)
    assert st["手机号"]["hit"] / st["手机号"]["exp"] >= phone
    assert st["身份证号"]["hit"] / st["身份证号"]["exp"] >= 1.0
    assert st["姓名"]["hit"] / st["姓名"]["exp"] >= rname
    assert st["地址"]["hit"] / st["地址"]["exp"] >= addr


def test_false_positive_rate_is_low():
    _, st = _eval("holdout_adversarial.csv")
    for typ, s in st.items():
        if s["det"]:
            assert s["fp"] / s["det"] <= 0.05, f"{typ} 误报率过高: {s}"


def test_placeholder_format_and_stable_index():
    r = mask_text("我叫王小二，电话13800138000，备用号也是13800138000")
    assert "〔姓名_1〕" in r["masked"]
    assert "〔手机号_1〕" in r["masked"]
    assert r["masked"].count("〔手机号_1〕") == 2      # 同值同序号
    assert "13800138000" not in r["masked"]


def test_restore_roundtrip():
    text = "联系人李雷，手机13800001111，住广州市天河区体育西路103号"
    r = mask_text(text)
    sess = MaskingSession()
    sess.mapping = r["mapping"]
    assert sess.restore(r["masked"]) == text


def test_negative_samples_no_detection():
    for t in ("请问明天上午几点可以面试？", "底薪和提成怎么算", "我们站点在文一西路，明天面试"):
        assert MaskingSession().detect(t) == [], t


def test_edge_number_styles():
    cases = {
        "138 0013 8000": "手机号",
        "138-0013-8000": "手机号",
        "+86 13800138000": "手机号",
        "44030519900101123X": "身份证号",
        "6222 0212 3456 7890 123": "银行卡号",
    }
    for raw, typ in cases.items():
        got = MaskingSession().detect(raw)
        assert got and got[0]["type"] == typ, (raw, got)


def test_order_number_not_treated_as_card():
    assert [s for s in MaskingSession().detect("订单号 2026110300012345678 请查询")
            if s["type"] == "银行卡号"] == []
