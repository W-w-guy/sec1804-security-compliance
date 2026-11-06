"""独立探针集回归（data/probe_20261106.csv）。

★ 为什么另开一组：samples_200.csv 与 holdout_adversarial.csv 都是我自己参与设计的语料，
  在上面拿 100% / 0 误报没有说服力 —— 那只是"我测了我自己想到的情况"。
  这一组是 2026-11-06 换一个身份（买家/审阅者）临时写的 25 条，不看检测器、只按真实业务话术写，
  一次就暴露了 8 个问题：

    1. 15 位旧身份证（1999 年前签发）整条漏检 —— 而验收点 2 写的是"身份证号召回率 100%"
    2. 复姓姓名「欧阳修文」漏检（单姓表按 2~3 字切分，复姓+双名两头落空）
    3. 「望京SOHO T1 2201」漏检，补上后又发现只吞了 T1、把 2201 留在明文里
    4. 「广州天河区体育西路」漏检（无门牌号的路名被"号码级标志"一票否决）
    5. 非 ASCII 拉丁名「Ayşe Yılmaz」漏检（ı/ş 在 Latin Extended-A，不在 À-ÿ 区间）
    6. 少数民族姓名「买买提·艾力」只抓到后半截
    7. 误报：车牌「粤B12345」里的"车牌"两字被当成姓名
    8. 评测脚本自身：norm() 不做中文数字/全角归一化，"一三八…"与"1380…"被算成两条不同的 PII

  这些都已修掉，本测试把 25 条钉成回归集，任何一条再退化都会红。
"""
from __future__ import annotations
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from tools.eval_masking import evaluate  # noqa: E402


@pytest.fixture(scope="module")
def rep():
    return evaluate(filename="probe_20261106.csv")


def test_no_misses_on_probe(rep):
    assert rep["misses"] == [], f"独立探针集出现漏检：{rep['misses']}"


def test_no_false_positives_on_probe(rep):
    assert rep["false_positives"] == [], f"独立探针集出现误报：{rep['false_positives']}"


def test_recall_meets_contract(rep):
    pt = rep["per_type"]
    assert pt["手机号"]["recall"] >= 1.0
    assert pt["身份证号"]["recall"] >= 1.0
    assert pt["姓名"]["recall"] >= 0.95
    assert pt["地址"]["recall"] >= 0.95


def test_no_partial_masking_leftover():
    """掩码之后必须扫不出同类型 PII（半截掩码是比漏检更危险的一类）。

    ★ 2026-11-06 补：一次对抗检查抓到这个：
        「我住西湖区文三路90号东部软件园3号楼」
      → 掩成「我住〔地址_1〕东部软件园3号楼」，楼宇名+楼号原样留在明文里。
      两个地址正则各认一半、互不覆盖，而占位符的存在会让审阅者以为这行已处理。
      修法：相邻片段合并 + 地址尾部续接楼宇名门牌。本测试守着"掩完再扫必须干净"。
    """
    import csv
    import json
    from app.masking import MaskingSession, mask_text

    bad = []
    for fn in ("samples_200.csv", "holdout_adversarial.csv", "probe_20261106.csv"):
        path = os.path.join(ROOT, "data", fn)
        for row in csv.DictReader(open(path, encoding="utf-8")):
            masked = mask_text(row["text"])["masked"]
            left = MaskingSession().detect(masked)
            if left:
                bad.append({"id": row["id"], "masked": masked,
                            "leftover": [(s["type"], s["text"]) for s in left]})
    assert not bad, f"掩码后仍能扫出 PII（半截掩码）：{json.dumps(bad[:5], ensure_ascii=False)}"
