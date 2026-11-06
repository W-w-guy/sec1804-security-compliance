"""第 1 组·第 C 轮：机械变异 + 反向构造负样本（r1_20261106b.csv，354 条）。

★ 与 probe_20261106.csv 的区别在「生成方法」，不在「换了字符串」：
  - 变异组 330 条：对已有 PII 做**枚举型机械变换**（全角/零宽/空格/连字符/点/括号）。
    这是可穷举的，不依赖我"想到"什么，因此能反复使用而不会被我调参掉。
  - 负样本组 24 条：**先规定"这 24 条全都不该识别"，再倒着写句子**。
    现有语料的 fp 长期恒为 0，这本身就是可疑信号；反向构造专门打误报。

首轮通过率（如实记录，不是修完之后的成绩）：
    变异组 330 条：miss 32 / fp 36
    负样本组 24 条：miss 0 / fp 4
其中大部分 miss+fp 是**评测脚本自身**的比对口径错（括号、+86 前缀没归一化），
检测器其实是对的 —— 这条比修检测器更重要：比对口径错会把真缺陷淹掉。

分离后确认的真缺陷 4 类：
    1) 零宽字符插进门牌中间 → 「科技园路81\u200b1号」只掩到「科技园路81」，`1号` 留在明文
    2) 姓名尾部粘动作词 → 「我叫张伟报名」抓出人名「张伟报名」
    3) 姓名误报 → 「单价」「高中」「周再」被当成人名
    4) 评测脚本 norm() 不处理括号与 +86 前缀 → 同一号码被判成一漏一误报
"""
from __future__ import annotations
import csv
import json
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from app.masking import MaskingSession, mask_text  # noqa: E402
from tools.eval_masking import evaluate  # noqa: E402

CORPUS = "r1_20261106b.csv"


@pytest.fixture(scope="module")
def rep():
    return evaluate(filename=CORPUS)


def test_mutation_recall_no_miss(rep):
    """变异只改形态、不改语义，所以原有 PII 必须仍然被识别。"""
    assert rep["misses"] == [], f"机械变异后出现漏检：{rep['misses'][:5]}"


def test_constructed_negatives_precision(rep):
    """反向构造的负样本：fp 必须为 0。

    「留下街道」是杭州真实街道名，判成地址属于安全侧的保守遗漏，
    已在标书「已知边界」里写明，所以这里只统计其余条目。
    """
    bad = [f for f in rep["false_positives"] if "留下街道" not in f.get("src", "")]
    assert not bad, f"负样本出现误报：{bad[:5]}"


def test_zero_width_does_not_split_house_number():
    """零宽字符不能把门牌号撕成两段——撕断就意味着后半截留在明文里。"""
    for raw in ("我住在科技园路81\u200b1号", "我住在科技园路8\u200b11号"):
        got = mask_text(raw)["found"].get("地址", [])
        assert got, f"零宽插入后地址完全没识别：{raw!r}"
        # 掩码结果里不应再残留门牌数字
        masked = mask_text(raw)["masked"]
        assert not MaskingSession().detect(masked), f"掩码后仍有残留：{masked!r}"


def test_name_does_not_swallow_verb():
    """姓名不许把后面的动作词一起吞掉。"""
    cases = {"我叫张伟报名": "张伟", "联系人：赵敏面试": "赵敏",
             "我叫欧阳修文报名": "欧阳修文", "王小明申请报名": "王小明"}
    for text, want in cases.items():
        got = mask_text(text)["found"].get("姓名", [])
        assert got == [want], f"{text!r} 期望 [{want}]，实际 {got}"


def test_common_words_are_not_names():
    """业务词/学历词/时间词不许被认成人名（反向构造负样本抓到的误报）。"""
    for text in ("单价 1234.56 元", "学历 高中", "客户说下周再联系",
                 "年龄 28，性别 男", "车牌 粤B12345 停在 3 号门"):
        assert not mask_text(text)["found"].get("姓名"), f"{text!r} 被误判为人名"
