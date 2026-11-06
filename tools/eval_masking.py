"""脱敏召回率 / 误报率评估：对 data/samples_200.csv 逐条跑检测与标注比对。"""
from __future__ import annotations
import csv
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app.masking import MaskingSession  # noqa: E402


_FW = {chr(0xFF10 + i): str(i) for i in range(10)}
_FW.update({chr(0xFF21 + i): chr(ord("A") + i) for i in range(26)})
_FW.update({chr(0xFF41 + i): chr(ord("a") + i) for i in range(26)})
# 中文数字 / 全角 / 分隔符：比对时必须先归一化，否则「一三八零零一三八零零零」和
# 「13800138000」是同一条 PII 却算两次不同 —— 报告里的召回率就不是召回率了。
# ★ 2026-11-06 补：这一条是独立探针集暴露的 —— 评测脚本自己不做形态归一化，
#   于是"中文数字写法"既可能被算成漏检，也可能被算成误报。
_CN = str.maketrans("零一二三四五六七八九〇两", "012345678902")


def norm(typ: str, s: str) -> str:
    s = s.strip().translate(_FW).translate(_CN)
    if typ in ("手机号", "身份证号", "银行卡号"):
        s = re.sub(r"[\s\-\+\.\(\）\)]", "", s).upper()
        # 国际区号前缀：+86 138… 与 138… 是同一个号，不归一化就会被算成一漏一误报。
        # ★ 2026-11-06 由机械变异语料抓到：`+86 (138)0013-8000` 被判 miss+fp 各一次，
        #   而检测器其实是对的 —— 错在比对口径。
        if typ == "手机号" and s.startswith("86") and len(s) == 13:
            s = s[2:]
        return s
    return re.sub(r"\s+", "", s)


def evaluate(strict_names: bool = True, filename: str = "samples_200.csv") -> dict:
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    rows = list(csv.DictReader(open(os.path.join(here, "data", filename), encoding="utf-8")))
    stats = {t: {"expected": 0, "hit": 0, "detected": 0, "fp": 0} for t in
             ("手机号", "身份证号", "银行卡号", "地址", "姓名", "邮箱")}
    misses, fps = [], []
    for r in rows:
        exp = json.loads(r["expect"])
        sess = MaskingSession(strict_names=strict_names)
        spans = sess.detect(r["text"])
        det = {}
        for s in spans:
            stats[s["type"]]["detected"] += 1
            det.setdefault(s["type"], []).append(norm(s["type"], s["text"]))
        for typ, values in exp.items():
            stats[typ]["expected"] += len(values)
            for v in values:
                nv = norm(typ, v)
                got = det.get(typ, [])
                if any(nv == g or nv in g or g in nv for g in got):
                    stats[typ]["hit"] += 1
                else:
                    misses.append({"id": r["id"], "type": typ, "value": v, "text": r["text"]})
        for s in spans:
            nv = norm(s["type"], s["text"])
            if not any(nv == norm(s["type"], v) or nv in norm(s["type"], v) or norm(s["type"], v) in nv
                       for v in exp.get(s["type"], [])):
                stats[s["type"]]["fp"] += 1
                fps.append({"id": r["id"], "type": s["type"], "text": s["text"], "src": r["text"]})
    report = {"file": filename, "samples": len(rows), "strict_names": strict_names, "per_type": {}}
    for typ, st in stats.items():
        rec = st["hit"] / st["expected"] if st["expected"] else 1.0
        prec = (st["detected"] - st["fp"]) / st["detected"] if st["detected"] else 1.0
        report["per_type"][typ] = {**st, "recall": round(rec, 4), "precision": round(prec, 4),
                                   "fp_rate": round(st["fp"] / max(1, st["detected"]), 4)}
    report["misses"] = misses[:40]
    report["false_positives"] = fps[:40]
    return report


if __name__ == "__main__":
    fn = sys.argv[1] if len(sys.argv) > 1 else "samples_200.csv"
    rep = evaluate(filename=fn)
    print(json.dumps({k: v for k, v in rep.items() if k in ("samples", "per_type")},
                     ensure_ascii=False, indent=1))
    print("misses:", len(rep["misses"]), "fps:", len(rep["false_positives"]))
    for m in rep["misses"][:6]:
        print("  MISS", m["type"], m["value"], "|", m["text"][:50])
    for f in rep["false_positives"][:6]:
        print("  FP  ", f["type"], f["text"], "|", f["src"][:50])
