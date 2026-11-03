"""生成 ≥200 条合成脱敏样本（含空格 / 连字符号码、地址混写、外文姓名等边界），带标注。"""
from __future__ import annotations
import csv
import json
import os
import random

SEED = 20261103
OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")

SUR = "赵钱孙李周吴郑王冯陈褚卫蒋沈韩杨朱秦尤许何吕施张孔曹严华金魏陶姜谢邹喻柏水窦章云苏潘葛范彭郎鲁韦马苗方俞任袁柳鲍史唐费廉岑薛雷贺倪汤滕殷罗毕郝邬安常乐"
GIVEN = ["伟", "芳", "娜", "秀英", "敏", "静", "丽", "强", "磊", "洋", "艳", "勇", "军", "杰", "娟",
         "涛", "明", "超", "秀兰", "霞", "平", "刚", "桂英", "文", "辉", "建国", "志强", "雨萱", "子豪", "欣怡"]
EN_FIRST = ["John", "Mary", "Anne-Marie", "O'Neil", "Peter", "Alice", "Jean", "Lucas"]
EN_LAST = ["Smith", "Johnson", "Brown", "Davis", "Wilson", "Clark", "Wright"]
CITY = [("广东省", "深圳市", "南山区"), ("浙江省", "杭州市", "西湖区"), ("江苏省", "南京市", "鼓楼区"),
        ("四川省", "成都市", "武侯区"), ("湖北省", "武汉市", "洪山区"), ("上海市", "上海市", "浦东新区")]
ROAD = ["科技园路", "文一西路", "中山北路", "人民南路", "光谷大道", "张江路", "望江东路", "解放路"]
COMMUNITY = ["翠苑小区", "香格里拉花园", "金色家园", "阳光公寓", "锦绣新村", "龙湖大厦"]


def phone(rng, style):
    head = rng.choice(["138", "139", "150", "158", "176", "188", "199", "133"])
    tail = "".join(rng.choice("0123456789") for _ in range(8))
    d = head + tail
    if style == "plain":
        return d
    if style == "space3_4_4":
        return f"{d[:3]} {d[3:7]} {d[7:]}"
    if style == "dash":
        return f"{d[:3]}-{d[3:7]}-{d[7:]}"
    if style == "plus86":
        return f"+86 {d}"
    if style == "86dash":
        return f"86-{d[:3]}-{d[3:7]}-{d[7:]}"
    return d


def idcard(rng, style="plain"):
    area = rng.choice(["440305", "330106", "320102", "510107", "420111", "310115"])
    y = rng.randint(1975, 2007)
    m = rng.randint(1, 12)
    dd = rng.randint(1, 28)
    seq = f"{rng.randint(0,999):03d}"
    chk = rng.choice("0123456789X")
    s = f"{area}{y}{m:02d}{dd:02d}{seq}{chk}"
    if style == "space":
        return f"{s[:6]} {s[6:14]} {s[14:]}"
    if style == "dash":
        return f"{s[:6]}-{s[6:14]}-{s[14:]}"
    return s


def bankcard(rng, style="grouped"):
    d = "62" + "".join(rng.choice("0123456789") for _ in range(17))
    if style == "grouped":
        return " ".join(d[i:i + 4] for i in range(0, 19, 4))
    if style == "dash":
        return "-".join(d[i:i + 4] for i in range(0, 19, 4))
    return d


def address(rng, style="full"):
    prov, city, dist = rng.choice(CITY)
    road = rng.choice(ROAD)
    num = rng.randint(1, 999)
    if style == "full":
        return f"{prov}{city}{dist}{road}{num}号{rng.randint(1,20)}栋{rng.randint(101,2508)}室"
    if style == "mixed":
        return f"{city}{road}{num}号"
    if style == "community":
        return f"{city}{dist}{rng.choice(COMMUNITY)}{rng.randint(1,30)}栋{rng.randint(1,8)}单元{rng.randint(101,1208)}室"
    if style == "town":
        return f"{prov}{city}{dist}{rng.choice(['西溪街道','龙岗镇','东山街道'])}{road}{num}号"
    return f"{city}{road}{num}号"


def cn_name(rng):
    return rng.choice(SUR) + rng.choice(GIVEN)


def en_name(rng):
    return f"{rng.choice(EN_FIRST)} {rng.choice(EN_LAST)}"


TEMPLATES = [
    ("我叫{name}，手机{phone}，想报名骑手。", ["name", "phone"]),
    ("姓名：{name}，联系电话：{phone}", ["name", "phone"]),
    ("我的手机号是{phone}，麻烦联系我", ["phone"]),
    ("身份证号{idcard}，手机{phone}", ["idcard", "phone"]),
    ("现住址：{address}，随时可以到站面试", ["address"]),
    ("地址{address}，手机{phone}，我叫{name}", ["address", "phone", "name"]),
    ("银行卡{card} 用于工资结算", ["card"]),
    ("联系人 {en}", ["en"]),
    ("骑手{name}申请调站，电话{phone}", ["name", "phone"]),
    ("本人{name}，住{address}", ["name", "address"]),
    ("您好，我想问下兼职政策，我在{address}附近", ["address"]),
    ("我叫{name}，{idcard}，住{address}，电话{phone}，卡号{card}", ["name", "idcard", "address", "phone", "card"]),
]

NEGATIVES = [
    "请问明天上午几点可以面试？", "站点还有名额吗，我想了解一下", "工资是一天一结还是月结？",
    "我有电动车，健康证正在办理中", "能不能安排晚上六点以后的时间", "我住在附近，十分钟能到",
    "底薪和提成怎么算", "需要带什么材料过去吗", "我之前做过两年外卖配送", "好的，谢谢你的解答",
    "全职和兼职有什么区别", "报名后多久会有回复",
]

TYPES = {"phone": "手机号", "idcard": "身份证号", "card": "银行卡号", "address": "地址",
         "name": "姓名", "en": "姓名"}


def build():
    rng = random.Random(SEED)
    rows = []
    styles_p = ["plain", "space3_4_4", "dash", "plus86", "86dash"]
    styles_a = ["full", "mixed", "community", "town"]
    for i in range(200):
        tpl, fields = TEMPLATES[i % len(TEMPLATES)]
        vals, expect = {}, {}
        if "name" in fields:
            vals["name"] = cn_name(rng); expect.setdefault("姓名", []).append(vals["name"])
        if "en" in fields:
            vals["en"] = en_name(rng); expect.setdefault("姓名", []).append(vals["en"])
        if "phone" in fields:
            vals["phone"] = phone(rng, styles_p[i % len(styles_p)])
            expect.setdefault("手机号", []).append(vals["phone"])
        if "idcard" in fields:
            vals["idcard"] = idcard(rng, ["plain", "space", "dash"][i % 3])
            expect.setdefault("身份证号", []).append(vals["idcard"])
        if "card" in fields:
            vals["card"] = bankcard(rng, ["grouped", "plain", "dash"][i % 3])
            expect.setdefault("银行卡号", []).append(vals["card"])
        if "address" in fields:
            vals["address"] = address(rng, styles_a[i % len(styles_a)])
            expect.setdefault("地址", []).append(vals["address"])
        rows.append({"id": f"S{i+1:03d}", "text": tpl.format(**vals),
                     "expect": json.dumps(expect, ensure_ascii=False), "kind": "pii"})
    for i, t in enumerate(NEGATIVES):
        rows.append({"id": f"N{i+1:03d}", "text": t, "expect": "{}", "kind": "negative"})
    # 补足边界：号码与地址相邻、多空格分隔、英文名夹中文
    rng2 = random.Random(SEED + 1)
    edges = []
    for i in range(8):
        addr = address(rng2, "mixed"); ph = phone(rng2, "plain")
        edges.append({"text": f"我住{addr}{ph}，请回电",
                      "expect": {"手机号": [ph], "地址": [addr]}})
    for i in range(4):
        nm = cn_name(rng2); ph = phone(rng2, "dash")
        edges.append({"text": f"姓名  {nm}   电话  {ph}",
                      "expect": {"姓名": [nm], "手机号": [ph]}})
    for i in range(4):
        nm = en_name(rng2); addr = address(rng2, "town")
        edges.append({"text": f"候选人 {nm} 住在{addr} 附近",
                      "expect": {"姓名": [nm], "地址": [addr]}})
    for idx, e in enumerate(edges):
        rows.append({"id": f"E{idx+1:03d}", "text": e["text"],
                     "expect": json.dumps(e["expect"], ensure_ascii=False), "kind": "edge"})
    return rows


if __name__ == "__main__":
    os.makedirs(OUT, exist_ok=True)
    rows = build()
    p = os.path.join(OUT, "samples_200.csv")
    with open(p, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=["id", "text", "expect", "kind"])
        w.writeheader()
        w.writerows(rows)
    print(f"wrote {p} rows={len(rows)}")
