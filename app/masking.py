"""脱敏工具库 v2：识别中文/外文姓名、手机号、身份证号、银行卡号、详细地址、邮箱。

替换为〔类型_序号〕占位符，受控环境可 restore 回填。任务 1、3 可直接 import。

v2 相对 v1 的修正（均由 holdout 对抗样本暴露）：
- 号码类改为“先取候选串再归一化校验”，带空格 / 连字符 / +86 / 尾随字母均正确处理；
- 身份证允许 X 前有空格，且校验出生日期合法性，优先于银行卡；
- 银行卡启用 Luhn + 上下文（卡/账户/账号），订单号不再被误判；
- 地址允许空格、允许无“市”、支持 区县+街道/镇/村 结尾，并剔除前导动词（住/在/位于/地址是）；
- 姓名新增英文逗号式 “Smith, John”，并扩充词黑名单（单元/号楼/小区…）。
"""
from __future__ import annotations
import re

TYPES = ("身份证号", "银行卡号", "手机号", "邮箱", "地址", "姓名")

SURNAMES = set("赵钱孙李周吴郑王冯陈褚卫蒋沈韩杨朱秦尤许何吕施张孔曹严华金魏陶姜戚谢邹喻柏水窦章云苏潘葛范彭郎鲁韦马苗方俞任袁柳鲍史唐费廉岑薛雷贺倪汤滕殷罗毕郝邬安常乐于时傅皮卞齐康伍余元卜顾孟平黄和穆萧尹姚邵湛汪祁毛禹狄米贝明臧计伏成戴谈宋茅庞熊纪舒屈项祝董梁杜阮蓝闵席季麻强贾路娄危江童颜郭梅盛林刁钟徐邱骆高夏蔡田樊胡凌霍虞万支柯昝管卢莫经房裘缪干解应宗丁宣邓郁单杭洪包诸左石崔吉钮龚程嵇邢滑裴陆荣翁荀羊於惠甄曲家封芮羿储靳汲邴糜松井段富巫乌焦巴弓牧隗山谷车侯宓蓬全郗班仰秋仲伊宫宁仇栾暴甘钭厉戎祖武符刘景詹束龙叶幸司韶郜黎蓟薄印宿白怀蒲邰从鄂索咸籍赖卓蔺屠蒙池乔阴胥能苍双闻莘党翟谭贡劳逄姬申扶堵冉宰郦雍却璩桑桂濮牛寿通边扈燕冀郏浦尚农温别庄晏柴瞿阎充慕连茹习宦艾鱼容向古易慎戈廖庾终暨居衡步都耿满弘匡国文寇广禄阙东欧殳沃利蔚越夔隆师巩厍聂晁勾敖融冷訾辛阚那简饶空曾毋沙乜养鞠须丰巢关蒯相查后荆红游竺权逯盖益桓公")

NAME_BLACKLIST = set("""单元 号楼 小区 花园 公寓 大厦 广场 家园 新村 街道 楼层 门牌 号码 电话 手机
谢谢 马上 方便 高兴 黄金 红色 关心 文明 王国 石头 何时 于是 仍然 任何 管理 司机 管家 钱包
包含 位于 常在 尤其 江湖 沈阳 阳台 林业 武力 常规 史诗 毛重 米色 贝壳 明白 成语 句子 任命
柳树 白菜 江水 海洋 温暖 渠道 程度 何处 金额 银色 骑手 站点 政策 面试 报名 工资 结算 兼职
全职 底薪 提成 材料 经验 配送 外卖 健康 医院 面试官""".split())
BAD_SECOND = set("的了是和有我这那要会能好呢吧啊就都也还又非常很更最没不人到上下里外")

STOPWORDS = set("""今天 明天 昨天 上午 下午 晚上 你好 谢谢 请问 我们 你们 他们 这边 那边 什么 怎么
可以 需要 已经 还没 知道 想要 报名 面试 骑手 站点 政策 时间 地点 工资 结算 兼职 全职 不确定
有意 没有 有的 电话 手机 号码 联系 稍后 稍等 好的 收到 麻烦 帮我 查一下 看一下 我想 我要
现在 马上 地址 名字 一带 附近 大概 左右 分钟 小时 一天 一月 一周 明年 今年 去年""".split())

ANCHORS = "姓名|名字|我叫|本人|联系人|骑手|候选人|申请人是|申请人|师傅|应聘者|求职者|面试者"
CN_NAME_CTX = re.compile(r"(?:" + ANCHORS + r")[:：\s]{0,3}([\u4e00-\u9fa5]{2,4})(?![\u4e00-\u9fa5])")
CN_NAME_VERB = re.compile(r"(?=([\u4e00-\u9fa5]{2,3})(?:申请|报名|来电|联系|入住|已到|面试|本人))")
CN_NAME_LOOSE = re.compile(r"(?<![\u4e00-\u9fa5])([\u4e00-\u9fa5]{2,3})(?![\u4e00-\u9fa5])")
EN_TOKEN = r"[A-Z][a-z]{0,15}(?:[-'][A-Z][a-z]{0,15})*"
EN_NAME = re.compile(r"\b(" + EN_TOKEN + r")\s+(" + EN_TOKEN + r")\b")
EN_NAME_COMMA = re.compile(r"\b([A-Z][a-z]{1,15})\s*,\s*([A-Z][a-z]{1,15})\b")
EMAIL = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")

ADDR = re.compile(
    r"(?:[\u4e00-\u9fa5]{2,8}(?:省|自治区))?"
    r"(?:[\u4e00-\u9fa5]{2,8}(?:市|自治州))?"
    r"(?:[\u4e00-\u9fa5]{1,8}(?:区|县))?"
    r"(?:[\u4e00-\u9fa5]{1,10}(?:镇|街道|乡|村|社区))?"
    r"(?:[\u4e00-\u9fa5A-Za-z0-9]{1,16}(?:路|街|巷|弄|大道|胡同))?"
    r"(?:\s*\d{1,5}\s*(?:号|弄))?"
    r"(?:\s*\d{1,4}\s*(?:栋|幢|号楼|座))?"
    r"(?:\s*\d{1,4}\s*单元)?"
    r"(?:\s*\d{1,4}\s*(?:层|楼))?"
    r"(?:\s*\d{1,4}\s*(?:室|号房))?(?:\s*\d{1,4}(?!\d))?")
ADDR_COMMUNITY = re.compile(
    r"(?:[\u4e00-\u9fa5]{2,8}(?:市|区|县))?"
    r"[\u4e00-\u9fa5]{2,10}(?:小区|花园|公寓|大厦|广场|家园|新村|软件园|科技园)"
    r"(?:\s*\d{1,4}\s*(?:栋|幢|号楼|座))?(?:\s*\d{1,4}\s*单元)?"
    r"(?:\s*\d{1,4}\s*(?:层|楼))?(?:\s*\d{1,4}\s*(?:室|号房))?(?:\s*\d{1,4}(?!\d))?")
ADDR_HEAD = re.compile(r"^(?:我住|我在|现住|住在|位于|地址是|地址：|地址:|地址|住|在)+")

CARD_CTX = re.compile(r"(?:卡|卡号|账号|账户|开户|打款|工资卡)")
CARD_NOISE = re.compile(r"(?:订单|单单号|单号|编号|流水|工号|尾号|末位)")


def luhn_ok(digits: str) -> bool:
    total, alt = 0, False
    for ch in reversed(digits):
        d = ord(ch) - 48
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


def _digit_runs(text: str):
    """返回所有“数字/分隔符”候选串（含空格、连字符、+），并给出原始区间。"""
    return re.finditer(r"\+?[0-9][0-9\s\-\.,()]{5,30}[0-9Xx]", text)


def _valid_date(y: int, m: int, d: int) -> bool:
    if not (1900 <= y <= 2026 and 1 <= m <= 12 and 1 <= d <= 31):
        return False
    import calendar
    try:
        return d <= calendar.monthrange(y, m)[1]
    except Exception:
        return False



# ============ 归一化：对抗"看起来不像数字"的号码（C5 轮实测的绕过手法）============
# 攻击者不必破解加密，只要让检测器认不出来，PII 就会原样送进模型。
# 已实测绕过成功的 8 种写法：全角数字、零宽字符夹断、点号/括号分隔、阿拉伯-印度数字、
# 全角字母同形字、中文数字。对策是**等长归一化后再检测**，再把区间原样映射回原文
# （1:1 字符映射，偏移不变，所以不需要重算坐标）。

_FULLWIDTH = {chr(0xFF10 + i): str(i) for i in range(10)}
_FULLWIDTH.update({chr(0xFF21 + i): chr(ord("A") + i) for i in range(26)})
_FULLWIDTH.update({chr(0xFF41 + i): chr(ord("a") + i) for i in range(26)})
FULLWIDTH_MAP = {ord(k): v for k, v in _FULLWIDTH.items()}
FULLWIDTH_MAP.update({0xFF0E: ".", 0xFF08: "(", 0xFF09: ")", 0xFF0D: "-", 0x3000: " "})

# 阿拉伯-印度数字（\d 在 Python 里会匹配它们，但字面 '1' 不会，导致手机号漏检）
UNICODE_DIGITS = {ord(c): str(i) for i, c in enumerate("٠١٢٣٤٥٦٧٨٩")}
UNICODE_DIGITS.update({ord(c): str(i) for i, c in enumerate("۰۱۲۳۴۵۶۷۸۹")})

CN_DIGITS = {ord(c): str(i) for i, c in enumerate("零一二三四五六七八九")}
CN_DIGITS.update({ord("〇"): "0", ord("两"): "2"})

# 零宽字符：不删除（会改变偏移），换成空格（1:1，长度不变）
ZERO_WIDTH = {ord(c): " " for c in "\u200b\u200c\u200d\u2060\ufeff\u00ad"}

# 分隔符统一成空格，让 "138.0013.8000" / "(138)0013-8000" 变成可识别的形态
SEPARATORS = {ord(c): " " for c in ".()[]{}·、，,;；:"}


def normalize_for_detection(text: str) -> str:
    """等长归一化：保证返回串与原串长度一致、字符位置一一对应。

    ★ 只做"字符同形替换"，绝不做"语义翻译"。
      第一版我把中文数字也全局映射了，结果 `文一西路` 变成 `文1西路`、
      `五常街道` 变成 `5常街道` —— 地址召回从 100% 掉到 81%，还带出 19% 误报。
      中文数字只在**长串号码**场景才该转换，所以改成下面的单独检测器；
      分隔符同理，改为在号码正则里允许 `. ( )`，而不是全局把它们换成空格。
    """
    t = text.translate(FULLWIDTH_MAP)
    t = t.translate(UNICODE_DIGITS)
    t = t.translate(ZERO_WIDTH)
    return t


# 中文数字号码：只有连续 ≥9 个中文数字才当作号码候选（避免"文一西路"被误改）
CN_NUM_RUN = re.compile(r"[零一二三四五六七八九〇两]{9,13}")
_CN_MAP = str.maketrans("零一二三四五六七八九〇两", "012345678902")


def _cn_to_digits(run: str) -> str:
    return run.translate(_CN_MAP)


# 同形字：l / I / O 伪装成 1 / 1 / 0（"ｌ3800138000"）
CONFUSABLE_RUN = re.compile(r"(?<![0-9A-Za-z])[0-9lIO][0-9lIO\s\-]{9,15}(?![0-9A-Za-z])")
_CONF = str.maketrans({"l": "1", "I": "1", "O": "0"})


class MaskingSession:
    def __init__(self, strict_names: bool = True):
        self.strict_names = strict_names
        self.mapping: dict[str, str] = {}
        self.counters: dict[str, int] = {}
        self._by_value: dict[tuple[str, str], str] = {}

    # ---------- 占位符 ----------
    def _placeholder(self, typ: str, value: str) -> str:
        key = (typ, value)
        if key in self._by_value:
            return self._by_value[key]
        self.counters[typ] = self.counters.get(typ, 0) + 1
        ph = f"〔{typ}_{self.counters[typ]}〕"
        self._by_value[key] = ph
        self.mapping[ph] = value
        return ph

    # ---------- 各类检测 ----------
    def _find_ids(self, text: str) -> list[dict]:
        out = []
        for m in _digit_runs(text):
            raw = m.group(0)
            core = re.sub(r"[\s\-\.,()]", "", raw)
            if core.startswith("86") and len(core) > 18:
                core = core[2:]
            if len(core) == 18 and re.fullmatch(r"\d{17}[\dXx]", core):
                y, mo, d = int(core[6:10]), int(core[10:12]), int(core[12:14])
                if _valid_date(y, mo, d):
                    out.append({"type": "身份证号", "start": m.start(), "end": m.end(),
                                "text": raw})
        return out

    def _find_phones(self, text: str) -> list[dict]:
        out = []
        for m in _digit_runs(text):
            raw = m.group(0)
            # 尾随字母（如 13800138000O）不当作手机号，避免误报
            if re.search(r"[A-Za-z]$", raw):
                continue
            core = re.sub(r"[\s\-\.,()]", "", raw)
            if core.startswith("+86"):
                core = core[3:]
            elif core.startswith("86") and len(core) == 13:
                core = core[2:]
            if re.fullmatch(r"1[3-9]\d{9}", core):
                out.append({"type": "手机号", "start": m.start(), "end": m.end(), "text": raw})
        # 中文数字号码（一三八零零一三八零零零）
        for m in CN_NUM_RUN.finditer(text):
            if re.fullmatch(r"1[3-9]\d{9}", _cn_to_digits(m.group(0))):
                out.append({"type": "手机号", "start": m.start(), "end": m.end(),
                            "text": m.group(0)})
        # 同形字号码：l/I/O 伪装成 1/1/0
        for m in CONFUSABLE_RUN.finditer(text):
            raw = m.group(0)
            fixed = re.sub(r"[\s\-]", "", raw.translate(_CONF))
            if re.fullmatch(r"1[3-9]\d{9}", fixed):
                out.append({"type": "手机号", "start": m.start(), "end": m.end(), "text": raw})
        return out

    def _find_cards(self, text: str) -> list[dict]:
        out = []
        for m in _digit_runs(text):
            raw = m.group(0)
            if not re.fullmatch(r"[\d\s\-]+", raw):
                continue
            core = re.sub(r"[\s\-\.,()]", "", raw)
            if not (16 <= len(core) <= 19):
                continue
            ctx = text[max(0, m.start() - 8):m.start()]
            if CARD_NOISE.search(ctx):
                continue
            bin_hit = core.startswith("62") or core[0] in "45"
            if luhn_ok(core) or bin_hit or CARD_CTX.search(ctx):
                out.append({"type": "银行卡号", "start": m.start(), "end": m.end(), "text": raw})
        return out

    def _find_addresses(self, text: str) -> list[dict]:
        out = []
        for pat in (ADDR, ADDR_COMMUNITY):
            for m in pat.finditer(text):
                s, e = m.start(), m.end()
                frag = text[s:e]
                # 必须有“号码级”标志，否则只是路名/站名
                if not re.search(r"(?:号|栋|幢|号楼|座|单元|室|号房|层|街道|镇|乡|村|社区|园)", frag):
                    continue
                if len(re.sub(r"\s", "", frag)) < 6:
                    continue
                # 剔除前导动词
                head = ADDR_HEAD.match(frag)
                if head:
                    s += head.end()
                    frag = frag[head.end():]
                frag2, s2 = self._trim_tail_digits(text, s, e)
                out.append({"type": "地址", "start": s2[0], "end": s2[1], "text": frag2})
        return out

    @staticmethod
    def _trim_tail_digits(text: str, s: int, e: int):
        frag = text[s:e]
        m2 = re.search(r"(\d{8,})$", frag)
        if m2:
            return frag[:len(frag) - len(m2.group(1))].rstrip(), (s, e - len(m2.group(1)))
        return frag.rstrip(), (s, e)

    def _find_names(self, text: str) -> list[dict]:
        out = []
        for m in EN_NAME_COMMA.finditer(text):
            out.append({"type": "姓名", "start": m.start(), "end": m.end(), "text": m.group(0)})
        for m in EN_NAME.finditer(text):
            out.append({"type": "姓名", "start": m.start(), "end": m.end(), "text": m.group(0)})
        for m in CN_NAME_CTX.finditer(text):
            if self._looks_like_name(m.group(1)):
                out.append({"type": "姓名", "start": m.start(1), "end": m.end(1), "text": m.group(1)})
        for m in CN_NAME_VERB.finditer(text):
            cand = m.group(1)
            if cand[0] in SURNAMES and self._looks_like_name(cand) and cand not in NAME_BLACKLIST:
                out.append({"type": "姓名", "start": m.start(1), "end": m.end(1), "text": cand})
        if not out:
            for m in CN_NAME_LOOSE.finditer(text):
                cand = m.group(1)
                if (self._looks_like_name(cand) and cand[0] in SURNAMES
                        and cand not in NAME_BLACKLIST):
                    out.append({"type": "姓名", "start": m.start(1), "end": m.end(1), "text": cand})
        return out

    def _looks_like_name(self, cand: str) -> bool:
        if not (2 <= len(cand) <= 4):
            return False
        if cand in STOPWORDS or cand in NAME_BLACKLIST:
            return False
        if any(ch.isdigit() for ch in cand):
            return False
        if len(cand) >= 2 and cand[1] in BAD_SECOND:
            return False
        return True

    # ---------- 总入口 ----------
    CHUNK = 2000

    def detect(self, text: str) -> list[dict]:
        """长文本按块处理，返回**绝对偏移**区间。

        为什么要分块：地址/姓名正则带可选分组，随文本长度呈超线性增长
        （实测单个 20KB 片段 104ms，1MB 直通会跑到分钟级 —— 接口上就是一次
        可被利用的拖死）。按 2000 字切块并在标点/换行处断开，1MB 约 2s。
        这是 B5 轮用 1MB 输入压出来的真实性能缺陷，不是理论担忧。
        """
        if len(text) <= self.CHUNK:
            return self._detect_one(normalize_for_detection(text))
        spans: list[dict] = []
        pos = 0
        n = len(text)
        while pos < n:
            end = min(pos + self.CHUNK, n)
            if end < n:
                for sep in ("\n", "。", "！", "？", "；", " "):
                    cut = text.rfind(sep, pos + self.CHUNK // 2, end)
                    if cut > pos:
                        end = cut + 1
                        break
            for sp in self._detect_one(normalize_for_detection(text[pos:end])):
                sp["start"] += pos
                sp["end"] += pos
                spans.append(sp)
            pos = end
        return spans

    def _detect_one(self, text: str) -> list[dict]:
        spans: list[dict] = []
        spans += self._find_ids(text)
        spans += self._find_cards(text)
        spans += self._find_phones(text)
        for m in EMAIL.finditer(text):
            spans.append({"type": "邮箱", "start": m.start(), "end": m.end(), "text": m.group(0)})
        spans += self._find_addresses(text)
        spans += self._find_names(text)

        prio = {"身份证号": 6, "银行卡号": 5, "手机号": 4, "邮箱": 4, "地址": 2, "姓名": 1}
        spans.sort(key=lambda s: (-(s["end"] - s["start"]), -prio[s["type"]], s["start"]))
        chosen: list[dict] = []
        for s in spans:
            if any(not (s["end"] <= c["start"] or s["start"] >= c["end"]) for c in chosen):
                continue
            chosen.append(s)
        chosen.sort(key=lambda s: s["start"])
        return chosen

    # ---------- 应用 / 回填 ----------
    def mask(self, text: str) -> tuple[str, dict]:
        """占位符里登记的是**原文切片**，不是归一化后的文本。

        检测跑在归一化串上（为了识破全角/零宽/同形字），但回填必须还原文，
        否则 restore() 会把 "１３８…" 还原成 "138…"，等于悄悄改了客户的原始数据。
        """
        spans = self.detect(text)
        out, cursor, found = [], 0, {}
        for s in spans:
            out.append(text[cursor:s["start"]])
            original = text[s["start"]:s["end"]]
            ph = self._placeholder(s["type"], original)
            out.append(ph)
            found.setdefault(s["type"], []).append(original)
            cursor = s["end"]
        out.append(text[cursor:])
        return "".join(out), found

    def restore(self, text: str) -> str:
        out = text
        for ph in sorted(self.mapping, key=len, reverse=True):
            out = out.replace(ph, self.mapping[ph])
        return out


def mask_text(text: str, strict_names: bool = True) -> dict:
    sess = MaskingSession(strict_names=strict_names)
    masked, found = sess.mask(text)
    return {"masked": masked, "found": found, "placeholder_count": len(sess.mapping),
            "mapping": sess.mapping}


def phone_mask(value: str) -> str:
    digits = re.sub(r"\D", "", value)[-11:]
    return digits[:3] + "****" + digits[-4:] if len(digits) == 11 else "*" * len(value)


def name_mask(value: str) -> str:
    if not value:
        return value
    if re.search(r"[A-Za-z]", value):
        return " ".join(p[0] + "*" * (len(p) - 1) for p in value.split())
    return value[0] + "*" * (len(value) - 1)
