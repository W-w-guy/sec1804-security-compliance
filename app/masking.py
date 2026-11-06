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

# 复姓（两字姓）。★ 2026-11-06 补：独立探针集里「收货人：欧阳修文」整条漏检。
# 单姓表里只有「欧」；LOOSE 正则按 2~3 字切分时「欧阳修」右侧紧跟「文」（仍是汉字）→ 右边界不成立，
# 而「阳修文」左侧不成立，两头落空。复姓必须按 3~4 字单独匹配。
COMPOUND_SURNAMES = set("""欧阳 太史 端木 上官 司马 东方 独孤 南宫 万俟 闻人 夏侯 诸葛 尉迟 公羊 赫连 澹台
公冶 宗政 濮阳 淳于 单于 太叔 申屠 公孙 仲孙 轩辕 令狐 钟离 宇文 长孙 慕容 鲜于 司空 闾丘
子车 亓官 司寇 巫马 公西 颛孙 壤驷 公良 漆雕 乐正 宰父 谷梁 拓跋 夹谷 段干 百里 东郭 南门
呼延 羊舌 微生 梁丘 左丘 东门 西门 第五 皇甫 司徒""".split())

NAME_BLACKLIST = set("""单元 号楼 小区 花园 公寓 大厦 广场 家园 新村 街道 楼层 门牌 号码 电话 手机
谢谢 马上 方便 高兴 黄金 红色 关心 文明 王国 石头 何时 于是 仍然 任何 管理 司机 管家 钱包
包含 位于 常在 尤其 江湖 沈阳 阳台 林业 武力 常规 史诗 毛重 米色 贝壳 明白 成语 句子 任命
柳树 白菜 江水 海洋 温暖 渠道 程度 何处 金额 银色 骑手 站点 政策 面试 报名 工资 结算 兼职
车牌 车号 车型 驾龄 年龄 性别 籍贯 民族 学历 婚姻 身高 体重 时段 区域 城市 部门 岗位 班次 待遇
单价 总价 金额 数量 件数 单价 高中 初中 小学 大学 本科 硕士 博士 大专 职高 技校 中专
今天 明天 昨天 下周 上周 本周 下月 上月 本月 明年 去年 今年 这周 那周 再见 联系 稍后
全职 底薪 提成 材料 经验 配送 外卖 健康 医院 面试官""".split())
BAD_SECOND = set("的了是和有我这那要会能好呢吧啊就都也还又非常很更最没不人到上下里外")

STOPWORDS = set("""今天 明天 昨天 上午 下午 晚上 你好 谢谢 请问 我们 你们 他们 这边 那边 什么 怎么
可以 需要 已经 还没 知道 想要 报名 面试 骑手 站点 政策 时间 地点 工资 结算 兼职 全职 不确定
有意 没有 有的 电话 手机 号码 联系 稍后 稍等 好的 收到 麻烦 帮我 查一下 看一下 我想 我要
现在 马上 地址 名字 一带 附近 大概 左右 分钟 小时 一天 一月 一周 明年 今年 去年""".split())

ANCHORS = "姓名|名字|我叫|本人|联系人|骑手|候选人|申请人是|申请人|师傅|应聘者|求职者|面试者"
_VERB_ALT = "申请|报名|来电|联系|入住|已到|面试|本人|咨询"
# 尾部边界：后面不是汉字，**或者**后面紧跟动作词（"我叫欧阳修文报名" 的"报名"就是边界）。
# ★ 2026-11-06：只写 (?!汉字) 会让"我叫欧阳修文报名"整条漏检 —— 4 字上限 + 后面还有汉字。
CN_NAME_CTX = re.compile(r"(?:" + ANCHORS + r")[:：\s]{0,3}([\u4e00-\u9fa5]{2,4})"
                         # 逻辑：后面"不是汉字" **或** "紧跟动作词"，两者满足其一即算边界。
                         # 写成 (?!汉字|(?=动词)) 是反的 —— 实测那样连"欧阳修文报名"都不匹配。
                         r"(?:(?![\u4e00-\u9fa5])|(?=(?:" + _VERB_ALT + r")))")
CN_NAME_VERB = re.compile(r"(?=([\u4e00-\u9fa5]{2,3})(?:申请|报名|来电|联系|入住|已到|面试|本人))")
CN_NAME_LOOSE = re.compile(r"(?<![\u4e00-\u9fa5])([\u4e00-\u9fa5]{2,3})(?![\u4e00-\u9fa5])")
# 复姓姓名：3~4 字（欧阳修文 / 司马光 / 上官婉儿）。单姓正则按 2~3 字切分，
# 遇到复姓+双名会因左右边界同时不成立而整条漏掉，所以必须单独一条。
CN_NAME_COMPOUND = re.compile(
    r"(?<![\u4e00-\u9fa5])(" + "|".join(sorted(COMPOUND_SURNAMES, key=len, reverse=True)) +
    r")[\u4e00-\u9fa5]{1,2}(?![\u4e00-\u9fa5])")
EN_TOKEN = r"[A-Z][a-z]{0,15}(?:[-'][A-Z][a-z]{0,15})*"
# 非 ASCII 拉丁字母（土耳其/北欧/西欧）：Ayşe Yılmaz、Müller、Ødegaard
# ★ 只写 À-ÿ（Latin-1 Supplement）不够：土耳其语 ı(U+0131)/ş(U+015F)/ğ(U+011F)
#   和 İ(U+0130) 都在 Latin Extended-A 里，第一版实测「Ayşe Yılmaz」仍然漏检。
EN_TOKEN_U = r"[A-Z\u00C0-\u024F][A-Za-z\u00C0-\u024F'’-]{1,15}"
EN_NAME_U = re.compile(r"\b(" + EN_TOKEN_U + r")\s+(" + EN_TOKEN_U + r")\b")
EN_NAME = re.compile(r"\b(" + EN_TOKEN + r")\s+(" + EN_TOKEN + r")\b")
# 民族姓名用间隔号连接：买买提·艾力 / 阿依古丽·买买提（单姓正则只会抓到后半截）
CN_NAME_DOT = re.compile(r"[\u4e00-\u9fa5]{2,6}[·•·][\u4e00-\u9fa5]{2,6}")
EN_NAME_COMMA = re.compile(r"\b([A-Z][a-z]{1,15})\s*,\s*([A-Z][a-z]{1,15})\b")
EMAIL = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")

ADDR = re.compile(
    r"(?:[\u4e00-\u9fa5]{2,8}(?:省|自治区))?"
    r"(?:[\u4e00-\u9fa5]{2,8}(?:市|自治州))?"
    r"(?:[\u4e00-\u9fa5]{1,8}(?:区|县))?"
    r"(?:[\u4e00-\u9fa5]{1,10}(?:镇|街道|乡|村|社区))?"
    r"(?:[\u4e00-\u9fa5A-Za-z0-9]{1,16}(?:路|街|巷|弄|大道|胡同))?"
    r"(?:\s*\d(?:\s*\d){0,5}\s*(?:号|弄))?"
    r"(?:\s*\d{1,4}\s*(?:栋|幢|号楼|座))?"
    r"(?:\s*\d{1,4}\s*单元)?"
    r"(?:\s*\d{1,4}\s*(?:层|楼))?"
    r"(?:\s*\d{1,4}\s*(?:室|号房))?(?:\s*\d{1,4}(?!\d))?")
ADDR_COMMUNITY = re.compile(
    r"(?:[\u4e00-\u9fa5]{2,8}(?:省|自治区))?"
    r"(?:[\u4e00-\u9fa5]{2,8}(?:市|自治州))?"
    r"(?:[\u4e00-\u9fa5]{1,8}(?:区|县))?"
    r"[\u4e00-\u9fa5A-Za-z]{2,10}(?:小区|花园|公寓|大厦|广场|家园|新村|软件园|科技园"
    r"|SOHO|soho|中心|产业园|工业园|创业园|商务楼|写字楼|园区|商城|大厦)"
    r"(?:\s*[A-Za-z]?\s*\d{1,4}\s*(?:栋|幢|号楼|座|楼))?(?:\s*\d{1,4}\s*单元)?"
    r"(?:\s*\d(?:\s*\d){0,3}\s*(?:层|楼))?(?:\s*\d(?:\s*\d){0,3}\s*(?:室|号房))?"
    # ★ 2026-11-06：楼栋码 + 房号可能连续出现两次（"T1 2201"），只留一组会把 2201 漏在明文里
    r"(?:\s*[A-Za-z]?\s*\d(?:\s*\d){0,3}(?!\d)){0,2}")
# 地址尾部续接：楼宇名 + 门牌（"…张江路100号汤臣一品8栋" / "…建国路88号SOHO现代城A座1201"）。
# ★ 2026-11-06 补：主地址正则只认"路名+门牌"那一段，后面的楼宇名+房号会被漏在明文里。
#   这条只在"紧跟地址、且后面确实带数字门牌"时才生效，避免把普通句子吞进地址。
ADDR_TAIL = re.compile(
    r"^\s*(?:[\u4e00-\u9fa5A-Za-z]{2,10})"
    r"(?:广场|城|苑|府|湾|里|中心|大厦|小区|花园|公寓|园区|新村|现代城)?"
    r"\s*[A-Za-z]?\s*\d(?:\s*\d){0,4}\s*(?:室|栋|幢|座|号楼|单元|层|楼)?")
ADDR_HEAD = re.compile(r"^(?:我住|我在|现住|住在|位于|地址是|地址：|地址:|地址|住|在)+")

CARD_CTX = re.compile(r"(?:卡|卡号|账号|账户|开户|打款|工资卡)")
# 15 位身份证必须带证件语境，否则 15 位流水号会被吞（宁可少报，不可把订单号报成身份证）
ID_CTX = re.compile(r"(?:身份证|证件|身份|证号|ID|id|老身份证)")
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
            # ★ 2026-11-06 补：15 位旧号（1999 年前签发）此前完全不认。
            #   验收点 2 写的是「身份证号召回率 100%」，而我们的语料只有 18 位，
            #   独立探针集里「老身份证 320311770706002」整条漏检 —— 这就是「在自造语料上 100%」。
            #   15 位必须以证件语境为前置（否则 15 位流水号/订单号会一起被吞），
            #   且地区码、出生日期都要能过校验。
            if len(core) == 15 and re.fullmatch(r"\d{15}", core):
                if ID_CTX.search(text[max(0, m.start() - 8):m.start()]):
                    area = int(core[:6]) if core[:6].isdigit() else 0
                    yy = int("19" + core[6:8])
                    if 110000 <= area <= 659000 and _valid_date(yy, int(core[8:10]), int(core[10:12])):
                        out.append({"type": "身份证号", "start": m.start(), "end": m.end(),
                                    "text": raw})
                continue
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
                # 必须有"号码级"标志，否则只是路名/站名。
                # ★ 2026-11-06 补两类：拉丁楼栋码（T1 / A座 / B2）——独立探针集里
                #   「北京市朝阳区望京SOHO T1 2201」整条漏检，就是因为标志只认中文的 号/栋/座；
                #   以及「区+路」这种无门牌但已到街道级的写法（广州天河区体育西路）。
                has_num = re.search(r"(?:号|栋|幢|号楼|座|单元|室|号房|层|街道|镇|乡|村|社区|园"
                                    r"|[A-Za-z]\s?\d{1,4})", frag)
                has_district = re.search(r"(?:市|区|县)", frag) and re.search(
                    r"(?:路|街|巷|弄|大道|胡同)", frag)
                if not (has_num or has_district):
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
        # 先续接"楼宇名+门牌"，再合并相邻片段（顺序不能反：续接要基于原始匹配区间）
        for sp in out:
            m2 = ADDR_TAIL.match(text[sp["end"]:])
            if m2:
                sp["end"] += m2.end()
                sp["text"] = text[sp["start"]:sp["end"]]
        return self._merge_adjacent(text, out)

    @staticmethod
    def _merge_adjacent(text: str, spans: list[dict]) -> list[dict]:
        """把相邻/重叠的同类片段合并成一段。

        ★ 2026-11-06 补（第 4 号缺陷的同类）：一次"掩码后再扫一遍"的对抗检查抓到这个：
            「我住西湖区文三路90号东部软件园3号楼」
          → 掩成「我住〔地址_1〕东部软件园3号楼」，后半截楼宇名+楼号完好留在明文里。
          两个正则（路名式 ADDR / 楼宇式 ADDR_COMMUNITY）各自只认自己那半，谁也不覆盖对方。
          **半截掩码比完全不掩更危险**：审阅者看到有〔地址_1〕就以为这行已经处理过了。
          对策：同类片段只要区间相邻（中间不隔字符）或重叠，就并成一段再整体掩掉。
        """
        if not spans:
            return spans
        spans = sorted(spans, key=lambda s: (s["start"], -s["end"]))
        merged: list[dict] = []
        for sp in spans:
            if merged and sp["start"] <= merged[-1]["end"]:
                last = merged[-1]
                if sp["end"] > last["end"]:
                    last["end"] = sp["end"]
                    last["text"] = text[last["start"]:last["end"]]
            else:
                merged.append(dict(sp))
        return merged

    @staticmethod
    def _trim_tail_digits(text: str, s: int, e: int):
        frag = text[s:e]
        m2 = re.search(r"(\d{8,})$", frag)
        if m2:
            return frag[:len(frag) - len(m2.group(1))].rstrip(), (s, e - len(m2.group(1)))
        return frag.rstrip(), (s, e)

    def _find_names(self, text: str) -> list[dict]:
        out = []
        for m in CN_NAME_DOT.finditer(text):
            out.append({"type": "姓名", "start": m.start(), "end": m.end(), "text": m.group(0)})
        for m in EN_NAME_COMMA.finditer(text):
            out.append({"type": "姓名", "start": m.start(), "end": m.end(), "text": m.group(0)})
        for m in EN_NAME.finditer(text):
            out.append({"type": "姓名", "start": m.start(), "end": m.end(), "text": m.group(0)})
        for m in EN_NAME_U.finditer(text):      # 非 ASCII 拉丁名（Ayşe Yılmaz）
            if m.group(0) not in [o["text"] for o in out]:
                out.append({"type": "姓名", "start": m.start(), "end": m.end(),
                            "text": m.group(0)})
        for m in CN_NAME_CTX.finditer(text):
            cand = self._strip_verb(m.group(1))
            if self._looks_like_name(cand):
                out.append({"type": "姓名", "start": m.start(1), "end": m.start(1) + len(cand),
                            "text": cand})
        for m in CN_NAME_VERB.finditer(text):
            cand = m.group(1)
            # ★ "下周再联系" 曾被切成「周再联系」→ 抓出人名「周再」。
            #   候选首字若紧跟在 下/上/本/这/那/明/去/今 之后，是时间词的一部分，不是姓名。
            # ★ 这条 lookahead 正则在同一段文字上会产生多个重叠候选：
            #     "王小明申请报名" → 王小明(0,3)/小明(1,3)/明申请(2,5)/申请(3,5)，
            #   而重叠消解会保留靠右的那个，于是最终抓出人名「明申请」。
            #   修法：候选首字之前只能是 句首 / 非汉字 / 姓名锚点字，否则判为切分噪声。
            #   这样 "王小明申请"(句首 ✓)、"我叫张伟报名"(前面是"叫" ✓) 都能抓，
            #   而 "下周再联系"(前面是"下") 被挡掉。
            prev = text[m.start(1) - 1] if m.start(1) > 0 else ""
            if prev and "\u4e00" <= prev <= "\u9fa5" and prev not in "叫是为：:的，,、 ":
                continue
            if cand[0] in SURNAMES and self._looks_like_name(cand) and cand not in NAME_BLACKLIST:
                out.append({"type": "姓名", "start": m.start(1), "end": m.end(1), "text": cand})
        # 复姓优先于单姓；只有当整串里没抓到别的姓名时才走宽松匹配（避免乱认）
        if not out:
            for m in CN_NAME_COMPOUND.finditer(text):
                cand = m.group(0)
                if cand not in NAME_BLACKLIST and cand not in STOPWORDS:
                    out.append({"type": "姓名", "start": m.start(), "end": m.end(), "text": cand})
        if not out:
            for m in CN_NAME_LOOSE.finditer(text):
                cand = m.group(1)
                if (self._looks_like_name(cand) and cand[0] in SURNAMES
                        and cand not in NAME_BLACKLIST):
                    out.append({"type": "姓名", "start": m.start(1), "end": m.end(1), "text": cand})
        return out

    # 姓名尾部粘上的动作词：正则允许 2~4 字，会把"张伟报名"整段当成名字。
    # ★ 2026-11-06 由独立探针语料抓到（"我叫张伟报名" → 人名「张伟报名」）。
    _VERB_TAIL = ("申请", "报名", "来电", "联系", "入住", "已到", "面试", "本人", "咨询")

    @classmethod
    def _strip_verb(cls, cand: str) -> str:
        for v in cls._VERB_TAIL:
            if cand.endswith(v) and len(cand) - len(v) >= 2:
                return cand[:-len(v)]
        return cand

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
