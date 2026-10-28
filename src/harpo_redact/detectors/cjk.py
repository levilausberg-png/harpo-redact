"""Layer 2h: names and addresses in Chinese, Japanese and Korean, by the structure the scripts give them.

Words are not set off by blanks in Chinese and Japanese, and a Korean address is a chain of units, so these are read
by their units and the words around them rather than by capital letters:

* Chinese: the administrative hierarchy (省, 市, 区, 县, 镇, 乡, 街道), roads (路, 街, 大道, 巷, 胡同) with their
  numbers, a road named after a word that says "located at" (位于, 地址是), and names led by a family name, single
  or compound (王, 李, 欧阳, 东方), after a title (尊敬的, Mr., 先生 after), a verb that takes a person (由...签署,
  致电, 联系) or written apart with blanks as transliterated text has them ("海城 徐 雍").
* Japanese: the 47 prefectures (都, 道, 府, 県), a municipality chain (市, 区, 町, 村, 郡), the block numbers of an
  address (3丁目4番5号, 3-11-30番地), a value labelled after itself ("323-0816（郵便番号）"), and names before an
  honorific (さん, 様, 君, 氏), after a closing (敬具) or led by one of the common family names (佐藤, 鈴木...).
* Korean: the 17 provinces and metropolitan cities, a city, district and neighbourhood chain (시, 구, 동, 읍, 면),
  road-name addresses (도로명주소: a road ending in 로 or 길, then its building number), lot numbers (번지), and
  names before an honorific (님, 씨) or after a title (군, 양), checked against the common family names (김, 이,
  박, 최, 정...).

A unit word alone is never enough where it is also an everyday word (超市 is a supermarket, 친구 a friend): such
units need two characters of name before them, a list of the everyday words, or a chain or a number around them.
Every pattern is bounded, so a scan is linear in the length of the text.
"""

from __future__ import annotations

import re
from collections.abc import Iterator

from ..entities import EntityType as E
from ..entities import Span, make_span

SOURCE = "cjk"

_HAN = "一-鿿"
_HIRA = "ぁ-ゖ"
_KATA = "゠-ヿ"
_HANGUL = "가-힯"
_LATIN_NAME = r"[A-Z][a-zà-ÿ]+(?:[\-'][A-Z]?[a-zà-ÿ]+)?"


def _span(start: int, end: int, text: str, etype: E, kind: str) -> Span:
    return make_span(start, end, etype, f"{SOURCE}:{kind}", " ".join(text[start:end].split()), 0.75)


# =========================================================================== Chinese
_ZH_SINGLE = (
    "王李张張刘劉陈陳杨楊黄黃赵趙吴吳周徐孙孫马馬朱胡郭何林罗羅高郑鄭梁谢謝宋唐许許韩韓冯馮邓鄧曹彭曾肖萧蕭田董潘袁蔡蒋蔣余于杜叶葉"
    "程魏苏蘇吕呂丁任卢盧姚沈钟鍾姜崔谭譚陆陸范汪廖石金韦韋贾賈夏付方邹鄒熊白孟秦邱侯江尹薛闫閆段雷龙龍黎史陶贺賀毛郝顾顧龚龔邵"
    "万萬覃武钱錢戴严嚴莫孔向常汤湯康易乔喬赖賴文施洪辛柯庄莊詹褚来來郁雍蓝藍谷翟甘牛欧歐耿关關殷齐齊尚俞葛祝阎閻包岳伍裴纪紀"
    "倪池路左焦鲁魯晏柴季巫童邢凌颜顏邬鄔卜单單米霍申宁寧柳涂司"
)
_ZH_COMPOUND = (
    "欧阳 歐陽 司马 司馬 上官 诸葛 諸葛 东方 東方 皇甫 尉迟 尉遲 公孙 公孫 慕容 长孙 長孫 宇文 司徒 夏侯 轩辕 軒轅 令狐 钟离 鍾離"  # noqa: SIM905
    " 西门 西門 南宫 南宮 独孤 獨孤 端木 澹台 公冶 申屠 闻人 聞人 东郭 東郭 濮阳 濮陽 呼延 百里 万俟 萬俟".split()
)
_ZH_SURNAME = rf"(?:{'|'.join(_ZH_COMPOUND)}|[{_ZH_SINGLE}])"
# Where a Chinese place or name can start: after anything that is not Han, or after a word that comes before one.
_ZH_BEFORE = "在于於到从從自的和与與及是为為往向住至经經由将將把赴回去来來离離近对對给給请請位"
_ZH_START = rf"(?:(?<![{_HAN}])|(?<=[{_ZH_BEFORE}]))"
_ZH_PROVINCES = (
    "北京|天津|上海|重庆|重慶|河北|山西|辽宁|遼寧|吉林|黑龙江|黑龍江|江苏|江蘇|浙江|安徽|福建|江西|山东|山東|河南|湖北|湖南|广东|廣東"
    "|海南|四川|贵州|貴州|云南|雲南|陕西|陝西|甘肃|甘肅|青海|台湾|台灣|内蒙古|內蒙古|广西|廣西|西藏|宁夏|寧夏|新疆|香港|澳门|澳門"
)
_ZH_UNIT = r"(?:省|市|区|區|县|縣|旗|镇|鎮|乡|鄉|街道)"
# Words that end in a unit without being a place: a supermarket, a stock market, a district of a kind.
_ZH_NOT_PLACES = frozenset(
    """城市 都市 超市 股市 上市 夜市 早市 集市 门市 門市 楼市 樓市 车市 車市 菜市 花市 黑市 闹市 鬧市 开市 開市 休市 收市 罢市
    地区 地區 社区 社區 小区 小區 市区 市區 城区 城區 郊区 郊區 园区 園區 景区 景區 校区 校區 片区 片區 辖区 轄區 灾区 災區 山区 山區
    工业区 工業區 开发区 開發區 商业区 商業區 住宅区 住宅區 风景区 風景區 保护区 保護區 自贸区 自貿區 示范区 示範區 生活区 生活區
    办公区 辦公區 核心区 核心區 管理区 管理區 服务区 服務區 试验区 試驗區 高新区 高新區 新城区 老城区 旧城区 中心区 中心區 居民区
    居民區 隔离区 隔離區 无人区 無人區 缓冲区 緩衝區 存储区 存儲區 数据区 數據區 等候区 等候區 吸烟区 吸煙區 禁区 禁區 专区 專區
    分区 分區 时区 時區 误区 誤區 雷区 雷區 盲区 盲區 战区 戰區 选区 選區 学区 學區 县城 縣城 乡镇 鄉鎮 城镇 城鎮 小镇 小鎮 古镇 古鎮
    乡村 鄉村 家乡 家鄉 故乡 故鄉 老乡 老鄉 他乡 他鄉 外乡 外鄉 街道办""".split()  # noqa: SIM905
)
_ZH_PLACE_RE = re.compile(
    rf"{_ZH_START}(?:(?:{_ZH_PROVINCES})(?:省|市|自治区|自治區|特别行政区|特別行政區|维吾尔自治区|壮族自治区|回族自治区)?"
    rf"|[{_HAN}]{{2,4}}{_ZH_UNIT})(?:[ \t]?[{_HAN}]{{2,5}}{_ZH_UNIT}){{0,3}}"
)
_ZH_ROAD = r"(?:路|街|大街|大道|道|巷|胡同|弄|里|條|条)"
_ZH_ROAD_START = rf"(?:(?<![{_HAN}])|(?<=[{_ZH_BEFORE}省市区區县縣镇鎮乡鄉]))"
_ZH_ROAD_RE = re.compile(
    rf"{_ZH_ROAD_START}[{_HAN}\d]{{1,8}}{_ZH_ROAD}(?:[ \t]?(?:路|街))?[ \t]?(?:\d{{1,5}}(?:[-－]\d{{1,4}})?[ \t]?(?:号|號|弄|室|栋|棟|楼|樓|幢)?)?"
)
# A road named after a word that places something there: "位于 文化西路", "地址是 东四三条 路 2427 号".
_ZH_AT_RE = re.compile(
    rf"(?:位于|位於|坐落于|坐落於|地址是|地址为|地址為|地址[:：]|住在|居住在|设在|設在|地点在|地點在|集合地点设在|送至|寄至|寄到)"
    rf"[ \t]?(?P<place>(?:[{_HAN}\d]{{1,8}}{_ZH_UNIT}[ \t]?){{0,3}}[{_HAN}\d]{{1,10}}{_ZH_ROAD}"
    rf"(?:[ \t]?(?:路|街))?(?:[ \t]?\d{{1,5}}[ \t]?(?:号|號)?)?)"
)
_ZH_NUMBER_RE = re.compile(r"(?<![\d.])\d{1,5}[ \t]?(?:号|號)(?=[ \t，,。；;）)]|$)")
_ZH_TITLES = (
    r"(?:Mr\.?|Mrs\.?|Ms\.?|Miss|Mx\.?|Dr\.?|Prof\.?|Teacher|先生|女士|小姐|老师|老師|博士|教授|经理|經理|同学|同學)"
)
_ZH_NAME_TOKENS = rf"[{_HAN}]{{1,3}}(?:[ \t][{_HAN}]{{1,3}}){{0,2}}"
# "尊敬的 Miss 芸蕾 郁乔 褚，", "亲爱的王伟：", "Teacher 白 晓昕（"
_ZH_GREETING_RE = re.compile(
    rf"(?:尊敬的|亲爱的|親愛的|敬爱的|敬愛的)[ \t]*(?:{_ZH_TITLES}[ \t]*)?(?P<name>{_ZH_NAME_TOKENS}|{_LATIN_NAME}(?:[ \t]{_LATIN_NAME}){{0,2}})"
    rf"(?=[ \t]*(?:{_ZH_TITLES}[ \t]*)?[，,：:！!。（(])"
)
_ZH_TITLE_NAME_RE = re.compile(
    rf"(?<![A-Za-z])(?:Mr\.?|Mrs\.?|Ms\.?|Miss|Dr\.?|Prof\.?|Teacher)[ \t]?(?P<name>{_ZH_NAME_TOKENS})(?![{_HAN}])"
)
# A verb that takes a person, then a name led by a family name: "由王伟签署", "请致电李娜", "联系人：张伟".
_ZH_CUE_RE = re.compile(
    rf"(?:由|致电|致電|联系|聯繫|联络|聯絡|发送给|發送給|寄给|寄給|感谢|感謝|我是|我叫|名叫|叫做|负责人[:：]|負責人[:：]|联系人[:：]|聯繫人[:：]"
    rf"|申请人[:：]|申請人[:：]|客户[:：]|客戶[:：]|患者[:：]|收件人[:：]|签名[:：]|簽名[:：]|经办人[:：]|經辦人[:：])[ \t]?"
    rf"(?P<name>{_ZH_SURNAME}(?!先生|女士|小姐|老师|老師|博士|教授|经理|經理|同学|同學)[{_HAN}]{{1,2}})"
    rf"(?=[ \t，,。（(：:]|签署|簽署|说|說|提交|负责|負責|先生|女士|$)"
)
# Han words set apart by blanks, one of them a lone family name: how transliterated and mixed text writes a name
# ("忠羿 蒋（年龄...", "海城 徐 雍（性别 M）").
_ZH_SPACED_RE = re.compile(
    rf"(?<![{_HAN}\w])(?P<name>[{_HAN}]{{1,3}}(?:[ \t][{_HAN}]{{1,3}}){{1,2}})(?=[ \t]?[（(，,：:在说說的]|$)"
)
_ZH_SURNAME_SET = frozenset(_ZH_SINGLE) | frozenset(_ZH_COMPOUND)


_ZH_LEADING = frozenset(_ZH_BEFORE + "我你他她它们們这這那个個去来來也都就还還")


def _zh_place_ok(surface: str) -> bool:
    """Not an everyday word that ends in a unit: "超市", "这个小区", "股市上市". A one-character modifier in front of a
    two-character one is a district's name ("西山区"), not a word before it."""
    for part in surface.split():
        for word in _ZH_NOT_PLACES:
            if part == word or (part.endswith(word) and (len(word) > 2 or len(part) - len(word) >= 2)):
                return False
    return True


def _zh_trim(text: str, start: int, end: int) -> int:
    """Where a place name starts once the words in front of it are dropped ("在西山区" is "西山区")."""
    while start < end - 2 and text[start] in _ZH_LEADING:
        start += 1
    return start


# A six-digit postcode before the word for an area: "430021地区", "830000区的客户服务中心".
_ZH_POSTCODE_AREA_RE = re.compile(r"(?<![\d\-.])\d{6}(?=地区|地區|区域|區域|区|區)")
# A name in Latin letters before a Chinese family name, then a sign: "Ranee 阮，", "Ms. Hayrunnisa 商，".
_ZH_LATIN_SURNAME_RE = re.compile(
    rf"(?<![A-Za-z])(?P<name>{_LATIN_NAME}(?:[ \t]{_LATIN_NAME}){{0,2}}[ \t]?(?:{'|'.join(_ZH_COMPOUND)}|[{_ZH_SINGLE}]))"
    r"(?=[，,：:！!。（(、；;])"
)


def find_zh_addresses(text: str) -> Iterator[Span]:
    for m in _ZH_POSTCODE_AREA_RE.finditer(text):
        yield _span(m.start(), m.end(), text, E.ADDRESS, "zh-postcode")
    for m in _ZH_PLACE_RE.finditer(text):
        start = _zh_trim(text, m.start(), m.end())
        if _zh_place_ok(text[start : m.end()]):
            yield _span(start, m.end(), text, E.LOCATION, "zh-place")
    for m in _ZH_ROAD_RE.finditer(text):
        surface = m.group()
        if any(c.isdigit() for c in surface[-6:]) or "号" in surface or "號" in surface:
            yield _span(m.start(), m.end(), text, E.ADDRESS, "zh-road")
    for m in _ZH_AT_RE.finditer(text):
        yield _span(m.start("place"), m.end("place"), text, E.ADDRESS, "zh-at")
    for m in _ZH_NUMBER_RE.finditer(text):
        before = text[max(0, m.start() - 12) : m.start()]
        if re.search(rf"(?:{_ZH_ROAD}|地址|位于|位於)", before):
            yield _span(m.start(), m.end(), text, E.ADDRESS, "zh-number")


def find_zh_names(text: str) -> Iterator[Span]:
    for pattern in (_ZH_GREETING_RE, _ZH_TITLE_NAME_RE, _ZH_CUE_RE, _ZH_LATIN_SURNAME_RE):
        for m in pattern.finditer(text):
            yield _span(m.start("name"), m.end("name"), text, E.PERSON, "zh-name")
    for m in _ZH_SPACED_RE.finditer(text):
        tokens = m.group("name").split()
        if any(t in _ZH_SURNAME_SET for t in tokens):
            yield _span(m.start("name"), m.end("name"), text, E.PERSON, "zh-spaced")


# =========================================================================== Japanese
_JA_PREFECTURES = (
    "北海道|青森県|岩手県|宮城県|秋田県|山形県|福島県|茨城県|栃木県|群馬県|埼玉県|千葉県|東京都|神奈川県|新潟県|富山県|石川県"
    "|福井県|山梨県|長野県|岐阜県|静岡県|愛知県|三重県|滋賀県|京都府|大阪府|兵庫県|奈良県|和歌山県|鳥取県|島根県|岡山県|広島県"
    "|山口県|徳島県|香川県|愛媛県|高知県|福岡県|佐賀県|長崎県|熊本県|大分県|宮崎県|鹿児島県|沖縄県"
)
_JA_NAME_CHARS = rf"[{_HAN}{_KATA}]"
_JA_BEFORE = "のにでとはがをへやも、。「」（）()　 "
_JA_START = rf"(?:(?<![{_HAN}{_KATA}])|(?<=[{_JA_BEFORE}]))"
_JA_NOT_PLACES = frozenset(
    """都市 大都市 中都市 小都市 各都市 全都市 政令市 中核市 特例市 指定都市 新都市 主要都市 地方都市 学園都市 姉妹都市 同市 当市 本市
    各市 地区 学区 選挙区 特区 管区 区域 区間 下町 城下町 門前町 港町 宿場町 農村 漁村 山村 各町 同町 当町 各村 同村 市町村 区市町村
    全区 各区 同区 当区 本区""".split()  # noqa: SIM905
)
# A municipality chain: "糸魚川市", "北九州市八幡西区", "稲敷郡美浦村", "広島市東区 牛田東".
_JA_PLACE_RE = re.compile(
    rf"{_JA_START}(?:(?:{_JA_PREFECTURES})[ \t]?)?(?:{_JA_NAME_CHARS}{{2,6}}(?:市|郡)|{_JA_NAME_CHARS}{{1,5}}(?:区|町|村))"
    rf"(?:[ \t]?{_JA_NAME_CHARS}{{1,6}}(?:市|区|町|村|郡))*"
    rf"|{_JA_START}(?:{_JA_PREFECTURES})"
)
# The block numbers of a Japanese address: "3丁目4番5号", "3-11-30 番地", "1-28-6号館".
_JA_BLOCK_RE = re.compile(
    r"(?<![\d\-])(?:\d{1,3}丁目(?:\d{1,4}番(?:地)?)?(?:\d{1,4}号?)?|\d{1,4}(?:[-－‐]\d{1,4}){1,3}[ \t]?(?:番地|番|号館|号室|号))"
)
_JA_HONORIFIC = r"(?:さん|様|さま|サマ|君|くん|ちゃん|殿|氏|先生|宛)"
_JA_TOKEN = rf"(?:[{_HAN}]{{1,4}}|[{_HIRA}]{{2,6}}|[{_KATA}]{{2,10}}|{_LATIN_NAME})"
# Names before an honorific, with or without a blank: "柴田 さん", "美菜津 松井 君", "かこさん", "Yanely 柴田 さん".
_JA_HONORIFIC_RE = re.compile(
    rf"(?<![{_HAN}{_HIRA}{_KATA}A-Za-z])(?P<name>{_JA_TOKEN}(?:[ \t　]{_JA_TOKEN}){{0,2}})[ \t　]?{_JA_HONORIFIC}"
)
_JA_CLOSING_RE = re.compile(rf"(?:敬具|草々|かしこ|拝)[ \t　\n]+(?P<name>{_JA_TOKEN}(?:[ \t　]{_JA_TOKEN}){{0,2}})")
_JA_LABEL_RE = re.compile(
    rf"(?:担当者?|差出人|送信者|作成者|申請者|署名|宛先|代表者|連絡先氏名|契約者|被保険者|患者名|利用者名)[ \t]*[:：][ \t]*"
    rf"(?P<name>{_JA_TOKEN}(?:[ \t　]{_JA_TOKEN}){{0,2}})"
)
_JA_SURNAMES = (  # noqa: SIM905
    "佐藤 鈴木 高橋 田中 伊藤 渡辺 渡邊 山本 中村 小林 加藤 吉田 山田 佐々木 山口 松本 井上 木村 林 斎藤 斉藤 清水 山崎 森 池田 橋本 阿部 石川"
    " 山下 中島 石井 小川 前田 岡田 長谷川 藤田 後藤 近藤 村上 遠藤 青木 坂本 福田 太田 西村 藤井 金子 岡本 藤原 中野 三浦 原田 中川 松田"
    " 竹内 小野 田村 中山 和田 石田 森田 上田 原 内田 柴田 酒井 宮崎 横山 高木 安藤 宮本 大野 小島 谷口 今井 工藤 高田 増田 丸山 杉山 村田"
    " 大塚 新井 小山 平野 藤本 河野 上野 野口 武田 松井 千葉 岩崎 菅原 木下 久保 佐野 野村 松尾 菊地 菊池 杉本 市川 古川 大西 島田 水野"
    " 桜井 高野 渡部 吉川 山内 西田 飯田 西川 小松 北村 安田 五十嵐 川口 平田 関 中田 久保田 服部 東 岩田 土屋 川崎 福島 本田 辻 樋口"
    " 秋山 田口 永井 山中 中西 吉村 川上 石原 大橋 松岡 馬場 浅野 荒木 大久保 野田 小池 星野 熊谷 松下 前川 堀 宮田 大谷 片山 北川"
).split()
_JA_SURNAME_RE = re.compile(
    rf"(?<![{_HAN}])(?P<name>(?:{'|'.join(sorted(_JA_SURNAMES, key=len, reverse=True))})[ \t　]?"
    rf"(?:[{_HAN}]{{1,3}}|(?!さん|さま|くん|ちゃん)[{_HIRA}]{{2,4}}))"
    rf"(?=[ \t　]?(?:が|は|を|に|と|の|へ|さん|様|氏|君|、|。|（|\(|$))"
)
_JA_NOT_NAMES = frozenset(
    "皆 お客 客 患者 社長 部長 課長 先生 生徒 学生 店長 会員 利用者 担当者 関係者 各位 運転手 奥 旦那 子供 お子 家族 弊社 貴社 御社 当社".split()  # noqa: SIM905
)
# A value labelled after itself: "323-0816（郵便番号）", "1-28-6（建物番号）".
_JA_AFTER_LABEL_RE = re.compile(
    r"(?<![\w\-])(?P<value>[0-9A-Za-z][0-9A-Za-z\-]{2,20})[ \t]?[（(](?P<label>郵便番号|建物番号|番地|住所|電話番号|携帯番号|会員番号|口座番号)[）)]"
)
_JA_AFTER_KIND = {"郵便番号": E.ADDRESS, "建物番号": E.ADDRESS, "番地": E.ADDRESS, "住所": E.ADDRESS,
                  "電話番号": E.PHONE, "携帯番号": E.PHONE, "会員番号": E.ACCOUNT_ID, "口座番号": E.ACCOUNT_ID}  # fmt: skip


# The block numbers of an address written without their units, after a place name or before the particle that puts
# something there: "下砂井8-30-16", "二ツ屋の8-19-7にあります", "大元 2-4-25にて". Not a date ("2024-05-14", four
# digits first), a phone ("03-1234-5678" starts with 0) or a section ("第3-1-2条").
_JA_BARE_BLOCK_RE = re.compile(
    rf"(?:(?P<place>[{_HAN}{_KATA}]{{2,6}})(?:の|[ \t　])?)?(?<![\d\-－‐第.])(?P<block>[1-9]\d{{0,2}}[-－‐]\d{{1,4}}[-－‐]\d{{1,4}})"
    r"(?![\d\-－‐.])"
)
# A Japanese postcode, with or without its mark: "〒870-1213", "224-0023 や広島市東区".
_JA_POSTCODE_RE = re.compile(r"(?:〒[ \t]?)?(?<![\d\-－‐.])\d{3}[-－‐]\d{4}(?![\d\-－‐.])")


def find_ja_addresses(text: str) -> Iterator[Span]:
    for m in _JA_BARE_BLOCK_RE.finditer(text):
        start = m.start("place") if m.group("place") and m.group("place") not in _JA_NOT_PLACES else m.start("block")
        yield _span(start, m.end("block"), text, E.ADDRESS, "ja-block")
    for m in _JA_POSTCODE_RE.finditer(text):
        yield _span(m.start(), m.end(), text, E.ADDRESS, "ja-postcode")
    for m in _JA_PLACE_RE.finditer(text):
        surface = m.group()
        if surface in _JA_NOT_PLACES or any(surface.endswith(w) and len(surface) - len(w) < 2 for w in _JA_NOT_PLACES):
            continue
        yield _span(m.start(), m.end(), text, E.LOCATION, "ja-place")
    for m in _JA_BLOCK_RE.finditer(text):
        yield _span(m.start(), m.end(), text, E.ADDRESS, "ja-block")
    for m in _JA_AFTER_LABEL_RE.finditer(text):
        if any(c.isdigit() for c in m.group("value")):
            yield _span(m.start("value"), m.end("value"), text, _JA_AFTER_KIND[m.group("label")], "ja-labelled")


# Words that stand next to a name without being part of it: closings, and honorifics written in front.
_JA_AROUND = frozenset("敬具 草々 かしこ 拝啓 前略 宛 様 さん 君 くん ちゃん 殿 氏 kun chan san sama".split())  # noqa: SIM905


# A name in Latin letters before a Japanese family name, as mixed text writes a foreign given name with one:
# "Viggo 青木 が主導", "Japhet Thevananth 高田が". The family name must end the name: a particle or a sign follows.
_JA_LATIN_SURNAME_RE = re.compile(
    rf"(?<![A-Za-z])(?P<name>{_LATIN_NAME}(?:[ \t]{_LATIN_NAME}){{0,2}}[ \t　]?"
    rf"(?:{'|'.join(sorted(_JA_SURNAMES, key=len, reverse=True))}))"
    rf"(?=[ \t　]?(?:が|は|を|に|と|の|へ|も|さん|様|氏|君|、|。|，|,|（|\(|：|:|」)|$)"
)


def find_ja_names(text: str) -> Iterator[Span]:
    for pattern in (_JA_HONORIFIC_RE, _JA_CLOSING_RE, _JA_LABEL_RE, _JA_SURNAME_RE, _JA_LATIN_SURNAME_RE):
        for m in pattern.finditer(text):
            start, end = m.start("name"), m.end("name")
            tokens = [(t.start() + start, t.end() + start, t.group()) for t in re.finditer(r"\S+", text[start:end])]
            while tokens and tokens[0][2] in _JA_AROUND:
                tokens = tokens[1:]
            while tokens and tokens[-1][2] in _JA_AROUND:
                tokens = tokens[:-1]
            if tokens and not any(t[2] in _JA_NOT_NAMES for t in tokens):
                yield _span(tokens[0][0], tokens[-1][1], text, E.PERSON, "ja-name")


# =========================================================================== Korean
_KO_REGIONS = (
    "서울특별시|부산광역시|대구광역시|인천광역시|광주광역시|대전광역시|울산광역시|세종특별자치시|경기도|강원특별자치도|강원도"
    "|충청북도|충청남도|전북특별자치도|전라북도|전라남도|경상북도|경상남도|제주특별자치도|제주도"
)
_KO_CITIES = (
    "수원|성남|고양|용인|부천|안산|안양|남양주|화성|평택|의정부|시흥|파주|김포|광명|군포|하남|오산|이천|안성|의왕|양주|포천|여주"
    "|동두천|과천|구리|춘천|원주|강릉|동해|태백|속초|삼척|청주|충주|제천|천안|공주|보령|아산|서산|논산|계룡|당진|전주|군산|익산"
    "|정읍|남원|김제|목포|여수|순천|나주|광양|포항|경주|김천|안동|구미|영주|영천|상주|문경|경산|창원|진주|통영|사천|김해|밀양|거제"
    "|양산|제주|서귀포|서울|부산|대구|인천|광주|대전|울산|세종"
)
_KO_PLACE_RE = re.compile(
    rf"(?<![{_HANGUL}])(?:(?:{_KO_REGIONS})|(?:{_KO_CITIES})시)(?:[ \t]?[{_HANGUL}]{{1,4}}(?:시|군|구))?"
    rf"(?:[ \t]?[{_HANGUL}]{{1,4}}\d?(?:동|읍|면|리|가))?(?:[ \t]?[{_HANGUL}]{{1,4}}\d?(?:동|읍|면|리|가))?"
    rf"|(?<![{_HANGUL}\d])[{_HANGUL}]{{1,4}}\d{{1,2}}동(?![{_HANGUL}])"
)
# A road-name address (도로명주소): the road, its number, the building number ("들안로28길 100", "세권로212번길 1083",
# "석현로 604번지"), and a lot number on its own ("100번지").
_KO_ROAD_RE = re.compile(
    rf"(?<![{_HANGUL}])[{_HANGUL}]{{1,8}}(?:대로|로|길)(?:\d{{1,4}}(?:번길|길))?(?:[ \t]?\d{{1,5}}(?:-\d{{1,4}})?(?:번지|호)?)?"
    rf"(?<=[\d길지호])(?![{_HANGUL}]{{0,1}}\d)"
    rf"|(?<![\d\-])\d{{1,5}}(?:-\d{{1,4}})?[ \t]?번지"
    rf"|(?<![\d\-])\d{{1,4}}동[ \t]\d{{1,4}}호"
)
# A postcode in brackets right after a place: "대전광역시(34127)".
_KO_PLACE_POSTCODE_RE = re.compile(rf"(?<=[{_HANGUL}])[(（](\d{{5}})[)）]")
_KO_SURNAMES = (
    "김이박최정강조윤장임한오서신권황안송류유전홍고문양손배백허남심노하곽성차주우구민진나지엄채원천방공현함변염여추도소석선설마길"
    "연위표명기반라왕금옥육인맹제모탁국어은편용예경봉사부가복태목형피두감음빈동온호범좌"
)
_KO_COMPOUND = ("남궁", "황보", "제갈", "사공", "선우", "서문", "독고", "동방")
_KO_HONORIFIC = r"(?:선생님|고객님|대표님|과장님|팀장님|부장님|사장님|교수님|원장님|기사님|님|씨|군|양)"
_KO_TOKEN = rf"(?:[{_HANGUL}]{{1,4}}|{_LATIN_NAME})"
# Names before an honorific, in one or more parts ("김민지 씨", "화리 어님", "승혜 El Alam Cali 님") and after a
# title in front ("군 다래 온님은", "양 은별 ...가").
_KO_HONORIFIC_RE = re.compile(
    rf"(?<![{_HANGUL}A-Za-z])(?:(?:군|양|gun|yang)[ \t]+)?(?P<name>{_KO_TOKEN}(?:[ \t]{_KO_TOKEN}){{0,3}})[ \t]?{_KO_HONORIFIC}"
    rf"(?=[{_HANGUL}]{{0,3}}(?:[^{_HANGUL}]|$))"
)
_KO_TITLE_RE = re.compile(
    rf"(?<![{_HANGUL}A-Za-z])(?:군|양)[ \t]+(?P<name>{_KO_TOKEN}(?:[ \t]{_KO_TOKEN}){{0,3}})(?=[ \t]?(?:는|은|이|가|을|를|의|께서|에게|님|씨))"
)
_KO_NOT_NAMES = frozenset(
    """고객 회원 선생 교수 사장 부장 과장 대리 팀장 원장 실장 이사 대표 기사 여러분 손님 환자 학생 형 누나 언니 오빠 어머니 아버지 할머니
    할아버지 엄마 아빠 담당자 관리자 작가 의사 간호사 박사 목사 신부 수녀 스님 회장 총장 소장 국장 차장 주임 반장 점장 매니저 선배
    후배 동생 친구 아드님 따님 부모 남편 아내 사용자 이용자 구매자 판매자 신청자 참가자 직원 관계자 귀하 본인 우리 저희 모두 각각""".split()  # noqa: SIM905
)


def _ko_name_ok(name: str) -> bool:
    tokens = name.split()
    if any(t in _KO_NOT_NAMES for t in tokens):
        return False
    hangul = [t for t in tokens if re.fullmatch(rf"[{_HANGUL}]+", t)]
    # A lone word before 님 must be a name: a family name and a given name, or a given name next to another part.
    if len(tokens) == 1 and hangul:
        word = hangul[0]
        return len(word) in (2, 3, 4) and (word[0] in _KO_SURNAMES or word[:2] in _KO_COMPOUND or len(word) == 2)
    return True


# A five-digit postcode next to a place or a road: "울산광역시 35015", "62373와 제주시 신제주".
_KO_POSTCODE_RE = re.compile(r"(?<![\d\-.,])\d{5}(?![\d\-]|[.,]\d)")
_KO_BETWEEN_RE = re.compile(r"[ \t,，]{0,2}(?:와|과|및|,)?[ \t]{0,2}")


def find_ko_addresses(text: str) -> Iterator[Span]:
    places: list[tuple[int, int]] = []
    for m in _KO_PLACE_RE.finditer(text):
        places.append(m.span())
        yield _span(m.start(), m.end(), text, E.LOCATION, "ko-place")
    for m in _KO_ROAD_RE.finditer(text):
        if any(c.isdigit() for c in m.group()):  # a road with no number is a road, not an address
            places.append(m.span())
            yield _span(m.start(), m.end(), text, E.ADDRESS, "ko-road")
    for m in _KO_PLACE_POSTCODE_RE.finditer(text):
        yield _span(m.start(1), m.end(1), text, E.ADDRESS, "ko-postcode")
    if places:
        ends = {b for _, b in places}
        starts = {a for a, _ in places}
        for m in _KO_POSTCODE_RE.finditer(text):
            after = _KO_BETWEEN_RE.match(text, m.end())
            right_after = any(
                b in ends and _KO_BETWEEN_RE.fullmatch(text, b, m.start()) for b in range(m.start() - 4, m.start() + 1)
            )
            if right_after or (after is not None and after.end() in starts):
                yield _span(m.start(), m.end(), text, E.ADDRESS, "ko-postcode")


def find_ko_names(text: str) -> Iterator[Span]:
    for pattern in (_KO_HONORIFIC_RE, _KO_TITLE_RE):
        for m in pattern.finditer(text):
            if _ko_name_ok(m.group("name")):
                yield _span(m.start("name"), m.end("name"), text, E.PERSON, "ko-name")


# =========================================================================== chat transcripts
# A transcript's speaker: a time, then a name, then a colon ("10:45 ちかよし: 「...」", "8:49:56 PM 山本: ...",
# "[14:02] 김민지: ..."). Two such lines make a transcript; one alone could be an agenda item ("10:00 開会: ...").
_CJK_WORD = rf"[{_HAN}{_HIRA}{_KATA}{_HANGUL}]{{1,8}}"
_CJK_SPEAKER_RE = re.compile(
    rf"(?m)^[ \t>*\-]*\[?\d{{1,2}}:\d{{2}}(?::\d{{2}})?(?:[ \t]?[AaPp]\.?[Mm]\.?)?\]?[ \t]*[-–]?[ \t]*"
    rf"(?P<name>(?:{_CJK_WORD}|{_LATIN_NAME})(?:[ \t　](?:{_CJK_WORD}|{_LATIN_NAME})){{0,3}})[ \t]*[:：]"
)
_NOT_SPEAKERS = frozenset(
    """システム 管理者 司会 司会者 全員 議長 ボット 会議 開会 閉会 休憩 受付 議題 担当 担当者 お知らせ 通知 自動応答 運営 事務局
    系统 管理员 管理員 主持人 全体 会议 會議 开始 開始 结束 結束 休息 通知 机器人 機器人 客服 助手 议题 議題
    시스템 관리자 사회자 전체 회의 시작 종료 휴식 공지 알림 봇 상담원 안내""".split()  # noqa: SIM905
)


def find_cjk_speakers(text: str) -> Iterator[Span]:
    found = [
        m for m in _CJK_SPEAKER_RE.finditer(text) if re.search(f"[{_HAN}{_HIRA}{_KATA}{_HANGUL}]", m.group("name"))
    ]
    if len(found) < 2:
        return
    for m in found:
        tokens = m.group("name").split()
        if any(t in _NOT_SPEAKERS for t in tokens):
            continue
        yield _span(m.start("name"), m.end("name"), text, E.PERSON, "speaker")


# =========================================================================== entry points
_ZH_ANY = re.compile(f"[{_HAN}]")
_JA_ANY = re.compile(f"[{_HIRA}{_KATA}]")
_KO_ANY = re.compile(f"[{_HANGUL}]")


def find_cjk_addresses(text: str) -> list[Span]:
    spans: list[Span] = []
    if text.isascii():
        return spans
    if _KO_ANY.search(text):
        spans.extend(find_ko_addresses(text))
    if _ZH_ANY.search(text):
        if _JA_ANY.search(text):
            spans.extend(find_ja_addresses(text))
        else:
            spans.extend(find_zh_addresses(text))
    return spans


def find_cjk_names(text: str) -> list[Span]:
    spans: list[Span] = []
    if text.isascii():
        return spans
    if ":" in text or "：" in text:
        spans.extend(find_cjk_speakers(text))
    if _KO_ANY.search(text):
        spans.extend(find_ko_names(text))
    if _ZH_ANY.search(text) or _JA_ANY.search(text):
        if _JA_ANY.search(text):
            spans.extend(find_ja_names(text))
        else:
            spans.extend(find_zh_names(text))
    return spans
