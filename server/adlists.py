"""
Расширенная блокировка рекламы: списки в формате AdBlock → файл geosite для xray.

Из списков берутся только правила «весь домен» (||example.com^), исключения
(@@||example.com^) соблюдаются. Результат — ext-файл с тегом ADS, который
агенты кладут рядом с geosite.dat и подключают правилом ext:nexalink-ads.dat:ads.
"""
import hashlib
import re
import urllib.request

AD_LISTS = [
    "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt",   # AdGuard DNS filter
    "https://easylist-downloads.adblockplus.org/ruadlist.txt",             # RU AdList
]
ASSET_NAME = "nexalink-ads.dat"
TAG = "ADS"

_RULE = re.compile(r"^(@@)?\|\|([a-z0-9][a-z0-9.-]*\.[a-z0-9-]{2,})\^(\$important)?$")


def parse(texts) -> list[str]:
    block, allow = set(), set()
    for text in texts:
        for line in text.splitlines():
            m = _RULE.match(line.strip().lower())
            if m:
                (allow if m.group(1) else block).add(m.group(2))
    # исключение убирает точный домен из блокировки; правило Domain в xray матчит и
    # поддомены, так что исключение поддомена заблокированного родителя не сработает —
    # для доменного списка это допустимо
    return sorted(block - allow)


def _varint(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)


def _field(num: int, payload: bytes) -> bytes:
    return _varint(num << 3 | 2) + _varint(len(payload)) + payload


def build_geosite(domains: list[str], tag: str = TAG) -> bytes:
    """GeoSiteList{entry: GeoSite{country_code, domain: [Domain{type=RootDomain(2), value}]}}"""
    entry = _field(1, tag.encode())
    for d in domains:
        entry += _field(2, b"\x08\x02" + _field(2, d.encode()))
    return _field(1, entry)


def fetch(urls=AD_LISTS, timeout=60) -> list[str]:
    texts = []
    for url in urls:
        req = urllib.request.Request(url, headers={"User-Agent": "vpnpanel-adlists/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            texts.append(r.read().decode("utf-8", "replace"))
    return texts


def build() -> tuple[bytes, int, str]:
    """→ (содержимое файла, число доменов, sha256)"""
    domains = parse(fetch())
    data = build_geosite(domains)
    return data, len(domains), hashlib.sha256(data).hexdigest()


if __name__ == "__main__":
    import sys
    data, n, sha = build()
    open(sys.argv[1] if len(sys.argv) > 1 else ASSET_NAME, "wb").write(data)
    print(f"{n} доменов, {len(data)} байт, sha256 {sha[:16]}")
