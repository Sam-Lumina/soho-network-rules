"""Check the public worktree or the exact Git index contents. Never print a match."""

import argparse
import base64
import binascii
from copy import deepcopy
from hashlib import sha256
from ipaddress import ip_address, ip_network
from itertools import product
import json
import os
from pathlib import Path
import re
import subprocess
from urllib.parse import parse_qsl, urlsplit

import yaml

from build_configs import (
    ACL, HAGEZI, META, PAGES, COMMUNITY_DATA, COMMUNITY_MEDIA, COMMUNITY_ADULT, COMMUNITY_GAMBLING,
    COMMUNITY_DIRECT, COMMUNITY_PROXY, TELEGRAM_IPS, FILTERS, community_providers, data_url, domain_rule,
    filter_rule, filter_settings, ip_rule, shadowrocket, telegram_ip_rules, threat_source, windows,
)


ROOT = Path(__file__).resolve().parents[1]
ROOT_FILES = {".gitignore", "README.md", "LICENSE", "THIRD_PARTY_NOTICES.md", "CONTRIBUTING.md", "SECURITY.md"}
OTHER_FILES = {
    ".github/workflows/check-and-publish.yml", ".github/workflows/community-catalog.yml",
    "rules/policy.json", "rules/community_sources.json", "tools/build_configs.py",
    "tools/build_rule_data.py", "tools/check_release.py", "tools/community_catalog.py", "tools/build_community_data.py",
}
ASSETS = {
    "LICENSE", "THIRD_PARTY_NOTICES.md", "SOURCE.md", "SHA256.json",
    "tif-mini.mrs", "meta-ads.list", "meta-international.list",
}
CONFIGS = {"dist/stable/mihomo-merge.yaml", "dist/stable/shadowrocket.conf", "dist/stable/shadowrocket-waimao.conf"}
COMMUNITY_LISTS = (COMMUNITY_MEDIA, COMMUNITY_ADULT, COMMUNITY_GAMBLING, COMMUNITY_PROXY, COMMUNITY_DIRECT)
COMMUNITY_FILES = {f"dist/{path}" for path in (*COMMUNITY_LISTS, TELEGRAM_IPS, f"{COMMUNITY_DATA}/SOURCE.md",
                                               f"{COMMUNITY_DATA}/SHA256.json")}
HULU_JAPAN = "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/HuluJapan.list"
POLYFORM_SHA256 = "ffcca38841adb694b6f380647e15f17c446a4d1656fed51a1e2041d064c94cc8"
GPL_SHA256 = "3972dc9744f6499f0f9b2dbf76696f2ae7ad8af9b23dde66d6af86c9dfb36986"
MIT_NOTICE_SHA256 = {
    "b9d84a22870d3f21c91a4c6e410c9cc51d00902f5233ad0c84011479244bf7d2",  # V2Fly
    "35f18e0331a1ecd1835400c50e3b367c2ce09f6c13d91c4a0f3cb11f71d3bbc3",  # Loyalsoldier
}
HOSTS = {
    "github.com", "api.github.com", "raw.githubusercontent.com", "sam-lumina.github.io", "polyformproject.org",
    "www.gnu.org", "gnu.org", "fsf.org", "www.fsf.org", "www.clashverge.dev", "apps.apple.com",
    "wiki.metacubex.one", "docs.github.com", "example.com", "core.telegram.org", "www.gstatic.com",
}
SENSITIVE_FIELDS = (r"password|passwd|token|client[_-]?secret|secret|authorization|api[_-]?key|private[_-]?key|uuid|cookie"
                    r"|short[_-]?id|public[_-]?key|pbk|sid|reality[_-]?opts")
# Literal addresses the checker itself uses as routing samples. Everything else must be a CIDR.
SAMPLE_ADDRESSES = {"149.154.167.41", "149.154.175.50", "95.161.76.101", "194.221.250.50", "2001:b28:f23d:f001::a",
                    "192.0.2.1"}
DOCUMENTATION = tuple(ip_network(row) for row in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32"))
IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?!\w|\.\w|/\d)")
IPV6 = re.compile(r"(?<![\w:.])(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}(?![\w:]|/\d)", re.I)
# Local-only list of exact values (server address, keys, IDs, personal domains) that must never be published.
# One value per line; the file lives outside the repository and CI runs without it.
PRIVATE_VALUES = Path(os.environ.get("SOHO_PRIVATE_VALUES") or Path.home() / ".soho-private" / "release-denylist.txt")
SENSITIVE_PARAM = re.compile(rf"(?:^|[_-])(?:key|auth|{SENSITIVE_FIELDS})(?:$|[_-])", re.I)
PATTERNS = {
    "proxy share URI": re.compile(r"\b(?:ss|ssr|vless|vmess|trojan|hysteria2?|hy2|tuic|wireguard|socks5?)://", re.I),
    "credential or endpoint field": re.compile(rf"^[ \t]*['\x22]?(?:{SENSITIVE_FIELDS}|server|port|username)['\x22]?[ \t]*:\s*[^\s#]", re.I | re.M),
    "credential assignment": re.compile(rf"\b(?:{SENSITIVE_FIELDS})[ \t]*=[ \t]*['\x22]?[\w+/-]{{8,}}", re.I),
    "GitHub token": re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{28,}|github_pat_[A-Za-z0-9_]{30,})\b"),
    "cloud or API key": re.compile(r"\b(?:(?:AKIA|ASIA)[A-Z0-9]{16}|AIza[a-zA-Z0-9_-]{35}|sk-[a-zA-Z0-9_-]{24,})\b"),
    "private key": re.compile(r"-----" + r"BEGIN (?:[A-Z0-9 ]*PRIVATE KEY|OPENSSH PRIVATE KEY)-----"),
    "node UUID": re.compile(r"\b[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\b", re.I),
    "email address": re.compile(r"\b[\w.+-]+@[a-z0-9.-]+\.[a-z]{2,}\b", re.I),
    "absolute local path": re.compile(r"(?i)(?:\b[A-Z]:[\\/](?:Users|ProgramData|Windows|[^\\/ \r\n]+)[\\/]|/(?:home|Users|private)/(?!\s)[^/\s]+/)"),
    "IP or domain with port": re.compile(r"(?i)(?:[a-z0-9-]+\.)+[a-z0-9-]+:\d{2,5}\b|\[[0-9a-f:]+\]:\d{2,5}\b"),
}
URL = re.compile(r"https?://[^\s<>\x22\x27\x60)\]}]+")
ENCODED = re.compile(r"(?<![\w+/-])[A-Za-z0-9+/_-]{40,}={0,2}(?![\w+/-])")
DOMAIN = re.compile(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")


def git(*args):
    return subprocess.check_output(["git", *args], cwd=ROOT)


def inventory(staged):
    if staged:
        for row in git("ls-files", "--stage", "-z").decode().split("\0"):
            if row:
                header, path = row.split("\t", 1)
                mode, digest, stage = header.split()
                if mode != "100644" or stage != "0":
                    raise ValueError(f"Unexpected Git file type or unresolved stage in {path}")
                yield path, git("cat-file", "blob", digest)
    else:
        for path in ROOT.rglob("*"):
            relative = path.relative_to(ROOT)
            if any(part in {".git", "__pycache__"} for part in relative.parts):
                continue
            if path.is_symlink():
                raise ValueError("Symlinks are excluded from the release")
            if path.is_file():
                yield relative.as_posix(), path.read_bytes()


def private_values():
    if not PRIVATE_VALUES.is_file():
        return ()
    rows = PRIVATE_VALUES.read_text(encoding="utf-8").splitlines()
    return tuple(row.strip() for row in rows if len(row.strip()) >= 6 and not row.lstrip().startswith("#"))


def ip_literals(body):
    for pattern in (IPV4, IPV6):
        for value in pattern.findall(body):
            try:
                address = ip_address(value)
            except ValueError:
                continue
            if str(address) not in SAMPLE_ADDRESSES and not any(
                    address.version == net.version and address in net for net in DOCUMENTATION):
                yield value


def content_findings(body):
    for name, pattern in PATTERNS.items():
        if pattern.search(body):
            yield name
    if any(ip_literals(body)):
        yield "bare IP address"
    if any(value.lower() in body.lower() for value in private_values()):
        yield "private value"
    for address in URL.findall(body):
        try:
            parsed = urlsplit(address.rstrip(".,;"))
            approved = (parsed.hostname in HOSTS and not parsed.username and not parsed.password
                        and parsed.port is None and not any(
                            SENSITIVE_PARAM.search(key) for key, _ in parse_qsl(parsed.query, keep_blank_values=True)))
        except ValueError:
            approved = False
        if not approved:
            yield "unapproved URL or URL credential"


def scan(body):
    yield from content_findings(body)
    for value in ENCODED.findall(body):
        try:
            text = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True).decode()
        except (binascii.Error, UnicodeError):
            continue
        if text.isprintable() or all(character.isprintable() or character in "\r\n\t" for character in text):
            if any(content_findings(text)) or re.search(r'(?i)["\x27](?:uuid|ps|add|password|server|privateKey)["\x27]\s*:', text):
                yield "encoded credential or proxy configuration"


def require(condition, description):
    if not condition:
        raise ValueError(description)


def valid_domain(host):
    return len(host) <= 253 and bool(DOMAIN.fullmatch(host))


def shadowrocket_check(files, directory, policy):
    raw = files["dist/stable/shadowrocket.conf"].decode()
    lines = [line for line in raw.splitlines() if line and not line.startswith("#")]
    require(lines == shadowrocket(policy).splitlines(), "Shadowrocket differs from policy")
    filters = filter_settings(policy)
    ad_url = data_url(policy, "meta-ads.list")
    selectors = {"threat": "DOMAIN-SET," + threat_source(policy), "ads": "RULE-SET," + ad_url}
    prefix = [filter_rule(selectors[module], exceptions) for module, exceptions in filters.items()]
    gambling_rule = f"RULE-SET,{PAGES}/{COMMUNITY_GAMBLING},REJECT"
    require(lines[1:2+len(prefix)] == [*prefix, gambling_rule],
            "Shadowrocket filters and gambling must precede business routing")
    config = [line.split(",") for line in ["[Rule]", *lines[1+len(prefix):]]]
    require(config[0] == ["[Rule]"] and config[-1] == ["FINAL", "DIRECT"], "Shadowrocket section or final route")
    require(sum(row[0] == "FINAL" for row in config) == 1, "Shadowrocket final route count")
    table = {}
    for leaf in ("meta-ads.list", "meta-international.list"):
        table[f"{PAGES}/{directory.removeprefix('dist/')}/{leaf}"] = [
            row.split(",") for row in files[f"{directory}/{leaf}"].decode().splitlines()
        ]
        require(all(len(row) == 2 and row[0] in {"DOMAIN", "DOMAIN-SUFFIX"} and valid_domain(row[1])
                    for row in table[f"{PAGES}/{directory.removeprefix('dist/')}/{leaf}"]), "Malformed Shadowrocket external rules")
    manifest = json.loads(files[f"dist/{COMMUNITY_DATA}/SHA256.json"])
    telegram_url = f"{PAGES}/{TELEGRAM_IPS}"
    telegram = files[f"dist/{TELEGRAM_IPS}"]
    telegram_entry = manifest["telegram-ip.list"]
    telegram_sources = telegram_entry["sources"]
    require(sha256(telegram).hexdigest() == telegram_entry["sha256"]
            and len(telegram) == telegram_entry["bytes"] and len(telegram_sources) == 1
            and re.fullmatch(re.escape(META) + r"/[a-f0-9]{40}/geo/geoip/telegram\.list", telegram_sources[0]["url"])
            and re.fullmatch(r"[a-f0-9]{64}", telegram_sources[0]["sha256"]),
            "Telegram IP data checksum or provenance mismatch")
    telegram_networks = set()
    for line in telegram.decode().splitlines():
        kind, prefix, option = line.split(",")
        network = ip_network(prefix)
        require(option == "no-resolve" and f"{kind},{prefix}" == ip_rule(prefix)
                and network.is_global and network.prefixlen >= (16 if network.version == 4 else 32),
                "Unexpected Telegram IP rule")
        telegram_networks.add(network)
    require(len(telegram_networks) == telegram_entry["count"] > 0
            and {network.version for network in telegram_networks} == {4, 6},
            "Incomplete Telegram IPv4/IPv6 package")
    for name in COMMUNITY_LISTS:
        community = files[f"dist/{name}"]
        entry = manifest[name.rsplit("/", 1)[1]]
        require(sha256(community).hexdigest() == entry["sha256"] and len(community) == entry["bytes"],
                "Community rule checksum mismatch")
        rows = {tuple(line.split(",")) for line in community.decode().splitlines()}
        require(len(rows) == entry["count"] > 0
                and all(len(row) == 2 and row[0] in {"DOMAIN", "DOMAIN-SUFFIX"} and valid_domain(row[1])
                        for row in rows), "Malformed community rule list")
        table[f"{PAGES}/{name}"] = rows
    for disposition in ("direct", "proxy"):
        name = f"services-{disposition}.list"
        paths = set()
        for source in manifest[name]["sources"]:
            match = re.fullmatch(re.escape(META) + r"/[a-f0-9]{40}/geo/geosite/([a-z0-9-]+(?:![a-z0-9-]+)?)\.list",
                                 source["url"])
            require(match and source["rules"] > 0 and re.fullmatch(r"[a-f0-9]{64}", source["sha256"]),
                    "Unreviewed MetaCubeX source or checksum")
            paths.add(match[1])
        require(paths == set(policy["community"][f"{disposition}_meta"]),
                "Community source inventory differs from the policy")
    gambling_sources = manifest["gambling.list"]["sources"]
    require(len(gambling_sources) == 1
            and re.fullmatch(re.escape(HAGEZI) + r"/[a-f0-9]{40}/wildcard/gambling\.txt",
                             gambling_sources[0]["url"])
            and re.fullmatch(r"[a-f0-9]{64}", gambling_sources[0]["sha256"]),
            "Unexpected gambling provenance")
    for path, entries in table.items():
        table[path] = set(map(tuple, entries))
    upstream = {url for row in policy["sets"] for url in row.get("shadowrocket_urls", ())}
    require(upstream == {HULU_JAPAN, *{
                f"https://raw.githubusercontent.com/poohyeban/shadowrocket-rules/main/rules/{name}/{name}.list"
                for name in ("Facebook", "Instagram")}},
            "Unreviewed Shadowrocket community rule source")
    community = community_providers(policy)
    upstream.update(url for _, url, _ in community if url.startswith(ACL + "/"))
    require(config[-len(community)-1:-1] == [["RULE-SET", url, outcome] for _, url, outcome in community],
            "Community routes must follow the existing rule precedence")
    telegram_rules = [line.split(",") for line in telegram_ip_rules(policy, telegram_url, ("PROXY",))]
    start = config.index(telegram_rules[0])
    require(config[start:start+len(telegram_rules)] == telegram_rules, "Telegram IP rules incomplete or out of order")
    for row in config[1:-1]:
        if row in telegram_rules:
            continue
        require(len(row) == 3 and row[-1] in {"DIRECT", "PROXY", "REJECT"}, "Malformed Shadowrocket rule")
        kind, item, outcome = row
        if kind == "RULE-SET":
            require(item in table or (item in upstream and outcome == "PROXY"), "Unknown Shadowrocket external rule list")
        else:
            require(kind in {"DOMAIN", "DOMAIN-SUFFIX"} and valid_domain(item), "Unknown Shadowrocket rule type")

    def matches(kind, name, host):
        return host == name or (kind == "DOMAIN-SUFFIX" and host.endswith("." + name))

    def in_set(entries, host):
        labels = host.split(".")
        return ("DOMAIN", host) in entries or any(
            ("DOMAIN-SUFFIX", ".".join(labels[index:])) in entries for index in range(len(labels)))

    ad_exemptions = {tuple(rule.split(",")) for rule in filters.get("ads", ())}

    def route(host, telegram_provider=True):
        # Check first-match order for the available lists. The external threat list is checked on-device.
        if "ads" in filters and in_set(table[ad_url], host) and not in_set(ad_exemptions, host):
            return "REJECT"
        try:
            address = ip_address(host)
        except ValueError:
            address = None
        for rule in config[1:]:
            if rule[0] == "FINAL":
                return rule[1]
            kind, target, action = rule[:3]
            if address is not None:
                if kind == "RULE-SET" and target == telegram_url and telegram_provider:
                    if any(address in network for network in telegram_networks):
                        return action
                elif kind in {"IP-CIDR", "IP-CIDR6"} and address in ip_network(target):
                    return action
            if kind == "RULE-SET" and target in table and in_set(table[target], host):
                return action
            if kind in {"DOMAIN", "DOMAIN-SUFFIX"} and matches(kind, target, host):
                return action
        raise ValueError("Shadowrocket rules have no final match")

    cases = {
        "PROXY": ("chatgpt.com", "api.openai.com", "github.com", "www.google.com", "mail.google.com", "www.youtube.com",
                  "web.telegram.org", "x.com", "www.linkedin.com", "web.whatsapp.com", "claude.ai", "grok.com",
                  "muse.ai", "auth.muse.ai", "www.facebook.com", "www.instagram.com", "auth.meta.com",
                  "www.netflix.com", "open.spotify.com", "www.twitch.tv", "www.formula1.com",
                  "www.disneyplus.com", "www.primevideo.com", "tv.apple.com", "www.max.com", "discord.com",
                  "www.tiktok.com", "www.perplexity.ai", "huggingface.co", "www.reddit.com", "www.wikipedia.org",
                  "gateway.discord.gg", "cdn.discordapp.com", "antigravity.google", "accounts.google.com",
                  "oauth2.googleapis.com", "cloudcode-pa.googleapis.com", "daily-cloudcode-pa.googleapis.com",
                  "jetski-webchannel.googleapis.com", "gemini.google", "gemini.google.com",
                  "geminiweb-pa.clients.google.com", "geminiweb-pa.clients6.google.com", "aistudio.google.com",
                  "generativelanguage.googleapis.com", "cursor.com", "windsurf.com", "mistral.ai", "openrouter.ai",
                  "elevenlabs.io", "deepwiki.com", "kimi.ai", "moonshot.ai", "minimax.io", "qoder.com",
                  "coderabbit.gallery.vsassets.io", "dash.cloudflare.com", "platform.dash.cloudflare.com",
                  "api.cloudflare.com", "brunhild.challenges.cloudflare.com", "a.nel.cloudflare.com",
                  "static.cloudflareinsights.com", "sample.pages.dev", "sample.workers.dev",
                  "sample.r2.dev", "sample.trycloudflare.com", "cloudflarechina.cn", "youtubei.googleapis.com",
                  "i.ytimg.com", "music.youtube.com", "yt3.ggpht.com", "dl.google.com", "dl.l.google.com",
                  "storage.googleapis.com"),
        "DIRECT": ("www.baidu.com", "www.taobao.com", "fe2cr.update.microsoft.com", "licdn.cn.cdn20.com",
                   "www.bilibili.com", "www.douyin.com", "www.icbc.com.cn", "store.steampowered.com",
                   "www.epicgames.com", "soho-test.invalid", "moonshot.cn", "copilot.com",
                   "copilot-stg.com", "copilot.cloud.microsoft", "copilot.microsoft.com"),
        "REJECT": tuple(host for host in ("doubleclick.net", "googlesyndication.com", "browser-intake-datadoghq.com",
                                         "o33249.ingest.sentry.io", "o33249.ingest.us.sentry.io", "openai.qualtrics.com")
                        if "ads" in filters and not in_set(ad_exemptions, host)),
    }
    for action, hosts in cases.items():
        require(all(route(host) == action for host in hosts), f"Shadowrocket sample mismatch for {action}")
    telegram_samples = ("149.154.167.41", "149.154.175.50", "95.161.76.101", "194.221.250.50", "2001:b28:f23d:f001::a")
    for provider_available in (True, False):
        require(all(route(host, provider_available) == "PROXY" for host in telegram_samples)
                and route("192.0.2.1", provider_available) == "DIRECT"
                and route("2001:db8::1", provider_available) == "DIRECT",
                "Telegram IP routing or cache-missing fallback failed")
    adult = table[f"{PAGES}/{COMMUNITY_ADULT}"]
    gambling = table[f"{PAGES}/{COMMUNITY_GAMBLING}"]
    require(all(kind == "DOMAIN-SUFFIX" and "." in host for kind, host in gambling),
            "Unexpected gambling match type")
    require(any(route(host) == "PROXY" for _, host in adult if not in_set(gambling, host)),
            "No adult-only domain matched PROXY")
    overlap = next((host for _, host in adult if in_set(gambling, host)), None)
    if overlap:
        require(route(overlap) == route("sub." + overlap) == "REJECT",
                "Gambling must reject overlapping categories and their subdomains")


def waimao_check(files, policy):
    """The trade variant must equal the baseline except for the group sections and retargeted business rows."""
    group = policy["waimao"]["group"]
    raw = files["dist/stable/shadowrocket-waimao.conf"].decode()
    lines = [line for line in raw.splitlines() if line and not line.startswith("#")]
    require(lines == shadowrocket(policy, waimao=True).splitlines(), "Shadowrocket trade variant differs from policy")
    base = shadowrocket(policy).splitlines()
    start = lines.index("[Rule]")
    head, rules = lines[:start], lines[start:]
    test = "url=https://www.gstatic.com/generate_204,timeout=5"
    require(head[:3] == ["[General]", "close-if-proxy-chain-missing = true", "[Proxy Group]"]
            # Only the 外贸 group ships: Shadowrocket's proxy chain cannot point at a group, so each device
            # sets 外贸-中转's chain to a concrete HK/JP node by hand.
            and head[3] == f"{group} = fallback,{group}-直连,{group}-中转,interval=60,{test}"
            and len(head) == 4,
            "Unexpected trade variant groups")
    # No node may ship in the public file: the trade nodes are added on each device.
    require(not any(line.startswith("[") and line not in ("[General]", "[Proxy Group]", "[Rule]") for line in lines),
            "Unexpected section in trade variant")
    business = {host for row in policy["sets"] if row["policy"] == "proxy" and row.get("waimao")
                for host in row["domains"]}
    extra = [line for line in rules if line not in base]
    require(extra == [line for line in rules if line.endswith("," + group)]
            and all(line.rsplit(",", 1)[0].split(",", 1)[1] in {*(h.removeprefix("+.") for h in business),
                                                               *(h.removeprefix("+.") for h in policy["waimao"]["domains"])}
                    for line in extra), "Trade variant retargets an unlisted host")
    # Pointing the group back at PROXY and dropping the trade-only hosts must give the baseline exactly.
    trade_only = {domain_rule(host) + "," + group for host in policy["waimao"]["domains"]}
    require([line.removesuffix("," + group) + ",PROXY" if line.endswith("," + group) else line
             for line in rules if line not in trade_only] == base,
            "Trade variant changed a non-business route")
    require(rules[-1] == "FINAL,DIRECT" and "DOMAIN-SUFFIX,github.com,PROXY" in rules
            and "DOMAIN-SUFFIX,youtube.com,PROXY" in rules and "DOMAIN,web.telegram.org,PROXY" in rules,
            "Trade variant must keep GitHub, YouTube and Telegram on PROXY and the direct fallback")
    for host in ("chatgpt.com", "api.openai.com", "claude.ai", "www.linkedin.com", "web.whatsapp.com",
                 "mail.google.com", "gemini.google.com", "www.perplexity.ai", "grok.com"):
        first = next(line for line in rules[1:] if (lambda kind, item: host == item or (
            kind == "DOMAIN-SUFFIX" and host.endswith("." + item)))(*line.split(",")[:2])
            and line.split(",")[0] in {"DOMAIN", "DOMAIN-SUFFIX"})
        require(first.endswith("," + group), f"Trade sample not routed to the group: {host}")
    for host, outcome in (("us-east-1.quick.aws", group), ("mail.google.com", group),
                          ("youtubei.googleapis.com", "PROXY"), ("i.ytimg.com", "PROXY"),
                          ("www.youtube.com", "PROXY"), ("dl.google.com", "PROXY"),
                          ("storage.googleapis.com", "PROXY")):
        first = next(line for line in rules[1:] if line.split(",")[0] in {"DOMAIN", "DOMAIN-SUFFIX"}
                     and (lambda kind, item: host == item or (kind == "DOMAIN-SUFFIX" and host.endswith("." + item)))(
                         *line.split(",")[:2]))
        require(first.endswith("," + outcome), f"Trade variant first match for {host} must be {outcome}")


def filter_check(policy):
    candidate = deepcopy(policy)
    candidate["ad_exceptions"] = ["github.com", "+.example.com"]
    candidate["threat_exceptions"] = ["www.baidu.com"]
    ads = "AND,(({source}),(NOT,((OR,((DOMAIN,github.com),(DOMAIN-SUFFIX,example.com)))))),REJECT"
    threat = "AND,(({source}),(NOT,((DOMAIN,www.baidu.com)))),REJECT"
    sources = {
        "threat": ("RULE-SET,soho-threat", "DOMAIN-SET," + threat_source(policy)),
        "ads": ("RULE-SET,soho-ads", "RULE-SET," + data_url(policy, "meta-ads.list")),
    }
    for ads_enabled, threat_enabled, allowlist_enabled in product((False, True), repeat=3):
        enabled = {"threat": threat_enabled, "ads": ads_enabled}
        candidate["modules"] = {
            name: {"enabled": value} for name, value in (*enabled.items(), ("allowlist", allowlist_enabled))
        }
        merge = windows(candidate)
        mobile = shadowrocket(candidate).splitlines()[1:]
        for rules, platform in ((merge["rules"], 0), (mobile, 1)):
            expected = []
            for module, is_enabled in enabled.items():
                source = sources[module][platform]
                if is_enabled:
                    template = ads if module == "ads" else threat
                    expected.append(template.format(source=source) if allowlist_enabled else source + ",REJECT")
                else:
                    require(all(source not in line for line in rules), f"Disabled filter referenced: {module}")
            gambling = ("RULE-SET,soho-gambling,REJECT" if platform == 0 else
                        f"RULE-SET,{PAGES}/{COMMUNITY_GAMBLING},REJECT")
            require(rules[:1+len(expected)] == [*expected, gambling], "Filter or exception order changed")
        for module, provider in FILTERS.items():
            require((provider in merge["rule-providers"]) == enabled[module], f"Unexpected provider: {module}")
        require("DOMAIN-SUFFIX,github.com,PROXY" in mobile and "DOMAIN,github.com,DIRECT" not in mobile
                and "DOMAIN-SUFFIX,microsoft.com,DIRECT" in mobile and mobile[-1] == "FINAL,DIRECT",
                "Filter switches changed independent business routes")


def check(files):
    policy = json.loads(files["rules/policy.json"])
    directory = "dist/data/" + policy["data_version"]
    allow = ROOT_FILES | OTHER_FILES | CONFIGS | COMMUNITY_FILES | {f"{directory}/{name}" for name in ASSETS}
    if set(files) != allow:
        raise ValueError(f"Unexpected paths: {sorted(set(files)-allow)}; missing paths: {sorted(allow-set(files))}")
    require(sha256(files["LICENSE"]).hexdigest() == POLYFORM_SHA256, "Official PolyForm license mismatch")
    require(sha256(files[directory + "/LICENSE"]).hexdigest() == GPL_SHA256, "Upstream GPL license mismatch")
    notice = files[directory + "/THIRD_PARTY_NOTICES.md"]
    mit_blocks = re.findall(rb"^```text\n(.*?)^```$", notice, re.MULTILINE | re.DOTALL)
    require(len(mit_blocks) == 2 and {sha256(block).hexdigest() for block in mit_blocks} == MIT_NOTICE_SHA256,
            "Missing or modified full-text MIT notices")
    manifest = json.loads(files[directory + "/SHA256.json"])
    require(set(manifest) == {"tif-mini.mrs", "meta-ads.list", "meta-international.list"}, "Unexpected data artifacts")
    for filename, entry in manifest.items():
        data = files[f"{directory}/{filename}"]
        require(len(data) == entry["bytes"] and sha256(data).hexdigest() == entry["sha256"], f"Data checksum mismatch: {filename}")
    require(manifest["tif-mini.mrs"]["sha256"] == policy["threat_mrs_sha256"], "Unaudited binary digest")
    require(files[directory + "/tif-mini.mrs"].startswith(bytes.fromhex("28b52ffd")), "Unexpected MRS container")
    for path, data in files.items():
        if path == directory + "/tif-mini.mrs":
            continue
        body = data.decode("utf-8")
        if "\0" in body:
            raise ValueError(f"Unexpected binary content in {path}")
        findings = set(scan(body))
        if path == f"dist/{COMMUNITY_GAMBLING}":
            # The published list contains UUID-shaped hostnames. Every line is
            # independently checked as a strict domain suffix below.
            findings.discard("node UUID")
        if findings:
            raise ValueError(f"{path}: {', '.join(sorted(findings))}")

    merge = yaml.safe_load(files["dist/stable/mihomo-merge.yaml"])
    require(merge == windows(policy), "Mihomo differs from policy")
    require(set(merge) == {"find-process-mode", "proxy-groups", "rule-providers", "rules"}, "Unexpected Merge settings")
    proxy, glob, business = merge["proxy-groups"]
    require(proxy["name"] == "PROXY" and glob == {"name": "GLOBAL", "type": "select", "proxies": ["PROXY"], "empty-fallback": "REJECT"}
            and proxy["type"] == "select" and proxy["proxies"] == ["REJECT"] and proxy["empty-fallback"] == "REJECT"
            and proxy["default-selected"] == "REJECT"
            and business == {"name": policy["waimao"]["group"], "type": "select", "proxies": ["PROXY"]},
            "Unsafe selector")
    providers = list(merge["rule-providers"].values())
    online = [provider for provider in providers if provider["type"] == "http"]
    community = community_providers(policy)
    filters = filter_settings(policy)
    expected_online = len(policy["sets"]) + len(community) + 1 - (len(FILTERS) - len(filters))
    approved_text = {HULU_JAPAN, f"{PAGES}/{COMMUNITY_GAMBLING}", f"{PAGES}/{TELEGRAM_IPS}",
                     *(url for _, url, _ in community)}
    require(len(providers) == expected_online + 4 and len(online) == expected_online and
            all(row["url"].startswith("https://") and
                (row["format"] == "mrs" or (row["url"] in approved_text and row["behavior"] == "classical"
                                            and row["format"] == "text")) and row["proxy"] == "PROXY"
                and row["interval"] == 86400 and row["path"].startswith("./rule-providers/soho-public/") for row in online),
            "Bad provider inventory")
    for row in online:
        if row["url"].startswith(PAGES + "/"):
            require("dist/" + row["url"].removeprefix(PAGES + "/") in files, "Missing Pages rule artifact")
    rules = merge["rules"]
    require(rules[-1] == "MATCH," + policy["windows_fallback"] and sum(row.startswith("MATCH,") for row in rules) == 1, "Unexpected final rule")
    prefix = [filter_rule(f"RULE-SET,{FILTERS[module]}", exceptions) for module, exceptions in filters.items()]
    require(rules[:1+len(prefix)] == [*prefix, "RULE-SET,soho-gambling,REJECT"],
            "Mihomo filters and gambling must precede business routing")
    telegram_rules = telegram_ip_rules(policy, "soho-telegram-ip", ("PROXY", "REJECT"))
    start = rules.index(telegram_rules[0])
    require(rules[start:start+len(telegram_rules)] == telegram_rules
            and start + len(telegram_rules) <= rules.index("RULE-SET,soho-cn,DIRECT"),
            "Telegram IP rules must proxy or reject before general direct routes")
    adult = rules.index("RULE-SET,soho-adult,PROXY")
    require(rules[adult + 1] == "RULE-SET,soho-adult,REJECT"
            and adult < rules.index("RULE-SET,soho-cn,DIRECT"),
            "Adult provider must follow block rules and precede broad direct routes")
    supplemental = [row["source"] for row in policy["sets"] if row["policy"] == "proxy_supplement"]
    tail = [f"RULE-SET,{source},{action}" for source in supplemental for action in ("PROXY", "REJECT")]
    for name, _, outcome in community:
        tail.append(f"RULE-SET,{name},{outcome}")
        if outcome == "PROXY":
            tail.append(f"RULE-SET,{name},REJECT")
    require(rules[-1-len(tail):-1] == tail,
            "Additional categories must follow existing routes and reject unmatched proxy transport")
    # Narrow before broad: YouTube and listed PROXY hosts precede the business suffixes (+.googleapis.com,
    # +.google.com); business rows match by name only, since the trade exit is IPv4-only server-side.
    group = policy["waimao"]["group"]
    early = rules.index("OR,((RULE-SET,soho-core-international),(RULE-SET,soho-youtube)),PROXY")
    require(early < rules.index("RULE-SET,soho-waimao-international," + group)
            < next(i for i, row in enumerate(rules) if "RULE-SET,soho-google" in row and row.endswith("," + group)),
            "YouTube and listed PROXY hosts must precede business routing")
    hosts = merge["rule-providers"]["soho-core-international"]["payload"]
    require(all(host in hosts for host in ("dl.google.com", "dl.l.google.com", "storage.googleapis.com")),
            "Large Google downloads must stay on PROXY")
    require(not any(row.endswith("," + group) and "0.0.0.0/0" in row for row in rules),
            "Business rows must not force a local IPv4 lookup")
    shadowrocket_check(files, directory, policy)
    waimao_check(files, policy)
    filter_check(policy)
    print(f"Checked {len(files)} approved files, license texts, providers and Shadowrocket sample routes.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--staged", action="store_true", help="Read verified bytes from the Git index")
    args = parser.parse_args()
    check(dict(inventory(args.staged)))
