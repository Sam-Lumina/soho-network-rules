"""Check the public worktree or the exact Git index contents. Never print a match."""

import argparse
import base64
import binascii
from hashlib import sha256
import json
from pathlib import Path
import re
import subprocess
from urllib.parse import parse_qsl, urlsplit

import yaml

from build_configs import PAGES, COMMUNITY_MEDIA


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
CONFIGS = {"dist/stable/mihomo-merge.yaml", "dist/stable/shadowrocket.conf"}
COMMUNITY_FILES = {f"dist/{COMMUNITY_MEDIA}", "dist/data/community-v1/SOURCE.md", "dist/data/community-v1/SHA256.json"}
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
    "wiki.metacubex.one", "docs.github.com", "example.com",
}
SENSITIVE_FIELDS = r"password|passwd|token|client[_-]?secret|secret|authorization|api[_-]?key|private[_-]?key|uuid|cookie|short[_-]?id"
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


def content_findings(body):
    for name, pattern in PATTERNS.items():
        if pattern.search(body):
            yield name
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
    config = [line.split(",") for line in raw.splitlines() if line and not line.startswith("#")]
    require(config[0] == ["[Rule]"] and config[-1] == ["FINAL", "DIRECT"], "Shadowrocket section or final route")
    require(sum(row[0] == "FINAL" for row in config) == 1, "Shadowrocket final route count")
    require(sum(row[0] == "DOMAIN-SET" for row in config) == 1, "Shadowrocket threat provider")
    table = {}
    for leaf in ("meta-ads.list", "meta-international.list"):
        table[f"{PAGES}/{directory.removeprefix('dist/')}/{leaf}"] = [
            row.split(",") for row in files[f"{directory}/{leaf}"].decode().splitlines()
        ]
        require(all(len(row) == 2 and row[0] in {"DOMAIN", "DOMAIN-SUFFIX"} and valid_domain(row[1])
                    for row in table[f"{PAGES}/{directory.removeprefix('dist/')}/{leaf}"]), "Malformed Shadowrocket external rules")
    community = files[f"dist/{COMMUNITY_MEDIA}"]
    media = json.loads(files["dist/data/community-v1/SHA256.json"])["media.list"]
    require(sha256(community).hexdigest() == media["sha256"] and len(community) == media["bytes"],
            "Community media checksum mismatch")
    table[f"{PAGES}/{COMMUNITY_MEDIA}"] = [line.split(",") for line in community.decode().splitlines()]
    require(all(len(row) == 2 and row[0] in {"DOMAIN", "DOMAIN-SUFFIX"} and valid_domain(row[1])
                for row in table[f"{PAGES}/{COMMUNITY_MEDIA}"]), "Malformed community media list")
    upstream = {url for row in policy["sets"] for url in row.get("shadowrocket_urls", ())}
    require(upstream == {HULU_JAPAN, *{
                f"https://raw.githubusercontent.com/poohyeban/shadowrocket-rules/main/rules/{name}/{name}.list"
                for name in ("Facebook", "Instagram")}},
            "Unreviewed Shadowrocket community rule source")
    for row in config[1:-1]:
        require(len(row) == 3 and row[-1] in {"DIRECT", "PROXY", "REJECT"}, "Malformed Shadowrocket rule")
        kind, item, outcome = row
        if kind == "DOMAIN-SET":
            require(outcome == "REJECT" and item ==
                    f"https://raw.githubusercontent.com/hagezi/dns-blocklists/{policy['threat_snapshot']}/wildcard/tif.mini-onlydomains.txt",
                    "Unexpected Shadowrocket threat source")
        elif kind == "RULE-SET":
            require(item in table or (item in upstream and outcome == "PROXY"), "Unknown Shadowrocket external rule list")
        else:
            require(kind in {"DOMAIN", "DOMAIN-SUFFIX"} and valid_domain(item), "Unknown Shadowrocket rule type")

    def matches(kind, name, host):
        return host == name or (kind == "DOMAIN-SUFFIX" and host.endswith("." + name))

    def route(host):
        # External DOMAIN-SET loading is validated on-device. Check first-match order for local data.
        for rule in config[1:]:
            if rule[0] == "FINAL":
                return rule[1]
            kind, target, action = rule
            if kind == "RULE-SET" and any(matches(*entry, host) for entry in table.get(target, ())):
                return action
            if kind in {"DOMAIN", "DOMAIN-SUFFIX"} and matches(kind, target, host):
                return action
        raise ValueError("Shadowrocket rules have no final match")

    cases = {
        "PROXY": ("chatgpt.com", "api.openai.com", "github.com", "www.google.com", "mail.google.com", "www.youtube.com",
                  "web.telegram.org", "x.com", "www.linkedin.com", "web.whatsapp.com", "claude.ai", "grok.com",
                  "muse.ai", "auth.muse.ai", "www.facebook.com", "www.instagram.com", "auth.meta.com",
                  "www.netflix.com", "open.spotify.com", "www.twitch.tv", "www.formula1.com"),
        "DIRECT": ("www.baidu.com", "www.taobao.com", "fe2cr.update.microsoft.com", "licdn.cn.cdn20.com", "soho-test.invalid"),
        "REJECT": ("doubleclick.net", "googlesyndication.com"),
    }
    for action, hosts in cases.items():
        require(all(route(host) == action for host in hosts), f"Shadowrocket sample mismatch for {action}")


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
        if findings:
            raise ValueError(f"{path}: {', '.join(sorted(findings))}")

    merge = yaml.safe_load(files["dist/stable/mihomo-merge.yaml"])
    require(set(merge) == {"find-process-mode", "proxy-groups", "rule-providers", "rules"}, "Unexpected Merge settings")
    proxy, glob = merge["proxy-groups"]
    require(proxy["name"] == "PROXY" and glob == {"name": "GLOBAL", "type": "select", "proxies": ["PROXY"], "empty-fallback": "REJECT"}
            and proxy["type"] == "select" and proxy["proxies"] == ["REJECT"] and proxy["empty-fallback"] == "REJECT"
            and proxy["default-selected"] == "REJECT", "Unsafe selector")
    providers = list(merge["rule-providers"].values())
    online = [provider for provider in providers if provider["type"] == "http"]
    require(len(providers) == len(policy["sets"]) + 2 and len(online) == len(policy["sets"]) and
            all(row["url"].startswith("https://") and
                (row["format"] == "mrs" or (row["url"] == HULU_JAPAN and row["behavior"] == "classical"
                                            and row["format"] == "text")) and row["proxy"] == "PROXY"
                and row["interval"] == 86400 and row["path"].startswith("./rule-providers/soho-public/") for row in online),
            "Bad provider inventory")
    for row in online:
        if row["url"].startswith(PAGES + "/"):
            require("dist/" + row["url"].removeprefix(PAGES + "/") in files, "Missing Pages rule artifact")
    rules = merge["rules"]
    require(rules[-1] == "MATCH,DIRECT" and sum(row.startswith("MATCH,") for row in rules) == 1, "Unexpected final rule")
    supplemental = [row["source"] for row in policy["sets"] if row["policy"] == "proxy_supplement"]
    require(rules[-1 - 2*len(supplemental):-1] ==
            [f"RULE-SET,{source},{action}" for source in supplemental for action in ("PROXY", "REJECT")],
            "Community rules must follow existing routes and reject when proxy cannot carry a match")
    shadowrocket_check(files, directory, policy)
    print(f"Checked {len(files)} approved files, license texts, providers and Shadowrocket sample routes.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--staged", action="store_true", help="Read verified bytes from the Git index")
    args = parser.parse_args()
    check(dict(inventory(args.staged)))
