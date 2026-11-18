"""Render both public configurations from the reviewed policy."""

import argparse
import json
from pathlib import Path
import re

import yaml


ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "rules/policy.json"
META = "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat"
HAGEZI = "https://raw.githubusercontent.com/hagezi/dns-blocklists"
PAGES = "https://sam-lumina.github.io/soho-network-rules"
COMMUNITY_DATA = "data/community-v1"
COMMUNITY_MEDIA = f"{COMMUNITY_DATA}/media.list"
COMMUNITY_ADULT = f"{COMMUNITY_DATA}/adult.list"
COMMUNITY_GAMBLING = f"{COMMUNITY_DATA}/gambling.list"
COMMUNITY_PROXY = f"{COMMUNITY_DATA}/services-proxy.list"
COMMUNITY_DIRECT = f"{COMMUNITY_DATA}/services-direct.list"
ACL = "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset"
PACKAGE = r"(?i)^C:\\Program Files\\WindowsApps\\OpenAI\.Codex_"
SIGNED_FAMILY = r"[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+_x64__2p2nqsd0c76g0\\app\\"


def logic(operator, *conditions):
    return operator + ",(" + ",".join("(" + condition + ")" for condition in conditions) + ")"


def domain_rule(token):
    if token.startswith("+."):
        return "DOMAIN-SUFFIX," + token[2:]
    return "DOMAIN," + token


def threat_source(policy):
    return f"{HAGEZI}/{policy['threat_snapshot']}/wildcard/tif.mini-onlydomains.txt"


def data_url(policy, path):
    return f"{PAGES}/data/{policy['data_version']}/{path}"


def community_providers(policy):
    """Keep the additional service routes in the same order on both clients."""
    routes = [
        ("soho-services-direct", f"{PAGES}/{COMMUNITY_DIRECT}", "DIRECT"),
        ("soho-services-proxy", f"{PAGES}/{COMMUNITY_PROXY}", "PROXY"),
    ]
    names = policy["community"]["proxy_acl"]
    if any(not re.fullmatch(r"[A-Za-z0-9]+", name) for name in names):
        raise ValueError("Invalid ACL4SSR rule filename")
    routes.extend((f"soho-acl-{name.lower()}", f"{ACL}/{name}.list", "PROXY") for name in names)
    return routes


def text_provider(name, url):
    return {
        "type": "http", "behavior": "classical", "format": "text",
        "path": f"./rule-providers/soho-public/{name.removeprefix('soho-')}.list",
        "url": url, "proxy": "PROXY", "interval": 86400,
    }


def windows(policy):
    providers = {}
    for row in policy["sets"]:
        name = row["source"]
        if "text_url" in row:
            providers[name] = text_provider(name, row["text_url"])
            continue
        address = data_url(policy, "tif-mini.mrs") if row["kind"] == "threat" else f"{META}/meta/{row['meta_path']}"
        providers[name] = {
            "type": "http",
            "behavior": "ipcidr" if row["kind"] == "ipcidr" else "domain",
            "format": "mrs",
            "path": f"./rule-providers/soho-public/{name.removeprefix('soho-')}.mrs",
            "url": address,
            "proxy": "PROXY",
            "interval": 86400,
        }
        if "meta_path" in row:
            providers[name]["path-in-bundle"] = row["meta_path"]

    community = community_providers(policy)
    providers.update((name, text_provider(name, url)) for name, url, _ in community)
    protected = {}
    for ipv4, key in ((True, "soho-core-ipv4"), (False, "soho-core-international")):
        rows = [row for row in policy["sets"] if row["policy"] == "proxy" and row["windows_ipv4_only"] == ipv4]
        hosts = [value for row in rows for value in row["domains"]]
        if not ipv4:
            hosts.extend(policy["proxy_exceptions"])
        providers[key] = {"type": "inline", "behavior": "domain", "payload": list(dict.fromkeys(hosts))}
        protected[ipv4] = logic("OR", "RULE-SET," + key, *("RULE-SET," + row["source"] for row in rows))

    # Public P2.9 retains the P2.8 rule order and exact Windows package allowlist.
    if policy["ad_exceptions"]:
        raise ValueError("Review an exact ad exception on both clients before enabling it.")
    rules = [f"RULE-SET,{row['source']},REJECT" for row in policy["sets"] if row["policy"] == "reject"]
    ipv4 = "IP-CIDR,0.0.0.0/0"
    for process in (r"ChatGPT\.exe$", r"resources\\codex\.exe$"):
        rules.append(logic("AND", "PROCESS-PATH-REGEX," + PACKAGE + SIGNED_FAMILY + process, protected[True], ipv4) + ",PROXY")
    rules += [
        "PROCESS-PATH-REGEX," + PACKAGE + r"[^\\]+\\,REJECT",
        "PROCESS-NAME,ChatGPT.exe,REJECT",
        "PROCESS-NAME,codex.exe,REJECT",
        logic("AND", protected[True], ipv4) + ",PROXY",
        protected[True] + ",REJECT",
    ]
    rules += [domain_rule(host) + ",DIRECT" for host in policy["direct_exceptions"]]
    rules += [protected[False] + ",PROXY", protected[False] + ",REJECT"]
    for row in policy["sets"]:
        if row["policy"] == "proxy_category":
            rules.extend(f"RULE-SET,{row['source']},{action}" for action in ("PROXY", "REJECT"))
    for row in policy["sets"]:
        if row["policy"] == "direct":
            suffix = ",no-resolve" if row["kind"] == "ipcidr" else ""
            rules.append("RULE-SET," + row["source"] + ",DIRECT" + suffix)
    for row in policy["sets"]:
        if row["policy"] == "proxy_supplement":
            rules.append("RULE-SET," + row["source"] + ",PROXY")
            rules.append("RULE-SET," + row["source"] + ",REJECT")
    for name, _, outcome in community:
        rules.append(f"RULE-SET,{name},{outcome}")
        if outcome == "PROXY":
            rules.append(f"RULE-SET,{name},REJECT")
    rules.append("MATCH," + policy["fallback"])
    return {
        "find-process-mode": "strict",
        "proxy-groups": [
            {"name": "PROXY", "type": "select", "proxies": ["REJECT"], "include-all-proxies": True,
             "include-all-providers": True, "exclude-type": "Direct|Compatible",
             "default-selected": "REJECT", "empty-fallback": "REJECT"},
            {"name": "GLOBAL", "type": "select", "proxies": ["PROXY"], "empty-fallback": "REJECT"},
        ],
        "rule-providers": providers,
        "rules": rules,
    }


def shadowrocket(policy):
    rows = [row for row in policy["sets"] if row["policy"] == "proxy"]
    rules = [
        "[Rule]",
        "DOMAIN-SET," + threat_source(policy) + ",REJECT",
        "RULE-SET," + data_url(policy, "meta-ads.list") + ",REJECT",
    ]
    if any(row.get("hagezi_path") for row in policy["sets"]):
        rules.append(f"RULE-SET,{PAGES}/{COMMUNITY_GAMBLING},REJECT")
    for ipv4_only in (True, False):
        if not ipv4_only:
            rules.extend(domain_rule(host) + ",DIRECT" for host in policy["direct_exceptions"])
        rules.extend(domain_rule(host) + ",PROXY" for row in rows if row["windows_ipv4_only"] == ipv4_only
                     for host in row["domains"])
    rules.extend(domain_rule(host) + ",PROXY" for host in policy["proxy_exceptions"])
    rules += [
        "RULE-SET," + data_url(policy, "meta-international.list") + ",PROXY",
    ]
    if any(row["policy"] == "proxy_category" for row in policy["sets"]):
        rules.append(f"RULE-SET,{PAGES}/{COMMUNITY_ADULT},PROXY")
    rules += [
        "DOMAIN-SUFFIX,microsoft.com,DIRECT",
        "DOMAIN-SUFFIX,windowsupdate.com,DIRECT",
    ]
    if any(row.get("shadowrocket_media") for row in policy["sets"]):
        rules.append(f"RULE-SET,{PAGES}/{COMMUNITY_MEDIA},PROXY")
    rules.extend("RULE-SET," + url + ",PROXY"
                 for row in policy["sets"] for url in row.get("shadowrocket_urls", ()))
    rules.extend(f"RULE-SET,{url},{outcome}" for _, url, outcome in community_providers(policy))
    rules.append("FINAL," + policy["fallback"])
    return "\n".join(rules) + "\n"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="Check that dist matches the shared policy")
    args = parser.parse_args()
    policy = json.loads(POLICY.read_bytes())
    notice = "# SOHO Network Rules | PolyForm-Noncommercial-1.0.0\n"
    url = "# https://polyformproject.org/licenses/noncommercial/1.0.0\n"
    stable = ROOT / "dist/stable"
    generated = {
        "mihomo-merge.yaml": notice + url + "# Clash Verge Rev subscription-level Merge; install over your own profile.\n"
                             + yaml.safe_dump(windows(policy), sort_keys=False, width=1000),
        "shadowrocket.conf": notice + url + "# FORMAT VERIFIED / LIVE TEST PENDING\n" + shadowrocket(policy),
    }
    for name, body in generated.items():
        path = stable / name
        expected = body.encode()
        if args.check:
            if not path.is_file() or path.read_bytes() != expected:
                raise SystemExit(f"Generated output differs: {name}")
        else:
            stable.mkdir(parents=True, exist_ok=True)
            path.write_bytes(expected)


if __name__ == "__main__":
    main()
