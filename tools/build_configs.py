"""Render both public configurations from the reviewed policy."""

import argparse
from ipaddress import ip_network
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
TELEGRAM_IPS = f"{COMMUNITY_DATA}/telegram-ip.list"
ACL = "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset"
PACKAGE = r"(?i)^C:\\Program Files\\WindowsApps\\OpenAI\.Codex_"
SIGNED_FAMILY = r"[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+_x64__2p2nqsd0c76g0\\app\\"
FILTERS = {"threat": "soho-threat", "ads": "soho-ads"}
LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
EXCEPTION_DOMAIN = re.compile(rf"{LABEL}(?:\.{LABEL})+")


def logic(operator, *conditions):
    return operator + ",(" + ",".join("(" + condition + ")" for condition in conditions) + ")"


def domain_rule(token):
    if token.startswith("+."):
        return "DOMAIN-SUFFIX," + token[2:]
    return "DOMAIN," + token


def filter_settings(policy):
    """Return active filters and the domain conditions they exempt."""
    modules = policy["modules"]
    for name in (*FILTERS, "allowlist"):
        if type(modules[name]["enabled"]) is not bool:
            raise ValueError(f"modules.{name}.enabled must be a JSON boolean")
    active = {}
    for module, key in (("threat", "threat_exceptions"), ("ads", "ad_exceptions")):
        entries = policy[key]
        if not isinstance(entries, list):
            raise ValueError(f"{key} must be a list of domains")
        for entry in entries:
            if not isinstance(entry, str):
                raise ValueError(f"Invalid domain in {key}")
            host = entry.removeprefix("+.")
            if len(host) > 253 or not EXCEPTION_DOMAIN.fullmatch(host) or host.rsplit(".", 1)[-1].isdigit():
                raise ValueError(f"Invalid domain in {key}")
        if modules[module]["enabled"]:
            enabled_entries = entries if modules["allowlist"]["enabled"] else []
            active[module] = tuple(domain_rule(entry) for entry in dict.fromkeys(enabled_entries))
    return active


def filter_rule(selector, exceptions):
    # Negate only this filter's match, then let subsequent rules decide the route.
    if exceptions:
        excluded = exceptions[0] if len(exceptions) == 1 else logic("OR", *exceptions)
        selector = logic("AND", selector, logic("NOT", excluded))
    return selector + ",REJECT"


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


def ip_rule(prefix):
    network = ip_network(prefix)
    kind = "IP-CIDR" if network.version == 4 else "IP-CIDR6"
    return f"{kind},{network}"


def telegram_ip_rules(policy, target, actions):
    selectors = [f"RULE-SET,{target}", *(ip_rule(prefix) for prefix in policy["telegram_ips"]["fallback"])]
    return [f"{selector},{action},no-resolve" for selector in selectors for action in actions]


def windows(policy):
    filters = filter_settings(policy)
    excluded = {source for module, source in FILTERS.items() if module not in filters}
    providers = {}
    for row in policy["sets"]:
        name = row["source"]
        if name in excluded:
            continue
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
    providers["soho-telegram-ip"] = text_provider("soho-telegram-ip", f"{PAGES}/{TELEGRAM_IPS}")
    # Business accounts use the "waimao" group. Public Stable points it at PROXY; a private layer may replace it.
    waimao = policy["waimao"]["group"]
    proxy_rows = [row for row in policy["sets"] if row["policy"] == "proxy"]
    names = {}
    for ipv4, keys in ((True, ("soho-core-ipv4", "soho-waimao-ipv4")),
                       (False, ("soho-core-international", "soho-waimao-international"))):
        for key, business in zip(keys, (False, True)):
            rows = [row for row in proxy_rows
                    if row["windows_ipv4_only"] == ipv4 and bool(row.get("waimao")) == business]
            hosts = [value for row in rows for value in row["domains"]]
            if not ipv4:
                hosts.extend(policy["waimao"]["domains"] if business else policy["proxy_exceptions"])
            providers[key] = {"type": "inline", "behavior": "domain", "payload": list(dict.fromkeys(hosts))}
            names[ipv4, business] = [key, *(row["source"] for row in rows)]

    def any_set(sources):
        selectors = ["RULE-SET," + source for source in sources]
        return selectors[0] if len(selectors) == 1 else logic("OR", *selectors)

    rules = [filter_rule(f"RULE-SET,{FILTERS[module]}", exceptions) for module, exceptions in filters.items()]
    rules.extend(f"RULE-SET,{row['source']},REJECT" for row in policy["sets"]
                 if row["policy"] == "reject" and row["source"] not in FILTERS.values())
    ipv4 = "IP-CIDR,0.0.0.0/0"
    desktop = "PROCESS-PATH-REGEX," + PACKAGE + SIGNED_FAMILY + r"ChatGPT\.exe$"
    cli = "PROCESS-PATH-REGEX," + PACKAGE + SIGNED_FAMILY + r"resources\\codex\.exe$"
    package = "PROCESS-PATH-REGEX," + PACKAGE + r"[^\\]+\\"
    # The embedded browser shares ChatGPT.exe, so let that exact executable fall through to business routing.
    guarded = logic("OR", package, "PROCESS-NAME,ChatGPT.exe")
    v4_proxy, v4_waimao = any_set(names[True, False]), any_set(names[True, True])
    rules += [
        logic("AND", cli, v4_waimao, ipv4) + "," + waimao,
        logic("AND", cli, v4_proxy, ipv4) + ",PROXY",
        logic("AND", guarded, logic("NOT", desktop)) + ",REJECT",
        logic("AND", v4_waimao, ipv4) + "," + waimao,
        logic("AND", v4_proxy, ipv4) + ",PROXY",
        any_set(names[True, False] + names[True, True]) + ",REJECT",
    ]
    rules += [domain_rule(host) + ",DIRECT" for host in policy["direct_exceptions"]]
    # Listed business hosts first, then PROXY categories (YouTube before Google), then business categories.
    business_hosts, *business_sets = names[False, True]
    for selector, outcome in ((any_set([business_hosts]), waimao), (any_set(names[False, False]), "PROXY"),
                              (any_set(business_sets), waimao)):
        rules += [selector + "," + outcome, selector + ",REJECT"]
    rules.extend(telegram_ip_rules(policy, "soho-telegram-ip", ("PROXY", "REJECT")))
    for row in policy["sets"]:
        if row["policy"] == "proxy_category":
            rules.extend(f"RULE-SET,{row['source']},{action}" for action in ("PROXY", "REJECT"))
    for row in policy["sets"]:
        if row["policy"] == "direct":
            if row["kind"] == "ipcidr":
                # Match business AI categories by name before the China IP check resolves them locally.
                for extra in policy["sets"]:
                    if extra["policy"] == "waimao_supplement":
                        rules += [f"RULE-SET,{extra['source']},{waimao}", f"RULE-SET,{extra['source']},REJECT"]
            # Resolve unmatched hosts so servers inside China stay direct before the proxy fallback.
            rules.append("RULE-SET," + row["source"] + ",DIRECT")
    for row in policy["sets"]:
        if row["policy"] == "proxy_supplement":
            rules.append("RULE-SET," + row["source"] + ",PROXY")
            rules.append("RULE-SET," + row["source"] + ",REJECT")
    for name, _, outcome in community:
        rules.append(f"RULE-SET,{name},{outcome}")
        if outcome == "PROXY":
            rules.append(f"RULE-SET,{name},REJECT")
    rules.append("MATCH," + policy["windows_fallback"])
    return {
        "find-process-mode": "strict",
        "proxy-groups": [
            {"name": "PROXY", "type": "select", "proxies": ["REJECT"], "include-all-proxies": True,
             "include-all-providers": True, "exclude-type": "Direct|Compatible",
             "default-selected": "REJECT", "empty-fallback": "REJECT"},
            {"name": "GLOBAL", "type": "select", "proxies": ["PROXY"], "empty-fallback": "REJECT"},
            {"name": waimao, "type": "select", "proxies": ["PROXY"]},
        ],
        "rule-providers": providers,
        "rules": rules,
    }


# Trade-group variant only: relay pool picks the subscription's HK/JP nodes, minus the ones that bill extra,
# IPv6-only, backup or info entries, and the device's own trade nodes. No commas: Shadowrocket splits on them.
RELAY_FILTER = r"^(?=.*(香港|日本))(?!.*(1\.5X|家宽|V6|备用|剩余|到期|官网|邮箱|外贸)).*$"


def shadowrocket_groups(policy):
    """Sections for the trade-group variant. The two trade nodes are added by hand on each device."""
    group = policy["waimao"]["group"]
    test = "url=https://www.gstatic.com/generate_204,timeout=5"
    return "\n".join([
        "[General]",
        "close-if-proxy-chain-missing = true",
        "[Proxy Group]",
        f"{group} = fallback,{group}-直连,{group}-中转,interval=60,{test}",
        f"{group}中转池 = fallback,policy-regex-filter={RELAY_FILTER},interval=300,{test}",
    ]) + "\n"


def shadowrocket(policy, waimao=False):
    """waimao=True keeps every rule and only retargets business rows (plus the listed trade hosts) at the group."""
    business = policy["waimao"]["group"] if waimao else "PROXY"
    rows = [row for row in policy["sets"] if row["policy"] == "proxy"]
    selectors = {"threat": "DOMAIN-SET," + threat_source(policy),
                 "ads": "RULE-SET," + data_url(policy, "meta-ads.list")}
    rules = ["[Rule]"]
    rules.extend(filter_rule(selectors[module], exceptions)
                 for module, exceptions in filter_settings(policy).items())
    if any(row.get("hagezi_path") for row in policy["sets"]):
        rules.append(f"RULE-SET,{PAGES}/{COMMUNITY_GAMBLING},REJECT")
    for ipv4_only in (True, False):
        if not ipv4_only:
            rules.extend(domain_rule(host) + ",DIRECT" for host in policy["direct_exceptions"])
        rules.extend(domain_rule(host) + "," + (business if row.get("waimao") else "PROXY")
                     for row in rows if row["windows_ipv4_only"] == ipv4_only for host in row["domains"])
    if waimao:
        rules.extend(domain_rule(host) + "," + business for host in policy["waimao"]["domains"])
    rules.extend(domain_rule(host) + ",PROXY" for host in policy["proxy_exceptions"])
    rules += [
        "RULE-SET," + data_url(policy, "meta-international.list") + ",PROXY",
    ]
    rules.extend(telegram_ip_rules(policy, f"{PAGES}/{TELEGRAM_IPS}", ("PROXY",)))
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
    return (shadowrocket_groups(policy) if waimao else "") + "\n".join(rules) + "\n"


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
                             + yaml.safe_dump(windows(policy), sort_keys=False, width=1000, allow_unicode=True),
        "shadowrocket.conf": notice + url + "# Baseline import, update and routing verified on two iPhones.\n" + shadowrocket(policy),
        "shadowrocket-waimao.conf": notice + url + "# Trade-group variant. Add your own nodes named 外贸-直连 and 外贸-中转 on the device.\n"
                                    + shadowrocket(policy, waimao=True),
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
