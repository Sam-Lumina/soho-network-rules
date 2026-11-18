# SPDX-License-Identifier: GPL-3.0-only
"""Convert approved MetaCubeX and HaGeZi categories into native rule lists."""

import argparse
from concurrent.futures import ThreadPoolExecutor
from hashlib import sha256
import json
import re
from urllib.request import urlopen

from build_configs import ROOT, POLICY, META, HAGEZI, COMMUNITY_DATA, COMMUNITY_ADULT, COMMUNITY_GAMBLING
from build_rule_data import download, domain_rules


def revision_at(repository, branch):
    with urlopen(f"https://api.github.com/repos/{repository}/git/ref/heads/{branch}", timeout=20) as reply:
        revision = json.load(reply)["object"]["sha"]
    if not re.fullmatch("[0-9a-f]{40}", revision):
        raise ValueError("Unexpected upstream revision")
    return revision


def fetch_rules(url):
    if url.startswith(HAGEZI + "/"):
        blob = download(url, limit=20_000_000)
        lines = [line for line in blob.decode("utf-8").splitlines() if line and not line.startswith("#")]
        if not all(line.startswith("*.") and "." in line[2:] for line in lines):
            raise ValueError("Unexpected HaGeZi wildcard syntax")
        rules = set(domain_rules("\n".join("+." + line[2:] for line in lines).encode()))
    else:
        blob = download(url)
        rules = set(domain_rules(blob))
    if not rules:
        raise ValueError("Empty community rule category")
    return rules, {"url": url, "sha256": sha256(blob).hexdigest(), "rules": len(rules)}


def build_list(sources):
    records = set()
    manifest = []
    with ThreadPoolExecutor(max_workers=5) as workers:
        for rules, source in workers.map(fetch_rules, sources):
            records.update(rules)
            manifest.append(source)
    if not records:
        raise ValueError("No approved rules for community list")
    content = ("\n".join(sorted(records)) + "\n").encode()
    return content, {"sha256": sha256(content).hexdigest(), "bytes": len(content),
                     "count": len(records), "sources": manifest}


def build():
    policy = json.loads(POLICY.read_bytes())
    parent = ROOT / "dist" / COMMUNITY_DATA
    meta = revision_at("MetaCubeX/meta-rules-dat", "meta")
    hagezi = revision_at("hagezi/dns-blocklists", "main")
    sources = {
        "media.list": [f"{META}/{meta}/{row['meta_path'].removesuffix('.mrs')}.list"
                       for row in policy["sets"] if row.get("shadowrocket_media")],
        COMMUNITY_ADULT.rsplit("/", 1)[1]: [f"{META}/{meta}/{row['meta_path'].removesuffix('.mrs')}.list"
                                            for row in policy["sets"] if row["policy"] == "proxy_category"],
        COMMUNITY_GAMBLING.rsplit("/", 1)[1]: [f"{HAGEZI}/{hagezi}/{row['hagezi_path']}"
                                               for row in policy["sets"] if row.get("hagezi_path")],
    }
    metadata = {}
    parent.mkdir(parents=True, exist_ok=True)
    for name, urls in sources.items():
        content, metadata[name] = build_list(urls)
        (parent / name).write_bytes(content)
        print(name, metadata[name]["count"], "rules from", len(urls), "approved categories")
    (parent / "SHA256.json").write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8", newline="\n")


if __name__ == "__main__":
    argparse.ArgumentParser(description=__doc__).parse_args()
    build()
