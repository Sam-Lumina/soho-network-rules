# SPDX-License-Identifier: GPL-3.0-only
"""Render the approved MetaCubeX media categories as Shadowrocket rules."""

import argparse
from concurrent.futures import ThreadPoolExecutor
from hashlib import sha256
import json
import re
from urllib.request import urlopen

from build_configs import ROOT, POLICY, META, COMMUNITY_MEDIA
from build_rule_data import download, domain_rules


def build():
    policy = json.loads(POLICY.read_bytes())
    parent = (ROOT / "dist" / COMMUNITY_MEDIA).parent
    with urlopen("https://api.github.com/repos/MetaCubeX/meta-rules-dat/git/ref/heads/meta", timeout=20) as reply:
        revision = json.load(reply)["object"]["sha"]
    if not re.fullmatch("[0-9a-f]{40}", revision):
        raise ValueError("Unexpected MetaCubeX revision")

    sources = [f"{META}/{revision}/{row['meta_path'].removesuffix('.mrs')}.list"
               for row in policy["sets"] if row.get("shadowrocket_media")]
    if not sources:
        raise ValueError("No approved community media categories")
    with ThreadPoolExecutor(max_workers=5) as workers:
        inputs = list(workers.map(download, sources))
    records = set()
    manifest = []
    for url, blob in zip(sources, inputs, strict=True):
        rules = set(domain_rules(blob))
        if not rules:
            raise ValueError(f"Empty community rule category: {url}")
        records.update(rules)
        manifest.append({"url": url, "sha256": sha256(blob).hexdigest(), "rules": len(rules)})
    content = ("\n".join(sorted(records)) + "\n").encode()
    metadata = {"media.list": {"sha256": sha256(content).hexdigest(),
                               "bytes": len(content), "sources": manifest}}
    parent.mkdir(parents=True, exist_ok=True)
    (parent / "media.list").write_bytes(content)
    (parent / "SHA256.json").write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8", newline="\n")
    print("Community media list", len(records), "rules from", len(manifest), "reviewed categories")


if __name__ == "__main__":
    argparse.ArgumentParser(description=__doc__).parse_args()
    build()
