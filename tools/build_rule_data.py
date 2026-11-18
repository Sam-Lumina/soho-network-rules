# SPDX-License-Identifier: GPL-3.0-only
"""Build separate third-party rule artifacts from pinned upstream source files."""

import argparse
from concurrent.futures import ThreadPoolExecutor
from hashlib import sha256
import json
from pathlib import Path
import re
import subprocess
from tempfile import TemporaryDirectory
from urllib.request import urlopen


ROOT = Path(__file__).resolve().parents[1]
META = "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat"
HAGEZI = "https://raw.githubusercontent.com/hagezi/dns-blocklists"
LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
DOMAIN = re.compile(rf"(?:{LABEL}\.)*{LABEL}")


def download(url, limit=8_000_000):
    with urlopen(url, timeout=30) as response:
        if response.url != url:
            raise ValueError("Unexpected redirect for a pinned rule file")
        data = response.read(limit + 1)
    if not data or len(data) > limit:
        raise ValueError("Unexpected source file size")
    return data


def convert(core, source_format, source, result):
    process = subprocess.run([core, "convert-ruleset", "domain", source_format, str(source), str(result)],
                             capture_output=True, timeout=45)
    if process.returncode:
        raise RuntimeError("Mihomo rule conversion failed")


def domain_rules(text):
    for line in text.decode("utf-8").splitlines():
        suffix = line.startswith("+.")
        host = line.removeprefix("+.")
        if len(host) > 253 or not DOMAIN.fullmatch(host) or (not suffix and "." not in host):
            raise ValueError("Unsupported upstream domain token")
        yield ("DOMAIN-SUFFIX," if suffix else "DOMAIN,") + host


def build(core, output, policy):
    version = subprocess.check_output([core, "-v"], timeout=10, text=True).splitlines()[0]
    if "v1.19.33 " not in version:
        raise SystemExit("Use Mihomo 1.19.33 to reproduce the validated artifacts.")
    notes = {}
    with TemporaryDirectory(prefix="soho-rule-build-") as directory:
        temp = Path(directory)
        tif = f"{HAGEZI}/{policy['threat_snapshot']}/wildcard/tif.mini-onlydomains.txt"
        plan = {
            row["source"]: f"{META}/{policy['meta_snapshot']}/{row['meta_path']}"
            for row in policy["sets"] if row["policy"] == "proxy" or row["kind"] == "advertising"
        }
        with ThreadPoolExecutor(max_workers=5) as pool:
            sources = dict(zip(plan, pool.map(download, plan.values()), strict=True))
        plain = download(tif)
        if sha256(plain).hexdigest() != policy["threat_input_sha256"]:
            raise ValueError("Pinned HaGeZi source SHA-256 mismatch")
        (temp / "tif.txt").write_bytes(plain)
        convert(core, "text", temp / "tif.txt", temp / "tif.mrs")
        threat = (temp / "tif.mrs").read_bytes()
        if sha256(threat).hexdigest() != policy["threat_mrs_sha256"]:
            raise ValueError("Compiled HaGeZi MRS differs from the audited snapshot")
        notes["tif-mini.mrs"] = {"source": tif, "source_sha256": sha256(plain).hexdigest()}
        lists = {"meta-international.list": [], "meta-ads.list": []}
        for name, blob in sources.items():
            source = temp / (name + ".mrs")
            source.write_bytes(blob)
            result = temp / (name + ".txt")
            convert(core, "mrs", source, result)
            records = list(domain_rules(result.read_bytes()))
            if not records:
                raise ValueError("Empty MetaCubeX provider")
            group = "meta-ads.list" if name == "soho-ads" else "meta-international.list"
            lists[group].extend(records)
            detail = {"url": plan[name], "sha256": sha256(blob).hexdigest(), "count": len(records)}
            notes.setdefault(group, {}).setdefault("sources", []).append(detail)

    artifacts = {"tif-mini.mrs": threat}
    for name, records in lists.items():
        records = sorted(set(records))
        notes[name]["count"] = len(records)
        artifacts[name] = ("\n".join(records) + "\n").encode()
    for name, data in artifacts.items():
        notes[name].update({"bytes": len(data), "sha256": sha256(data).hexdigest()})
    artifacts["SHA256.json"] = (json.dumps(notes, indent=2, sort_keys=True) + "\n").encode()
    output.mkdir(parents=True, exist_ok=True)
    for name, data in artifacts.items():
        (output / name).write_bytes(data)
    print("Compiled 3 rule artifacts from pinned upstream data.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--mihomo", required=True, help="Path to the Mihomo 1.19.33 executable")
    parser.add_argument("--output", type=Path, required=True, help="Destination for compiled rule files")
    options = parser.parse_args()
    policy = json.loads((ROOT / "rules/policy.json").read_bytes())
    build(options.mihomo, options.output, policy)
