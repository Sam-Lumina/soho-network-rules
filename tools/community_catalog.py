"""Compare ranked GitHub routing catalogs without changing a device configuration."""

import argparse
from concurrent.futures import ThreadPoolExecutor
import csv
import json
import os
from pathlib import Path
import re
from urllib.error import URLError
from urllib.parse import quote
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener


ROOT = Path(__file__).resolve().parents[1]
GITHUB = "https://api.github.com"
ALIASES = {
    "abematv": "abema",
    "appletv": "apple-tvplus",
    "bbciplayer": "bbc",
    "category-porn": "adult",
    "china": "cn",
    "claude": "anthropic",
    "claudeai": "anthropic",
    "disneyplus": "disney",
    "f1": "formula1",
    "gmail": "google-mail",
    "grok": "xai",
    "hbo-go-hkg": "hbo",
    "hbomax": "hbo",
    "neteasemusic": "netease",
    "steamcn": "steam-cn",
    "youtubemusic": "youtube",
}
REVIEW_REQUIRED = re.compile(
    r"(?:^|[-_])(?:adult|bank|betting|crypto|cryptocurrency|finance|gambling|gov|payment|porn|securities)(?:$|[-_])"
)
AGGREGATES = {
    "acceleratedirectsites", "ai", "all", "applications", "cncidr", "direct", "download", "game", "global",
    "gfw", "greatfire", "lancidr", "proxy", "reject", "tld-not-cn", "telegramcidr",
    "geolocation-cn", "geolocation-not-cn",
}
MIXED_OR_SENSITIVE = {
    "akamai", "amazon", "appleid", "cloudflare", "mastercard", "paypal", "steamregioncheck",
    "stripe", "visa", "wise",
}


class SameOrigin(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def github_tree(repo, ref, recursive=False):
    address = f"{GITHUB}/repos/{repo}/git/trees/{quote(ref, safe='')}"
    if recursive:
        address += "?recursive=1"
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "SOHO-Community-Rules"}
    if token := os.environ.get("SOHO_CATALOG_GITHUB_TOKEN"):
        headers["Authorization"] = f"Bearer {token}"
    request = Request(address, headers=headers)
    opener = build_opener(ProxyHandler({}), SameOrigin())
    with opener.open(request, timeout=20) as response:
        tree = json.load(response)
    if tree.get("truncated"):
        raise ValueError(f"GitHub returned a partial tree for {repo}")
    return tree


def source_files(source):
    repo = source["repo"]
    tree = github_tree(repo, source["branch"])
    revision = tree["sha"]
    directory = source["directory"]
    for folder in filter(None, directory.split("/")):
        sha = next(entry["sha"] for entry in tree["tree"]
                   if entry["type"] == "tree" and entry["path"] == folder)
        tree = github_tree(repo, sha)
    matcher = re.compile(source["file_pattern"], re.I)
    files = []
    for entry in github_tree(repo, tree["sha"], recursive=True)["tree"]:
        match = matcher.fullmatch(entry["path"])
        if entry["type"] == "blob" and match:
            path = f"{directory}/{entry['path']}" if directory else entry["path"]
            files.append({"category": match[1], "path": path, "sha": entry["sha"]})
    if not files:
        raise ValueError(f"{repo} produced an empty catalog")
    return {"repo": repo, "role": source["role"], "revision": revision,
            "files": sorted(files, key=lambda row: row["path"])}


def category_key(label):
    name = label.casefold().replace("!", "not-")
    name = re.sub(r"[ _]+", "-", name)
    folded = name.replace("-", "")
    return ALIASES.get(name, ALIASES.get(folded, name))


def reviewed_routes(policy):
    actions = {"direct": "DIRECT", "proxy": "PROXY", "proxy_supplement": "PROXY",
               "proxy_category": "PROXY", "reject": "REJECT"}
    routes = {}
    for entry in policy["sets"]:
        if entry["kind"] == "advertising" and not policy["modules"]["ads"]["enabled"]:
            continue
        source_path = entry.get("meta_path") or entry.get("text_url")
        if source_path and entry["kind"] != "ipcidr":
            routes[category_key(Path(source_path).stem)] = actions[entry["policy"]]
    for group, categories in policy["community"].items():
        action = group.split("_", 1)[0].upper()
        routes.update((category_key(name), action) for name in categories)
    return routes


def decide(label, reviewed):
    if label in reviewed:
        return reviewed[label], "existing-policy"
    if label in AGGREGATES or label.startswith("geolocation-"):
        return "", "aggregate-review"
    if label in MIXED_OR_SENSITIVE or REVIEW_REQUIRED.search(label):
        return "", "sensitive-review"
    if label.endswith("-cn") and not label.endswith("-not-cn"):
        return "DIRECT", "china-scope"
    return "DIRECT", "existing-default"


def compare(snapshots, policy):
    reviewed = reviewed_routes(policy)
    choices = {}
    report = []
    for rank, source in enumerate(snapshots, 1):
        for row in source["files"]:
            label = row["category"].split("@", 1)[0]
            key = category_key(label)
            action, reason = decide(key, reviewed)
            disposition = reason
            if source["role"] == "template":
                action, reason = "", "client-template"
            elif "@" in row["category"]:
                action, reason = "", "regional-or-attribute-variant"
            elif source["role"] == "comparison":
                reason = "comparison-only"
            elif source["role"] == "data-source":
                reason = "upstream-of-ranked-provider"
            elif key in choices:
                reason = "same-content" if row["sha"] == choices[key][1] else "same-category-different-content"
            else:
                choices[key] = (source["repo"], row["sha"])
            report.append({
                "rank": rank, "source": source["repo"], "category": row["category"],
                "normalized_category": key, "preferred_source": choices.get(key, ("", ""))[0],
                "suggested_action": action, "policy_status": disposition,
                "reason": reason, "path": row["path"], "sha": row["sha"]
            })
    return report


def changes(previous, current):
    def fingerprint(snapshot):
        return {(source["repo"], entry["path"]): entry["sha"]
                for source in snapshot for entry in source["files"]}
    old = fingerprint(previous)
    new = fingerprint(current)
    return {name: sorted(items) for name, items in {
        "added": new.keys() - old.keys(), "removed": old.keys() - new.keys(),
        "changed": {item for item in new.keys() & old.keys() if new[item] != old[item]},
    }.items()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--previous", type=Path)
    args = parser.parse_args()
    sources = json.loads((ROOT / "rules/community_sources.json").read_bytes())
    policy = json.loads((ROOT / "rules/policy.json").read_bytes())
    with ThreadPoolExecutor(max_workers=6) as workers:
        try:
            snapshots = list(workers.map(source_files, sources))
        except (URLError, StopIteration, ValueError) as exc:
            raise SystemExit(f"Community inventory failed: {type(exc).__name__}: {exc}") from exc
    report = compare(snapshots, policy)
    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / "catalog.json").write_text(json.dumps(snapshots, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    with (args.output / "coverage.csv").open("w", newline="", encoding="utf-8-sig") as stream:
        writer = csv.DictWriter(stream, fieldnames=report[0].keys())
        writer.writeheader()
        writer.writerows(report)
    if args.previous:
        previous = json.loads(args.previous.read_bytes())
        delta = changes(previous, snapshots)
        (args.output / "changes.json").write_text(json.dumps(delta, indent=2) + "\n", encoding="utf-8")
        print("Catalog changes", {name: len(items) for name, items in delta.items()})
    for source in snapshots:
        print(source["repo"], len(source["files"]), source["role"])


if __name__ == "__main__":
    main()
