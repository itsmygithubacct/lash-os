"""Validate the bash-os release pin and lash-os's matching version series."""
import argparse
import json
from pathlib import Path
import re
import urllib.parse
import urllib.request

NUMBER = r"(?:0|[1-9][0-9]*)"
BASE_VERSION = rf"{NUMBER}\.{NUMBER}\.{NUMBER}"


def release_metadata(root):
    root = Path(root)
    version = (root / "VERSION").read_text().strip()
    upstream = (root / "vendor/bash-os/VERSION").read_text().strip()
    pin = json.loads((root / "SOURCE.json").read_text())["bash_os"]
    if not re.fullmatch(BASE_VERSION, upstream):
        raise ValueError("The vendored bash-os VERSION must be MAJOR.MINOR.PATCH")
    if not re.fullmatch(re.escape(upstream) + r"(?:\.[1-9][0-9]*)?", version):
        raise ValueError(f"lash-os VERSION must be {upstream} or {upstream}.N with N >= 1")
    if pin.get("version") != upstream or pin.get("release_tag") != "v" + upstream:
        raise ValueError("SOURCE.json must name the vendored bash-os version and release tag")
    if not re.fullmatch(r"[0-9a-f]{40}", pin.get("revision", "")):
        raise ValueError("SOURCE.json must pin the complete bash-os release commit")
    identity = dict(line.split("=", 1) for line in (root / "config/os-release").read_text().splitlines()
                    if "=" in line and not line.startswith("#"))
    for key in ("VERSION", "VERSION_ID"):
        if identity.get(key, "").strip('"') != version:
            raise ValueError(f"config/os-release {key} must match lash-os VERSION")
    return {"version": version, "bash_os": {
        "version": upstream, "tag": pin["release_tag"], "revision": pin["revision"],
        "source": pin["source"],
    }}


def fetch_json(url):
    request = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json",
                                                  "User-Agent": "lash-os-release",
                                                  "Cache-Control": "no-cache"})
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)


def require_latest_release(metadata, fetch=fetch_json):
    upstream = metadata["bash_os"]
    source = urllib.parse.urlparse(upstream["source"])
    if source.scheme != "https" or source.netloc != "github.com" or not re.fullmatch(r"/[\w.-]+/[\w.-]+", source.path):
        raise ValueError("The bash-os source must identify its public GitHub repository")
    api = "https://api.github.com/repos" + source.path
    latest = fetch(api + "/releases/latest")
    if latest.get("draft") or latest.get("prerelease") or latest.get("tag_name") != upstream["tag"]:
        raise ValueError(f"Pinned {upstream['tag']} is not the latest published bash-os release: {latest.get('tag_name')}")
    commit = fetch(api + "/commits/" + urllib.parse.quote(upstream["tag"], safe=""))
    if commit.get("sha") != upstream["revision"]:
        raise ValueError("The pinned bash-os commit does not match its published release tag")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check-latest", action="store_true", help="also verify the latest published release on GitHub")
    args = parser.parse_args()
    metadata = release_metadata(Path(__file__).resolve().parents[1])
    if args.check_latest:
        require_latest_release(metadata)
    print(json.dumps(metadata, indent=2))


if __name__ == "__main__":
    main()
