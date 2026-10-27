#!/usr/bin/env python3
"""Reject release-version drift and tags that do not identify the vendored commit."""
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from release_version import release_metadata, require_latest_release


class ReleaseVersionTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        (self.root / "vendor/bash-os").mkdir(parents=True)
        (self.root / "config").mkdir()
        (self.root / "vendor/bash-os/VERSION").write_text("0.1.2\n")
        self.pin = {"version": "0.1.2", "release_tag": "v0.1.2", "revision": "a" * 40,
                    "source": "https://github.com/itsmygithubacct/bash-os"}
        self.write_pin()
        self.set_version("0.1.2")

    def write_pin(self):
        (self.root / "SOURCE.json").write_text(json.dumps({"bash_os": self.pin}))

    def set_version(self, version):
        (self.root / "VERSION").write_text(version + "\n")
        (self.root / "config/os-release").write_text(f'VERSION="{version}"\nVERSION_ID="{version}"\n')

    def test_base_and_lash_only_revisions(self):
        for version in ("0.1.2", "0.1.2.1", "0.1.2.29"):
            with self.subTest(version=version):
                self.set_version(version)
                self.assertEqual(release_metadata(self.root)["version"], version)

    def test_rejects_wrong_base_and_invalid_suffix(self):
        for version in ("0.1.1", "0.1.3", "0.1.2.0", "0.1.2.01", "0.1.2.1.1", "0.1.2-dev"):
            with self.subTest(version=version):
                self.set_version(version)
                with self.assertRaises(ValueError):
                    release_metadata(self.root)

    def test_rejects_old_vendor_version(self):
        (self.root / "vendor/bash-os/VERSION").write_text("0.1.0\n")
        with self.assertRaisesRegex(ValueError, "VERSION must be 0.1.0"):
            release_metadata(self.root)

    def test_rejects_inconsistent_pin_or_guest_identity(self):
        for key, value in (("version", "0.1.1"), ("release_tag", "v0.1.1"), ("revision", "a" * 7)):
            with self.subTest(key=key):
                original = self.pin[key]
                self.pin[key] = value
                self.write_pin()
                with self.assertRaises(ValueError):
                    release_metadata(self.root)
                self.pin[key] = original
        self.write_pin()
        (self.root / "config/os-release").write_text('VERSION="0.1.2"\nVERSION_ID="0.1.0"\n')
        with self.assertRaisesRegex(ValueError, "VERSION_ID"):
            release_metadata(self.root)

    def test_latest_release_requires_matching_tag_and_commit(self):
        metadata = release_metadata(self.root)
        def fetch(url):
            return {"tag_name": "v0.1.2", "draft": False, "prerelease": False} if url.endswith("latest") else {"sha": "a" * 40}
        require_latest_release(metadata, fetch)
        for response in ({"tag_name": "v0.1.3"}, {"tag_name": "v0.1.2", "prerelease": True}):
            with self.subTest(response=response), self.assertRaises(ValueError):
                require_latest_release(metadata, lambda url: response)
        with self.assertRaisesRegex(ValueError, "commit does not match"):
            require_latest_release(metadata, lambda url: fetch(url) if url.endswith("latest") else {"sha": "b" * 40})


if __name__ == "__main__":
    unittest.main()
