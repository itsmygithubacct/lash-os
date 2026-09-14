#!/usr/bin/env python3
"""Check source refresh and actual Make invalidation without building the image."""
import os
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / "scripts"))
from source_tree import sync_tree


class SourceTreeTests(unittest.TestCase):
    def test_refresh_and_preserve_build_caches(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, destination = root / "source", root / "destination"
            (source / "loadables").mkdir(parents=True)
            (source / "loadables/tool.c").write_text("old source")
            (source / "loadables/deleted.c").write_text("removed later")
            (source / "unchanged").write_text("keep timestamp")
            (source / "alias").symlink_to("unchanged")
            sync_tree(source, destination)
            original_mtime = (destination / "unchanged").stat().st_mtime_ns
            for name in ["build", "out", "dl"]:
                (destination / name).mkdir()
                (destination / name / "cached").write_text("preserve")
            (destination / "loadables/tool.c").write_text("derived adaptation")
            (source / "loadables/tool.c").write_text("new upstream source")
            (source / "loadables/deleted.c").unlink()
            (source / "loadables/added.c").write_text("new file")
            (source / "alias").unlink()
            (source / "alias").symlink_to("loadables/added.c")
            sync_tree(source, destination)
            self.assertEqual((destination / "loadables/tool.c").read_text(), "new upstream source")
            self.assertFalse((destination / "loadables/deleted.c").exists())
            self.assertEqual((destination / "loadables/added.c").read_text(), "new file")
            self.assertEqual(os.readlink(destination / "alias"), "loadables/added.c")
            self.assertEqual((destination / "unchanged").stat().st_mtime_ns, original_mtime)
            for name in ["build", "out", "dl"]:
                self.assertEqual((destination / name / "cached").read_text(), "preserve")
            # Preparation must restore pristine input before adapting it again.
            (destination / "loadables/tool.c").write_text("derived adaptation")
            sync_tree(source, destination)
            self.assertEqual((destination / "loadables/tool.c").read_text(), "new upstream source")

    def make_fixture(self, root, research):
        paths = [
            "scripts/prepare-bash.py", "scripts/adapt-workspaces.py", "scripts/compile-bash.py",
            "scripts/compile-deps.py", "scripts/build-full.py", "tests/source-tree.py",
            "scripts/build-portable.py", "scripts/build-sandbox.py", "scripts/dev.py",
            "scripts/elf_dependencies.py", "config/os-release", "tests/workspace.py",
            "SOURCE.json", "CMakeLists.txt", "flake.nix", "flake.lock",
            "vendor/bash-os/build.sh", "vendor/bash-os/config/dependencies.json",
            "vendor/bash-os/loadables/tool.c",
        ]
        for name in paths:
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("fixture")
        shutil.copy2(ROOT / "scripts/source_tree.py", root / "scripts/source_tree.py")
        shutil.copy2(ROOT / "scripts/workspace.py", root / "scripts/workspace.py")
        for name in ["include", "vendor/musl-headers"]:
            (root / name).mkdir(parents=True)
        for path in root.rglob("*"):
            os.utime(path, (100, 100))
        for name in ["build/native-full.stamp", "build/full-bitcode.stamp", "build/deps.stamp",
                     "build/kernel-full/linux-bash-os", "build/portable/linux-bash-os",
                     "build/portable/sandbox-init",
                     "out/full/linux-bash-os", "out/full/bash.bpf.o", "out/portable/linux-bash-os"]:
            path = research / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.touch()
            os.utime(path, (200, 200))

    def test_make_tracks_edits_additions_and_removals(self):
        for change in ["none", "edit", "add", "remove", "config", "local-config"]:
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
                root = Path(directory) / "release"
                research = Path(directory) / "research"
                self.make_fixture(root, research)
                config = Path(directory) / "local.json"
                config.write_text(json.dumps({"research": str(research)}))
                os.utime(config, (100, 100))
                env = {key: value for key, value in os.environ.items() if not key.startswith("LASHOS_")}
                env["LASHOS_CONFIG"] = str(config)
                folder = root / "vendor/bash-os/loadables"
                if change == "edit":
                    os.utime(folder / "tool.c", (300, 300))
                elif change == "add":
                    (folder / "added.c").write_text("added")
                    os.utime(folder, (300, 300))
                elif change == "remove":
                    (folder / "tool.c").unlink()
                    os.utime(folder, (300, 300))
                elif change == "config":
                    os.utime(root / "vendor/bash-os/config/dependencies.json", (300, 300))
                elif change == "local-config":
                    os.utime(config, (300, 300))
                result = subprocess.run(["make", "-n", "-f", str(ROOT / "Makefile"), "build"],
                                        cwd=root, env=env, text=True, capture_output=True, check=True)
                self.assertFalse((root / "build").exists())
                self.assertFalse((root / "out").exists())
                if change == "none":
                    self.assertNotIn("prepare-bash.py --profile full", result.stdout)
                    self.assertNotIn("compile-bash.py --profile full --source", result.stdout)
                    self.assertNotIn("scripts/build-full.py", result.stdout)
                    self.assertNotIn("scripts/build-portable.py", result.stdout)
                    self.assertNotIn("scripts/build-sandbox.py", result.stdout)
                elif change == "local-config":
                    self.assertNotIn("prepare-bash.py --profile full", result.stdout)
                    self.assertNotIn("scripts/build-full.py", result.stdout)
                    self.assertIn("scripts/build-sandbox.py", result.stdout)
                else:
                    self.assertIn("prepare-bash.py --profile full", result.stdout)
                    self.assertIn("compile-bash.py --profile full --source", result.stdout)


if __name__ == "__main__":
    unittest.main()
