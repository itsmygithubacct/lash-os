#!/usr/bin/env python3
"""Check workspace isolation, configuration precedence and cache relocation."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import workspace


class WorkspaceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.home = Path(self.temporary.name)
        self.source = self.home / "projects/lash-os/lashos"
        self.config = self.home / ".local/projects/lash-os/lashos/config.json"
        self.research = self.home / "research/projects/lash-os/lashos"

    def configure(self, data):
        self.config.parent.mkdir(parents=True, exist_ok=True)
        self.config.write_text(json.dumps(data))

    def resolve(self, env=None):
        return workspace.settings(env or {}, home=self.home, source=self.source)

    def command(self, *args):
        env = {key: value for key, value in os.environ.items() if not key.startswith("LASHOS_")}
        env["LASHOS_CONFIG"] = str(self.config)
        return subprocess.run([sys.executable, "-B", str(ROOT / "scripts/workspace.py"), *args],
                              env=env, text=True, capture_output=True)

    def test_defaults_are_external_and_lookup_writes_nothing(self):
        paths = self.resolve()
        self.assertEqual(paths["config"], self.config)
        self.assertEqual(paths["research"], self.research)
        self.assertEqual(paths["build"], self.research / "build")
        self.assertEqual(paths["output"], self.research / "out")
        self.assertEqual(list(self.home.iterdir()), [])

    def test_config_and_environment_precedence(self):
        self.configure({"research": str(self.research), "output": "artifacts", "qemu": "/opt/qemu"})
        paths = self.resolve()
        self.assertEqual(paths["output"], self.config.parent / "artifacts")
        self.assertEqual(paths["qemu"], Path("/opt/qemu"))
        paths = self.resolve({"LASHOS_BUILD_DIR": str(self.home / "scratch"),
                              "LASHOS_QEMU": "/opt/other-qemu"})
        self.assertEqual(paths["build"], self.home / "scratch")
        self.assertEqual(paths["qemu"], Path("/opt/other-qemu"))
        self.assertEqual(paths["research"], self.research)

    def test_rejects_invalid_and_in_tree_output_settings(self):
        for data in [{"unknown": "x"}, {"research": None}, {"build": ""},
                     {"output": 42}, {"build": str(self.source / "build")},
                     {"reports": str(self.source)}, []]:
            with self.subTest(data=data):
                self.configure(data)
                with self.assertRaises(ValueError):
                    self.resolve()
        alias = self.home / "alias"
        self.source.mkdir(parents=True)
        alias.symlink_to(self.source, target_is_directory=True)
        self.configure({"output": str(alias / "out")})
        with self.assertRaises(ValueError):
            self.resolve()

    def test_cli_overrides_and_make_path_validation(self):
        self.configure({"research": str(self.research), "build": "path with spaces"})
        result = self.command("--get", "build")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), str(self.config.parent / "path with spaces"))
        result = self.command("--make-path", "build")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Make output paths", result.stderr)
        self.assertFalse(self.research.exists())

    def test_clean_keeps_outputs_downloads_and_reports(self):
        self.configure({"research": str(self.research)})
        for name in ["build", "out", "downloads", "reports"]:
            directory = self.research / name
            directory.mkdir(parents=True)
            (directory / "keep").write_text(name)
        result = self.command("--clean")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse((self.research / "build").exists())
        for name in ["out", "downloads", "reports"]:
            self.assertEqual((self.research / name / "keep").read_text(), name)
        self.assertTrue(self.config.exists())

    def test_clean_rejects_parent_of_preserved_data(self):
        self.configure({"research": str(self.research), "build": str(self.home)})
        result = self.command("--clean")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Refusing to clean", result.stderr)
        self.assertTrue(self.config.exists())

    def test_relocated_cmake_cache_is_archived_without_losing_artifacts(self):
        build = self.research / "build/portable"
        build.mkdir(parents=True)
        cache = build / "CMakeCache.txt"
        cache.write_text("CMAKE_HOME_DIRECTORY:INTERNAL=/old/source\n"
                         "CMAKE_CACHEFILE_DIR:INTERNAL=/old/build\n")
        (build / "CMakeFiles").mkdir()
        (build / "CMakeFiles/old").write_text("metadata")
        (build / "linux-bash-os").write_bytes(b"executable")
        with patch.object(workspace, "RESEARCH", self.research):
            workspace.prepare_cmake(build, self.source)
            self.assertFalse(cache.exists())
            self.assertEqual((build / "linux-bash-os").read_bytes(), b"executable")
            archives = list((self.research / "relocated-cmake").iterdir())
            self.assertEqual(len(archives), 1)
            self.assertEqual((archives[0] / "CMakeFiles/old").read_text(), "metadata")
            cache.write_text(f"CMAKE_HOME_DIRECTORY:INTERNAL={self.source}\n"
                             f"CMAKE_CACHEFILE_DIR:INTERNAL={build}\n")
            workspace.prepare_cmake(build, self.source)
            self.assertTrue(cache.exists())
            self.assertEqual(list((self.research / "relocated-cmake").iterdir()), archives)


if __name__ == "__main__":
    unittest.main()
