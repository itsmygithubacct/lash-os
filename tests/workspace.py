#!/usr/bin/env python3
"""Check workspace isolation, configuration precedence and cache relocation."""
import json
import os
from pathlib import Path
import runpy
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

    def command(self, *args, home=None):
        env = {key: value for key, value in os.environ.items() if not key.startswith("LASHOS_")}
        env["LASHOS_CONFIG"] = str(self.config)
        if home is not None:
            env["HOME"] = str(home)
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

    def test_make_path_accepts_plus_and_at(self):
        self.configure({"research": str(self.home / "user@example+lab/research")})
        result = self.command("--make-path", "build")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), str(self.home / "user@example+lab/research/build"))

    def test_clean_keeps_outputs_downloads_and_reports(self):
        self.configure({"research": str(self.research)})
        for name in ["build", "out", "downloads", "reports"]:
            directory = self.research / name
            directory.mkdir(parents=True)
            (directory / "keep").write_text(name)
        (self.research / "build" / workspace.BUILD_MARKER).touch()
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

    def test_clean_requires_a_recognizable_build_tree(self):
        documents = self.home / "Documents"
        documents.mkdir()
        (documents / "notes.txt").write_text("user data")
        self.configure({"research": str(self.research), "build": str(documents)})
        result = self.command("--clean")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("not recognizably a lashos build tree", result.stderr)
        self.assertEqual((documents / "notes.txt").read_text(), "user data")
        # Trees created before the marker existed are recognized by their stamps.
        (documents / "native-full.stamp").touch()
        result = self.command("--clean")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(documents.exists())

    def test_clean_rejects_source_cache_inside_build(self):
        build = self.research / "build"
        (build / "cache").mkdir(parents=True)
        (build / workspace.BUILD_MARKER).touch()
        self.configure({"research": str(self.research), "source_cache": str(build / "cache")})
        result = self.command("--clean")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Refusing to clean", result.stderr)
        self.assertTrue((build / "cache").is_dir())

    def test_clean_compares_the_resolved_home_directory(self):
        real = self.home / "users/real"
        real.mkdir(parents=True)
        (real / workspace.BUILD_MARKER).touch()
        alias = self.home / "alias"
        alias.symlink_to(real, target_is_directory=True)
        self.configure({"research": str(self.research), "build": str(alias)})
        result = self.command("--clean", home=alias)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Refusing to clean", result.stderr)
        self.assertTrue(real.is_dir())

    def test_mark_build_creates_or_adopts_only_build_trees(self):
        self.configure({"research": str(self.research)})
        result = self.command("--mark-build")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((self.research / "build" / workspace.BUILD_MARKER).is_file())
        other = self.home / "other"
        other.mkdir()
        (other / "file").write_text("unrelated")
        self.configure({"research": str(self.research), "build": str(other)})
        result = self.command("--mark-build")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("not a lashos build tree", result.stderr)
        self.assertFalse((other / workspace.BUILD_MARKER).exists())
        (other / "deps.stamp").touch()
        result = self.command("--mark-build")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((other / workspace.BUILD_MARKER).is_file())

    def test_harness_work_directories_are_dedicated(self):
        paths = self.resolve()
        for unsafe in [Path("/"), Path.home(), workspace.ROOT / "reports", paths["research"], paths["build"]]:
            with self.subTest(unsafe=unsafe), self.assertRaises(ValueError):
                workspace.prepare_work(unsafe, paths)
        occupied = self.home / "projects/data"
        (occupied / "home").mkdir(parents=True)
        with self.assertRaises(ValueError):
            workspace.prepare_work(occupied, paths)
        self.assertFalse((occupied / workspace.WORK_MARKER).exists())
        fresh = workspace.prepare_work(self.home / "reports/new", paths)
        self.assertTrue((fresh / workspace.WORK_MARKER).is_file())
        legacy = self.home / "reports/legacy"
        (legacy / "runtime").mkdir(parents=True)
        (legacy / "result.json").write_text("{}")
        self.assertEqual(workspace.prepare_work(legacy, paths), legacy.resolve())
        self.assertEqual(workspace.prepare_work(legacy, paths), legacy.resolve())

    def test_build_source_state_matches_later_commits(self):
        repository = self.home / "repository"
        repository.mkdir()

        def git(*arguments):
            return subprocess.run(["git", "-c", "user.name=Test", "-c", "user.email=test@example.invalid",
                                   "-c", "commit.gpgsign=false", *arguments], cwd=repository,
                                  check=True, capture_output=True, text=True).stdout.strip()

        git("init", "-q")
        (repository / "src.c").write_text("one\n")
        (repository / "README.md").write_text("documentation\n")
        git("add", ".")
        git("commit", "-q", "-m", "base")
        (repository / "src.c").write_text("two\n")
        (repository / "new.c").write_text("new\n")
        state = workspace.source_state(repository)
        self.assertEqual(set(state["changed"]), {"src.c", "new.c"})
        git("add", ".")
        git("commit", "-q", "-m", "built source")
        self.assertEqual(workspace.source_differences(state, git("rev-parse", "HEAD"), repository), [])
        (repository / "README.md").write_text("release notes\n")
        (repository / "src.c").write_text("three\n")
        git("commit", "-q", "-a", "-m", "after the build")
        self.assertEqual(workspace.source_differences(state, git("rev-parse", "HEAD"), repository), ["src.c"])
        self.assertEqual(workspace.source_differences({"revision": None, "changed": None}, "HEAD", repository),
                         ["<build source was not recorded>"])

    def test_release_requires_the_pinned_runtime(self):
        release = runpy.run_path(str(ROOT / "scripts/package-release.py"))
        runtime = runpy.run_path(str(ROOT / "scripts/runtime.py"))
        linux = json.loads((ROOT / "config/runtime-sources.json").read_text())["linux"]
        patches = {name: runtime["digest"](ROOT / "patches" / name) for name in runtime["KERNEL_PATCHES"]}

        def manifest(arch, **changes):
            value = {"format": "LASHOS-VM-v1", "runtime": "pinned",
                     "package_sources": json.loads((ROOT / "config/runtime" / (arch + ".json")).read_text()),
                     "kernel": {"architecture": arch, "linux": linux, "patches": patches}}
            value.update(changes)
            return value

        release["require_pinned_runtime"]("riscv64", manifest("riscv64"))
        release["require_pinned_runtime"]("x86_64", manifest("x86_64"))
        # Another architecture's named patches are not required.
        generic = {name: value for name, value in patches.items() if not name.startswith("linux-riscv64-")}
        release["require_pinned_runtime"]("x86_64", manifest(
            "x86_64", kernel={"architecture": "x86_64", "linux": linux, "patches": generic}))
        # Kernels built before patch tracking lack the generic vmalloc deadlock fix.
        legacy = manifest("x86_64")
        legacy["kernel"] = {"architecture": "x86_64", "linux": linux}
        unpatched = manifest("riscv64")
        unpatched["kernel"] = {"architecture": "riscv64", "linux": linux}
        for arch, candidate in [("x86_64", manifest("x86_64", runtime="build-host")),
                                ("x86_64", manifest("x86_64", kernel="local/vmlinuz", package_sources=None)),
                                ("aarch64", manifest("x86_64")), ("riscv64", unpatched), ("x86_64", legacy)]:
            with self.subTest(arch=arch, candidate=candidate.get("runtime")), self.assertRaises(ValueError):
                release["require_pinned_runtime"](arch, candidate)

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
