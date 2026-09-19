#!/usr/bin/env python3
"""Check source refresh and actual Make invalidation without building the image."""
import importlib.util
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
    def test_rejects_overlapping_trees_before_changing_files(self):
        for relationship in ["same", "child", "parent", "symlink-parent"]:
            with self.subTest(relationship=relationship), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                source = root / "source"
                source.mkdir()
                marker = source / "source.c"
                marker.write_text("preserve the source")
                destination = {"same": source, "child": source / "copy", "parent": root,
                               "symlink-parent": root / "alias"}[relationship]
                if relationship == "symlink-parent":
                    destination.symlink_to(root, target_is_directory=True)
                with self.assertRaisesRegex(ValueError, "must not overlap"):
                    sync_tree(source, destination)
                self.assertEqual(marker.read_text(), "preserve the source")
                self.assertEqual(list(source.iterdir()), [marker])

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
            "scripts/elf_dependencies.py", "scripts/runtime.py", "config/os-release", "tests/workspace.py",
            "SOURCE.json", "CMakeLists.txt", "flake.nix", "flake.lock",
            "patches/capsule-test.patch",
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
                     "build/native.stamp", "build/bitcode.stamp",
                     "build/kernel-full/linux-bash-os", "build/portable/linux-bash-os",
                     "build/portable/sandbox-init",
                     "out/full/linux-bash-os", "out/full/bash.bpf.o", "out/portable-host/linux-bash-os"]:
            path = research / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.touch()
            os.utime(path, (200, 200))

    def run_make(self, directory, root, research, *arguments, check=True):
        env = {key: value for key, value in os.environ.items() if not key.startswith("LASHOS_")}
        env.update(LASHOS_CONFIG=str(Path(directory) / "missing.json"), LASHOS_RESEARCH_DIR=str(research))
        return subprocess.run(["make", "-n", "-f", str(ROOT / "Makefile"), *arguments],
                              cwd=root, env=env, text=True, capture_output=True, check=check)

    def test_list_rejects_names_make_cannot_track(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            def listing(name):
                return subprocess.run([sys.executable, "-B", str(ROOT / "scripts/source_tree.py"), "list", name],
                                      cwd=root, text=True, capture_output=True)

            (root / "safe").mkdir()
            (root / "safe/c++@v1.c").write_text("safe")
            result = listing("safe")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.splitlines(), ["safe", "safe/c++@v1.c"])
            for name in ["with space.c", "percent%.c", "colon:.c", "glob*.c", "hash#.c", "dollar$.c",
                         "equals=.c", "bracket[.c", "back\\slash.c"]:
                with self.subTest(name=name):
                    unsafe = root / "unsafe"
                    shutil.rmtree(unsafe, ignore_errors=True)
                    unsafe.mkdir()
                    (unsafe / name).write_text("unsafe")
                    result = listing("unsafe")
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("Rename build inputs", result.stderr)
                    self.assertEqual(result.stdout, "")

    def test_make_accepts_plus_and_at_in_workspace_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "release"
            research = Path(directory) / "user@example+research"
            self.make_fixture(root, research)
            result = self.run_make(directory, root, research, "build")
            self.assertNotIn("prepare-bash.py --profile full", result.stdout)
            os.utime(root / "vendor/bash-os/loadables/tool.c", (300, 300))
            result = self.run_make(directory, root, research, "build")
            self.assertIn("prepare-bash.py --profile full", result.stdout)

    def test_build_host_runtime_has_separate_output_and_architecture_guard(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "release"
            research = Path(directory) / "research"
            self.make_fixture(root, research)
            os.utime(root / "scripts/build-sandbox.py", (300, 300))
            result = self.run_make(directory, root, research, "test-sandbox")
            self.assertIn("python3 -B scripts/build-sandbox.py\n", result.stdout)
            self.assertIn(f"--binary {research.resolve()}/out/portable-host/linux-bash-os", result.stdout)
            self.assertNotIn("/out/portable/", result.stdout)
            result = self.run_make(directory, root, research, "portable", "BUILD_MACHINE=aarch64", check=False)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("make portable-x86_64, portable-aarch64 or portable-riscv64", result.stderr)
            result = self.run_make(directory, root, research, "portable-aarch64", "BUILD_MACHINE=aarch64")
            self.assertIn("scripts/build-sandbox.py --arch aarch64", result.stdout)

    def test_initramfs_ignores_builder_permissions(self):
        spec = importlib.util.spec_from_file_location("bundle", ROOT / "scripts/build-sandbox.py")
        bundle = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(bundle)
        archives = []
        with tempfile.TemporaryDirectory() as directory:
            for variant, (folder, regular, executable) in enumerate([(0o700, 0o600, 0o700),
                                                                      (0o775, 0o664, 0o775)]):
                stage = Path(directory) / str(variant)
                for name in ["etc", "bin", "tmp"]:
                    (stage / name).mkdir(parents=True)
                (stage / "etc/hosts").write_text("127.0.0.1 localhost\n")
                (stage / "init").write_text("#!/bin/sh\n")
                (stage / "bin/sh").symlink_to("../init")
                (stage / "etc/hosts").chmod(regular)
                (stage / "init").chmod(executable)
                for name in ["etc", "bin"]:
                    (stage / name).chmod(folder)
                (stage / "tmp").chmod(0o1777)
                archives.append(bytes(bundle.newc(stage)))
        self.assertEqual(archives[0], archives[1])
        modes, data, offset = {}, archives[0], 0
        while True:
            fields = [int(data[offset + 6 + 8 * i:offset + 14 + 8 * i], 16) for i in range(13)]
            name = data[offset + 110:offset + 110 + fields[11] - 1].decode()
            offset = (offset + 110 + fields[11] + 3) & ~3
            offset = (offset + fields[6] + 3) & ~3
            if name == "TRAILER!!!":
                break
            self.assertEqual(fields[2:4], [0, 0])
            modes[name] = fields[1]
        self.assertEqual(modes["init"], 0o100755)
        self.assertEqual(modes["etc/hosts"], 0o100644)
        self.assertEqual(modes["etc"], 0o40755)
        self.assertEqual(modes["tmp"], 0o41777)
        self.assertEqual(modes["bin/sh"], 0o120777)

    def test_make_rebuilds_bitcode_when_toolchain_changes(self):
        for changed in ["flake.nix", "flake.lock", "patches/capsule-test.patch"]:
            with self.subTest(changed=changed), tempfile.TemporaryDirectory() as directory:
                root = Path(directory) / "release"
                research = Path(directory) / "research"
                self.make_fixture(root, research)
                os.utime(root / changed, (300, 300))
                env = {key: value for key, value in os.environ.items() if not key.startswith("LASHOS_")}
                env.update(LASHOS_CONFIG=str(Path(directory) / "missing.json"),
                           LASHOS_RESEARCH_DIR=str(research))
                targets = [research / "build" / name for name in
                           ["full-bitcode.stamp", "bitcode.stamp", "deps.stamp"]]
                result = subprocess.run(["make", "-n", "-f", str(ROOT / "Makefile"), *map(str, targets)],
                                        cwd=root, env=env, text=True, capture_output=True, check=True)
                self.assertIn("scripts/compile-bash.py --profile full", result.stdout)
                self.assertIn("scripts/compile-bash.py\n", result.stdout)
                self.assertIn("scripts/compile-deps.py", result.stdout)
                # Native references are configured in the pinned shell; Capsule patches do not affect them.
                native = changed != "patches/capsule-test.patch"
                self.assertEqual("scripts/prepare-bash.py --profile full" in result.stdout, native)
                self.assertEqual("scripts/prepare-bash.py >" in result.stdout, native)

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
