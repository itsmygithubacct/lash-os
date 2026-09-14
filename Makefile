.DEFAULT_GOAL := build
WORKSPACE := python3 -B scripts/workspace.py
BUILD := $(shell $(WORKSPACE) --make-path build)
OUT := $(shell $(WORKSPACE) --make-path output)
REPORTS := $(shell $(WORKSPACE) --make-path reports)
CONFIG := $(shell $(WORKSPACE) --make-path config)
ifeq ($(BUILD),)
$(error Invalid external build path; check local workspace configuration)
endif
ifeq ($(OUT),)
$(error Invalid external output path; check local workspace configuration)
endif
ifeq ($(REPORTS),)
$(error Invalid external report path; check local workspace configuration)
endif
ifeq ($(CONFIG),)
$(error Invalid configuration path; check LASHOS_CONFIG)
endif
LOCAL_CONFIG := $(wildcard $(CONFIG))
export LASHOS_BUILD_DIR := $(BUILD)
export LASHOS_OUTPUT_DIR := $(OUT)
export LASHOS_REPORTS_DIR := $(REPORTS)
export PYTHONDONTWRITEBYTECODE := 1
DEV := python3 -B scripts/dev.py
GUEST_HEADERS := $(shell rg --files include vendor/musl-headers)
PORT_SOURCES := $(wildcard src/* vendor/musl-c/* vendor/capsule-host/*)
SDK_INPUTS := flake.nix flake.lock $(wildcard patches/capsule-*.patch)
BUILD_CONFIG := scripts/workspace.py CMakeLists.txt $(wildcard VERSION cmake/*.cmake)
BASH_SOURCE_INPUTS := $(shell python3 -B scripts/source_tree.py list vendor/bash-os)
HOST_TEST_INPUTS := $(wildcard tests/*.c) tests/source-tree.py tests/workspace.py scripts/source_tree.py
PORTABLE_INPUTS := $(wildcard cmake/portable/*) scripts/build-portable.py scripts/elf_dependencies.py scripts/dev.py $(wildcard VERSION)
KERNEL_JOBS ?= 4

.PHONY: build full pure portable bundle prepare bitcode run demo verify paths test-workspace test-vm test-host test-processes test-portable test-portable-processes test-mount-cwd test-portable-mount-cwd test-sandbox test-mlkem test-sha1dc clean
build full: $(OUT)/full/linux-bash-os
	cp $(OUT)/full/linux-bash-os $(OUT)/linux-bash-os.tmp
	mv -f $(OUT)/linux-bash-os.tmp $(OUT)/linux-bash-os
	cp $(OUT)/full/bash.bpf.o $(OUT)/bash.bpf.o.tmp
	mv -f $(OUT)/bash.bpf.o.tmp $(OUT)/bash.bpf.o
pure: $(OUT)/pure/linux-bash-os
portable: $(OUT)/portable/linux-bash-os
.PHONY: portable-all portable-x86_64 portable-aarch64 portable-riscv64 release-candidates
release-candidates: portable-all
	$(DEV) python3 -B scripts/package-release.py
portable-all: portable-x86_64 portable-aarch64 portable-riscv64
portable-x86_64 portable-aarch64 portable-riscv64: portable-%: $(BUILD)/kernel-full/linux-bash-os
	$(DEV) python3 -B scripts/prepare-runtime.py --arch $*
	$(DEV) python3 -B scripts/build-kernel.py --arch $* --jobs $(KERNEL_JOBS)
	$(DEV) --shell $(if $(filter x86_64,$*),portable,portable-$*) python3 -B scripts/build-portable.py --arch $*
	$(DEV) python3 -B scripts/build-sandbox.py --arch $*
prepare: $(BUILD)/native-full.stamp
bitcode: $(BUILD)/full-bitcode.stamp

$(BUILD)/native-full.stamp: scripts/prepare-bash.py scripts/workspace.py scripts/source_tree.py scripts/adapt-workspaces.py SOURCE.json $(BASH_SOURCE_INPUTS)
	mkdir -p $(BUILD)
	$(DEV) python3 -B scripts/prepare-bash.py --profile full > $(BUILD)/prepare-full.log 2>&1 || { tail -60 $(BUILD)/prepare-full.log; exit 1; }
	touch $@

$(BUILD)/full-bitcode.stamp: $(BUILD)/native-full.stamp scripts/compile-bash.py $(GUEST_HEADERS)
	$(DEV) python3 -B scripts/compile-bash.py --profile full --source $(BUILD)/native-full/source/build/bash-5.3 --output $(BUILD)/full-bitcode
	touch $@

$(BUILD)/deps.stamp: scripts/compile-deps.py scripts/workspace.py vendor/bash-os/config/dependencies.json $(GUEST_HEADERS)
	$(DEV) python3 -B scripts/compile-deps.py
	touch $@

$(BUILD)/kernel-full/linux-bash-os: $(BUILD)/full-bitcode.stamp $(BUILD)/deps.stamp $(BUILD_CONFIG) scripts/build-full.py $(PORT_SOURCES) $(GUEST_HEADERS) $(SDK_INPUTS) $(HOST_TEST_INPUTS)
	$(DEV) python3 -B scripts/build-full.py
	touch $@

$(BUILD)/portable/linux-bash-os $(BUILD)/portable/sandbox-init &: $(BUILD)/kernel-full/linux-bash-os $(PORTABLE_INPUTS) $(PORT_SOURCES) $(GUEST_HEADERS) $(SDK_INPUTS) $(HOST_TEST_INPUTS)
	$(DEV) --shell portable python3 -B scripts/build-portable.py
	touch $(BUILD)/portable/linux-bash-os $(BUILD)/portable/sandbox-init

$(OUT)/full/linux-bash-os $(OUT)/portable/linux-bash-os &: $(BUILD)/kernel-full/linux-bash-os $(BUILD)/portable/linux-bash-os $(BUILD)/portable/sandbox-init scripts/build-sandbox.py $(wildcard scripts/runtime.py) config/os-release $(LOCAL_CONFIG)
	python3 -B scripts/build-sandbox.py

bundle: $(BUILD)/kernel-full/linux-bash-os $(BUILD)/portable/linux-bash-os $(BUILD)/portable/sandbox-init
	python3 -B scripts/build-sandbox.py
	cp $(OUT)/full/linux-bash-os $(OUT)/linux-bash-os.tmp
	mv -f $(OUT)/linux-bash-os.tmp $(OUT)/linux-bash-os
	cp $(OUT)/full/bash.bpf.o $(OUT)/bash.bpf.o.tmp
	mv -f $(OUT)/bash.bpf.o.tmp $(OUT)/bash.bpf.o

$(BUILD)/native.stamp: scripts/prepare-bash.py scripts/workspace.py scripts/source_tree.py SOURCE.json $(BASH_SOURCE_INPUTS)
	mkdir -p $(BUILD)
	$(DEV) python3 -B scripts/prepare-bash.py > $(BUILD)/prepare.log 2>&1 || { tail -60 $(BUILD)/prepare.log; exit 1; }
	touch $@

$(BUILD)/bitcode.stamp: $(BUILD)/native.stamp scripts/compile-bash.py $(GUEST_HEADERS)
	$(DEV) python3 -B scripts/compile-bash.py
	touch $@

$(OUT)/pure/linux-bash-os: $(BUILD)/bitcode.stamp $(BUILD_CONFIG) $(PORT_SOURCES) $(GUEST_HEADERS) $(SDK_INPUTS) $(HOST_TEST_INPUTS)
	$(DEV) python3 -B scripts/build-full.py --profile pure
	mkdir -p $(OUT)/pure
	cp $(BUILD)/kernel/linux-bash-os $(OUT)/pure/linux-bash-os.tmp
	mv -f $(OUT)/pure/linux-bash-os.tmp $(OUT)/pure/linux-bash-os
	cp $(BUILD)/kernel/bash.bpf.o $(OUT)/pure/bash.bpf.o.tmp
	mv -f $(OUT)/pure/bash.bpf.o.tmp $(OUT)/pure/bash.bpf.o

run: build
	$(OUT)/linux-bash-os

demo: build
	$(OUT)/linux-bash-os --stats examples/demo.sh

verify: test-vm

test-vm: build
	python3 -B scripts/test-vm.py --build $(BUILD)/kernel-full --reference $(BUILD)/native-full/source/out/bash-kernel-reference --cases tests/full-cases.sh --init tests/full-init.sh --memory 8192 --timeout 1500

test-host: build
	$(DEV) ctest --test-dir $(BUILD)/kernel-full --output-on-failure

test-processes: build
	python3 -B scripts/test-vm.py --build $(BUILD)/kernel-full --reference $(BUILD)/native-full/source/out/bash-kernel-reference --cases tests/process-cases.sh --init tests/process-init.sh --memory 8192 --timeout 360

test-portable: portable
	$(DEV) --shell portable ctest --test-dir $(BUILD)/portable --output-on-failure
	python3 -B scripts/test-vm.py --build $(BUILD)/portable --portable --work $(REPORTS)/vm-portable --reference $(BUILD)/native-full/source/out/bash-kernel-reference --cases tests/full-cases.sh --init tests/full-init.sh --memory 8192 --timeout 1500

test-portable-processes: portable
	python3 -B scripts/test-vm.py --build $(BUILD)/portable --portable --work $(REPORTS)/vm-portable-processes --reference $(BUILD)/native-full/source/out/bash-kernel-reference --cases tests/process-cases.sh --init tests/process-init.sh --memory 8192 --timeout 360

test-mount-cwd: build
	python3 -B scripts/test-vm.py --build $(BUILD)/kernel-full --work $(REPORTS)/vm-mount-cwd --cases tests/mount-cwd-cases.sh --init tests/mount-cwd-init.sh --memory 8192 --timeout 600

test-portable-mount-cwd: portable
	python3 -B scripts/test-vm.py --build $(BUILD)/portable --portable --work $(REPORTS)/vm-portable-mount-cwd --cases tests/mount-cwd-cases.sh --init tests/mount-cwd-init.sh --memory 8192 --timeout 600

test-sandbox: portable
	python3 -B scripts/test-sandbox.py

test-mlkem: $(BUILD)/full-bitcode.stamp
	$(WORKSPACE) --prepare-cmake $(BUILD)/mlkem-test tests/mlkem
	$(DEV) cmake -S tests/mlkem -B $(BUILD)/mlkem-test -UBpfCapsule_DIR -UCODEGEN_OPTIONS
	$(DEV) cmake --build $(BUILD)/mlkem-test -j4
	python3 -B scripts/test-vm.py --build $(BUILD)/mlkem-test --reference $(BUILD)/mlkem-test/native-check --init tests/mlkem/init.sh --memory 2048 --timeout 150

test-sha1dc: $(BUILD)/full-bitcode.stamp
	$(WORKSPACE) --prepare-cmake $(BUILD)/sha1dc-test tests/sha1dc
	$(DEV) cmake -S tests/sha1dc -B $(BUILD)/sha1dc-test -UBpfCapsule_DIR -UCODEGEN_OPTIONS
	$(DEV) cmake --build $(BUILD)/sha1dc-test -j4
	python3 -B scripts/test-vm.py --build $(BUILD)/sha1dc-test --reference $(BUILD)/sha1dc-test/native-check --init tests/sha1dc/init.sh --memory 2048 --timeout 150

paths:
	$(WORKSPACE)

test-workspace:
	python3 -B tests/workspace.py
	python3 -B tests/source-tree.py

clean:
	$(WORKSPACE) --clean
