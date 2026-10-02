# Build, test and package the ME7 toolkit. The GitHub workflows run these same targets.
#
#   make                  test + extension
#   make test             me7tools pytest (image tests skip without ../ME7Sum/bins)
#   make extension        Ghidra extension zip in ghidra-extension/dist/
#   make ghidra           download GHIDRA_VERSION into build/ghidra (CI; optional locally)
#   make changelog        release notes for unreleased commits (git-cliff)
#
# GHIDRA_INSTALL_DIR: an existing Ghidra install. If unset, Gradle falls back to
# ~/.gradle/gradle.properties; `make GHIDRA_INSTALL_DIR=download` uses build/ghidra.

SHELL := /bin/bash

GHIDRA_VERSION ?= 12.1.2
GHIDRA_DL := build/ghidra/ghidra_$(GHIDRA_VERSION)_PUBLIC
ifeq ($(GHIDRA_INSTALL_DIR),download)
override GHIDRA_INSTALL_DIR := $(CURDIR)/$(GHIDRA_DL)
EXTENSION_DEPS := $(GHIDRA_DL)/support/buildExtension.gradle
endif

# vX.Y.Z tag -> X.Y.Z; later commits add git describe's -N-gHASH, local edits -dirty.
VERSION ?= $(patsubst v%,%,$(shell git describe --tags --match 'v[0-9]*' --dirty --always 2>/dev/null))

PYTHON ?= python3
VENV := tools/me7tools/.venv

.PHONY: all test extension ghidra changelog version clean help

all: test extension

$(VENV)/.installed: tools/me7tools/pyproject.toml
	$(PYTHON) -m venv $(VENV)
	$(VENV)/bin/pip install -q -e "tools/me7tools[dev]"
	touch $@

test: $(VENV)/.installed
	$(VENV)/bin/pytest -q tools/me7tools

extension: $(EXTENSION_DEPS)
	cd ghidra-extension && ./gradlew -q buildExtension -PME7_VERSION=$(VERSION) \
		$(if $(GHIDRA_INSTALL_DIR),-PGHIDRA_INSTALL_DIR=$(GHIDRA_INSTALL_DIR))
	@ls ghidra-extension/dist/ME7Ghidra-$(VERSION)-*.zip

ghidra: $(GHIDRA_DL)/support/buildExtension.gradle

$(GHIDRA_DL)/support/buildExtension.gradle:
	mkdir -p build/ghidra
	url=$$(curl -fsSL $${GITHUB_TOKEN:+-H "Authorization: Bearer $$GITHUB_TOKEN"} \
		https://api.github.com/repos/NationalSecurityAgency/ghidra/releases/tags/Ghidra_$(GHIDRA_VERSION)_build \
		| grep -o 'https://[^"]*/ghidra_$(GHIDRA_VERSION)_PUBLIC_[0-9]*\.zip' | head -1) && \
	test -n "$$url" && curl -fsSL -o build/ghidra/ghidra.zip "$$url"
	unzip -q -o build/ghidra/ghidra.zip -d build/ghidra
	rm build/ghidra/ghidra.zip
	touch $@

changelog:
	git cliff --offline --unreleased --strip header

version:
	@echo $(VERSION)

clean:
	rm -rf ghidra-extension/build ghidra-extension/dist

help:
	@sed -n '3,9p' Makefile
