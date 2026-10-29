prefix ?= /usr

SOURCE_DATE_EPOCH ?= $(shell git log -1 --pretty=%ct)
# https://reproducible-builds.org/docs/archives/
TAR_REPRODUCIBLE = tar --mtime="@${SOURCE_DATE_EPOCH}" --sort=name --owner=0 --group=0 --numeric-owner --pax-option=exthdr.name=%d/PaxHeaders/%f,delete=atime,delete=ctime

UNAME_S := $(shell uname -s)

ifeq ($(UNAME_S),Linux)
all: bin manpages
else
# The man pages document the Linux command line
all: bin
endif

# The workspace check is Linux only: bcvk-nbd builds only for Linux
.PHONY: bin
bin: nbd-server
ifeq ($(UNAME_S),Linux)
	cargo check --workspace
endif
	cargo build --release

# Generate man pages from markdown sources
# This delegates to the xtask which handles:
# - Syncing CLI options into markdown
# - Flexible section number handling
# - Version placeholder replacement
# - go-md2man conversion
# - Apostrophe handling fixes
.PHONY: manpages
manpages:
	cargo run --release --package xtask -- manpages

# This gates CI by default. Note that for clippy, we gate on
# only the clippy correctness and suspicious lints, plus a select
# set of default rustc warnings.
# We intentionally don't gate on this for local builds in cargo.toml
# because it impedes iteration speed.
CLIPPY_CONFIG = -A clippy::all -D clippy::correctness -D clippy::suspicious -D clippy::disallowed-methods -Dunused_imports -Ddead_code
validate:
	cargo fmt -- --check -l
	cargo test --no-run --workspace
	cargo clippy -- $(CLIPPY_CONFIG)
	cargo clippy -p bcvk-nbd -- $(CLIPPY_CONFIG)
	env RUSTDOCFLAGS='-D warnings' cargo doc --lib
.PHONY: validate

install:
	install -D -m 0755 -t $(DESTDIR)$(prefix)/bin target/release/bcvk
	@# Install all generated man pages to their appropriate sections
	@if [ -d target/man ]; then \
	  for manpage in target/man/*.[1-9]; do \
	    section=$$(echo $$manpage | sed 's/.*\.\([0-9]\)$$/\1/'); \
	    install -D -m 0644 $$manpage -t $(DESTDIR)$(prefix)/share/man/man$$section/; \
	  done; \
	fi

makesudoinstall:
	make
	sudo make install

sync-manpages:
	cargo run --release --package xtask -- sync-manpages

update-manpages:
	cargo run --release --package xtask -- update-manpages

update-generated: sync-manpages manpages

.PHONY: all bin install manpages update-generated makesudoinstall sync-manpages update-manpages nbd-server

# Cross-compile NBD server for podman machine (needed on macOS/Windows, no-op on Linux)
NBD_ARCH := $(shell rustc -vV | awk '/^host:/ {split($$2, a, "-"); print a[1]}')
NBD_TARGET := $(NBD_ARCH)-unknown-linux-gnu

.PHONY: nbd-server
nbd-server:
ifneq ($(UNAME_S),Linux)
	PATH="$(HOME)/.rustup/toolchains/stable-$(shell rustc -vV | awk '/^host:/ {print $$2}')/bin:$(HOME)/.cargo/bin:$(PATH)" \
	  cargo zigbuild --target $(NBD_TARGET) --release -p bcvk-nbd
	mkdir -p target/nbd-server
	cp target/$(NBD_TARGET)/release/bcvk-nbd target/nbd-server/bcvk-nbd
endif
