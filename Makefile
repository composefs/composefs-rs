PREFIX ?= /usr/local
DESTDIR ?=
LIBDIR ?= $(PREFIX)/lib

.PHONY: build-capi install-capi

build-capi:
	cargo build --release -p composefs-capi

install-capi: build-capi
	LIBDIR=$(DESTDIR)$(LIBDIR) crates/composefs-capi/install.sh $(DESTDIR)$(PREFIX)
