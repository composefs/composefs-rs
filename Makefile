PREFIX ?= /usr/local
DESTDIR ?=
LIBDIR ?= $(PREFIX)/lib
SBINDIR ?= $(PREFIX)/sbin
BINDIR ?= $(PREFIX)/bin

.PHONY: build-capi install-capi build-ctl install-ctl

build-capi:
	cargo build --release -p composefs-capi

install-capi: build-capi
	LIBDIR=$(DESTDIR)$(LIBDIR) crates/composefs-capi/install.sh $(DESTDIR)$(PREFIX)

build-ctl:
	cargo build --release -p composefs-ctl

install-ctl: build-ctl
	install -d $(DESTDIR)$(BINDIR) $(DESTDIR)$(SBINDIR)
	install -m 755 target/release/cfsctl $(DESTDIR)$(BINDIR)/cfsctl
	ln -sf $(BINDIR)/cfsctl $(DESTDIR)$(SBINDIR)/mount.composefs
	ln -sf $(BINDIR)/cfsctl $(DESTDIR)$(BINDIR)/mkcomposefs
	ln -sf $(BINDIR)/cfsctl $(DESTDIR)$(BINDIR)/composefs-info
