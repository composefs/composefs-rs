PREFIX ?= /usr/local
DESTDIR ?=
LIBDIR ?= $(PREFIX)/lib
SBINDIR ?= $(PREFIX)/sbin
BINDIR ?= $(PREFIX)/bin
MANDIR ?= $(PREFIX)/share/man

.PHONY: build-capi install-capi build-ctl install-ctl build-setup-root install-setup-root install-man install

build-capi:
	cargo build --release -p composefs-capi

install-capi: build-capi
	DESTDIR=$(DESTDIR) LIBDIR=$(LIBDIR) crates/composefs-capi/install.sh $(PREFIX)

build-ctl:
	cargo build --release -p composefs-ctl

install-ctl: build-ctl
	install -d $(DESTDIR)$(BINDIR) $(DESTDIR)$(SBINDIR)
	install -m 755 target/release/cfsctl $(DESTDIR)$(BINDIR)/cfsctl
	ln -sf $(BINDIR)/cfsctl $(DESTDIR)$(SBINDIR)/mount.composefs
	ln -sf $(BINDIR)/cfsctl $(DESTDIR)$(BINDIR)/mkcomposefs
	ln -sf $(BINDIR)/cfsctl $(DESTDIR)$(BINDIR)/composefs-info

build-setup-root:
	cargo build --release -p composefs-setup-root

install-setup-root: build-setup-root
	install -d $(DESTDIR)$(SBINDIR)
	install -m 755 target/release/composefs-setup-root $(DESTDIR)$(SBINDIR)/composefs-setup-root

install: install-ctl install-capi

install-man:
	install -d $(DESTDIR)$(MANDIR)/man1 $(DESTDIR)$(MANDIR)/man5 $(DESTDIR)$(MANDIR)/man8
	for md in man/*.md; do \
		base=$$(basename "$$md" .md); \
		case "$$base" in \
			mount.composefs) section=8 ;; \
			composefs-dump)  section=5 ;; \
			*)               section=1 ;; \
		esac; \
		pandoc -s -t man "$$md" -o $(DESTDIR)$(MANDIR)/man$$section/$$base.$$section; \
	done
