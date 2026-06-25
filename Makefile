PREFIX ?= /usr/local
DESTDIR ?=
LIBDIR ?= $(PREFIX)/lib
SBINDIR ?= $(PREFIX)/sbin
BINDIR ?= $(PREFIX)/bin
MANDIR ?= $(PREFIX)/share/man

.PHONY: build-capi install-capi build-ctl install-ctl install-man

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
