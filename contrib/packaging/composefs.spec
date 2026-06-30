%bcond man 1

Name:           composefs
Version:        0.7.0
Release:        1%{?dist}
Summary:        Tools to handle creating and mounting composefs images

License:        MIT OR Apache-2.0
URL:            https://github.com/composefs/composefs-rs
Source0:        https://github.com/composefs/composefs-rs/releases/download/v%{version}/%{name}-rs-%{version}.tar.xz

BuildRequires:  cargo >= 1.88.0
BuildRequires:  rust >= 1.88.0
BuildRequires:  gcc
BuildRequires:  openssl-devel
%if %{with man}
BuildRequires:  pandoc
%endif

Requires:       %{name}-libs = %{version}-%{release}
Obsoletes:      composefs < 2.0

%description
Tools to handle creating and mounting composefs images. The composefs
project combines several underlying Linux features to provide a very
flexible mechanism to support read-only mountable filesystem trees,
stacking on top of an underlying "lower" Linux filesystem.

This is the Rust implementation of composefs.

%package        devel
Summary:        Devel files for %{name}
Requires:       %{name}%{?_isa} = %{version}-%{release}
Requires:       %{name}-libs%{?_isa} = %{version}-%{release}

%description    devel
Devel files for %{name}.

%package        libs
Summary:        Libraries for %{name}
License:        MIT OR Apache-2.0

%description    libs
Library files for %{name}.

%prep
%autosetup -n %{name}-rs-%{version} -p1

%build
cargo build --release -p composefs-ctl -p composefs-capi -p composefs-setup-root

%install
make install install-setup-root DESTDIR=%{buildroot} PREFIX=%{_prefix} BINDIR=%{_bindir} SBINDIR=%{_sbindir} LIBDIR=%{_libdir}

%if %{with man}
make install-man DESTDIR=%{buildroot} MANDIR=%{_mandir}
%endif

# Remove static library
rm -f %{buildroot}%{_libdir}/libcomposefs.a

%files devel
%{_includedir}/libcomposefs
%{_libdir}/libcomposefs.so
%{_libdir}/pkgconfig/%{name}.pc

%files libs
%license LICENSE-MIT LICENSE-APACHE
%{_libdir}/libcomposefs.so.*

%files
%license LICENSE-MIT LICENSE-APACHE
%doc README.md
%{_bindir}/cfsctl
%{_bindir}/mkcomposefs
%{_bindir}/composefs-info
%{_sbindir}/mount.composefs
%{_sbindir}/composefs-setup-root
%if %{with man}
%{_mandir}/man1/mkcomposefs.1*
%{_mandir}/man1/composefs-info.1*
%{_mandir}/man5/composefs-dump.5*
%{_mandir}/man8/mount.composefs.8*
%endif

%changelog
%autochangelog
