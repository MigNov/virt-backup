Name:		virt-backup
Version:	0.0.1
Release:	3%{?dist}
Summary:	Utility to backup virtual machines using libvirt API and LZMA compression (if installed)

Group:		Applications/Emulators
License:	GPL
Source0:	virt-backup-%{version}.tar.gz
BuildRoot:	%(mktemp -ud %{_tmppath}/%{name}-%{version}-%{release}-XXXXXX)
BuildRequires:	libvirt-devel libxml2-devel e2fsprogs-devel

%description
The virt-backup utility is the libvirt-based utility to backup various types of virtual
machines using information provided by libvirt API. Virt-backup supports both raw file
copying and LZMA compression when LZMA library is found using pkg-config.

%prep
%setup -q

%build
%configure
make %{?_smp_mflags}


%install
rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT


%clean
rm -rf $RPM_BUILD_ROOT


%files
%defattr(-,root,root,-)
%{_bindir}/virt-backup
%doc



%changelog
* Fri Aug 06 2010 Michal Novotny <minovotn@redhat.com>
- Update to v0.0.2
- Block API added for local connections
- configure for project created
- debuginfo package enabled

* Sun Jul 25 2010 Michal Novotny <minovotn@redhat.com> 
- Initial release (v0.0.1)
