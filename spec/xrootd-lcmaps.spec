
Name: xrootd-lcmaps
Version: 0.0.1
Release: 4
Summary: LCMAPS plugin for xrootd

Group: System Environment/Daemons
License: BSD
URL: svn://t2.unl.edu/brian/XrdLcmaps
Source0: %{name}-%{version}.tar.gz
BuildRoot: %(mktemp -ud %{_tmppath}/%{name}-%{version}-%{release}-XXXXXX)
BuildRequires: xrootd-devel >= 1.4.1 lcmaps
Requires: xrootd >= 1.4.1 lcmaps

%description
%{summary}

%prep
%setup -q

%build
%configure --with-xrootd-incdir=/usr/include/xrootd --with-lcmaps-incdir=/usr/include/lcmaps
make

%install
rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT

rm -rf $RPM_BUILD_ROOT/%{_libdir}/*.la
rm -rf $RPM_BUILD_ROOT/%{_libdir}/*.a

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root,-)
%{_libdir}/libXrdLcmaps*

%changelog
* Thu Sep 17 2010 Brian Bockelman <bbockelm@cse.unl.edu> 0.0.1-4
- Recompile for new LCMAPS library.
- Try and fix C++ vs C linker issues.
- Link in all the required lcmaps libraries.

* Wed Sep 16 2010 Brian Bockelman <bbockelm@cse.unl.edu> 0.0.1-1
- Initial integration of LCMAPS into Xrootd.

