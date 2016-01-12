Name: xrootd-lcmaps
Version: 1.1.0
Release: 1%{?dist}
Summary: LCMAPS plugin for xrootd

Group: System Environment/Daemons
License: BSD
URL: https://github.com/bbockelm/xrootd-lcmaps
# Generated from:
# git-archive master | gzip -7 > ~/rpmbuild/SOURCES/xrootd-lcmaps.tar.gz
Source0: %{name}.tar.gz
BuildRoot: %(mktemp -ud %{_tmppath}/%{name}-%{version}-%{release}-XXXXXX)
BuildRequires: xrootd-libs-devel
BuildRequires: xrootd-server-libs >= 1:4.1.0
BuildRequires: xrootd-server-devel >= 1:4.1.0
BuildRequires: lcmaps-interface
BuildRequires: lcmaps
BuildRequires: cmake
BuildRequires: voms-devel
Requires: xrootd-server >= 1:3.2

%description
%{summary}

%prep
%setup -n %{name}-%{version}

%build
cmake -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_BUILD_TYPE=RelWithDebInfo .

make VERBOSE=1 %{?_smp_mflags}

%install
rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root,-)
# We keep the .so here (and not in a -devel subpackage) because it is actually
# a shared library.
%{_libdir}/libXrdLcmaps.so
%{_libdir}/libXrdLcmaps.so.0
%{_libdir}/libXrdLcmaps.so.0.0.2
%config(noreplace) %{_sysconfdir}/xrootd/lcmaps.cfg

%changelog
* Mon Jan 11 2016 Brian Bockelman <bbockelm@cse.unl.edu> - 1.1.0-1
- Add caching support to HTTP.

* Mon Jan 04 2016 Brian Bockelman <bbockelm@cse.unl.edu> - 1.0.0-1
- Add support for a HTTP security extractor.
- Mark as 1.0 release.

* Mon Nov 19 2012 Brian Bockelman <bbockelm@cse.unl.edu> - 0.0.7-1
- Fix config parsing issues.

* Mon Nov 12 2012 Brian Bockelman - 0.0.6-1
- Fix SL6 compilation issues.

* Mon Oct 22 2012 Brian Bockelman <bbockelm@cse.unl.edu> - 0.0.5-1
- Switch to cmake.

* Mon Feb 13 2012 Brian Bockelman <bbockelm@cse.unl.edu> - 0.0.4-1
- Various bugfixes from Matevz Tadel.

* Fri Sep 16 2011 Brian Bockelman <bbockelm@cse.unl.edu> - 0.0.3-1
- Updated to match mapping callout found in Xrootd 3.1.

* Tue May 17 2011 Brian Bockelman <bbockelm@cse.unl.edu> 0.0.2-6
- Update RPM deps for CERN-based xrootd RPM.

* Wed Mar 30 2011 Brian Bockelman <bbockelm@cse.unl.edu> 0.0.2-5
- Update Koji for 32-bit build.

* Fri Dec 24 2010 Brian Bockelman <bbockelm@cse.unl.edu> 0.0.2-4
- Update sample config line based on xrootd 3.0.0 final plugin code.

* Mon Sep 20 2010 Brian Bockelman <bbockelm@cse.unl.edu> 0.0.2-3
- Update dependency info based on Mock/Koji errors.
- Added some forgotten plugin deps.

* Fri Sep 17 2010 Brian Bockelman <bbockelm@cse.unl.edu> 0.0.2-1
- Add the sample LCMAPS configuration.
- Updated to the new tarball.  Calls the LCMAPS library directly instead of via helpers.

* Thu Sep 17 2010 Brian Bockelman <bbockelm@cse.unl.edu> 0.0.1-4
- Recompile for new LCMAPS library.
- Try and fix C++ vs C linker issues.
- Link in all the required lcmaps libraries.

* Wed Sep 16 2010 Brian Bockelman <bbockelm@cse.unl.edu> 0.0.1-1
- Initial integration of LCMAPS into Xrootd.

