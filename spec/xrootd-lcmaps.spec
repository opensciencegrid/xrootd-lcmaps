
Name: xrootd-lcmaps
Version: 0.0.6
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
BuildRequires: lcmaps-interface
BuildRequires: lcmaps
BuildRequires: cmake
Requires: xrootd-server >= 1:3.2

%package devel
Summary: Development libraries for the Xrootd LCMAPS plugin
Group: System Environment/Development

License: BSD

%description
%{summary}

%description devel
%{summary}

%prep
%setup -q -c -n %{name}-%{version}

%build
#cmake -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_BUILD_TYPE=RelWithDebInfo .
%cmake -DCMAKE_BUILD_TYPE=RelWithDebInfo .
make VERBOSE=1 %{?_smp_mflags}

%install
rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root,-)
%{_libdir}/libXrdLcmaps.so.0
%{_libdir}/libXrdLcmaps.so.0.0.1
%config(noreplace) %{_sysconfdir}/xrootd/lcmaps.cfg

%files devel
%defattr(-,root,root,-)
%{_libdir}/libXrdLcmaps.so

%changelog
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

