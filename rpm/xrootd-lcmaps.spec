
Name: xrootd-lcmaps
Version: 1.4.1
Release: 1%{?dist}
Summary: LCMAPS plugin for xrootd

Group: System Environment/Daemons
License: BSD
URL: https://github.com/opensciencegrid/xrootd-lcmaps
# Generated from:
# git archive v%{version} --prefix=xrootd-lcmaps-%{version}/ | gzip -7 > ~/rpmbuild/SOURCES/xrootd-lcmaps-%{version}.tar.gz
Source0: %{name}-%{version}.tar.gz
BuildRequires: xrootd-server-libs >= 1:4.1.0
BuildRequires: xrootd-server-devel >= 1:4.1.0
BuildRequires: lcmaps-interface
BuildRequires: lcmaps
BuildRequires: cmake
BuildRequires: voms-devel

# For Globus-based chain verification
BuildRequires: globus-gsi-credential-devel
BuildRequires: globus-gsi-cert-utils-devel
BuildRequires: globus-common-devel
BuildRequires: globus-gsi-sysconfig-devel
BuildRequires: globus-gsi-callback-devel

Requires: xrootd-server >= 1:4.6.1

%description
%{summary}

%prep

%setup -q

%build

%if 0%{?el6}
echo "*** This version does not build on EL 6 ***"
exit 1
%endif

#cmake -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_BUILD_TYPE=RelWithDebInfo .
%cmake -DCMAKE_BUILD_TYPE=RelWithDebInfo .
make VERBOSE=1 %{?_smp_mflags}

%install
make install DESTDIR=$RPM_BUILD_ROOT

%files
%defattr(-,root,root,-)
# We keep the .so here (and not in a -devel subpackage) because it is actually
# a shared library.
%{_libdir}/libXrdLcmaps.so
%{_libdir}/libXrdLcmaps.so.0
%{_libdir}/libXrdLcmaps.so.0.0.2
%config(noreplace) %{_sysconfdir}/xrootd/lcmaps.cfg

%changelog
* Mon Sep 10 2018 Carl Edquist <edquist@cs.wisc.edu> - 1.4.1-1
- Use single mutex for LCMAPS calls from XrdLcmaps and XrdHttpLcmaps (#16)
- Drop OWNER_EXECUTE for lcmaps.cfg (#17)

* Tue Jan 02 2018 Brian Bockelman <bbockelm@cse.unl.edu> - 1.4.0-1
- Allow authentication to continue even when authz fails.

* Tue Aug 29 2017 Brian Bockelman <bbockelm@cse.unl.edu> - 1.3.5-1
- Fix ability to specify an alternate policy name.

* Mon Aug 07 2017 Marian Zvada <marian.zvada@cern.ch> - 1.3.4-1
- includes cleanup of various OpesnSSL-related bugs from 1.3.4 github tag
- no need patch from SW-2848 for OSG3.4 build

* Mon Jul 31 2017 Mátyás Selmeci <matyas@cs.wisc.edu> - 1.3.3-4
- Always enable VOMS attributes verification (SOFTWARE-2848)

* Fri Jul 28 2017 Brian Bockelman <bbockelm@cse.unl.edu> - 1.3.4-1
- Cleanup various OpenSSL-related bugs.

* Wed May 31 2017 Carl Edquist <edquist@cs.wisc.edu> - 1.3.3-3
- Don't build 1.3.3 for EL6 (SOFTWARE-2738)

* Wed May 31 2017 Carl Edquist <edquist@cs.wisc.edu> - 1.3.3-2
- Update patch to apply against 1.3.3 sources (SOFTWARE-2738)

* Fri May 26 2017 Marian Zvada <marian.zvada@cern.ch> - 1.3.3-1
- new release tagged; added Lock CertStore patch

* Fri May 26 2017 Brian Bockelman <bbockelm@cse.unl.edu> - 1.3.3-1
- Avoid segfault triggered by a reload without the mutex.

* Wed May 24 2017 Marian Zvada <marian.zvada@cern.ch> - 1.3.2-2
- Fix bugleaks and memory warnings for 4.6.1
- STAS-18

* Thu Mar 30 2017 Brian Bockelman <bbockelm@cse.unl.edu> - 1.3.2-1
- Only perform verification in Globus, not raw OpenSSL.

* Mon Feb 20 2017 Brian Bockelman <bbockelm@cse.unl.edu> - 1.3.1-1
- Fix population of the role security entity
- Fix various memory leaks.

* Sun Dec 11 2016 Brian Bockelman <bbockelm@cse.unl.edu> - 1.3.0-1
- Change X509 verification to be based on Globus libraries

* Thu Jan 14 2016 Brian Bockelman <bbockelm@cse.unl.edu> - 1.2.0-1
- Have VOMS attributes forward to the xrootd credential.

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

* Fri Sep 17 2010 Brian Bockelman <bbockelm@cse.unl.edu> 0.0.1-4
- Recompile for new LCMAPS library.
- Try and fix C++ vs C linker issues.
- Link in all the required lcmaps libraries.

* Thu Sep 16 2010 Brian Bockelman <bbockelm@cse.unl.edu> 0.0.1-1
- Initial integration of LCMAPS into Xrootd.

