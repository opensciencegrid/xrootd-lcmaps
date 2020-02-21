
Name: xrootd-lcmaps
Version: 1.7.5
Release: 2%{?dist}
Summary: LCMAPS plugin for xrootd

Group: System Environment/Daemons
License: BSD
URL: https://github.com/opensciencegrid/xrootd-lcmaps
# Generated from:
# git archive v${VERSION} --prefix=xrootd-lcmaps-$VERSION/ | gzip -7 > ~/rpmbuild/SOURCES/xrootd-lcmaps-$VERSION.tar.gz
Source0: %{name}-%{version}.tar.gz

%define xrootd_current 4.11
%define xrootd_next 5.0

BuildRequires: xrootd-server-devel >= 1:%{xrootd_current}.0-1
BuildRequires: xrootd-server-devel <  1:%{xrootd_next}.0-1
BuildRequires: lcmaps-interface
BuildRequires: lcmaps
BuildRequires: cmake
BuildRequires: voms-devel

# For C++11 compatibility, inspired by frontier-squid:
# http://svnweb.cern.ch/world/wsvn/frontier/rpms/frontier-squid4/tags/frontier-squid-4.3-1.1/SPECS/frontier-squid.spec
%if 0%{?el6}
BuildRequires: devtoolset-2-toolchain
BuildRequires: scl-utils
%endif

# For Globus-based chain verification
BuildRequires: globus-gsi-credential-devel
BuildRequires: globus-gsi-cert-utils-devel
BuildRequires: globus-common-devel
BuildRequires: globus-gsi-sysconfig-devel
BuildRequires: globus-gsi-callback-devel

Requires: xrootd-server >= 1:%{xrootd_current}.0-1
Requires: xrootd-server <  1:%{xrootd_next}.0-1

%description
%{summary}

%prep

%setup -q

%build

%if 0%{?el6}
scl enable devtoolset-2 '
%endif

#cmake -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_BUILD_TYPE=RelWithDebInfo .
%cmake -DCMAKE_BUILD_TYPE=RelWithDebInfo .
make VERBOSE=1 %{?_smp_mflags}

%if 0%{?el6}
'
%endif

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
%config(noreplace) %{_sysconfdir}/xrootd/config.d/10-xrootd-lcmaps.cfg
%config %{_sysconfdir}/xrootd/config.d/40-xrootd-lcmaps.cfg

%changelog
* Fri Feb 21 2020 Diego Davila <didavila@ucad.edu> - 1.7.5-2
- Rebuild against xrootd 5.0 (SOFTWARE-3923)

* Fri Jan 10 2020 Diego Davila <didavila@ucad.edu> - 1.7.5-1
- Allow lcmaps policy to be read from config file for http

* Mon Oct 21 2019 Carl Edquist <edquist@cs.wisc.edu> - 1.7.4-4
- Rebuild against xrootd 4.11 (SOFTWARE-3830)

* Tue Sep 17 2019 Diego Davila <didavila@ucsd.edu> - 1.7.4-3
- Enforce building and installing with same version of xrootd

* Tue Aug 27 2019 Brian Lin <blin@cs.wisc.edu> - 1.7.4-2
- Require XRootD 4.10.0 due to incompatibility with 4.9.1

* Fri Aug 16 2019 Brian Lin <blin@cs.wisc.edu> - 1.7.4-1
- Make default configuration opt-in (SOFTWARE-3534)

* Thu Aug 01 2019 Brian Lin <blin@cs.wisc.edu> - 1.7.3-1
- Add support for unauthenticated Stash Caches and Origins
- Fix authzfunparms syntax
- Use the canonical LCMAPS config location in the default config

* Fri Jul 26 2019 Diego Davila <didavila@ucsd.edu> - 1.7.2-1
- Adding 40-xrootd-lcmaps.cfg to CMakeLists.txt
- Adding .travis.yml

* Fri Jul 26 2019 Diego Davila <didavila@ucsd.edu> - 1.7.1-1
- Adding directory config.d and file config.d/40-xrootd-lcmaps.cfg (SOFTWARE-3534)
- Changing xrootd requirement to 4.9.0

* Tue Feb 05 2019 Brian Bockelman <brian.bockelman@cern.ch> - 1.7.0-1
- Add key=value config syntax.
- Prior config syntax no longer requires a minimum of three arguments.

* Wed Jan 02 2019 Brian Lin <blin@cs.wisc.edu> - 1.6.0-1
- Add EL6 support

* Wed Jan 02 2019 Brian Lin <blin@cs.wisc.edu> - 1.5.2-1
- Unify XRootD/HTTP monitoring info by copying the DN and VOMS attributes into the info field

* Fri Dec 21 2018 Brian Bockelman <bbockelm@cse.unl.edu> - 1.5.1-1
- As specified, skip callout for HTTP

* Thu Nov 22 2018 Brian Bockelman <bbockelm@cse.unl.edu> - 1.5.0-1
- Add mode to skip LCMAPS callout

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

