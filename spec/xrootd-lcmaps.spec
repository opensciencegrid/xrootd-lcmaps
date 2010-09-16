
Name: xrootd-lcmaps
Version: 0.0.1
Release: 1
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
* Tue Aug 24 2010 Brian Bockelman <bbockelm@cse.unl.edu> 0.0.1-1
- Initial integration of LCMAPS into Xrootd.

