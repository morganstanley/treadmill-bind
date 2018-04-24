Name:           treadmill-bind
Version:        5.1
Release:        2%{?dist}
Summary:        Treadmill bind preload shared library.

License:        Apache 2.0
URL:            https://github.com/Morgan-Stanley/treadmill-pid1 
Source0:        %{name}-%{version}.tar.gz 


%description
Treadmill bind preload library.


%prep
%setup -q


%build
%configure
make %{?_smp_mflags}


%install
rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT


%files
%defattr(-,root,root,-)
%{_libdir}/libtreadmill_bind_preload.a
%{_libdir}/libtreadmill_bind_preload.la
%{_libdir}/libtreadmill_bind_preload.so
%{_libdir}/libtreadmill_bind_preload.so.0
%{_libdir}/libtreadmill_bind_preload.so.0.0.0
%doc


%changelog
* Tue Apr 17 2018 Andrei Keis andreikeis@noreply.github.com - 1.0-2
- Initial RPM release.

