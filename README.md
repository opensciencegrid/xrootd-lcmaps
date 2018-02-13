# LCMAPS Callout for XRootD

This XRootD plugin provides a way to integrate the [XRootD](http://xrootd.org/) authorization subsystem with the
[LCMAPS authorization](https://wiki.nikhef.nl/grid/LCMAPS) infrastructure.  This allows for a site's configuration
of GSI and VOMS-based authentication and authorization to apply to an XRootD service.

The LCMAPS callout provides the XRootD authorization subsystem with:

* A Unix username corresponding to the GSI / VOMS identity.
* The corresponding end-entity-credential subject (colloquially known as the user's DN).
* VOMS information such as the corresponding VO and VOMS role.
* The credential's VOMS groups as the list of XRootD groups.

It works with both the XRootD and HTTPS protocol interfaces for XRootD.

## Compiling

The plugin requires:

* A working C++11 compiler,
* CMake 2.6 or later,
* The XRootD server headers (4.x or later),
* Globus development headers (`globus-gsi-credential`, `globus-gsi-cert-utils`),
* and the LCMAPS headers (and version from 2014 or later).

To compile, we recommend an out-of-source build.  From an empty directory, run:

```
cmake ../path/to/source
make
make install
```

## Configuration

The following lines in the XRootD configuration file will enable the LCMAPS plugin based on `/etc/lcmaps.db`

```
sec.protocol /usr/lib64 gsi -certdir:/etc/grid-security/certificates -cert:/etc/grid-security/xrd/xrdcert.pem \
                            -key:/etc/grid-security/xrd/xrdkey.pem -crl:1 \
                            -authzfun:libXrdLcmaps.so -authzfunparms:--lcmapscfg,/etc/lcmaps.db,--loglevel,0 \
                            -gmapopt:10 -gmapto:0

http.secxtractor /usr/lib64/libXrdLcmaps.so
```

Only the library name (`/usr/lib64/libXrdLcmaps.so`) and the `-authzfun`/`-authzfunparms` are relevant to the plugins;
the remaining arguments are simply part of the XRootD configuration.

The following command line flags are accepted:

* `lcmapscfg`: Filename of the configuration file.  If not specified, it uses `/etc/lcmaps.db`.
* `loglevel`: The LCMAPS log level.  LCMAPS typically logs to syslog (`/var/log/messages`).  0 is default for XRootD, but
  higher levels may be useful for debugging.
* `policy`: The policy to execute out of the LCMAPS configuration file; defaults to one named `xrootd_policy`.

Note that `osg` used to be a separate flag for this plug-in; it is no longer applicable and is ignored.
