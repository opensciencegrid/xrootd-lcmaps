
lib_LTLIBRARIES = libXrdLcmaps.la

INCLUDES = -I$(top_srcdir)/src

libXrdLcmaps_la_SOURCES = src/XrdLcmaps.cc

libXrdLcmaps_la_CXXFLAGS = -DLCMAPS_GSI_MODE=1
libXrdLcmaps_la_LDFLAGS = -llcmaps -llcmaps_return_account_from_pem

EXTRA_DIST = spec/xrootd-lcmaps.spec bootstrap

