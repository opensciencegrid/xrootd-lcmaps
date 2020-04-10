
FIND_PATH(XROOTD_INCLUDES XrdVersion.hh
  HINTS
  ${XROOTD_DIR}
  $ENV{XROOTD_DIR}
  /usr
  /opt/xrootd/
  PATH_SUFFIXES include/xrootd
  PATHS /opt/xrootd
)

FIND_PATH(XROOTD_SERVER_INCLUDES XrdHttp/XrdHttpSecXtractor.hh
  HINTS
  ${XROOTD_DIR}
  $ENV{XROOTD_DIR}
  /usr
  /opt/xrootd/
  PATH_SUFFIXES include/xrootd
  PATHS /opt/xrootd
)

INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(Xrootd DEFAULT_MSG XROOTD_INCLUDES XROOTD_SERVER_INCLUDES)

