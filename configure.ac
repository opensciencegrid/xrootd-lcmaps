
AC_PREREQ(2.57)
AC_INIT(xrootd-lcmaps,0.0.2,xrootd-demonstrator@opensciencegrid.org)
AC_CONFIG_SRCDIR([src/XrdLcmaps.cc])

AC_PROG_CXX
AC_PROG_CC
AC_PROG_INSTALL

AC_LANG_CPLUSPLUS

AM_INIT_AUTOMAKE

AC_ARG_WITH(xrootd-libdir,
            [  --with-xrootd-libdir=PATH        path to xrootd libraries],
            XROOTD_LIBDIR=-L$withval)
AC_SUBST(XROOTD_LIBDIR)
AC_ARG_WITH(xrootd-incdir,
            [  --with-xrootd-incdir=PATH        path to xrootd header files],
            XROOTD_INCDIR=-I$withval)
AC_SUBST(XROOTD_INCDIR)

AC_ARG_WITH(lcmaps-libdir,
            [  --with-lcmaps-libdir=PATH        directory path to liblcmaps.so library],
            LCMAPS_LIBDIR=-L$withval)
AC_SUBST(LCMAP_LIBDIR)
AC_ARG_WITH(lcmaps-incdir,
            [  --with-lcmaps-incdir=PATH        directory path to lcmaps.h header file],
            LCMAPS_INCDIR=-I$withval)
AC_SUBST(LCMAPS_INCDIR)

# determines shared library needed for loading modules
AC_LIBTOOL_DLOPEN
# init for libtool
AC_PROG_LIBTOOL

AM_PROG_CC_C_O

# libhdfs.so
LDFLAGS="$LCMAPS_LIBDIR $XROOTD_LIBDIR $LDFLAGS"
AC_CHECK_LIB([lcmaps],[getMajorVersionNumber],[:],
            ,)
             #AC_MSG_ERROR([Failed linking test for lcmaps.so]),
LDFLAGS=$LDFLAGS_BUP

CXXFLAGS="$LCMAPS_INCDIR $XROOTD_INCDIR $INCLUDES $CXXFLAGS"
AC_CHECK_HEADER([lcmaps.h])

AC_OUTPUT(Makefile)

