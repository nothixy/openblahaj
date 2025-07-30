#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.72])
AC_INIT(
    [openBLAHAJ],
    [1.0.0],
    [fl.valentin1904@gmail.com]
)
AM_SILENT_RULES([yes])
AC_CONFIG_SRCDIR([build-aux/config.h.in])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_AUX_DIR([build-aux])
AC_REQUIRE_AUX_FILE([tap-driver.sh])
AM_INIT_AUTOMAKE([subdir-objects foreign -Wall])

#AC_CANONICAL_HOST

AX_CHECK_ENABLE_DEBUG(
	[no],
	[DEBUG],
	[NDEBUG]
)

AC_ARG_ENABLE(
	static,
	[AS_HELP_STRING(
		[--enable-static],
		[compile a static release]
	)],
	[case "${enableval}" in
		yes) case "${host_os}" in darwin*) AC_MSG_ERROR([can't build static binaries on OSX]);; esac; static=true; AC_DEFINE(
				[OB_BUILD_STATIC],
				[1],
				[Create a static build]
			);;
		no) static=false;;
		*) AC_MSG_ERROR([bad value ${enableval} for --enable-static]);;
	esac],
	[static=false]
)

AC_ARG_ENABLE(
	bluetooth,
	[AS_HELP_STRING(
		[--enable-bluetooth],
		[compile with bluetooth support]
	)],
	[case "${enableval}" in
		yes) bluetooth=true; AC_DEFINE(
			[OB_BUILD_BLUETOOTH],
			[1],
			[Build bluetooth support]
		);;
		no) bluetooth=false;;
		*) AC_MSG_ERROR([bad value ${enableval} for --enable-bluetooth]);;
	esac],
	[bluetooth=false]
)

AC_ARG_ENABLE(
	dbus,
	[AS_HELP_STRING(
		[--enable-dbus],
		[compile with dbus support]
	)],
	[case "${enableval}" in
		yes) dbus=true; AC_DEFINE(
			[OB_BUILD_DBUS],
			[1],
			[Build dbus support]
		);;
		no) dbus=false;;
		*) AC_MSG_ERROR([bad value ${enableval} for --enable-dbus]);;
	esac],
	[dbus=false]
)

AM_CONDITIONAL([STATIC_RELEASE], [test x$static = xtrue])
AM_CONDITIONAL([BUILD_BLUETOOTH], [test x$bluetooth = xtrue])
AM_CONDITIONAL([BUILD_DBUS], [test x$dbus = xtrue])

# Checks for programs.
AC_PROG_CXX
AC_PROG_CC
AC_PROG_AWK
AC_PROG_INSTALL
AC_PROG_MKDIR_P

# Checks for libraries.
AC_SEARCH_LIBS(
	[pcap_init],
	[pcap],
	[],
	[AC_MSG_ERROR([bad value ${enableval} for --enable-static])]
)

# Checks for header files.

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL
AC_C_INLINE

# Checks for library functions.

AC_CONFIG_FILES([Makefile
				doc_generation/Doxyfile
				tests/Makefile
				src/Makefile])

AC_CONFIG_FILES([tests/commandline1.ftest], [chmod +x tests/commandline1.ftest])
AC_CONFIG_FILES([tests/commandline2.stest], [chmod +x tests/commandline2.stest])
AC_CONFIG_FILES([tests/capture.test], [chmod +x tests/capture.test])
AC_CONFIG_LINKS([tests/empty.cap:tests/empty.cap])

DX_PS_FEATURE(OFF)
DX_PDF_FEATURE(OFF)
DX_DOT_FEATURE(ON)
DX_INIT_DOXYGEN(
	[openBLAHAJ],
	[${top_builddir}/doc_generation/Doxyfile],
	[doc]
)

AC_OUTPUT

