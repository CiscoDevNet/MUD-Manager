#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT(MUD-Manager, 2.1dev, mud@cisco.com)
AM_INIT_AUTOMAKE([foreign subdir-objects])
AC_OUTPUT(Makefile src/Makefile dbtools/Makefile webui/Makefile)
LT_INIT
AC_CONFIG_MACRO_DIRS([m4])
AC_CONFIG_SRCDIR([src/acl.h])
AC_CONFIG_HEADERS([config.h])

AC_ARG_WITH(composer,
            [AS_HELP_STRING([[--with-composer=location of composer]],
                            [path to composer.])],
[
        if test "$withval" != "yes" ; then
    	  COMPOSER="$withval"
    	fi
])
AC_PATH_PROG([COMPOSER],composer)
AC_ARG_WITH(webui,
            [AS_HELP_STRING([[--with-webui=Web Directory]],
                            [path to the web directory, no default if used.])],
[
	with_webui=true
        if test "$withval" != "yes" ; then
    	  WEBUI="$withval"
    	else
	  AC_MSG_FAILURE([No webui directory provided],1)
    	fi
	if test x$COMPOSER = x; then
	  AC_MSG_FAILURE([composer not found])
	fi
])
AC_SUBST(WEBUI)
AM_CONDITIONAL([BUILDUI],[test x$with_webui = xtrue ])

# Checks for programs.
AC_PROG_CXX
AC_PROG_CC
AC_PROG_AWK
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_CPP
AC_PROG_MKDIR_P


# Checks for libraries.

AC_CHECK_LIB([cjson], [cJSON_Parse])

AC_CHECK_LIB([cjson_utils], [cJSONUtils_MergePatch])

AC_CHECK_LIB([crypto], [X509V3_get_d2i])

AC_CHECK_LIB([curl], [curl_easy_setopt])

AC_CHECK_LIB([dl], [dlopen])

AC_CHECK_LIB([m], [round])

AC_CHECK_LIB([pthread], [pthread_create])

AC_CHECK_LIB([ssl], [BIO_new_ssl])


if test "x$prefix" = "xNONE"; then
   prefix="/usr/local"
fi

if test "x$PKG_CONFIG_PATH" = x
then
   export PKG_CONFIG_PATH="$prefix/lib/pkgconfig"
else
   export PKG_CONFIG_PATH="$prefix/lib/pkgconfig:$PKG_CONFIG_PATH"
fi

PKG_CHECK_MODULES([MONGOC],[libmongoc-1.0],[],[])

# AC_SEARCH_LIBS(mongoc-1.0,[], [AC_ERROR[Could not find libmongoc-1.0]])
# AC_SEARCH_LIBS(libbson-1.0,[], [AC_ERROR[Could not find libbson-1.0]])


# Checks for header files.
AC_CHECK_HEADERS([cJSON.h arpa/inet.h fcntl.h inttypes.h limits.h mach/mach.h malloc.h netdb.h netinet/in.h stddef.h stdint.h stdlib.h string.h sys/socket.h sys/time.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL
AC_C_INLINE
AC_TYPE_INT64_T
AC_TYPE_OFF_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UID_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T
AC_CHECK_TYPES([ptrdiff_t])

# Checks for library functions.
AC_FUNC_FORK
AC_FUNC_FSEEKO
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_CHECK_FUNCS([clock_gettime dup2 gettimeofday localtime_r memchr memmove memset rmdir select socket strcasecmp strchr strcspn strdup strerror strndup strrchr strspn strstr strtol strtoul strtoull uname])

AC_OUTPUT
