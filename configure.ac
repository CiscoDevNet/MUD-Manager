# Copyright (c) 2017-2018 by Cisco Systems, Inc.
# All rights reserved.

AC_INIT([MUD Manager], 1.0)
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_AUX_DIR(config)
AM_INIT_AUTOMAKE(foreign)
AC_PROG_CC
AC_CONFIG_FILES(Makefile)

#
# Libcrypto is required
#

AC_ARG_WITH(ssl-dir,
	[  --with-ssl-dir=PATH     Specify path to OpenSSL installation ],
	[  if test "x$withval" = "xno" ; then
    	       echo "OpenSSL is required"; exit 1
	   else
		ssldir=$withval
	   fi
	]
)

saved_LIBS="$LIBS"
saved_LDFLAGS="$LDFLAGS"
saved_CPPFLAGS="$CPPFLAGS"

if test "x$ssldir" != "x" ; then
    # Try to use $ssldir/lib if it exists, otherwise just $ssldir 
    if test -d "$ssldir/lib" ; then
        LDFLAGS="-L$ssldir/lib $saved_LDFLAGS"
    else
        LDFLAGS="-L$ssldir $saved_LDFLAGS"
    fi
    # Try to use $ssldir/include if it exists, otherwise just $ssldir
    if test -d "$ssldir/include" ; then
        CPPFLAGS="-I$ssldir/include $saved_CPPFLAGS"
    else
        CPPFLAGS="-I$ssldir $saved_CPPFLAGS"
    fi
    LIBS="$savedLIBS -lssl -lcrypto"
else
# Search for openssl and crypto libraries in standard paths
    AC_SEARCH_LIBS([EVP_EncryptInit], [crypto], [], 
                   [AC_MSG_ERROR([unable to find openssl crypto library])]
                  )
    AC_SEARCH_LIBS([SSL_CTX_new], [ssl], [], 
                   [AC_MSG_ERROR([unable to find openssl ssl library])]
                  )
    AC_CHECK_HEADER([openssl/x509v3.h])
fi

#
# Find mongoc
#
AC_ARG_WITH(mongoc,
	    [  --with-mongoc=PATH     Specify path to MongoDB C Driver library ],
	[  if test "x$withval" = "xno" ; then
    	       echo "MongoDB C Driver library is required"; exit 1
	   else
		mongoclibdir=$withval
	   fi
	]
)
saved_LIBS="$LIBS"
saved_CPPFLAGS="$CPPFLAGS"
if test "x$mongoclibdir" = "x" ; then
    # Not given. Check /usr/local
    mongoclibdir=/usr/local/lib
fi
if test ! -d $mongoclibdir ; then
    echo "MongoDB C Driver library directory $mongoclibdir doesn't exist. Where is it?"
    exit 1
fi
#
# Look for the library name (e.g., libmongoc-1.0.<stuff>)
# A temporary hack is to look for libmongoc*.so and hope we get one hit that
# we can play with.
#
if test -f $mongoclibdir/libmongoc*.so ; then
    libname=`basename $mongoclibdir/libmongoc*.so | sed 's/\.so//'`
    shortlibname=`echo $libname | sed 's/lib//'`
#    echo "libname is $libname"
#    echo "shortlibname is $shortlibname"
    LIBS="$saved_LIBS -L$mongoclibdir -l$shortlibname"
fi
#
# Now find the header file.
#
incname=`dirname $mongoclibdir`/include
if test -d $incname/$libname; then 
    CPPFLAGS="$saved_CPPFLAGS -I$incname/$libname"
else
    echo "Could not find mongoc include files in $incname/$libname"
    echo "Where are mongoc include files?"; exit 1
fi

#
# Find bson
#
AC_ARG_WITH(bson,
	    [  --with-bson=PATH     Specify path to bson library ],
	[  if test "x$withval" = "xno" ; then
    	       echo "Bson library is required"; exit 1
	   else
		bsonlibdir=$withval
	   fi
	]
)
saved_LIBS="$LIBS"
saved_CPPFLAGS="$CPPFLAGS"
if test "x$bsonlibdir" = "x" ; then
    # Not given. Check /usr/local
    bsonlibdir=/usr/local/lib
fi
if test ! -d $bsonlibdir ; then
    echo "Bson library directory $bsonlibdir doesn't exist. Where is it?"
    exit 1
fi
#
# Look for the library name (e.g., libbson-1.0.<stuff>)
# A temporary hack is to look for libbson*.so and hope we get one hit that
# we can play with.
#
if test -f $bsonlibdir/libbson*.so ; then
    libname=`basename $bsonlibdir/libbson*.so | sed 's/\.so//'`
    shortlibname=`echo $libname | sed 's/lib//'`
#    echo "libname is $libname"
#    echo "shortlibname is $shortlibname"
    LIBS="$saved_LIBS -L$bsonlibdir -l$shortlibname"
fi
#
# Now find the header file.
#
incname=`dirname $bsonlibdir`/include
if test -d $incname/$libname; then 
    CPPFLAGS="$saved_CPPFLAGS -I$incname/$libname"
else
    echo "Could not find bson include files in $incname/$libname"
    echo "Where are bson include files?"; exit 1
fi

#
# Find cJSON
#
AC_ARG_WITH(cjson,
	    [  --with-cjson=PATH     Specify path to cjson library ],
	[  if test "x$withval" = "xno" ; then
    	       echo "cjson library is required"; exit 1
	   else
		cjsonlibdir=$withval
	   fi
	]
)
saved_LIBS="$LIBS"
saved_CPPFLAGS="$CPPFLAGS"
if test "x$cjsonlibdir" = "x" ; then
    # Not given. Check /usr/local
    cjsonlibdir=/usr/local/lib
fi
if test ! -d $cjsonlibdir ; then
    echo "cjson library directory $cjsonlibdir doesn't exist. Where is it?"
    exit 1
fi
#
# Look for the library name (e.g., libcjson.<stuff>)
# A temporary hack is to look for libcjson.so and hope we get one hit that
# we can play with.
#
if test -f $cjsonlibdir/libcjson.so ; then
    libname=`basename $cjsonlibdir/libcjson.so | sed 's/\.so//'`
    shortlibname=`echo $libname | sed 's/lib//'`
#    echo "libname is $libname"
#    echo "shortlibname is $shortlibname"
    LIBS="$saved_LIBS -L$cjsonlibdir -l$shortlibname"
fi
#
# Now find the header file.
#
incname=`dirname $cjsonlibdir`/include
if test -d $incname/$shortlibname; then 
    CPPFLAGS="$saved_CPPFLAGS -I$incname/$shortlibname"
else
    echo "Could not find cjson include files in $incname/$shortlibname"
    echo "Where are cjson include files?"; exit 1
fi

#
# Find cjson_utils
#
AC_ARG_WITH(cjson_utils,
	    [  --with-cjson-utils=PATH     Specify path to cjson_utils library ],
	[  if test "x$withval" = "xno" ; then
    	       echo "cjson_utils library is required"; exit 1
	   else
		cjson_utilslibdir=$withval
	   fi
	]
)
saved_LIBS="$LIBS"
saved_CPPFLAGS="$CPPFLAGS"
if test "x$cjson_utilslibdir" = "x" ; then
    # Not given. Check /usr/local
    cjson_utilslibdir=/usr/local/lib
fi
if test ! -d $cjson_utilslibdir ; then
    echo "cjson library directory $cjson_utilslibdir doesn't exist. Where is it?"
    exit 1
fi
#
# Look for the library name (e.g., libcjson_utils.<stuff>)
# A temporary hack is to look for libcjson_utils.so and hope we get one hit that
# we can play with.
#
if test -f $cjson_utilslibdir/libcjson_utils.so ; then
    libname=`basename $cjson_utilslibdir/libcjson_utils.so | sed 's/\.so//'`
    shortlibname=`echo $libname | sed 's/lib//'`
#    echo "libname is $libname"
#    echo "shortlibname is $shortlibname"
    LIBS="$saved_LIBS -L$cjson_utilslibdir -l$shortlibname"
fi


#
# Find libcurl
#
AC_ARG_WITH(libcurl,
	    [  --with-libcurl=PATH     Specify path to libcurl],
	[  if test "x$withval" = "xno" ; then
    	       echo "libcurl library is required"; exit 1
	   else
		libcurldir=$withval
	   fi
	]
)
saved_LIBS="$LIBS"
saved_CPPFLAGS="$CPPFLAGS"
if test "x$libcurldir" = "x" ; then
    # Not given. Check /usr/local
    libcurldir=/usr/local/lib
fi
if test ! -d $libcurldir ; then
    echo "libcurl directory $libcurldir doesn't exist. Where is it?"
    exit 1
fi
AC_SEARCH_LIBS([dlopen], [dl], [], 
               [AC_MSG_ERROR([unable to find dl library])]
              )
AC_SEARCH_LIBS([cos], [m], [],
               [AC_MSG_ERROR([unable to find math library])]
              )
AC_SEARCH_LIBS([pthread_create], [pthread], [],
               [AC_MSG_ERROR([unable to find pthread library])]
              )

AC_CHECK_HEADER([pthread.h])

LIBS="$saved_LIBS $LIBS"

AC_OUTPUT
