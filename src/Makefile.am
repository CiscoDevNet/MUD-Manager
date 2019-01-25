
AM_CFLAGS=-I$(top_srcdir) $(M_CPPFLAGS) -DMG_ENABLE_SSL -Wall -W $(MONGOC_CFLAGS) -Icivetweb -I$(includedir)/cjson
LDADD= $(MONGOC_LIBS)



bin_PROGRAMS = mud_manager mud_test_client

mud_manager_SOURCES = mud_manager.c log.c sessions.c acl_types.c \
		      cisco_dacl.c mud_fs_client.c \
		      civetweb/civetweb.c civetweb/civetweb.h


mud_test_client_SOURCES = mud_test_client.c

