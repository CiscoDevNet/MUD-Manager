bin_PROGRAMS = mud_manager mud_test_client

include_HEADERS = acl.h log.h sessions.h acl_types.h cisco_dacl.h

dist_bin_SCRIPTS = dbtools/mud_clobber_db dbtools/mud_show_db

AM_CPPFLAGS = -I$(top_srcdir) $(M_CPPFLAGS)

mud_manager_SOURCES = mud_manager.c log.c sessions.c acl_types.c \
		      cisco_dacl.c
nodist_mud_manager_SOURCES = mongoose.c config.status config.cache config.log \
			     configure.lineno config.status.lineno

mud_test_client_SOURCES = mud_test_client.c
nodist_mud_test_client_SOURCES = mongoose.c

EXTRA_DIST = APIDOCS.txt LICENSE mud_manager_conf.json examples

AM_CFLAGS = -DMG_ENABLE_SSL -Wall -W

install-data-local:
	if ! test -e ${sysconfdir}/mud_manager_conf.json ; then \
	    ${INSTALL_DATA} ${sysconfdir}/mud_manager_conf.json; \
	fi
