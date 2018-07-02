bin_PROGRAMS = mud_manager 
noinst_PROGRAMS = test_client
#sysconf_DATA = mud_manager_conf.json

AM_CPPFLAGS = -I$(top_srcdir) $(M_CPPFLAGS)

mud_manager_SOURCES = mud_manager.c log.c sessions.c
nodist_mud_manager_SOURCES = mongoose.c config.status config.cache config.log \
				configure.lineno config.status.lineno

test_client_SOURCES = test_client.c
nodist_test_client_SOURCES = mongoose.c

EXTRA_DIST = log.h README_MUD_Controller.txt mudctrl_config.json APIDOCS.txt LICENSE mud_manager_conf.json

AM_CFLAGS = -DMG_ENABLE_SSL -Wall -W

install-data-local:
	if ! test -e ${sysconfdir}/mud_manager_conf.json ; then \
	    ${INSTALL_DATA} ${sysconfdir}/mud_manager_conf.json; \
	fi
