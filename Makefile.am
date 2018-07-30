bin_PROGRAMS = mud_manager mud_test_client

noinst_HEADERS = acl.h log.h sessions.h acl_types.h cisco_dacl.h \
                 mud_fs_client.h

dist_bin_SCRIPTS = dbtools/mud_clobber_db dbtools/mud_show_db

AM_CPPFLAGS = -I$(top_srcdir) $(M_CPPFLAGS) -I$(srcdir)/civetweb

mud_manager_SOURCES = mud_manager.c log.c sessions.c acl_types.c \
		      cisco_dacl.c mud_fs_client.c \
		      civetweb/civetweb.c civetweb/civetweb.h
nodist_mud_manager_SOURCES = config.status config.cache config.log \
			     configure.lineno config.status.lineno

mud_test_client_SOURCES = mud_test_client.c

EXTRA_DIST = APIDOCS.txt LICENSE mud_manager_conf.json examples README.md \
       civetweb/md5.inl civetweb/sha1.inl civetweb/handle_form.inl \
       civetweb/timer.inl


AM_CFLAGS = -DMG_ENABLE_SSL -Wall -W

install-data-local:
	if ! test -e ${sysconfdir}/mud_manager_conf.json ; then \
	    $(MKDIR_P) "${sysconfdir}" || exit 1; \
	    chmod u+rwx,go+rx "${sysconfdir}" || exit 1; \
	    ${INSTALL_DATA} $(srcdir)/mud_manager_conf.json ${sysconfdir}/mud_manager_conf.json; \
	fi

uninstall-local:
	rm -f ${sysconfdir}/mud_manager_conf.json
