
AM_CPPFLAGS = \
	-I$(srcdir) \
	$(ADD_THESE_DEFINES)


libgenauthz_htaccess_la_LDFLAGS = -avoid-version -lgenauthz_core -lhtaccess

plugindir = $(MODULEDIR)
plugin_LTLIBRARIES = libgenauthz_htaccess.la

libgenauthz_htaccess_la_SOURCES = \
	genauthz_htaccess_main.c

