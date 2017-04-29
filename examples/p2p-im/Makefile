# This Makefile builds and installs the libpurple plugin.

# Using -Wno-unused-parameter here, since libpurple predefines those
# parameters, and we don't always need them.

# Not using -Werror, since on Debian 9 -pedantic points to an error in
# libpurple/certificate.h.

# C99 is needed to initialize large structures with less boilerplate,
# and glib requires it anyway. GNU extensions are also handy, so using
# gnu99.

CC          = gcc
CFLAGS     += -std=gnu99 -Wall -Wextra -Wno-unused-parameter -pedantic \
		-g -DPURPLE_PLUGINS -fPIC -DPIC -shared \
		`pkg-config --cflags purple glib-2.0`
LDLIBS     += `pkg-config --libs purple glib-2.0`
PLUGIN_DIR  = `pkg-config --variable=plugindir purple`
SOURCES     = libpurple-fifo-plugin.c
PLUGIN_ID   = prpl-defanor-fifo
TARGET      = ${PLUGIN_ID}.so

all:
	${CC} ${CFLAGS} ${SOURCES} ${LDLIBS} -o ${TARGET}

install:
	install ${TARGET} ${PLUGIN_DIR}

uninstall:
	rm -f ${PLUGIN_DIR}/${TARGET}

clean:
	rm -f ${TARGET}
