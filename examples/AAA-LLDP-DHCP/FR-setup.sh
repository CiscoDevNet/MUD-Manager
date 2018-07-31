#!/bin/bash

RADDB=/usr/local/etc/raddb
PATCHDIR=`pwd`

cd ${RADDB};

echo "Patching configuration files"
patch -p0 <${PATCHDIR}/FR-diffs.txt

echo "Adding necessary links"
   (cd mods-enabled; \
    ln -s ../mods-available/rest rest; \
    ln -s ../mods-available/perl perl)
