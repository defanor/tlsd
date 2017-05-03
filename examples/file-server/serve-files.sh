#!/bin/sh
# Serves a single file and exits.

ROOT="/srv/tlsd/files"

if   read -r LINE
then echo "${SHA256}: ${LINE}" 1>&2
     FILEPATH="${ROOT}/$(echo "${LINE}" | sed -e 's/\.\.//g')"
     if   [ -f "${FILEPATH}" ]
     then cat "${FILEPATH}"
     else echo "${FILEPATH} is not a file"
     fi
fi
