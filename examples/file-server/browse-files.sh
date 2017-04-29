#!/bin/sh
# Serves files and directory listings.

ROOT="/srv/tlsd/files"

while read -r LINE
do
    echo "${SHA256}: ${LINE}" 1>&2
    FILEPATH="${ROOT}/$(echo "${LINE}" | sed -e 's/\.\.//g')"
    if   [ -d "${FILEPATH}" ]
    then ls -l "${FILEPATH}"
    elif [ -f "${FILEPATH}" ]
    then cat "${FILEPATH}"
    else echo "${FILEPATH} is neither a file nor a directory";
    fi
done
