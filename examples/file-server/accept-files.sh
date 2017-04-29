#!/bin/sh
# Accept files from remote users.

ROOT="/srv/tlsd/files"
USERDIR="${ROOT}/${ALIAS}"

if read -r LINE
then if   [ -d "${USERDIR}" ]
     then cat > "${USERDIR}/$(echo "${LINE}" | sed -e 's/\.\.//g')"
     else echo "No directory for you!"
     fi
fi
