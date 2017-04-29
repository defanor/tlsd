#!/bin/sh

CHATDIR="/var/lib/tlsd-im/"

for DIR in $(find "${CHATDIR}" -maxdepth 1 -mindepth 1 -type d)
do  if [ -f "${DIR}/address" ]
    then flock -n "${DIR}/lock" cat "${DIR}/address" > "${CHATDIR}connect"
    fi
done
