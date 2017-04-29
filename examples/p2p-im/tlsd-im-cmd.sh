#!/bin/sh

create_fifo () {
    if [ ! -e "${CHATDIR}${SHA256}/$1" ]
    then mkfifo -m 660 "${CHATDIR}${SHA256}/$1"
    fi
}

CHATDIR="/var/lib/tlsd-im/"
mkdir -m 770 -p "${CHATDIR}${SHA256}/"
create_fifo "in"
create_fifo "out"
flock -n "${CHATDIR}${SHA256}/lock" std2fifo -c "${CHATDIR}"
