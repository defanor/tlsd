#!/bin/sh

CHATDIR="/var/lib/tlsd-im/"
mkdir -p "${CHATDIR}"

if [ ! -e "${CHATDIR}connect" ]
then echo foo > /tmp/bar
     mkfifo "${CHATDIR}connect"
fi

tail -f "${CHATDIR}connect" | torify tlsd -p 18765 -- tlsd-im-cmd.sh
