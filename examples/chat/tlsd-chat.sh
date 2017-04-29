#!/bin/sh

NAME="${ALIAS}[$$]"

quit () {
    echo "$(date -u +%R) * ${NAME} quits" | nc localhost 7000
}
trap quit EXIT

JOINMSG="$(date -u +%R) * ${NAME} joins"
echo "${JOINMSG}"
echo "${JOINMSG}" | nc localhost 7000
while read -r LINE
do    echo "$(date -u +%R) ${NAME}: ${LINE}"
done  | stdbuf -oL tr -d '\000-\011\013-\037' | nc localhost 7000
