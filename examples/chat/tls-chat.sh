#!/bin/sh
rlwrap gnutls-cli --insecure --x509keyfile ~/.tls/key.pem  \
       --x509certfile ~/.tls/cert.pem "${1}" --port="${2}" \
    | while read -r LINE
do  echo "${LINE}"
    case "${LINE}" in
        *"${USER}"*) printf '\a' ;;
    esac
done
