#!/bin/sh
# Basic authentication test. The test is slow and unreliable: it uses
# `sleep` where something like `expect` would be more suitable,
# doesn't perform any checks except for the final one, the port is
# hardcoded, etc. And maybe it would be easier to just rewrite it in
# C. But including this for now, since there is nothing else yet, and
# it still may be useful for testing.

builddir="${builddir:-.}"
TLSD="${builddir}/tlsd"
certdir="${certdir:-.}"
result=1

quit () {
    rm -f client-cmd-out
    kill %1 %2
    exit $result
}
trap quit EXIT

mkfifo client-cmd-out
# Run the server
${TLSD} -k "${certdir}/test-key-1.pem" -c "${certdir}/test-cert-1.pem" \
        -i tlsd-test-server -p 45678 -- \
        sh -c 'echo "${SIDE} talks to ${SHA256}"' </dev/null &
sleep 10
# Run the client, connect to the server
echo 'localhost 45678' \
    | ${TLSD} -k "${certdir}/test-key-2.pem" -c "${certdir}/test-cert-2.pem" \
              -i tlsd-test-client -- sh -c \
              '( echo "${SIDE} talks to ${SHA256}" && cat ) > client-cmd-out' &
sleep 10
# Check the output
diff client-cmd-out - << EOF
CLIENT talks to 70ec32556b3682681bd45d32609cfaa13391b69a5994c5cc3b8d2b249085cd0a
SERVER talks to c287d5c79baf7eb44756f5cad81d2f84402c57dcdf2957d70c0b11d05cbf5f80
EOF
result=$?
