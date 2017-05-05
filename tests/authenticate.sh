#!/bin/sh
# Basic authentication test.

builddir="${builddir:-.}"
TLSD="${builddir}/tlsd"
testdir="${testdir:-.}"
result=1

quit () {
    rm -f server-out client-cmd-out
    exit $result
}
trap quit EXIT
mkfifo server-out client-cmd-out

# Run the server
${TLSD} -k "${testdir}/test-key-1.pem" -c "${testdir}/test-cert-1.pem" \
        -e -i tlsd-test-server -- \
        sh -c 'echo "${SIDE} talks to ${SHA256}"' </dev/null 2>server-out &
{ PORT=`${testdir}/wait-for-initialization.sed` || ( kill %1; cat; exit )
  ${TLSD} -k "${testdir}/test-key-2.pem" -c "${testdir}/test-cert-2.pem" \
          -i tlsd-test-client -- sh -c \
          '( echo "${SIDE} talks to ${SHA256}" && cat ) > client-cmd-out' \
          <<<"localhost ${PORT}" &
  diff client-cmd-out - << EOF
CLIENT talks to 70ec32556b3682681bd45d32609cfaa13391b69a5994c5cc3b8d2b249085cd0a
SERVER talks to c287d5c79baf7eb44756f5cad81d2f84402c57dcdf2957d70c0b11d05cbf5f80
EOF
  result=$?
  kill %1 %2
  cat
} < server-out
